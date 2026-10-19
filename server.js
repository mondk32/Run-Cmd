// Bash runner cho Render. Không cần thư viện ngoài.
// ENV: API_KEY (>=16 ký tự) hoặc API_KEY_SHA256, tuỳ chọn: TIMEOUT_MS, MAX_OUTPUT, MAX_CONCURRENT, ALLOW_INTERPRETERS=1
const http = require('http');
const crypto = require('crypto');
const { spawn } = require('child_process');

const PORT = Number(process.env.PORT) || 10000;
const TIMEOUT_MS = Number(process.env.TIMEOUT_MS) || 20000;
const MAX_OUTPUT = Number(process.env.MAX_OUTPUT) || 20000;
const MAX_CONCURRENT = Number(process.env.MAX_CONCURRENT) || 3;
const ALLOW_INTERPRETERS = process.env.ALLOW_INTERPRETERS === '1';

// ---------- API key ----------
const sha = (s) => crypto.createHash('sha256').update(s).digest();
let EXPECTED;
if (process.env.API_KEY_SHA256) {
  EXPECTED = Buffer.from(process.env.API_KEY_SHA256.trim(), 'hex');
  if (EXPECTED.length !== 32) { console.error('API_KEY_SHA256 phải là 64 ký tự hex'); process.exit(1); }
} else if (process.env.API_KEY && process.env.API_KEY.length >= 16) {
  EXPECTED = sha(process.env.API_KEY);
} else {
  console.error('Thiếu API_KEY (>=16 ký tự) hoặc API_KEY_SHA256');
  process.exit(1);
}
delete process.env.API_KEY;
delete process.env.API_KEY_SHA256;

function keyOk(provided) {
  if (!provided) return false;
  return crypto.timingSafeEqual(sha(provided), EXPECTED);
}

// ---------- Chặn brute-force + rate limit ----------
const fails = new Map();   // ip -> {n, until}
const hits = new Map();    // ip -> [timestamps]
const MAX_FAILS = 5, BLOCK_MS = 15 * 60 * 1000, RATE_PER_MIN = 30;

function clientIp(req) {
  const xf = req.headers['x-forwarded-for'];
  return (xf ? xf.split(',')[0].trim() : req.socket.remoteAddress) || 'unknown';
}
function isBlocked(ip) {
  const f = fails.get(ip);
  return f && f.until && f.until > Date.now();
}
function recordFail(ip) {
  const f = fails.get(ip) || { n: 0, until: 0 };
  f.n += 1;
  if (f.n >= MAX_FAILS) { f.until = Date.now() + BLOCK_MS; f.n = 0; }
  fails.set(ip, f);
}
function rateLimited(ip) {
  const now = Date.now();
  const arr = (hits.get(ip) || []).filter((t) => now - t < 60000);
  arr.push(now);
  hits.set(ip, arr);
  return arr.length > RATE_PER_MIN;
}
setInterval(() => {
  const now = Date.now();
  for (const [ip, f] of fails) if (!f.until || f.until < now) if (f.n === 0) fails.delete(ip);
  for (const [ip, a] of hits) if (!a.some((t) => now - t < 60000)) hits.delete(ip);
}, 60000).unref();

// ---------- Chính sách lệnh: cấm tạo file / tải về ----------
const BLOCKED_WORDS = new Set([
  // tạo / ghi / xoá / đổi file
  'tee', 'touch', 'mkdir', 'mktemp', 'cp', 'mv', 'dd', 'ln', 'truncate', 'install', 'rsync',
  'tar', 'unzip', 'zip', 'gzip', 'gunzip', 'bzip2', 'xz', 'rm', 'rmdir', 'chmod', 'chown', 'shred',
  // tải về / mạng
  'curl', 'wget', 'aria2c', 'git', 'pip', 'pip3', 'npm', 'npx', 'yarn', 'pnpm',
  'apt', 'apt-get', 'apk', 'dpkg', 'nc', 'ncat', 'netcat', 'socat', 'ssh', 'scp', 'sftp', 'ftp', 'telnet',
  // thoát khỏi bộ lọc / hệ thống
  'eval', 'exec', 'source', 'sudo', 'su', 'mount', 'crontab', 'at', 'nohup', 'kill', 'pkill', 'killall', 'xargs',
]);
const INTERPRETER_RE = /^(python[\d.]*|perl|ruby|php|node(js)?|deno|bun|lua|tclsh|gcc|cc|make)$/;

function checkCommand(cmd) {
  if (cmd.includes('\0')) return 'ký tự không hợp lệ';
  // bỏ quote và backslash để chống t''ouch, t\ouch
  const flat = cmd.replace(/['"\\]/g, '');

  // redirect ghi file: cho phép >/dev/null và 2>&1
  const noSafeRedirect = flat
    .replace(/\d*>>?\s*\/dev\/(null|stdout|stderr)\b/g, '')
    .replace(/\d*>&\d/g, '');
  if (/>/.test(noSafeRedirect)) return 'không cho phép ghi file (>, >>)';

  if (/\/dev\/(tcp|udp)\//.test(flat)) return 'không cho phép truy cập mạng';
  if (/\/proc\b|\benviron\b/.test(flat)) return 'không cho phép đọc /proc';
  if (/\bsed\b[^|;&]*\s-[a-zA-Z]*i/.test(flat)) return 'không cho phép sed -i';
  if (/\s-(exec|execdir|delete|fprint|fprintf|fls|ok)\b/.test(flat)) return 'không cho phép find -exec/-delete';
  if (/\bsystem\s*\(/.test(flat)) return 'không cho phép system()';

  const tokens = flat.match(/[A-Za-z0-9_.\/-]+/g) || [];
  for (const t of tokens) {
    const base = t.split('/').pop();
    if (BLOCKED_WORDS.has(base)) return `lệnh "${base}" bị cấm (tạo file / tải về)`;
    if (!ALLOW_INTERPRETERS && INTERPRETER_RE.test(base)) return `"${base}" bị cấm (có thể tạo file / tải về)`;
  }
  return null;
}

// ---------- Chạy bash thật ----------
let running = 0;
function runBash(command, timeoutMs) {
  return new Promise((resolve) => {
    running++;
    const child = spawn('bash', ['--noprofile', '--norc', '-c', command], {
      cwd: '/tmp',
      detached: true,
      stdio: ['ignore', 'pipe', 'pipe'],
      // env sạch: không để lộ key hay biến của Render
      env: { PATH: '/usr/local/bin:/usr/bin:/bin', HOME: '/tmp', LANG: 'C.UTF-8', TERM: 'dumb' },
    });
    let stdout = '', stderr = '', truncated = false, timedOut = false;
    const add = (cur, chunk) => {
      if (cur.length >= MAX_OUTPUT) { truncated = true; return cur; }
      const s = cur + chunk.toString('utf8');
      if (s.length > MAX_OUTPUT) { truncated = true; return s.slice(0, MAX_OUTPUT); }
      return s;
    };
    child.stdout.on('data', (d) => { stdout = add(stdout, d); });
    child.stderr.on('data', (d) => { stderr = add(stderr, d); });
    const timer = setTimeout(() => {
      timedOut = true;
      try { process.kill(-child.pid, 'SIGKILL'); } catch (_) {}
    }, timeoutMs);
    const done = (code) => {
      clearTimeout(timer);
      running--;
      resolve({ exit_code: code, stdout, stderr, timed_out: timedOut, truncated });
    };
    child.on('close', (code) => done(code));
    child.on('error', (e) => { stderr += e.message; done(-1); });
  });
}

// ---------- HTTP ----------
function send(res, status, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Content-Length': Buffer.byteLength(body) });
  res.end(body);
}

const server = http.createServer((req, res) => {
  const url = (req.url || '').split('?')[0];

  if (req.method === 'GET' && url === '/health') {
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    return res.end('ok');
  }
  if (!(req.method === 'POST' && url === '/run')) return send(res, 404, { error: 'not_found' });

  const ip = clientIp(req);
  if (isBlocked(ip)) return send(res, 429, { error: 'ip_blocked' });

  // Kiểm tra key TRƯỚC khi đọc body: sai key là dừng luôn
  const auth = req.headers['authorization'] || '';
  const provided = auth.startsWith('Bearer ') ? auth.slice(7).trim() : (req.headers['x-api-key'] || '').toString();
  if (!keyOk(provided)) {
    recordFail(ip);
    res.setHeader('Connection', 'close');
    return send(res, 401, { error: 'unauthorized' });
  }

  if (rateLimited(ip)) return send(res, 429, { error: 'rate_limited' });
  if (running >= MAX_CONCURRENT) return send(res, 429, { error: 'busy' });

  let size = 0;
  const chunks = [];
  req.on('data', (c) => {
    size += c.length;
    if (size > 10 * 1024) { send(res, 413, { error: 'body_too_large' }); req.destroy(); return; }
    chunks.push(c);
  });
  req.on('end', async () => {
    if (res.writableEnded) return;
    let body;
    try { body = JSON.parse(Buffer.concat(chunks).toString('utf8')); }
    catch { return send(res, 400, { error: 'invalid_json' }); }

    const command = body && body.command;
    if (typeof command !== 'string' || !command.trim() || command.length > 4000) {
      return send(res, 400, { error: 'command phải là chuỗi 1-4000 ký tự' });
    }
    const reason = checkCommand(command);
    if (reason) return send(res, 403, { error: 'blocked', reason });

    const t = Math.min(Number(body.timeout_ms) || TIMEOUT_MS, TIMEOUT_MS);
    const result = await runBash(command, t);
    send(res, 200, result);
  });
});

server.listen(PORT, '0.0.0.0', () => console.log('bash runner listening on', PORT));
