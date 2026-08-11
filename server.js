/**
 * BioAgent Backend - Slurm 集群桥接服务
 */
const express    = require('express');
const { Client } = require('ssh2');
const path       = require('path');
const fs         = require('fs');
const crypto     = require('crypto');

const CONFIG_FILE = path.join(__dirname, 'cluster.config.json');
const PID_FILE    = path.join(__dirname, 'server.pid');
const PORT        = process.env.PORT || 3000;
// 只监听本机回环地址；如需局域网访问，可设置环境变量 HOST=0.0.0.0
const HOST = process.env.HOST || '127.0.0.1';

/* ── 配置读写 ── */
let config = {};
try {
  if (fs.existsSync(CONFIG_FILE)) {
    const raw = JSON.parse(fs.readFileSync(CONFIG_FILE, 'utf8'));
    // 只保留非敏感信息；SSH 密码永不落盘，重启后需重新输入
    config = { host: raw.host || '', port: raw.port || 22, username: raw.username || '' };
  }
} catch (_) {}

function saveConfig(c) {
  config = c;
  fs.writeFileSync(CONFIG_FILE, JSON.stringify({ host: c.host, port: c.port || 22, username: c.username }, null, 2));
}

/* ── 会话鉴权：登录成功后签发随机令牌，所有监控接口需携带 ── */
const sessions = new Map(); // token -> 过期时间(ms)，每次访问滑动续期
const MAX_SESSIONS = 32;
const SESSION_TTL_MS = 12 * 60 * 60 * 1000;

function pruneSessions() {
  const now = Date.now();
  for (const [t, exp] of sessions) if (exp <= now) sessions.delete(t);
}

function issueToken() {
  pruneSessions();
  if (sessions.size >= MAX_SESSIONS) {
    const oldest = sessions.keys().next().value;
    if (oldest) sessions.delete(oldest);
  }
  const token = crypto.randomBytes(32).toString('hex');
  sessions.set(token, Date.now() + SESSION_TTL_MS);
  return token;
}

/* ── 登录/测试接口限流：防止局域网内对 SSH 口令做暴力尝试 ── */
const authThrottle = new Map(); // ip -> 尝试时间戳列表
const THROTTLE_MAX = 8;
const THROTTLE_WINDOW_MS = 60 * 1000;

function throttled(key) {
  const now = Date.now();
  if (authThrottle.size > 1000) {
    for (const [k, v] of authThrottle) {
      const live = v.filter(t => now - t < THROTTLE_WINDOW_MS);
      if (live.length) authThrottle.set(k, live); else authThrottle.delete(k);
    }
  }
  const arr = (authThrottle.get(key) || []).filter(t => now - t < THROTTLE_WINDOW_MS);
  if (arr.length >= THROTTLE_MAX) { authThrottle.set(key, arr); return true; }
  arr.push(now);
  authThrottle.set(key, arr);
  return false;
}

function bearerToken(req) {
  const h = req.headers.authorization || '';
  return h.startsWith('Bearer ') ? h.slice(7).trim() : '';
}

function setupTokenOk(req) {
  // 管理员可通过环境变量 SETUP_TOKEN 为“首次初始化”加一道口令：
  // 未设置时保持原有行为（仅监听回环地址，风险可控）。
  const expected = process.env.SETUP_TOKEN;
  if (!expected) return true;
  const provided = String((req.body || {}).setupToken || '');
  const a = crypto.createHash('sha256').update(String(provided)).digest();
  const b = crypto.createHash('sha256').update(String(expected)).digest();
  return crypto.timingSafeEqual(a, b);
}

function auth(req, res, next) {
  const t = bearerToken(req);
  if (t) {
    const exp = sessions.get(t);
    if (exp && exp > Date.now()) {
      sessions.set(t, Date.now() + SESSION_TTL_MS); // 每次访问顺延过期时间
      req.token = t;
      return next();
    }
    if (exp) sessions.delete(t);
  }
  return res.status(401).json({ error: 'unauthorized' });
}

/* ── SSH 基础 ── */
const SSH_OPTS = () => ({
  host: config.host, port: config.port || 22,
  username: config.username, password: config.password,
  readyTimeout: 10000, keepaliveInterval: 10000, keepaliveCountMax: 3,
});

function requireConfig(opts) {
  const o = opts || SSH_OPTS();
  if (!o.host || !o.username || !o.password)
    throw new Error('Cluster not configured');
}

/**
 * 单条命令：开一条连接执行
 */
function sshExec(cmd, timeoutMs = 30000, opts) {
  return new Promise((resolve, reject) => {
    try { requireConfig(opts); } catch (e) { return reject(e); }
    const conn = new Client();
    let stdout = '', stderr = '';
    const MARKER = '___BIOAGENT_OUT___';
    const timer = setTimeout(() => { conn.end(); reject(new Error('SSH timeout')); }, timeoutMs);
    conn.on('ready', () => {
      conn.exec(`echo '${MARKER}'; ${cmd}`, { pty: false }, (err, stream) => {
        if (err) { clearTimeout(timer); conn.end(); return reject(err); }
        stream.on('close', (code) => {
          clearTimeout(timer); try { conn.end(); } catch (_) {}
          const idx = stdout.indexOf(MARKER);
          if (idx >= 0) stdout = stdout.substring(idx + MARKER.length + 1);
          resolve({ stdout, stderr, code });
        }).on('error', (err) => {
          clearTimeout(timer); try { conn.end(); } catch (_) {}
          reject(err);
        }).on('data', (d) => { stdout += d.toString(); })
          .stderr.on('data', (d) => { stderr += d.toString(); });
      });
    }).on('error', (err) => { clearTimeout(timer); try { conn.end(); } catch (_) {} reject(err); });
    conn.connect(opts || SSH_OPTS());
  });
}

/**
 * 多条命令：只开【一条】SSH 连接，并行跑多个 channel。
 * 返回 { name: { stdout, stderr, code }, ... }
 */
function sshExecMany(cmds, timeoutMs = 40000, opts) {
  return new Promise((resolve, reject) => {
    try { requireConfig(opts); } catch (e) { return reject(e); }
    const conn = new Client();
    const results = {};
    const MARKER = '___BIOAGENT_OUT___';
    const names = Object.keys(cmds);
    let pending = names.length;
    let settled = false;

    const finish = () => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      try { conn.end(); } catch (_) {}
      resolve(results);
    };
    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      try { conn.end(); } catch (_) {}
      // 超时：未完成的部分标记错误，其余保留
      for (const n of names) if (!results[n]) results[n] = { stdout: '', stderr: 'SSH timeout', code: -1 };
      reject(new Error('SSH timeout'));
    }, timeoutMs);

    conn.on('ready', () => {
      for (const n of names) {
        conn.exec(`echo '${MARKER}'; ${cmds[n]}`, { pty: false }, (err, stream) => {
          if (err) {
            results[n] = { stdout: '', stderr: err.message, code: -1 };
            if (--pending <= 0) finish();
            return;
          }
          let stdout = '', stderr = '', streamSettled = false;
          stream.on('close', (code) => {
            if (streamSettled) return; streamSettled = true;
            const idx = stdout.indexOf(MARKER);
            if (idx >= 0) stdout = stdout.substring(idx + MARKER.length + 1);
            results[n] = { stdout, stderr, code };
            if (--pending <= 0) finish();
          }).on('error', (err) => {
            if (streamSettled) return; streamSettled = true;
            results[n] = { stdout: '', stderr: err.message, code: -1 };
            if (--pending <= 0) finish();
          }).on('data', (d) => { stdout += d.toString(); })
            .stderr.on('data', (d) => { stderr += d.toString(); });
        });
      }
    }).on('error', (err) => {
      if (settled) return;
      settled = true; clearTimeout(timer);
      try { conn.end(); } catch (_) {}
      reject(err);
    }).on('close', () => {
      // 连接意外断开：未完成的部分标记错误
      if (settled) return;
      for (const n of names) if (!results[n]) results[n] = { stdout: '', stderr: 'SSH connection closed', code: -1 };
      finish();
    });
    conn.connect(opts || SSH_OPTS());
  });
}

/* ── 输出解析（供各 API 复用） ── */

function parseSinfo(stdout) {
  const partitions = {};
  stdout.trim().split('\n').filter(Boolean).forEach(line => {
    const cols = line.split('\x1f');
    if (cols.length < 7) return;
    const [part, nodes, allocIdle, state, nodelist, cpus, mem] = cols;
    const [a, i] = (allocIdle || '0/0').split('/').map(Number);
    if (!partitions[part]) partitions[part] = { name: part, totalNodes: 0, totalAlloc: 0, totalIdle: 0, states: {}, cpus, mem };
    const p = partitions[part];
    p.totalNodes += parseInt(nodes) || 0; p.totalAlloc += a; p.totalIdle += i;
    p.states[state] = (p.states[state] || 0) + (parseInt(nodes) || 0);
  });
  return { partitions: Object.values(partitions) };
}

function classifyNodeState(st) {
  const s = String(st || '').toUpperCase();
  if (s.startsWith('IDLE')) return 'idle';
  if (s.startsWith('MIX')) return 'mixed';
  if (s.startsWith('ALLOC')) return 'alloc';
  if (s.startsWith('DOWN') || s.startsWith('DRAIN') || s.startsWith('FAIL') ||
      s.startsWith('NOT_RESPONDING') || s.startsWith('MAINT') || s.startsWith('POWER')) return 'down';
  return 'other';
}

function parseNodes(stdout) {
  const blocks = stdout.split('\n\n').filter(b => b.trim());
  const nodes = blocks.map(block => {
    const get = (key) => { const m = block.match(new RegExp('\\b' + key + '=([^\\s]+)')); return m ? m[1] : ''; };
    const cpuAlloc = parseInt(get('CPUAlloc')) || 0, cpuTot = parseInt(get('CPUTot')) || 0;
    const allocMem = parseInt(get('AllocMem')) || 0, realMem = parseInt(get('RealMemory')) || 0, freeMem = parseInt(get('FreeMem')) || 0;
    // SLURM 对无 GPU 的节点输出 Gres=(null)，统一归为 'none'
    const rawGres = get('Gres');
    const gres = (rawGres && rawGres !== '(null)' && rawGres !== 'none') ? rawGres : 'none';
    const rawGresUsed = get('GresUsed');
    const gresUsed = (rawGresUsed && rawGresUsed !== '(null)') ? rawGresUsed : '';
    return {
      name: get('NodeName'),
      cpuAlloc, cpuTot,
      cpuUtil: cpuTot > 0 ? Math.round(cpuAlloc / cpuTot * 100) : 0,
      realMemory: realMem, allocMem, freeMem,
      memUtil: realMem > 0 ? Math.round(allocMem / realMem * 100) : 0,
      state: get('State'),
      partitions: get('Partitions'),
      gres, gresUsed,
      cpuLoad: parseFloat(get('CPULoad')) || 0,
      arch: get('Arch'),
      os: get('OS'),
      sockets: get('Sockets'),
      coresPerSocket: get('CoresPerSocket'),
      threadsPerCore: get('ThreadsPerCore'),
      nodeAddr: get('NodeAddr'),
      nodeHostname: get('NodeHostname'),
    };
  });
  const summary = nodes.reduce((acc, n) => {
    acc.totalCpu += n.cpuTot; acc.allocCpu += n.cpuAlloc; acc.totalMem += n.realMemory; acc.allocMem += n.allocMem;
    const c = classifyNodeState(n.state);
    if (c === 'idle') acc.idleCount++;
    else if (c === 'mixed') acc.mixedCount++;
    else if (c === 'alloc') acc.allocCount++;
    else if (c === 'down') acc.downCount++;
    else acc.otherCount++;
    return acc;
  }, { totalCpu: 0, allocCpu: 0, totalMem: 0, allocMem: 0, idleCount: 0, mixedCount: 0, allocCount: 0, downCount: 0, otherCount: 0 });
  return { nodes, summary };
}

function parseSqueue(stdout) {
  const jobs = stdout.trim().split('\n').filter(Boolean).map(line => {
    const cols = line.split('\x1f'); const [jobid, partition, name, state, time, nodes, reason, gpu] = cols;
    return { jobid, partition, name, state: (state || '').trim(), time, nodes, reason, gpu: gpu || '' };
  });
  const pending = jobs.filter(j => j.state === 'PD').length;
  const running = jobs.filter(j => j.state === 'R').length;
  return { jobs, pending, running };
}

function parseDf(stdout) {
  const lines = stdout.trim().split('\n');
  const mounts = lines.slice(1).filter(line => {
    const cols = line.split(/\s+/); const fsType = cols[0] || ''; const mnt = cols[cols.length - 1] || '';
    return !fsType.startsWith('tmpfs') && !fsType.startsWith('devtmpfs') && !fsType.startsWith('squashfs') && !mnt.startsWith('/dev') && !mnt.startsWith('/boot') && !mnt.startsWith('/snap') && !mnt.startsWith('/run') && !mnt.startsWith('/sys') && !mnt.startsWith('/proc');
  }).map(line => {
    const cols = line.split(/\s+/); return { filesystem: cols[0] || '', size: cols[1] || '', used: cols[2] || '', avail: cols[3] || '', usePct: cols[4] || '', mounted: cols[5] || '' };
  });
  return { mounts };
}

function parseFree(stdout) {
  const line = stdout.trim().split('\n').find(l => l.startsWith('Mem:'));
  if (!line) return { error: 'free parse failed' };
  const cols = line.split(/\s+/);
  return { total: cols[1] || '', used: cols[2] || '', free: cols[3] || '', available: cols[6] || '' };
}

/* squeue：优先带 %b（每节点 TRES，含 GPU）；老版本不支持 %b 时自动降级重试 */
async function runSqueue(user) {
  const fmt = '%.8i\x1f%.10P\x1f%.12j\x1f%.2t\x1f%.10M\x1f%.4D\x1f%R\x1f%b';
  const run = (f) => sshExec(`squeue -u "${user}" -o "${f}" --noheader 2>&1`, 15000);
  let r = await run(fmt);
  if (r.code !== 0 && /unknown format specifier|invalid format/i.test(String(r.stdout) + String(r.stderr))) {
    r = await run('%.8i\x1f%.10P\x1f%.12j\x1f%.2t\x1f%.10M\x1f%.4D\x1f%R');
  }
  return r;
}

/* ── Express ── */
const app = express();
app.disable('x-powered-by');
app.use(express.json({ limit: '32kb' }));

// 只暴露前端需要的静态文件，绝不暴露 server.js / package.json / cluster.config.json / node_modules
app.get('/', (_req, res) => res.redirect('/cluster.html'));
app.get('/cluster.html', (_req, res) => res.set('Cache-Control', 'no-store').sendFile(path.join(__dirname, 'cluster.html')));
app.get('/logo.png', (_req, res) => res.sendFile(path.join(__dirname, 'logo.png')));
// 本地图标库（离线可用）
app.use('/vendor', express.static(path.join(__dirname, 'vendor')));

app.get('/api/health', (_req, res) => res.json({ ok: true }));

/**
 * 登录：验证 SSH 凭据后把配置保存在内存并签发会话令牌。
 * - 首次启动（尚无任何会话）时免令牌，用于初始化；
 * - 已有会话时必须携带有效令牌才能修改配置。
 * SSH 密码只存在于内存，绝不写入 cluster.config.json。
 */
function validateLoginBody(body) {
  const { host, port, username, password } = body || {};
  const cleanHost = String(host || '').trim();
  const cleanUser = String(username || '').trim();
  const cleanPass = String(password || '');
  const cleanPort = parseInt(port, 10) || 22;

  if (!/^[A-Za-z0-9._\-\[\]:]+$/.test(cleanHost)) return { error: '集群地址格式不正确' };
  if (cleanPort < 1 || cleanPort > 65535) return { error: '端口无效' };
  if (!/^[A-Za-z0-9._\-]+$/.test(cleanUser)) return { error: 'SSH 用户名格式不正确' };
  if (!cleanPass) return { error: 'SSH 密码不能为空' };
  return { candidate: { host: cleanHost, port: cleanPort, username: cleanUser, password: cleanPass } };
}

async function testCredentials(candidate) {
  // 真实连接测试：验证 hostname/whoami/sinfo 均可用
  const r = await sshExec('hostname && whoami && sinfo --version 2>&1', 15000, candidate);
  if (r.code !== 0) throw new Error(r.stderr || r.stdout || 'exit ' + r.code);
  return r.stdout.split('\n')[0].trim();
}

function isSameCluster(a, b) {
  if (!b || !b.host) return false;
  return String(a.host).toLowerCase() === String(b.host).toLowerCase() &&
         (a.port || 22) === (b.port || 22) &&
         String(a.username) === String(b.username);
}

app.post('/api/slurm/login', async (req, res) => {
  if (throttled(req.ip)) return res.status(429).json({ error: '尝试过于频繁，请稍后再试' });
  const v = validateLoginBody(req.body);
  if (v.error) return res.status(400).json({ error: v.error });
  const t = bearerToken(req);
  const authed = t && sessions.has(t);
  const sameCluster = isSameCluster(v.candidate, config);
  // 已有其他会话时：只有“换成一个不同的集群”才需要有效令牌；
  // 用当前已配置集群的相同凭据重新登录（多标签页 / 令牌被淘汰）无需令牌。
  if (sessions.size > 0 && !authed && !sameCluster) {
    return res.status(401).json({ error: '已有其他会话。请先在已登录的标签页操作；如需更换集群，请先退出其他会话后重试' });
  }
  // 首次初始化：若设置了 SETUP_TOKEN，必须先提供正确口令（防止局域网内先到先得）
  if (sessions.size === 0 && !setupTokenOk(req)) {
    return res.status(401).json({ error: '需要正确的初始化口令 (SETUP_TOKEN)' });
  }

  // 先用候选凭据做真实连接测试，成功后才覆盖当前配置并签发会话
  try {
    const hostname = await testCredentials(v.candidate);
    config = v.candidate;
    cachedHomeDir = ''; // 用户可能已更换，必须重新探测 home 目录
    saveConfig(config);
    return res.json({ ok: true, token: issueToken(), hostname });
  } catch (e) {
    return res.json({ ok: false, error: 'SSH 连接失败: ' + e.message });
  }
});

// 仅验证凭据：不修改配置、不签发令牌（供登录页“测试连接”使用）
app.post('/api/slurm/test', async (req, res) => {
  if (throttled(req.ip)) return res.status(429).json({ error: '尝试过于频繁，请稍后再试' });
  const v = validateLoginBody(req.body);
  if (v.error) return res.status(400).json({ error: v.error });
  try {
    const hostname = await testCredentials(v.candidate);
    return res.json({ ok: true, hostname });
  } catch (e) {
    return res.json({ ok: false, error: 'SSH 连接失败: ' + e.message });
  }
});

/* Config */
// 公开返回基础信息（是否已配置、是否需要初始化口令），
// 详细连接信息仅对持有有效令牌的请求返回
app.get('/api/slurm/config', (_req, res) => {
  const t = bearerToken(_req);
  const authed = t && sessions.has(t);
  res.json({
    configured: !!config.host,
    setupTokenRequired: !!process.env.SETUP_TOKEN,
    config: authed ? { host: config.host, port: config.port || 22, username: config.username } : undefined,
  });
});

// 以下其余 /api 接口均需会话令牌；同时禁止浏览器缓存接口响应
app.use('/api', (_req, res, next) => { res.set('Cache-Control', 'no-store'); next(); });
app.use('/api', auth);

app.post('/api/slurm/logout', (req, res) => {
  sessions.delete(req.token);
  res.json({ ok: true });
});

/* sinfo */
app.get('/api/slurm/sinfo', async (_req, res) => {
  try {
    const r = await sshExec('sinfo -o "%P\x1f%D\x1f%A\x1f%t\x1f%N\x1f%c\x1f%m" --noheader 2>&1', 15000);
    if (r.code !== 0) throw new Error(r.stderr || r.stdout);
    res.json(parseSinfo(r.stdout));
  } catch (e) { res.json({ error: e.message }); }
});

/* scontrol */
app.get('/api/slurm/nodes', async (_req, res) => {
  try {
    const r = await sshExec('scontrol show nodes', 20000);
    if (r.code !== 0) throw new Error(r.stderr || r.stdout);
    res.json(parseNodes(r.stdout));
  } catch (e) { res.json({ error: e.message }); }
});

/* squeue */
app.get('/api/slurm/squeue', async (_req, res) => {
  if (!config.username) return res.json({ jobs: [] });
  try {
    const r = await runSqueue(config.username);
    if (r.code !== 0) throw new Error(r.stderr || r.stdout);
    res.json(parseSqueue(r.stdout));
  } catch (e) { res.json({ error: e.message, jobs: [] }); }
});

/* sacctmgr show assoc — 获取账户关联配额 */
app.get('/api/slurm/assoc', async (_req, res) => {
  try {
    const r = await sshExec('sacctmgr show assoc format=User,Account,GrpTRES --noheader --parsable2 2>&1', 15000);
    if (r.code !== 0) throw new Error(r.stderr || r.stdout);
    const lines = r.stdout.trim().split('\n').filter(Boolean);
    const associations = lines.map(line => {
      const cols = line.split('|');
      const user = cols[0] || '';
      const account = cols[1] || '';
      const grpTRES = cols[2] || '';
      // 解析 GrpTRES 字符串: "cpu=800,gres/gpu=4,mem=64G"
      let grpCpus = 0, grpMemMb = 0, grpGpus = 0;
      grpTRES.split(',').forEach(pair => {
        const eqIdx = pair.indexOf('=');
        if (eqIdx < 0) return;
        const k = pair.substring(0, eqIdx).trim();
        const v = pair.substring(eqIdx + 1).trim();
        if (k === 'cpu') grpCpus = parseInt(v) || 0;
        else if (k === 'mem') {
          // mem 可能有单位: 64G, 64000M, 2T
          const val = parseFloat(v) || 0;
          if (/[Gg]/.test(v)) grpMemMb = val * 1024;
          else if (/[Tt]/.test(v)) grpMemMb = val * 1024 * 1024;
          else grpMemMb = val; // 无单位则视为 MB
        }
        else if (k === 'gres/gpu' || k === 'gpu') grpGpus = parseInt(v) || 0;
      });
      return { user, account, grp_cpus: grpCpus, grp_mem: grpMemMb, grp_gpus: grpGpus, grp_tres: grpTRES };
    });
    res.json({ associations });
  } catch (e) { res.json({ error: e.message, associations: [] }); }
});

/* df -h */
app.get('/api/slurm/df', async (_req, res) => {
  try {
    const r = await sshExec('df -h 2>&1', 15000);
    if (r.code !== 0) throw new Error(r.stderr || r.stdout);
    res.json(parseDf(r.stdout));
  } catch (e) { res.json({ error: e.message, mounts: [] }); }
});

/* free -h */
app.get('/api/slurm/free', async (_req, res) => {
  try {
    const r = await sshExec('free -h | grep -v Swap 2>&1', 10000);
    if (r.code !== 0) throw new Error(r.stderr || r.stdout);
    res.json(parseFree(r.stdout));
  } catch (e) { res.json({ error: e.message }); }
});

/* user disk */
app.get('/api/slurm/userdf', async (_req, res) => {
  try {
    const home = await getHomeDir();
    const q = String(home || '').replace(/'/g, `'\\''`);
    const r = await sshExec(`du -sh -- '${q}' 2>&1`, 10000);
    if (r.code !== 0) throw new Error(r.stderr || r.stdout);
    const m = r.stdout.trim().match(/^([\d.]+[KMGTP]?)\s+/);
    res.json({ userDir: home, usage: m ? m[1] : '' });
  } catch (e) { res.json({ error: e.message }); }
});

/**
 * 一键拉全量：一条 SSH 连接搞定所有监控数据，减少集群连接压力
 */
app.get('/api/slurm/all', async (_req, res) => {
  try {
    // du -sh 家目录可能很慢，单独走 /api/slurm/userdf，避免阻塞整页数据
    const [results, squeueR] = await Promise.all([
      sshExecMany({
        sinfo: 'sinfo -o "%P\x1f%D\x1f%A\x1f%t\x1f%N\x1f%c\x1f%m" --noheader 2>&1',
        nodes: 'scontrol show nodes 2>&1',
        df:    'df -h 2>&1',
        free:  'free -h | grep -v Swap 2>&1',
      }, 40000),
      runSqueue(config.username || ''),
    ]);
    results.squeue = squeueR;

    const sec = (name, parser) => {
      const r = results[name];
      if (!r) return { error: 'no result' };
      if (r.code !== 0) return { error: (r.stderr || r.stdout || 'exit ' + r.code) };
      try { return parser(r.stdout); } catch (e) { return { error: e.message }; }
    };

    res.json({
      sinfo:  sec('sinfo', parseSinfo),
      nodes:  sec('nodes', parseNodes),
      squeue: sec('squeue', parseSqueue),
      df:     sec('df', parseDf),
      free:   sec('free', parseFree),
    });
  } catch (e) { res.json({ error: e.message }); }
});

let cachedHomeDir = '';
async function getHomeDir() {
  if (cachedHomeDir) return cachedHomeDir;
  try {
    const r = await sshExec("echo HOME=$HOME 2>/dev/null | grep HOME=", 10000);
    const m = r.stdout.match(/HOME=(\/\S+)/);
    if (m) cachedHomeDir = m[1];
  } catch (_) {}
  if (!cachedHomeDir) cachedHomeDir = config.username ? '/home/' + config.username : '';
  return cachedHomeDir;
}

/* PID 文件：供 BioAgent.vbs 精确关闭自己，避免误杀其它 node 进程 */
try { fs.writeFileSync(PID_FILE, String(process.pid)); } catch (_) {}
process.on('exit', () => { try { fs.unlinkSync(PID_FILE); } catch (_) {} });
process.on('SIGINT', () => { process.exit(0); });

const isLoopback = HOST === '127.0.0.1' || HOST === 'localhost' || HOST === '::1' || HOST === '0:0:0:0:0:0:0:1';

app.listen(PORT, HOST, async () => {
  try { const h = await getHomeDir(); if (h) console.log('  Work dir: ' + h); } catch (_) {}
  console.log('\n=== BioAgent Slurm Bridge v2 ===\n  Frontend: http://localhost:' + PORT + '/cluster.html\n  Cluster: ' + (config.host || 'not configured') + '\n  User: ' + (config.username || 'not configured') + '\n');
  if (!isLoopback && !process.env.SETUP_TOKEN) {
    console.warn('\n  [警告] 正在监听非回环地址(' + HOST + ')且未设置 SETUP_TOKEN，\n' +
      '  首次登录无需口令即可初始化集群配置，局域网内其他人可能抢先接管。\n' +
      '  建议以环境变量 SETUP_TOKEN=<随机口令> 启动，并在登录页填写初始化口令。');
  }
});
