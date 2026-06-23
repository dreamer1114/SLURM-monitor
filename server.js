/**
 * BioAgent Backend - Slurm 集群桥接服务
 */
const express    = require('express');
const { Client } = require('ssh2');
const cors       = require('cors');
const path       = require('path');
const fs         = require('fs');
const crypto     = require('crypto');
const os         = require('os');

const CONFIG_FILE = path.join(__dirname, 'cluster.config.json');
const PORT        = process.env.PORT || 3000;

/* ── 密码加密 ── */
function getMachineKey() {
  const interfaces = os.networkInterfaces();
  let mac = 'unknown';
  for (const name of Object.keys(interfaces)) {
    for (const iface of interfaces[name]) {
      if (!iface.internal && iface.mac && iface.mac !== '00:00:00:00:00:00') {
        mac = iface.mac; break;
      }
    }
    if (mac !== 'unknown') break;
  }
  // 用 MAC 地址 + 固定 salt 派生出 32 字节 AES 密钥
  return crypto.createHash('sha256').update(mac + 'BioAgent_Slurm_Monitor_v1').digest();
}

function encryptPassword(plaintext) {
  if (!plaintext) return '';
  const key = getMachineKey();
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
  let enc = cipher.update(plaintext, 'utf8', 'hex');
  enc += cipher.final('hex');
  return iv.toString('hex') + ':' + enc;
}

function decryptPassword(encrypted) {
  if (!encrypted || !encrypted.includes(':')) return '';
  try {
    const key = getMachineKey();
    const [ivHex, ciphertext] = encrypted.split(':');
    const decipher = crypto.createDecipheriv('aes-256-cbc', key, Buffer.from(ivHex, 'hex'));
    let dec = decipher.update(ciphertext, 'hex', 'utf8');
    dec += decipher.final('utf8');
    return dec;
  } catch (_) { return ''; }
}

/* ── 配置读写 ── */
let config = {};
try {
  if (fs.existsSync(CONFIG_FILE)) {
    const raw = JSON.parse(fs.readFileSync(CONFIG_FILE, 'utf8'));
    if (raw.encrypted) {
      raw.password = decryptPassword(raw.encrypted);
      delete raw.encrypted;
    } else if (raw.password) {
      // 旧格式（明文）→ 自动迁移到加密格式
      saveConfig(raw);
    }
    config = raw;
  }
} catch (_) {}

function saveConfig(c) {
  // 密码加密后才写入文件，内存中仍保留明文
  const toWrite = { host: c.host, port: c.port, username: c.username };
  if (c.password) toWrite.encrypted = encryptPassword(c.password);
  config = c;
  fs.writeFileSync(CONFIG_FILE, JSON.stringify(toWrite, null, 2));
}

/* SSH */
function sshExec(cmd, timeoutMs = 30000) {
  return new Promise((resolve, reject) => {
    if (!config.host || !config.username || !config.password)
      return reject(new Error('Cluster not configured'));
    const conn = new Client();
    let stdout = '', stderr = '';
    const MARKER = '___BIOAGENT_OUT___';
    const timer = setTimeout(() => { conn.end(); reject(new Error('SSH timeout')); }, timeoutMs);
    conn.on('ready', () => {
      conn.exec(`echo '${MARKER}'; ${cmd}`, { pty: false }, (err, stream) => {
        if (err) { clearTimeout(timer); conn.end(); return reject(err); }
        stream.on('close', (code) => {
          clearTimeout(timer); conn.end();
          const idx = stdout.indexOf(MARKER);
          if (idx >= 0) stdout = stdout.substring(idx + MARKER.length + 1);
          resolve({ stdout, stderr, code });
        }).on('data', (d) => { stdout += d.toString(); })
          .stderr.on('data', (d) => { stderr += d.toString(); });
      });
    }).on('error', (err) => { clearTimeout(timer); reject(err); });
    conn.connect({
      host: config.host, port: config.port || 22,
      username: config.username, password: config.password,
      readyTimeout: 10000, keepaliveInterval: 10000, keepaliveCountMax: 3,
    });
  });
}

const app = express();
app.use(cors());
app.use(express.json({ limit: '32kb' }));
app.use(express.static(path.join(__dirname)));

app.get('/api/health', (_req, res) => res.json({ ok: true }));

/* Config */
app.get('/api/slurm/config', (_req, res) => {
  res.json({ configured: !!config.host, config: { host: config.host, port: config.port || 22, username: config.username } });
});
app.post('/api/slurm/config', (req, res) => {
  const { host, port, username, password } = req.body;
  if (!host || !username || !password) return res.status(400).json({ error: 'Missing fields' });
  saveConfig({ host, port: parseInt(port) || 22, username, password });
  res.json({ ok: true });
});
app.post('/api/slurm/test', async (_req, res) => {
  try {
    const r = await sshExec('hostname && whoami && sinfo --version 2>&1', 15000);
    res.json({ ok: r.code === 0, hostname: r.stdout.split('\n')[0].trim(), error: r.stderr || (r.code !== 0 ? 'exit ' + r.code : '') });
  } catch (e) { res.json({ ok: false, error: e.message }); }
});

/* sinfo */
app.get('/api/slurm/sinfo', async (_req, res) => {
  try {
    const r = await sshExec('sinfo -o "%P|%D|%A|%t|%N|%c|%m" --noheader 2>&1', 15000);
    if (r.code !== 0) throw new Error(r.stderr || r.stdout);
    const partitions = {};
    r.stdout.trim().split('\n').filter(Boolean).forEach(line => {
      const cols = line.split('|');
      if (cols.length < 7) return;
      const [part, nodes, allocIdle, state, nodelist, cpus, mem] = cols;
      const [a, i] = (allocIdle || '0/0').split('/').map(Number);
      if (!partitions[part]) partitions[part] = { name: part, totalNodes: 0, totalAlloc: 0, totalIdle: 0, states: {}, cpus, mem };
      const p = partitions[part];
      p.totalNodes += parseInt(nodes) || 0; p.totalAlloc += a; p.totalIdle += i;
      p.states[state] = (p.states[state] || 0) + (parseInt(nodes) || 0);
    });
    res.json({ partitions: Object.values(partitions) });
  } catch (e) { res.json({ error: e.message }); }
});

/* scontrol */
app.get('/api/slurm/nodes', async (_req, res) => {
  try {
    const r = await sshExec('scontrol show nodes', 20000);
    if (r.code !== 0) throw new Error(r.stderr || r.stdout);
    const blocks = r.stdout.split('\n\n').filter(b => b.trim());
    const nodes = blocks.map(block => {
      const get = (key) => { const m = block.match(new RegExp('\\b' + key + '=([^\\s]+)')); return m ? m[1] : ''; };
      const cpuAlloc = parseInt(get('CPUAlloc')) || 0, cpuTot = parseInt(get('CPUTot')) || 0;
      const allocMem = parseInt(get('AllocMem')) || 0, realMem = parseInt(get('RealMemory')) || 0, freeMem = parseInt(get('FreeMem')) || 0;
      return { name: get('NodeName'), cpuAlloc, cpuTot, cpuUtil: cpuTot > 0 ? Math.round(cpuAlloc / cpuTot * 100) : 0, realMemory: realMem, allocMem, freeMem, memUtil: realMem > 0 ? Math.round(allocMem / realMem * 100) : 0, state: get('State'), partitions: get('Partitions'), gres: get('Gres') || 'none', cpuLoad: parseFloat(get('CPULoad')) || 0 };
    });
    const summary = nodes.reduce((acc, n) => {
      acc.totalCpu += n.cpuTot; acc.allocCpu += n.cpuAlloc; acc.totalMem += n.realMemory; acc.allocMem += n.allocMem;
      if (n.state === 'IDLE') acc.idleCount++; else if (n.state.startsWith('MIX')) acc.mixedCount++; else if (n.state === 'DOWN' || n.state === 'DRAIN') acc.downCount++; else acc.otherCount++;
      return acc;
    }, { totalCpu: 0, allocCpu: 0, totalMem: 0, allocMem: 0, idleCount: 0, mixedCount: 0, downCount: 0, otherCount: 0 });
    res.json({ nodes, summary });
  } catch (e) { res.json({ error: e.message }); }
});

/* squeue */
app.get('/api/slurm/squeue', async (_req, res) => {
  if (!config.username) return res.json({ jobs: [] });
  try {
    const r = await sshExec('squeue -u "' + config.username + '" -o "%.8i|%.10P|%.12j|%.2t|%.10M|%.4D|%R|%b" --noheader 2>&1', 15000);
    if (r.code !== 0) throw new Error(r.stderr || r.stdout);
    const jobs = r.stdout.trim().split('\n').filter(Boolean).map(line => {
      const cols = line.split('|'); const [jobid, partition, name, state, time, nodes, reason, gpu] = cols;
      return { jobid, partition, name, state: state.trim(), time, nodes, reason, gpu: gpu || '' };
    });
    const pending = jobs.filter(j => j.state === 'PD').length;
    const running = jobs.filter(j => j.state === 'R').length;
    res.json({ jobs, pending, running });
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
    const lines = r.stdout.trim().split('\n');
    const mounts = lines.slice(1).filter(line => {
      const cols = line.split(/\s+/); const fsType = cols[0] || ''; const mnt = cols[cols.length - 1] || '';
      return !fsType.startsWith('tmpfs') && !fsType.startsWith('devtmpfs') && !fsType.startsWith('squashfs') && !mnt.startsWith('/dev') && !mnt.startsWith('/boot') && !mnt.startsWith('/snap') && !mnt.startsWith('/run') && !mnt.startsWith('/sys') && !mnt.startsWith('/proc');
    }).map(line => {
      const cols = line.split(/\s+/); return { filesystem: cols[0] || '', size: cols[1] || '', used: cols[2] || '', avail: cols[3] || '', usePct: cols[4] || '', mounted: cols[5] || '' };
    });
    res.json({ mounts });
  } catch (e) { res.json({ error: e.message, mounts: [] }); }
});

/* free -h */
app.get('/api/slurm/free', async (_req, res) => {
  try {
    const r = await sshExec('free -h | grep -v Swap 2>&1', 10000);
    if (r.code !== 0) throw new Error(r.stderr || r.stdout);
    const line = r.stdout.trim().split('\n')[1];
    const cols = line.split(/\s+/);
    res.json({ total: cols[1] || '', used: cols[2] || '', free: cols[3] || '', available: cols[6] || '' });
  } catch (e) { res.json({ error: e.message }); }
});

/* user disk */
app.get('/api/slurm/userdf', async (_req, res) => {
  try {
    const home = await getHomeDir();
    const r = await sshExec('du -sh ' + home + ' 2>&1', 20000);
    if (r.code !== 0) throw new Error(r.stderr || r.stdout);
    const m = r.stdout.trim().match(/^([\d.]+[KMGTP]?)\s+/);
    res.json({ userDir: home, usage: m ? m[1] : '' });
  } catch (e) { res.json({ error: e.message }); }
});

/* exec */
app.post('/api/slurm/exec', async (req, res) => {
  const { command } = req.body;
  if (!command || typeof command !== 'string') return res.status(400).json({ error: 'no command' });
  if (command.length > 500) return res.status(400).json({ error: 'too long' });
  const allowed = ['sinfo', 'squeue', 'scontrol', 'sacct', 'hostname', 'whoami', 'sbatch', 'scancel', 'sprio', 'sstat'];
  const cmdBase = command.trim().split(/\s+/)[0];
  if (!allowed.some(a => cmdBase.startsWith(a))) return res.status(403).json({ error: 'not allowed: ' + cmdBase });
  try {
    const r = await sshExec(command, 30000);
    res.json({ stdout: r.stdout, stderr: r.stderr, code: r.code, ok: r.code === 0 });
  } catch (e) { res.json({ ok: false, error: e.message }); }
});

/* ================================
   Pipeline
   ================================ */

const PIPELINE_STEPS = {
  1: {
    name: 'NanoPlot_QC',
    desc: 'NanoPlot long-read QC',
    conda: '/ampha/tenant/fafu/private/user/wjw/miniconda3/envs/nanoplot',
    module: '',
    resources: { cpus: '${threads}', mem: '16G', partition: 'cpu01', time: '02:00:00' },
    // 输入模式: fastq / summary / bam
    scriptBody: (p, mode) => {
      const t = p.threads1 || 20;
      const o = p.out1 || 'nanoplot_out';
      const maxlen = p.maxlen1 || '40000';
      const inp = p.fastq1 || '';
      if (mode === 'summary') {
        return `
mkdir -p ${o}
NanoPlot --summary ${inp} --loglength -o ${o} 2>&1`;
      } else if (mode === 'bam') {
        return `
mkdir -p ${o}
NanoPlot -t ${t} --color yellow --bam ${inp} --downsample 10000 -o ${o} 2>&1`;
      }
      // default: fastq
      return `
mkdir -p ${o}
NanoPlot -t ${t} --fastq ${inp} --maxlength ${maxlen} --plots dot --legacy hex -o ${o} 2>&1`;
    },
    scriptBodyBatch: (p) => {
      const t = p.threads1 || 20;
      const o = p.out1 || 'batch_out';
      const maxlen = p.maxlen1 || '40000';
      const dir = p.dir1 || '';
      const pat = p.pat1 || '*.fastq.gz';
      return [
        'IN_DIR="' + dir + '"',
        'PATTERN="' + pat + '"',
        'OUT_ROOT="' + o + '"',
        'THREADS=' + t,
        'MAXLEN=' + maxlen,
        'echo "[BioAgent] Batch NanoPlot: $IN_DIR/$PATTERN"',
        'FILES=()',
        'while IFS= read -r -d \'\\0\' f; do FILES+=("$f"); done < <(find "$IN_DIR" -maxdepth 1 -type f -name "$PATTERN" -print0 2>/dev/null)',
        'TOTAL=${#FILES[@]}',
        'if [ "$TOTAL" -eq 0 ]; then echo "No files"; exit 1; fi',
        'echo "Found $TOTAL files"',
        'COUNTER=0',
        'for f in "${FILES[@]}"; do',
        '  base=$(basename "$f")',
        '  sample=$(echo "$base" | sed \'s/\\.[^.]*$//\' | sed \'s/\\..*$//\')',
        '  COUNTER=$((COUNTER + 1))',
        '  SAMPLE_OUT="${OUT_ROOT}/${sample}"',
        '  mkdir -p "$SAMPLE_OUT"',
        '  echo "[$COUNTER/$TOTAL] Processing: $sample"',
        '  NanoPlot -t "$THREADS" --fastq "$f" --maxlength "$MAXLEN" --plots dot --legacy hex -o "$SAMPLE_OUT" 2>&1',
        '  echo "[$COUNTER/$TOTAL] Done: $sample"',
        'done',
        'echo "Batch complete: $TOTAL files"',
      ].join('\n');
    }
  }
};

function generateSbatch(stepNum, params, homeDir) {
  const bioDir = homeDir + '/bioagent_jobs';
  const cfg = PIPELINE_STEPS[stepNum];
  if (!cfg) throw new Error('Unknown step: ' + stepNum);

  const threads = params['threads' + stepNum] || params.threads || 20;
  const outDir  = params['out' + stepNum]  || params.outDir || 'step' + stepNum + '_out';
  const partition = params.partition || cfg.resources.partition;
  const mem = cfg.resources.mem;
  const cpusStr = cfg.resources.cpus.replace('${threads}', threads);
  const mode = params.mode || 'single';
  const nanoplotMode = params.nanoplotMode || 'fastq';

  // Resolve conda path
  let condaActivate;
  if (cfg.conda.startsWith('/')) {
    // absolute path to env
    condaActivate = 'export PATH="' + cfg.conda + '/bin:$PATH"';
  } else {
    // env name - use conda activate
    condaActivate = [
      'for __src in ' + homeDir + '/miniconda3/etc/profile.d/conda.sh ' + homeDir + '/anaconda3/etc/profile.d/conda.sh /opt/conda/etc/profile.d/conda.sh; do',
      '  if [ -f "$__src" ]; then source "$__src"; break; fi',
      'done',
      'conda activate ' + cfg.conda + ' 2>/dev/null || source activate ' + cfg.conda + ' 2>/dev/null || true',
    ].join('\n');
  }

  let body;
  if (mode === 'batch') {
    body = cfg.scriptBodyBatch(params);
  } else {
    body = cfg.scriptBody(params, nanoplotMode);
  }

  let header = '#!/bin/bash\n';
  header += '#SBATCH -J BA' + stepNum + '_' + cfg.name + '\n';
  header += '#SBATCH -o ' + bioDir + '/' + stepNum + '/slurm-%j.out\n';
  header += '#SBATCH -e ' + bioDir + '/' + stepNum + '/slurm-%j.err\n';
  header += '#SBATCH -c ' + cpusStr + '\n';
  header += '#SBATCH --mem=' + mem + '\n';
  header += '#SBATCH -p ' + partition + '\n';
  header += '#SBATCH -t ' + cfg.resources.time + '\n';
  header += '#SBATCH --nodes=1\n';
  header += '#SBATCH --ntasks=1\n\n';
  header += 'set -euo pipefail\n\n';
  header += 'echo "=== BioAgent Step ' + stepNum + ': ' + cfg.name + ' ==="\n';
  header += 'echo "JobID: $SLURM_JOB_ID"\n';
  header += 'echo "Node: $(hostname)"\n';
  header += 'echo "Date: $(date \'+%Y-%m-%d %H:%M:%S\')"\n';
  header += 'echo "================================="\n\n';
  header += '# Conda\n';
  header += condaActivate + '\n\n';
  header += 'mkdir -p ' + outDir + '\n\n';
  header += 'cd ' + outDir + '\n';
  header += body + '\n\n';
  header += 'echo "================================="\n';
  header += 'echo "Done: $(date \'+%Y-%m-%d %H:%M:%S\')"\n';

  return header;
}

/* Test script */
function generateTestScript(homeDir) {
  const bioDir = homeDir + '/bioagent_jobs';
  return '#!/bin/bash\n#SBATCH -J BA_TEST\n#SBATCH -o ' + bioDir + '/test/slurm-%j.out\n#SBATCH -e ' + bioDir + '/test/slurm-%j.err\n#SBATCH -c 2\n#SBATCH --mem=4G\n#SBATCH -p cpu01\n#SBATCH -t 00:10:00\n#SBATCH --nodes=1\n\nset -euo pipefail\necho "=== BioAgent Test ==="\necho "JobID: $SLURM_JOB_ID"\necho "Node: $(hostname)"\necho "Date: $(date)"\necho "================================="\necho "HOSTNAME: $(hostname)"\necho "USER: $(whoami)"\necho "CPUs: $(nproc --all)"\necho "MEM:"\nfree -h\necho ""\necho "SINFO:"\nsinfo --version 2>&1 || true\necho ""\necho "CONDA:"\nconda info --envs 2>&1 || true\necho ""\necho "Output dir: ' + bioDir + '/test/"\necho "================================="\necho "Done"';
}

/* Submit */
async function submitSbatch(scriptContent, scriptName) {
  const home = await getHomeDir();
  const dir = home + '/bioagent_jobs/' + scriptName.replace(/\..*$/, '');
  await sshExec('mkdir -p ' + dir, 10000);
  const b64 = Buffer.from(scriptContent).toString('base64');
  let r = await sshExec('echo ' + b64 + ' | base64 -d > ' + dir + '/run.sh 2>/dev/null', 15000);
  if (r.code !== 0) r = await sshExec('echo ' + b64 + ' | base64 --decode > ' + dir + '/run.sh 2>/dev/null', 15000);
  if (r.code !== 0) {
    const lines = scriptContent.split('\n');
    let cmd = '> ' + dir + '/run.sh\n';
    for (const line of lines) cmd += 'printf \'%s\n\' \'' + line.replace(/'/g, "'\\''") + '\' >> ' + dir + '/run.sh\n';
    cmd += 'chmod +x ' + dir + '/run.sh';
    r = await sshExec(cmd, 30000);
  }
  if (r.code !== 0) throw new Error('Write script failed: ' + (r.stderr || r.stdout));
  r = await sshExec('cd ' + dir + ' && sbatch run.sh 2>&1', 15000);
  if (r.code !== 0) throw new Error(r.stderr || r.stdout || 'sbatch failed');
  const m = r.stdout.match(/Submitted batch job (\d+)/);
  if (!m) throw new Error('sbatch output unrecognized: ' + r.stdout);
  return { jobid: m[1], dir };
}

let cachedHomeDir = '';
async function getHomeDir() {
  if (cachedHomeDir) return cachedHomeDir;
  try {
    const r = await sshExec("echo HOME=$HOME 2>/dev/null | grep HOME=", 10000);
    const m = r.stdout.match(/HOME=(\/\S+)/);
    if (m) cachedHomeDir = m[1];
  } catch (_) {}
  if (!cachedHomeDir) cachedHomeDir = '/home/' + config.username;
  return cachedHomeDir;
}

async function getJobStatus(jobid) {
  let r = await sshExec('sacct -j ' + jobid + ' --format State,ExitCode,Elapsed --noheader -P 2>/dev/null | head -3 | grep -v \'\\.batch\\|\\sextern\' | head -1', 10000);
  let line = r.stdout.trim().split('\n').filter(l => l.trim() && !l.includes('batch') && !l.includes('extern'))[0];
  if (line) {
    const parts = line.split('|');
    const state = (parts[0] || '').trim();
    if (state && state !== 'PENDING' && state !== 'RUNNING') return { state, exitCode: parts[1] || '', time: parts[2] || '' };
    if (state === 'RUNNING') return { state, exitCode: '', time: parts[2] || '' };
  }
  r = await sshExec('squeue -j ' + jobid + ' -o "%T|%M|%r" --noheader 2>/dev/null | tail -1', 10000);
  const sq = r.stdout.trim().split('\n').filter(l => l.trim() && !l.includes('Welcome')).map(l => l.trim()).filter(Boolean).pop();
  if (sq) { const [state, time, reason] = sq.split('|'); if (state && !state.includes(' ')) return { state, time, reason }; }
  r = await sshExec('sacct -j ' + jobid + ' --format State --noheader -P 2>/dev/null | head -1', 10000);
  const last = r.stdout.trim().split('\n').filter(l => l.trim() && !l.includes('batch') && !l.includes('extern'))[0];
  if (last) return { state: last.trim(), time: '' };
  return { state: 'PENDING', time: '' };
}

async function getJobLog(jobid, dir) {
  const out = await sshExec('cat ' + dir + '/slurm-' + jobid + '.out 2>&1', 10000);
  const err = await sshExec('cat ' + dir + '/slurm-' + jobid + '.err 2>&1', 10000);
  return { stdout: out.stdout, stderr: err.stderr };
}

/* API endpoints */
app.post('/api/pipeline/test', async (_req, res) => {
  try {
    const home = await getHomeDir();
    const script = generateTestScript(home);
    const { jobid, dir } = await submitSbatch(script, 'test');
    res.json({ ok: true, jobid, dir, message: 'Submitted JOBID: ' + jobid });
  } catch (e) { res.json({ ok: false, error: e.message }); }
});

app.post('/api/pipeline/run', async (req, res) => {
  const { step } = req.body;
  const params = req.body.params || req.body;
  if (!step || !PIPELINE_STEPS[step]) return res.status(400).json({ error: 'Invalid step: ' + step + '. Available: ' + Object.keys(PIPELINE_STEPS).join(', ') });
  try {
    const home = await getHomeDir();
    const script = generateSbatch(step, params, home);
    const tag = 'step' + step;
    const { jobid, dir } = await submitSbatch(script, tag);
    res.json({ ok: true, jobid, dir, step, message: 'Step ' + step + ' submitted, JOBID: ' + jobid });
  } catch (e) { res.json({ ok: false, step, error: e.message }); }
});

app.get('/api/pipeline/status/:jobid', async (req, res) => {
  try {
    const status = await getJobStatus(req.params.jobid);
    res.json({ jobid: req.params.jobid, ...status });
  } catch (e) { res.json({ jobid: req.params.jobid, error: e.message }); }
});

app.get('/api/pipeline/log/:jobid', async (req, res) => {
  const { dir } = req.query;
  if (!dir) return res.status(400).json({ error: 'no dir param' });
  try {
    const log = await getJobLog(req.params.jobid, dir);
    res.json({ jobid: req.params.jobid, ...log });
  } catch (e) { res.json({ jobid: req.params.jobid, error: e.message }); }
});

app.get('/api/pipeline/config', async (_req, res) => {
  const home = await getHomeDir();
  const steps = {};
  for (const [n, cfg] of Object.entries(PIPELINE_STEPS)) {
    steps[n] = { name: cfg.name, desc: cfg.desc, conda: cfg.conda, resources: cfg.resources };
  }
  res.json({ bioagentDir: home + '/bioagent_jobs', steps });
});

app.listen(PORT, '0.0.0.0', async () => {
  try { console.log('  Work dir: ' + (await getHomeDir()) + '/bioagent_jobs'); } catch (_) {}
  console.log('\n=== BioAgent Slurm Bridge v2 ===\n  Frontend: http://localhost:' + PORT + '/pacbio.html\n  Cluster: ' + (config.host || 'not configured') + '\n  User: ' + (config.username || 'not configured') + '\n');
});
