// KernelSeal demo application: a real Node HTTP service that depends on secrets.
//
// Started via: kernelseal-exec -- node demo/node-app/server.js
//
// The shim fetches this process's secrets from the agent and applies them to the
// environment before exec'ing node, so they arrive as ordinary environment
// variables. The same handshake marks this PID protected first, which is why the
// environment is unreadable from outside the process.
//
// Node is a deliberately better test subject than `sleep`:
//
//   1. The Go shim is multithreaded, so execve() zaps its sibling threads. That
//      is what used to be misreported as this process exiting, dropping kernel
//      protection microseconds after it was installed.
//   2. Node itself is multithreaded, and POST /workers exits threads on demand
//      long after startup. A single-threaded target cannot exercise that at all.
//
// No npm dependencies: everything here is Node stdlib, so the demo runs on a
// fresh host without a package install step.

'use strict';

const http = require('node:http');
const crypto = require('node:crypto');
const os = require('node:os');
const path = require('node:path');
const { Worker, isMainThread } = require('node:worker_threads');

const PORT = Number(process.env.PORT || 8080);
const TOKEN_TTL_SECONDS = 900;

// Worker bodies run in this same file, so guard the server setup. Reached only
// when spawned by POST /workers.
if (!isMainThread) {
  // Real work, not a sleep: a key derivation keeps the thread on the CPU for a
  // measurable interval before it exits, which is the event we care about.
  crypto.pbkdf2Sync(crypto.randomBytes(16), crypto.randomBytes(16), 20000, 32, 'sha256');
  return;
}

// ---------------------------------------------------------------------------
// Secrets
// ---------------------------------------------------------------------------

// A service that cannot authenticate anything is not usable, so refuse to start
// without its signing key rather than serving requests insecurely. This also
// makes a misconfigured secret source fail loudly instead of silently starting
// an unprotected process.
const JWT_SECRET = process.env.JWT_SECRET;
const API_KEY = process.env.API_KEY;

const missing = ['JWT_SECRET', 'API_KEY'].filter((name) => !process.env[name]);
if (missing.length > 0) {
  console.error(`[FATAL] missing required secrets: ${missing.join(', ')}`);
  console.error('[FATAL] start this through the shim: kernelseal-exec -- node ' +
    path.relative(process.cwd(), __filename));
  console.error('[FATAL] and check the agent logged "[REGISTER] N secrets registered for binary: node" with N > 0');
  process.exit(1);
}

// Never log a secret value. A fingerprint is enough to confirm delivery and to
// tell two different values apart, and it is safe to put in a response body.
function fingerprint(value) {
  return crypto.createHash('sha256').update(value).digest('hex').slice(0, 12);
}

// ---------------------------------------------------------------------------
// Tokens (HS256, hand-rolled to avoid a dependency)
// ---------------------------------------------------------------------------

function b64url(buf) {
  return Buffer.from(buf).toString('base64')
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function sign(payload) {
  const header = b64url(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
  const body = b64url(JSON.stringify(payload));
  const mac = crypto.createHmac('sha256', JWT_SECRET).update(`${header}.${body}`).digest();
  return `${header}.${body}.${b64url(mac)}`;
}

function verify(token) {
  const parts = String(token || '').split('.');
  if (parts.length !== 3) {
    throw new Error('malformed token');
  }

  const [header, body, mac] = parts;
  const expected = b64url(
    crypto.createHmac('sha256', JWT_SECRET).update(`${header}.${body}`).digest());

  // Constant-time compare: a length-independent equality check here would leak
  // the signature one byte at a time.
  const got = Buffer.from(mac);
  const want = Buffer.from(expected);
  if (got.length !== want.length || !crypto.timingSafeEqual(got, want)) {
    throw new Error('bad signature');
  }

  const payload = JSON.parse(Buffer.from(body, 'base64').toString('utf8'));
  if (typeof payload.exp !== 'number' || payload.exp < Math.floor(Date.now() / 1000)) {
    throw new Error('expired');
  }
  return payload;
}

// ---------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------

let workersSpawned = 0;
let workersExited = 0;

function json(res, status, body) {
  const payload = JSON.stringify(body);
  res.writeHead(status, {
    'content-type': 'application/json',
    'content-length': Buffer.byteLength(payload),
  });
  res.end(payload);
}

async function readBody(req, limit = 64 * 1024) {
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > limit) {
      throw new Error('body too large');
    }
    chunks.push(chunk);
  }
  return Buffer.concat(chunks).toString('utf8');
}

// Spawn n workers and resolve once every one of them has exited. The exits are
// the point: each one fires sched_process_exit with this process's tgid.
function churnThreads(n) {
  return new Promise((resolve, reject) => {
    let done = 0;
    let failed = null;

    for (let i = 0; i < n; i++) {
      const worker = new Worker(__filename);
      workersSpawned++;

      worker.on('error', (err) => { failed = failed || err; });
      worker.on('exit', () => {
        workersExited++;
        if (++done === n) {
          failed ? reject(failed) : resolve();
        }
      });
    }
  });
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://localhost:${PORT}`);

  try {
    if (req.method === 'GET' && url.pathname === '/healthz') {
      return json(res, 200, { ok: true });
    }

    // Reports enough to prove secret delivery worked without disclosing values.
    if (req.method === 'GET' && url.pathname === '/whoami') {
      return json(res, 200, {
        pid: process.pid,
        node: process.version,
        uptimeSeconds: Math.round(process.uptime()),
        cpus: os.cpus().length,
        secrets: {
          JWT_SECRET: { present: true, fingerprint: fingerprint(JWT_SECRET) },
          API_KEY: { present: true, fingerprint: fingerprint(API_KEY) },
          DATABASE_URL: { present: Boolean(process.env.DATABASE_URL) },
        },
        threads: { spawned: workersSpawned, exited: workersExited },
      });
    }

    // Uses API_KEY to authenticate the caller and JWT_SECRET to mint the token,
    // so a successful call proves both secrets arrived intact.
    if (req.method === 'POST' && url.pathname === '/login') {
      const supplied = req.headers['x-api-key'];
      const suppliedBuf = Buffer.from(String(supplied || ''));
      const expectedBuf = Buffer.from(API_KEY);
      if (suppliedBuf.length !== expectedBuf.length ||
          !crypto.timingSafeEqual(suppliedBuf, expectedBuf)) {
        return json(res, 401, { error: 'invalid api key' });
      }

      let user = 'anonymous';
      const body = await readBody(req);
      if (body) {
        user = String(JSON.parse(body).user || user);
      }

      const now = Math.floor(Date.now() / 1000);
      return json(res, 200, {
        token: sign({ sub: user, iat: now, exp: now + TOKEN_TTL_SECONDS }),
        expiresIn: TOKEN_TTL_SECONDS,
      });
    }

    if (req.method === 'GET' && url.pathname === '/me') {
      const auth = String(req.headers.authorization || '');
      const token = auth.startsWith('Bearer ') ? auth.slice(7) : '';
      try {
        return json(res, 200, { claims: verify(token) });
      } catch (err) {
        return json(res, 401, { error: err.message });
      }
    }

    // The regression lever: exit real OS threads while the process keeps running
    // and holding its secrets.
    if (req.method === 'POST' && url.pathname === '/workers') {
      const n = Math.min(Math.max(Number(url.searchParams.get('n') || 4), 1), 32);
      await churnThreads(n);
      return json(res, 200, {
        pid: process.pid,
        requested: n,
        spawned: workersSpawned,
        exited: workersExited,
      });
    }

    return json(res, 404, { error: 'not found' });
  } catch (err) {
    return json(res, 500, { error: err.message });
  }
});

server.listen(PORT, '127.0.0.1', () => {
  console.log(`[OK]   node demo app listening on http://127.0.0.1:${PORT}`);
  console.log(`[OK]   pid ${process.pid}, node ${process.version}`);
  console.log(`[OK]   JWT_SECRET fingerprint ${fingerprint(JWT_SECRET)}`);
  console.log(`[OK]   API_KEY    fingerprint ${fingerprint(API_KEY)}`);
  console.log(`[INFO] DATABASE_URL ${process.env.DATABASE_URL ? 'set' : 'not set'}`);
  console.log('[INFO] the values above never appear in logs, only their fingerprints');
});

for (const signal of ['SIGINT', 'SIGTERM']) {
  process.on(signal, () => {
    console.log(`[STOP] ${signal} received, shutting down`);
    server.close(() => process.exit(0));
  });
}
