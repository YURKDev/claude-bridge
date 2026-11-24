// Claude Bridge server: MCP endpoint (/mcp) + OAuth pairing + relay to the Roblox script.
// Node 18+, zero dependencies.  Run:  node server.js   (env: PORT, PUBLIC_URL)
// STATUS: written without running it; not tested against claude.ai yet.
'use strict';
const http = require('http');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const PORT = Number(process.env.PORT || 3000);
const STATE_FILE = path.join(__dirname, 'state.json');
const POLL_HOLD_MS = 15000;            // long-poll hold time for the Roblox script
const CLIENT_ALIVE_MS = 35000;         // script counts as connected if it polled within this window
const ACCESS_TTL = 24 * 3600 * 1000;
const REFRESH_TTL = 90 * 24 * 3600 * 1000;
const AUTH_ATTEMPTS = 10;              // pairing-code attempts per IP per window
const AUTH_WINDOW_MS = 10 * 60 * 1000;
const MAX_SESSIONS = 5000;
const CODE_ALPHABET = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789';
const PROTOCOLS = ['2025-06-18', '2025-03-26', '2024-11-05'];
const MAX_TEXT = 200000;

const rnd = (n = 32) => crypto.randomBytes(n).toString('hex');
const clamp = (v, lo, hi) => Math.min(hi, Math.max(lo, Number.isFinite(+v) ? +v : lo));
const nullMap = (o) => Object.assign(Object.create(null), o || {});

// ---------- persisted state ----------
const st = { sessions: nullMap(), codes: nullMap(), access: nullMap(), refresh: nullMap(), oauthClients: nullMap() };
try {
  const loaded = JSON.parse(fs.readFileSync(STATE_FILE, 'utf8'));
  for (const k of Object.keys(st)) st[k] = nullMap(loaded[k]);
} catch { /* first run */ }
let saveTimer = null;
const save = () => {
  clearTimeout(saveTimer);
  saveTimer = setTimeout(() => fs.writeFile(STATE_FILE, JSON.stringify(st), () => {}), 200);
};

// ---------- runtime (not persisted) ----------
const runtime = new Map();
const authCodes = new Map(); // oauth authorization codes
const attempts = new Map();  // ip -> {n, reset}
const rtOf = (secret) => {
  let r = runtime.get(secret);
  if (!r) {
    r = { pending: [], inflight: new Map(), waiter: null, lastSeen: 0, inbox: [], replies: [], inboxWaiters: [] };
    runtime.set(secret, r);
  }
  return r;
};
const isLinked = (secret) => Object.values(st.access).some((t) => t.secret === secret && t.exp > Date.now());
const newCode = () => {
  let c;
  do {
    const b = crypto.randomBytes(8);
    c = [...b].map((x) => CODE_ALPHABET[x % CODE_ALPHABET.length]).join('');
    c = c.slice(0, 4) + '-' + c.slice(4);
  } while (st.codes[c]);
  return c;
};

// ---------- http helpers ----------
const json = (res, code, obj, headers = {}) => {
  res.writeHead(code, { 'content-type': 'application/json', 'cache-control': 'no-store', ...headers });
  res.end(JSON.stringify(obj));
};
const html = (res, code, body) => {
  res.writeHead(code, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' });
  res.end(body);
};
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const cors = (res) => {
  res.setHeader('access-control-allow-origin', '*');
  res.setHeader('access-control-allow-headers', 'content-type, authorization, x-secret, mcp-protocol-version, mcp-session-id');
  res.setHeader('access-control-allow-methods', 'GET, POST, DELETE, OPTIONS');
  res.setHeader('access-control-expose-headers', 'www-authenticate');
};
const readBody = (req, limit = 5e6) => new Promise((resolve, reject) => {
  const chunks = []; let size = 0;
  req.on('data', (c) => { size += c.length; if (size > limit) { reject(new Error('body too large')); req.destroy(); } else chunks.push(c); });
  req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
  req.on('error', reject);
});
const parseBody = (req, raw) => {
  const ct = req.headers['content-type'] || '';
  if (ct.includes('urlencoded')) return Object.fromEntries(new URLSearchParams(raw));
  try { return JSON.parse(raw || '{}'); } catch { return null; }
};
const baseUrl = (req) => process.env.PUBLIC_URL || `${req.headers['x-forwarded-proto'] || 'http'}://${req.headers.host}`;
const clientIp = (req) => String(req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim();

// ---------- relay to the Roblox script ----------
function sendPoll(secret) {
  const r = rtOf(secret);
  const w = r.waiter;
  if (!w) return;
  r.waiter = null;
  clearTimeout(w.timer);
  r.lastSeen = Date.now();
  json(w.res, 200, { cmds: r.pending.splice(0), replies: r.replies.splice(0), linked: isLinked(secret), code: st.sessions[secret].code });
}
function flush(secret) {
  const r = rtOf(secret);
  if (r.waiter && (r.pending.length || r.replies.length)) sendPoll(secret);
}
function dispatch(secret, type, args, timeoutMs = 30000) {
  const r = rtOf(secret);
  if (Date.now() - r.lastSeen > CLIENT_ALIVE_MS) {
    return Promise.reject(new Error('The Roblox script is not connected (it has not polled recently). Execute it in the game and check the in-game panel.'));
  }
  const id = rnd(8);
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => { r.inflight.delete(id); reject(new Error(`Timed out after ${timeoutMs} ms waiting for the game.`)); }, timeoutMs);
    r.inflight.set(id, { resolve, reject, timer });
    r.pending.push({ id, type, args });
    flush(secret);
  });
}

// ---------- MCP tools ----------
const pathHelp = 'Paths look like "Workspace/Map/Part" (also "game.Workspace.Map" when no name contains a dot). Aliases: Players/LocalPlayer, Players/<name>/Character, Workspace/Camera.';
const TOOLS = [
  { name: 'execute', description: 'Run Luau inside the connected Roblox client (executor). Use `return` to send values back; prints during the run are captured. Globals injected: R(path[,timeoutSeconds]) resolves a path safely (waits for it, returns nil plus a reason with the real child names instead of throwing "not found"); A(pathOrInstance[,enabled=true]) anchors every BasePart under it and keeps it anchored. ' + pathHelp,
    inputSchema: { type: 'object', properties: { code: { type: 'string' }, timeout: { type: 'number', description: 'seconds, default 15, max 120' } }, required: ['code'] } },
  { name: 'explore', description: 'Dex-style tree of the game. Output: indented "Name [Class] (childCount)". ' + pathHelp,
    inputSchema: { type: 'object', properties: { path: { type: 'string', description: 'default "game"' }, depth: { type: 'number', description: 'default 1, max 6' }, max: { type: 'number', description: 'max nodes, default 200' } } } },
  { name: 'properties', description: 'Read properties and attributes of one instance. Pass `names` for specific properties, otherwise a common set is tried. ' + pathHelp,
    inputSchema: { type: 'object', properties: { path: { type: 'string' }, names: { type: 'array', items: { type: 'string' } } }, required: ['path'] } },
  { name: 'anchor', description: 'Anchor (or unanchor) every BasePart under a path. With persist=true (default) it re-anchors if the game unanchors a part and anchors parts added later. This only changes the local client; other players see it only where the client has network ownership.',
    inputSchema: { type: 'object', properties: { path: { type: 'string' }, enabled: { type: 'boolean' }, persist: { type: 'boolean' } }, required: ['path'] } },
  { name: 'console', description: 'Last N entries of the Roblox output log.',
    inputSchema: { type: 'object', properties: { limit: { type: 'number', description: 'default 50, max 500' } } } },
  { name: 'script_source', description: 'Source of a LocalScript/ModuleScript/Script via decompile() if the executor has it, otherwise .Source.',
    inputSchema: { type: 'object', properties: { path: { type: 'string' }, maxLength: { type: 'number' } }, required: ['path'] } },
  { name: 'files', description: 'List/read/write/delete files in the executor workspace folder only (relative paths, no ".."). This is NOT the PC file system and not the game files.',
    inputSchema: { type: 'object', properties: { action: { type: 'string', enum: ['list', 'read', 'write', 'delete'] }, path: { type: 'string' }, content: { type: 'string' } }, required: ['action'] } },
  { name: 'chat_read', description: 'Read messages the user typed into the in-game chat box (they are only delivered when you call this). wait = seconds to wait for a message (0-25).',
    inputSchema: { type: 'object', properties: { wait: { type: 'number' } } } },
  { name: 'chat_reply', description: 'Show a message in the in-game chat panel.',
    inputSchema: { type: 'object', properties: { text: { type: 'string' } }, required: ['text'] } },
  { name: 'status', description: 'Executor name, place/job id, local player and which executor functions exist.', inputSchema: { type: 'object', properties: {} } },
];

async function callTool(secret, name, a) {
  const r = rtOf(secret);
  switch (name) {
    case 'execute': { const t = clamp(a.timeout ?? 15, 1, 120); return dispatch(secret, 'execute', { code: String(a.code || ''), timeout: t }, (t + 5) * 1000); }
    case 'explore': case 'properties': case 'anchor': case 'console': case 'files': return dispatch(secret, name, a);
    case 'script_source': return dispatch(secret, 'source', a);
    case 'status': return dispatch(secret, 'status', {}, 10000);
    case 'chat_read': {
      const wait = clamp(a.wait ?? 0, 0, 25);
      if (!r.inbox.length && wait > 0) {
        await new Promise((resolve) => { const t = setTimeout(resolve, wait * 1000); r.inboxWaiters.push(() => { clearTimeout(t); resolve(); }); });
      }
      const m = r.inbox.splice(0);
      return m.length ? m.map((x) => `[${new Date(x.at).toISOString()}] ${x.text}`).join('\n') : '(no new messages)';
    }
    case 'chat_reply': r.replies.push(String(a.text || '').slice(0, 4000)); flush(secret); return 'sent';
    default: throw new Error('Unknown tool ' + name);
  }
}

async function handleRpc(msg, secret) {
  const { id, method, params } = msg || {};
  const isNote = id === undefined || id === null;
  if (method === 'initialize') {
    const pv = PROTOCOLS.includes(params?.protocolVersion) ? params.protocolVersion : PROTOCOLS[0];
    return { jsonrpc: '2.0', id, result: { protocolVersion: pv, capabilities: { tools: {} }, serverInfo: { name: 'claude-bridge', version: '1.0.0' } } };
  }
  if (method === 'ping') return { jsonrpc: '2.0', id, result: {} };
  if (method === 'tools/list') return { jsonrpc: '2.0', id, result: { tools: TOOLS } };
  if (method === 'tools/call') {
    try {
      let text = String(await callTool(secret, params?.name, params?.arguments || {}));
      if (text.length > MAX_TEXT) text = text.slice(0, MAX_TEXT) + '\n[truncated]';
      return { jsonrpc: '2.0', id, result: { content: [{ type: 'text', text }] } };
    } catch (e) {
      return { jsonrpc: '2.0', id, result: { content: [{ type: 'text', text: 'Error: ' + e.message }], isError: true } };
    }
  }
  if (isNote) return null;
  return { jsonrpc: '2.0', id, error: { code: -32601, message: 'Method not found' } };
}

// ---------- OAuth ----------
const pkceOk = (verifier, challenge) => crypto.createHash('sha256').update(String(verifier || '')).digest('base64url') === challenge;
function issueTokens(secret, clientId) {
  const access = rnd(32), refresh = rnd(32);
  st.access[access] = { secret, clientId, exp: Date.now() + ACCESS_TTL };
  st.refresh[refresh] = { secret, clientId, exp: Date.now() + REFRESH_TTL };
  save();
  return { access_token: access, token_type: 'Bearer', expires_in: Math.floor(ACCESS_TTL / 1000), refresh_token: refresh };
}
const authPage = (p, error) => `<!doctype html><meta name=viewport content="width=device-width,initial-scale=1"><title>Link Claude</title>
<style>body{font-family:system-ui;background:#262624;color:#ebe9e2;display:grid;place-items:center;min-height:100vh;margin:0}
form{background:#30302d;padding:32px;border-radius:16px;width:min(360px,90vw)}h1{margin:0 0 8px;font-size:20px}p{color:#a09d94;font-size:14px}
input{width:100%;box-sizing:border-box;padding:14px;font:600 24px ui-monospace,monospace;letter-spacing:3px;text-align:center;border-radius:10px;border:1px solid #55554f;background:#262624;color:#d97757;text-transform:uppercase}
button{width:100%;margin-top:14px;padding:14px;border:0;border-radius:10px;background:#d97757;color:#fff;font-weight:700;font-size:15px;cursor:pointer}.err{color:#e15a5a}</style>
<form method=post action=/authorize><h1>Link Claude to your game</h1><p>Type the code shown in the in-game panel.</p>
${error ? `<p class=err>${esc(error)}</p>` : ''}
${['response_type', 'client_id', 'redirect_uri', 'code_challenge', 'code_challenge_method', 'state'].map((k) => `<input type=hidden name=${k} value="${esc(p[k])}">`).join('')}
<input name=code maxlength=9 autocomplete=off autofocus placeholder="XXXX-XXXX"><button>Link</button></form>`;

function validateAuthParams(p) {
  const client = st.oauthClients[p.client_id];
  if (!client) return 'Unknown client_id.';
  if (!client.redirect_uris.includes(p.redirect_uri)) return 'redirect_uri was not registered.';
  if (p.response_type !== 'code') return 'response_type must be "code".';
  if (!p.code_challenge || p.code_challenge_method !== 'S256') return 'PKCE (S256) is required.';
  return null;
}

// ---------- server ----------
const server = http.createServer(async (req, res) => {
  try {
    cors(res);
    if (req.method === 'OPTIONS') { res.writeHead(204).end(); return; }
    const url = new URL(req.url, 'http://x');
    const p = url.pathname;
    const base = baseUrl(req);

    if (p === '/') return html(res, 200, '<p>Claude Bridge server is running.</p>');

    // --- OAuth discovery ---
    if (p.startsWith('/.well-known/oauth-protected-resource')) {
      return json(res, 200, { resource: base + '/mcp', authorization_servers: [base], bearer_methods_supported: ['header'] });
    }
    if (p.startsWith('/.well-known/oauth-authorization-server')) {
      return json(res, 200, {
        issuer: base, authorization_endpoint: base + '/authorize', token_endpoint: base + '/token', registration_endpoint: base + '/register',
        response_types_supported: ['code'], grant_types_supported: ['authorization_code', 'refresh_token'],
        code_challenge_methods_supported: ['S256'], token_endpoint_auth_methods_supported: ['none'],
      });
    }
    if (p === '/register' && req.method === 'POST') {
      const b = parseBody(req, await readBody(req, 1e5));
      const uris = b && Array.isArray(b.redirect_uris) ? b.redirect_uris.filter((u) => typeof u === 'string' && /^(https:\/\/|http:\/\/(localhost|127\.0\.0\.1))/.test(u)) : [];
      if (!uris.length) return json(res, 400, { error: 'invalid_redirect_uri' });
      const keys = Object.keys(st.oauthClients);
      if (keys.length >= 500) delete st.oauthClients[keys[0]];
      const client_id = rnd(16);
      st.oauthClients[client_id] = { redirect_uris: uris };
      save();
      return json(res, 201, { client_id, client_id_issued_at: Math.floor(Date.now() / 1000), redirect_uris: uris, client_name: String(b.client_name || 'client'),
        grant_types: ['authorization_code', 'refresh_token'], response_types: ['code'], token_endpoint_auth_method: 'none' });
    }
    if (p === '/authorize' && req.method === 'GET') {
      const q = Object.fromEntries(url.searchParams);
      const bad = validateAuthParams(q);
      return bad ? html(res, 400, `<p>${esc(bad)}</p>`) : html(res, 200, authPage(q));
    }
    if (p === '/authorize' && req.method === 'POST') {
      const f = parseBody(req, await readBody(req, 1e5)) || {};
      const bad = validateAuthParams(f);
      if (bad) return html(res, 400, `<p>${esc(bad)}</p>`);
      const ip = clientIp(req);
      const a = attempts.get(ip) || { n: 0, reset: Date.now() + AUTH_WINDOW_MS };
      if (Date.now() > a.reset) { a.n = 0; a.reset = Date.now() + AUTH_WINDOW_MS; }
      if (++a.n > AUTH_ATTEMPTS) { attempts.set(ip, a); return html(res, 429, authPage(f, 'Too many attempts. Wait a few minutes.')); }
      attempts.set(ip, a);
      let code = String(f.code || '').toUpperCase().replace(/[^A-Z0-9]/g, '');
      if (code.length === 8) code = code.slice(0, 4) + '-' + code.slice(4);
      const secret = st.codes[code];
      if (!secret || !st.sessions[secret]) return html(res, 200, authPage(f, 'Wrong code. Check the in-game panel.'));
      delete st.codes[code];                                  // one-time use: rotate the code
      const fresh = newCode(); st.sessions[secret].code = fresh; st.codes[fresh] = secret; save();
      const ac = rnd(24);
      authCodes.set(ac, { secret, clientId: f.client_id, redirectUri: f.redirect_uri, challenge: f.code_challenge, exp: Date.now() + 5 * 60 * 1000 });
      const dest = new URL(f.redirect_uri);
      dest.searchParams.set('code', ac);
      if (f.state) dest.searchParams.set('state', f.state);
      res.writeHead(302, { location: dest.toString() }).end();
      return;
    }
    if (p === '/token' && req.method === 'POST') {
      const b = parseBody(req, await readBody(req, 1e5)) || {};
      if (b.grant_type === 'authorization_code') {
        const rec = authCodes.get(b.code);
        authCodes.delete(b.code);
        if (!rec || rec.exp < Date.now() || rec.clientId !== b.client_id || rec.redirectUri !== b.redirect_uri || !pkceOk(b.code_verifier, rec.challenge)) {
          return json(res, 400, { error: 'invalid_grant' });
        }
        return json(res, 200, issueTokens(rec.secret, rec.clientId));
      }
      if (b.grant_type === 'refresh_token') {
        const rec = st.refresh[b.refresh_token];
        if (!rec || rec.exp < Date.now() || rec.clientId !== b.client_id) return json(res, 400, { error: 'invalid_grant' });
        delete st.refresh[b.refresh_token];
        return json(res, 200, issueTokens(rec.secret, rec.clientId));
      }
      return json(res, 400, { error: 'unsupported_grant_type' });
    }

    // --- MCP ---
    if (p === '/mcp') {
      const tok = (req.headers.authorization || '').replace(/^Bearer\s+/i, '');
      const rec = st.access[tok];
      if (!rec || rec.exp < Date.now() || !st.sessions[rec.secret]) {
        return json(res, 401, { error: 'unauthorized' }, { 'www-authenticate': `Bearer resource_metadata="${base}/.well-known/oauth-protected-resource"` });
      }
      if (req.method === 'DELETE') { res.writeHead(200).end(); return; }
      if (req.method !== 'POST') { res.writeHead(405, { allow: 'POST' }).end(); return; }
      const msg = parseBody(req, await readBody(req));
      if (msg === null) return json(res, 400, { jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } });
      if (Array.isArray(msg)) {
        const out = (await Promise.all(msg.map((m) => handleRpc(m, rec.secret)))).filter(Boolean);
        return out.length ? json(res, 200, out) : (res.writeHead(202).end(), undefined);
      }
      const out = await handleRpc(msg, rec.secret);
      return out ? json(res, 200, out) : (res.writeHead(202).end(), undefined);
    }

    // --- Roblox script API ---
    if (p === '/api/register' && req.method === 'POST') {
      const b = parseBody(req, await readBody(req, 1e5)) || {};
      let secret = typeof b.secret === 'string' && st.sessions[b.secret] ? b.secret : null;
      if (!secret) {
        if (Object.keys(st.sessions).length >= MAX_SESSIONS) return json(res, 429, { error: 'too_many_sessions' });
        secret = rnd(24);
        const code = newCode();
        st.sessions[secret] = { code }; st.codes[code] = secret; save();
      }
      rtOf(secret).lastSeen = Date.now();
      return json(res, 200, { secret, code: st.sessions[secret].code, linked: isLinked(secret) });
    }
    if (p.startsWith('/api/')) {
      const secret = String(req.headers['x-secret'] || '');
      if (!st.sessions[secret]) return json(res, 401, { error: 'unknown_session' });
      const r = rtOf(secret);
      if (p === '/api/poll') {
        r.lastSeen = Date.now();
        if (r.waiter) sendPoll(secret);                       // release a stale waiter
        const timer = setTimeout(() => sendPoll(secret), POLL_HOLD_MS);
        r.waiter = { res, timer };
        req.on('close', () => { if (r.waiter && r.waiter.res === res) { clearTimeout(timer); r.waiter = null; } });
        flush(secret);
        return;
      }
      if (p === '/api/result' && req.method === 'POST') {
        const b = parseBody(req, await readBody(req)) || {};
        const f = r.inflight.get(b.id);
        if (f) {
          clearTimeout(f.timer); r.inflight.delete(b.id);
          b.ok ? f.resolve(String(b.result ?? '')) : f.reject(new Error(String(b.error || 'unknown error')));
        }
        return json(res, 200, { ok: !!f });
      }
      if (p === '/api/chat' && req.method === 'POST') {
        const b = parseBody(req, await readBody(req, 1e5)) || {};
        const text = String(b.text || '').slice(0, 4000);
        if (text) { r.inbox.push({ at: Date.now(), text }); if (r.inbox.length > 200) r.inbox.shift(); r.inboxWaiters.splice(0).forEach((fn) => fn()); }
        return json(res, 200, { ok: true });
      }
    }
    json(res, 404, { error: 'not_found' });
  } catch (e) {
    console.error(e);
    if (!res.headersSent) json(res, 500, { error: 'server_error' });
  }
});

setInterval(() => {
  const now = Date.now();
  for (const [k, v] of Object.entries(st.access)) if (v.exp < now) delete st.access[k];
  for (const [k, v] of Object.entries(st.refresh)) if (v.exp < now) delete st.refresh[k];
  for (const [k, v] of authCodes) if (v.exp < now) authCodes.delete(k);
  for (const [k, v] of attempts) if (v.reset < now) attempts.delete(k);
  save();
}, 3600 * 1000).unref();

server.listen(PORT, () => console.log(`Claude Bridge server on :${PORT}  (MCP URL: <PUBLIC_URL>/mcp)`));
