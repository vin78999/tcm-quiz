'use strict';

const http = require('http');
const https = require('https');
const crypto = require('crypto');

const DAY_MS = 86400000;
const MAX_BODY_BYTES = 256 * 1024;
const TOKEN_TTL_MS = 7 * DAY_MS;
const ADMIN_TOKEN_TTL_MS = 8 * 60 * 60 * 1000;
const DS_URL = 'https://api.deepseek.com/v1/chat/completions';

const CONFIG = {
  deepseekKey: process.env.DEEPSEEK_KEY || process.env.DS_KEY || '',
  deepseekModel: process.env.DEEPSEEK_MODEL || 'deepseek-v4-flash',
  jwtSecret: process.env.JWT_SECRET || '',
  adminPasswordHash: process.env.ADMIN_PASSWORD_HASH || '',
  ossBucket: process.env.OSS_BUCKET || '',
  ossRegion: process.env.OSS_REGION || 'oss-cn-shenzhen',
  ossAccessKeyId: process.env.OSS_AK_ID || '',
  ossAccessKeySecret: process.env.OSS_AK_SEC || '',
  allowedOrigins: (process.env.ALLOWED_ORIGINS || 'https://vin78999.github.io')
    .split(',').map(value => value.trim()).filter(Boolean),
  allowLocalhost: process.env.ALLOW_LOCALHOST === 'true',
};

function log(event, details = {}) {
  console.log(JSON.stringify({ ts: new Date().toISOString(), event, ...details }));
}

function normalizeEmail(email) {
  return String(email || '').trim().toLowerCase();
}

function validEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) && email.length <= 254;
}

function safeEqualHex(left, right) {
  try {
    const leftText = String(left);
    const rightText = String(right);
    if (!/^[0-9a-f]+$/i.test(leftText) || !/^[0-9a-f]+$/i.test(rightText)) return false;
    if (leftText.length % 2 || rightText.length % 2) return false;
    const a = Buffer.from(leftText, 'hex');
    const b = Buffer.from(rightText, 'hex');
    return a.length > 0 && a.length === b.length && crypto.timingSafeEqual(a, b);
  } catch {
    return false;
  }
}

function makePasswordRecord(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return { hashAlg: 'scrypt-v1', salt, hash };
}

function verifyPassword(password, user) {
  if (!user || !user.salt || !user.hash) return false;
  if (user.hashAlg === 'scrypt-v1') {
    const actual = crypto.scryptSync(password, user.salt, 64).toString('hex');
    return safeEqualHex(actual, user.hash);
  }
  const legacy = crypto.createHmac('sha256', user.salt).update(password).digest('hex');
  return safeEqualHex(legacy, user.hash);
}

function encodeAdminPassword(password) {
  const record = makePasswordRecord(password);
  return ['scrypt-v1', record.salt, record.hash].join('$');
}

function verifyAdminPassword(password, encoded) {
  const parts = String(encoded || '').split('$');
  if (parts.length !== 3 || parts[0] !== 'scrypt-v1') return false;
  return verifyPassword(password, { hashAlg: parts[0], salt: parts[1], hash: parts[2] });
}

function signToken(payload, secret = CONFIG.jwtSecret) {
  if (!secret) throw new Error('JWT secret is not configured');
  const encoded = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const signature = crypto.createHmac('sha256', secret).update(encoded).digest('hex');
  return encoded + '.' + signature;
}

function makeToken(uid, email, type = 'user', now = Date.now(), secret = CONFIG.jwtSecret) {
  const ttl = type === 'admin' ? ADMIN_TOKEN_TTL_MS : TOKEN_TTL_MS;
  return signToken({ uid, email, type, iat: now, exp: now + ttl }, secret);
}

function verifyToken(token, expectedType = 'user', now = Date.now(), secret = CONFIG.jwtSecret) {
  try {
    const [encoded, signature, extra] = String(token || '').split('.');
    if (!encoded || !signature || extra || !secret) return null;
    const expected = crypto.createHmac('sha256', secret).update(encoded).digest('hex');
    if (!safeEqualHex(signature, expected)) return null;
    const payload = JSON.parse(Buffer.from(encoded, 'base64url').toString('utf8'));
    if (payload.type !== expectedType || !payload.uid || !payload.exp || payload.exp <= now) return null;
    return payload;
  } catch {
    return null;
  }
}

function userKey(email) {
  const digest = crypto.createHash('sha256').update(normalizeEmail(email)).digest('hex');
  return '/users/' + digest + '.json';
}

function ossRequest(method, key, bodyObj) {
  return new Promise((resolve, reject) => {
    if (!CONFIG.ossBucket || !CONFIG.ossAccessKeyId || !CONFIG.ossAccessKeySecret) {
      reject(new Error('Storage is not configured'));
      return;
    }
    const host = CONFIG.ossBucket + '.' + CONFIG.ossRegion + '.aliyuncs.com';
    const date = new Date().toUTCString();
    const body = bodyObj === undefined || bodyObj === null ? '' : JSON.stringify(bodyObj);
    const contentType = body ? 'application/json' : '';
    const stringToSign = [method, '', contentType, date, '/' + CONFIG.ossBucket + key].join('\n');
    const signature = crypto.createHmac('sha1', CONFIG.ossAccessKeySecret)
      .update(stringToSign).digest('base64');
    const options = {
      hostname: host,
      port: 443,
      path: key,
      method,
      headers: {
        Host: host,
        Date: date,
        Authorization: 'OSS ' + CONFIG.ossAccessKeyId + ':' + signature,
      },
    };
    if (body) {
      options.headers['Content-Type'] = contentType;
      options.headers['Content-Length'] = Buffer.byteLength(body);
    }
    const request = https.request(options, response => {
      let buffer = '';
      response.setEncoding('utf8');
      response.on('data', chunk => { buffer += chunk; });
      response.on('end', () => {
        if (response.statusCode === 404) return resolve(null);
        if (response.statusCode >= 200 && response.statusCode < 300) {
          if (!buffer) return resolve(true);
          try { return resolve(JSON.parse(buffer)); } catch { return resolve(buffer); }
        }
        reject(new Error('Storage request failed: ' + response.statusCode));
      });
    });
    request.setTimeout(10000, () => request.destroy(new Error('Storage request timed out')));
    request.on('error', reject);
    if (body) request.write(body);
    request.end();
  });
}

const defaultStorage = {
  get: key => ossRequest('GET', key, null),
  put: (key, value) => ossRequest('PUT', key, value),
  delete: key => ossRequest('DELETE', key, null),
};

function readBody(request, limit = MAX_BODY_BYTES) {
  return new Promise((resolve, reject) => {
    let size = 0;
    let buffer = '';
    request.setEncoding('utf8');
    request.on('data', chunk => {
      size += Buffer.byteLength(chunk);
      if (size > limit) {
        reject(Object.assign(new Error('Request body too large'), { statusCode: 413 }));
        request.destroy();
        return;
      }
      buffer += chunk;
    });
    request.on('end', () => {
      if (!buffer) return resolve({});
      try { resolve(JSON.parse(buffer)); }
      catch { reject(Object.assign(new Error('Invalid JSON'), { statusCode: 400 })); }
    });
    request.on('error', reject);
  });
}

function sendJson(response, statusCode, body) {
  response.writeHead(statusCode, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
  });
  response.end(JSON.stringify(body));
}

function isAllowedOrigin(origin, allowedOrigins = CONFIG.allowedOrigins, allowLocalhost = CONFIG.allowLocalhost) {
  if (!origin) return true;
  return allowedOrigins.includes(origin) || (allowLocalhost && /^http:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/.test(origin));
}

function applyCors(request, response, allowedOrigins = CONFIG.allowedOrigins, allowLocalhost = CONFIG.allowLocalhost) {
  const origin = request.headers.origin;
  if (origin && isAllowedOrigin(origin, allowedOrigins, allowLocalhost)) {
    response.setHeader('Access-Control-Allow-Origin', origin);
    response.setHeader('Vary', 'Origin');
  }
  response.setHeader('Access-Control-Allow-Methods', 'POST, GET, OPTIONS');
  response.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  response.setHeader('Access-Control-Max-Age', '600');
  return isAllowedOrigin(origin, allowedOrigins, allowLocalhost);
}

function clientIp(request) {
  const forwarded = String(request.headers['x-forwarded-for'] || '').split(',')[0].trim();
  return forwarded || request.headers['x-real-ip'] || request.socket.remoteAddress || 'unknown';
}

function createRateLimiter(now = () => Date.now()) {
  const buckets = new Map();
  return function allow(key, limit, windowMs) {
    const timestamp = now();
    const current = buckets.get(key);
    if (!current || current.resetAt <= timestamp) {
      buckets.set(key, { count: 1, resetAt: timestamp + windowMs });
      return true;
    }
    if (current.count >= limit) return false;
    current.count += 1;
    return true;
  };
}

function bearerToken(request) {
  const value = String(request.headers.authorization || '');
  return value.startsWith('Bearer ') ? value.slice(7).trim() : '';
}

function sanitizeAccount(account) {
  return {
    uid: account.uid,
    email: account.email,
    createdAt: account.createdAt || null,
    expiresAt: account.expiresAt || null,
    disabled: Boolean(account.disabled),
  };
}

async function loadAccounts(storage) {
  const data = await storage.get('/admin/accounts.json');
  return data && Array.isArray(data.accounts) ? data.accounts : [];
}

async function saveAccounts(storage, accounts) {
  await storage.put('/admin/accounts.json', { accounts, updatedAt: Date.now() });
}

function accountState(accounts, uid) {
  return accounts.find(account => account.uid === uid) || null;
}

function accountError(account, now = Date.now()) {
  if (!account) return null;
  if (account.disabled) return 'USER_DISABLED';
  if (account.expiresAt && account.expiresAt <= now) return 'USER_EXPIRED';
  return null;
}

function validateMessages(messages) {
  if (!Array.isArray(messages) || messages.length < 1 || messages.length > 20) return false;
  let total = 0;
  for (const message of messages) {
    if (!message || !['system', 'user', 'assistant'].includes(message.role) || typeof message.content !== 'string') return false;
    total += message.content.length;
  }
  return total <= 12000;
}

function createHandler(options = {}) {
  const storage = options.storage || defaultStorage;
  const fetchImpl = options.fetchImpl || global.fetch;
  const config = options.config || CONFIG;
  const now = options.now || (() => Date.now());
  const allowRate = options.rateLimiter || createRateLimiter(now);

  return async function handler(request, response) {
    const requestId = request.headers['x-fc-request-id'] || crypto.randomUUID();
    const originAllowed = applyCors(request, response, config.allowedOrigins, config.allowLocalhost);
    if (!originAllowed) return sendJson(response, 403, { error: 'ORIGIN_NOT_ALLOWED' });
    if (request.method === 'OPTIONS') {
      response.writeHead(204);
      response.end();
      return;
    }

    const path = new URL(request.url || '/', 'http://localhost').pathname;
    const ip = clientIp(request);
    if (path === '/health' && request.method === 'GET') {
      return sendJson(response, 200, { ok: true, version: '4.0.0' });
    }
    if (request.method !== 'POST' && !(request.method === 'GET' && path === '/admin/accounts')) {
      return sendJson(response, 405, { error: 'METHOD_NOT_ALLOWED' });
    }

    let body = {};
    try {
      if (request.method === 'POST') body = await readBody(request);
    } catch (error) {
      return sendJson(response, error.statusCode || 400, { error: error.statusCode === 413 ? 'BODY_TOO_LARGE' : 'INVALID_JSON' });
    }

    try {
      if (path === '/auth/register') {
        return sendJson(response, 403, { error: 'ACCOUNT_CREATION_REQUIRES_ADMIN' });
      }

      if (path === '/auth/login') {
        if (!allowRate('login:' + ip, 10, 15 * 60 * 1000)) return sendJson(response, 429, { error: 'TOO_MANY_ATTEMPTS' });
        const email = normalizeEmail(body.email);
        const password = String(body.password || '');
        if (!validEmail(email) || !password) return sendJson(response, 400, { error: 'INVALID_CREDENTIALS' });
        const user = await storage.get(userKey(email));
        if (!user || !verifyPassword(password, user)) return sendJson(response, 401, { error: 'INVALID_CREDENTIALS' });
        const accounts = await loadAccounts(storage);
        const stateError = accountError(accountState(accounts, user.uid), now());
        if (stateError) return sendJson(response, 403, { error: stateError });
        if (user.hashAlg !== 'scrypt-v1') {
          await storage.put(userKey(email), { ...user, ...makePasswordRecord(password), upgradedAt: now() });
        }
        log('login_success', { requestId, uid: user.uid });
        return sendJson(response, 200, { uid: user.uid, email, idToken: makeToken(user.uid, email, 'user', now(), config.jwtSecret) });
      }

      if (path === '/admin/login') {
        if (!allowRate('admin-login:' + ip, 5, 15 * 60 * 1000)) return sendJson(response, 429, { error: 'TOO_MANY_ATTEMPTS' });
        if (!verifyAdminPassword(String(body.password || ''), config.adminPasswordHash)) {
          return sendJson(response, 401, { error: 'INVALID_ADMIN_PASSWORD' });
        }
        return sendJson(response, 200, { token: makeToken('admin', 'admin', 'admin', now(), config.jwtSecret), expiresIn: ADMIN_TOKEN_TTL_MS / 1000 });
      }

      if (path.startsWith('/admin/')) {
        const admin = verifyToken(bearerToken(request), 'admin', now(), config.jwtSecret);
        if (!admin) return sendJson(response, 401, { error: 'ADMIN_AUTH_REQUIRED' });
        let accounts = await loadAccounts(storage);

        if (path === '/admin/accounts' && request.method === 'GET') {
          return sendJson(response, 200, { accounts: accounts.map(sanitizeAccount) });
        }

        if (path === '/admin/accounts/create') {
          const email = normalizeEmail(body.email);
          const password = String(body.password || '');
          const months = Math.min(24, Math.max(1, Number.parseInt(body.months, 10) || 3));
          if (!validEmail(email) || password.length < 10) return sendJson(response, 400, { error: 'INVALID_ACCOUNT_INPUT' });
          if (await storage.get(userKey(email))) return sendJson(response, 409, { error: 'EMAIL_EXISTS' });
          const uid = crypto.randomBytes(16).toString('hex');
          const createdAt = now();
          const expiresAt = createdAt + months * 30 * DAY_MS;
          await storage.put(userKey(email), { uid, email, ...makePasswordRecord(password), at: createdAt });
          accounts.push({ uid, email, createdAt, expiresAt, disabled: false });
          await saveAccounts(storage, accounts);
          log('admin_account_created', { requestId, uid });
          return sendJson(response, 200, { account: sanitizeAccount(accounts[accounts.length - 1]) });
        }

        if (path === '/admin/accounts/renew') {
          const months = Math.min(24, Math.max(1, Number.parseInt(body.months, 10) || 3));
          const account = accountState(accounts, String(body.uid || ''));
          if (!account) return sendJson(response, 404, { error: 'ACCOUNT_NOT_FOUND' });
          account.expiresAt = Math.max(now(), account.expiresAt || 0) + months * 30 * DAY_MS;
          account.disabled = false;
          await saveAccounts(storage, accounts);
          return sendJson(response, 200, { account: sanitizeAccount(account) });
        }

        if (path === '/admin/accounts/disable') {
          const account = accountState(accounts, String(body.uid || ''));
          if (!account) return sendJson(response, 404, { error: 'ACCOUNT_NOT_FOUND' });
          account.disabled = body.disabled !== false;
          await saveAccounts(storage, accounts);
          return sendJson(response, 200, { account: sanitizeAccount(account) });
        }

        if (path === '/admin/accounts/delete') {
          const account = accountState(accounts, String(body.uid || ''));
          if (!account) return sendJson(response, 404, { error: 'ACCOUNT_NOT_FOUND' });
          await storage.delete(userKey(account.email));
          await storage.delete('/sync/' + account.uid + '.json');
          accounts = accounts.filter(item => item.uid !== account.uid);
          await saveAccounts(storage, accounts);
          log('admin_account_deleted', { requestId, uid: account.uid });
          return sendJson(response, 200, { ok: true });
        }

        if (path === '/admin/accounts/migrate') {
          const incoming = Array.isArray(body.accounts) ? body.accounts.slice(0, 500) : [];
          let migrated = 0;
          for (const candidate of incoming) {
            const email = normalizeEmail(candidate.email);
            if (!validEmail(email) || !candidate.uid || !candidate.expiresAt) continue;
            const user = await storage.get(userKey(email));
            if (!user || user.uid !== candidate.uid) continue;
            if (accountState(accounts, user.uid)) continue;
            accounts.push({ uid: user.uid, email, createdAt: candidate.createdAt || user.at || now(), expiresAt: Number(candidate.expiresAt), disabled: false });
            migrated += 1;
          }
          if (migrated) await saveAccounts(storage, accounts);
          return sendJson(response, 200, { migrated, accounts: accounts.map(sanitizeAccount) });
        }

        return sendJson(response, 404, { error: 'NOT_FOUND' });
      }

      if (path === '/sync/save' || path === '/sync/load') {
        const token = bearerToken(request) || body.idToken;
        const user = verifyToken(token, 'user', now(), config.jwtSecret);
        if (!user || (body.uid && body.uid !== user.uid)) return sendJson(response, 401, { error: 'LOGIN_REQUIRED' });
        const accounts = await loadAccounts(storage);
        const stateError = accountError(accountState(accounts, user.uid), now());
        if (stateError) return sendJson(response, 403, { error: stateError });
        if (path === '/sync/load') {
          const data = await storage.get('/sync/' + user.uid + '.json');
          return sendJson(response, 200, { records: data && Array.isArray(data.records) ? data.records : [] });
        }
        const records = Array.isArray(body.records) ? body.records.slice(0, 200) : [];
        await storage.put('/sync/' + user.uid + '.json', {
          records,
          userName: String(body.userName || '').slice(0, 100),
          lang: String(body.lang || 'zh').slice(0, 10),
          ts: now(),
        });
        return sendJson(response, 200, { ok: true });
      }

      if (path === '/' || path === '/ai') {
        const user = verifyToken(bearerToken(request), 'user', now(), config.jwtSecret);
        if (!user) return sendJson(response, 401, { error: 'LOGIN_REQUIRED_FOR_AI' });
        if (!allowRate('ai:' + user.uid + ':' + ip, 30, 60 * 60 * 1000)) return sendJson(response, 429, { error: 'AI_RATE_LIMIT' });
        const accounts = await loadAccounts(storage);
        const stateError = accountError(accountState(accounts, user.uid), now());
        if (stateError) return sendJson(response, 403, { error: stateError });
        if (!config.deepseekKey) return sendJson(response, 503, { error: 'AI_NOT_CONFIGURED' });
        if (!validateMessages(body.messages)) return sendJson(response, 400, { error: 'INVALID_MESSAGES' });
        const maxTokens = Math.min(1200, Math.max(100, Number.parseInt(body.max_tokens, 10) || 600));
        const upstream = await fetchImpl(DS_URL, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + config.deepseekKey },
          body: JSON.stringify({ model: config.deepseekModel, messages: body.messages, max_tokens: maxTokens, temperature: 0.7, stream: true }),
        });
        if (!upstream.ok) {
          log('ai_upstream_error', { requestId, status: upstream.status });
          return sendJson(response, 502, { error: 'AI_UPSTREAM_ERROR' });
        }
        response.writeHead(200, {
          'Content-Type': 'text/event-stream; charset=utf-8',
          'Cache-Control': 'no-cache, no-store',
          'X-Accel-Buffering': 'no',
        });
        const reader = upstream.body.getReader();
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          response.write(value);
        }
        response.end();
        log('ai_success', { requestId, uid: user.uid, maxTokens });
        return;
      }

      return sendJson(response, 404, { error: 'NOT_FOUND' });
    } catch (error) {
      log('request_error', { requestId, path, message: error.message });
      if (!response.headersSent) return sendJson(response, 500, { error: 'INTERNAL_ERROR', requestId });
      response.end();
    }
  };
}

if (require.main === module) {
  const missing = [];
  if (!CONFIG.jwtSecret) missing.push('JWT_SECRET');
  if (!CONFIG.adminPasswordHash) missing.push('ADMIN_PASSWORD_HASH');
  if (missing.length) log('config_warning', { missing });
  const port = Number(process.env.FC_SERVER_PORT || 9000);
  http.createServer(createHandler()).listen(port, '0.0.0.0', () => {
    log('server_started', { port, version: '4.0.0' });
  });
}

module.exports = {
  CONFIG,
  accountError,
  createHandler,
  createRateLimiter,
  encodeAdminPassword,
  isAllowedOrigin,
  makePasswordRecord,
  makeToken,
  normalizeEmail,
  userKey,
  validEmail,
  validateMessages,
  verifyAdminPassword,
  verifyPassword,
  verifyToken,
};
