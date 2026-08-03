'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');

process.env.JWT_SECRET = 'integration-secret-that-is-long-enough';

const { CONFIG, createHandler, encodeAdminPassword } = require('../index');

function memoryStorage() {
  const values = new Map();
  return {
    values,
    async get(key) {
      const value = values.get(key);
      return value === undefined ? null : structuredClone(value);
    },
    async put(key, value) {
      values.set(key, structuredClone(value));
      return true;
    },
    async delete(key) {
      values.delete(key);
      return true;
    },
  };
}

async function withServer(callback) {
  const storage = memoryStorage();
  let now = 1700000000000;
  const config = {
    ...CONFIG,
    jwtSecret: process.env.JWT_SECRET,
    adminPasswordHash: encodeAdminPassword('very-secure-admin-password'),
    deepseekKey: '',
    allowedOrigins: ['https://vin78999.github.io'],
  };
  const server = http.createServer(createHandler({ storage, config, now: () => now }));
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const base = 'http://127.0.0.1:' + server.address().port;
  try {
    await callback({ base, storage, setNow: value => { now = value; } });
  } finally {
    await new Promise(resolve => server.close(resolve));
  }
}

async function api(base, path, options = {}) {
  const response = await fetch(base + path, {
    ...options,
    headers: { Origin: 'https://vin78999.github.io', 'Content-Type': 'application/json', ...(options.headers || {}) },
  });
  const body = await response.json();
  return { response, body };
}

test('admin creates an expiring account and user authentication protects AI', async () => {
  await withServer(async ({ base, storage, setNow }) => {
    const blockedOrigin = await fetch(base + '/health', { headers: { Origin: 'https://evil.example' } });
    assert.equal(blockedOrigin.status, 403);

    const publicRegister = await api(base, '/auth/register', { method: 'POST', body: '{}' });
    assert.equal(publicRegister.response.status, 403);

    const invalidSupport = await api(base, '/support/request', {
      method: 'POST', body: JSON.stringify({ type: 'technical', email: 'bad-email', message: 'too short' }),
    });
    assert.equal(invalidSupport.response.status, 400);

    const support = await api(base, '/support/request', {
      method: 'POST',
      body: JSON.stringify({
        type: 'technical',
        email: 'visitor@example.com',
        message: 'The assessment page does not advance after I select an answer.',
      }),
    });
    assert.equal(support.response.status, 200);
    assert.match(support.body.ticketId, /^TCM-[0-9A-F]{8}$/);

    const adminLogin = await api(base, '/admin/login', {
      method: 'POST', body: JSON.stringify({ password: 'very-secure-admin-password' }),
    });
    assert.equal(adminLogin.response.status, 200);
    assert.ok(adminLogin.body.token);

    const supportList = await api(base, '/admin/support', {
      method: 'GET', headers: { Authorization: 'Bearer ' + adminLogin.body.token },
    });
    assert.equal(supportList.response.status, 200);
    assert.equal(supportList.body.tickets.length, 1);
    assert.equal(supportList.body.tickets[0].email, 'visitor@example.com');

    const resolvedSupport = await api(base, '/admin/support/resolve', {
      method: 'POST',
      headers: { Authorization: 'Bearer ' + adminLogin.body.token },
      body: JSON.stringify({ id: support.body.ticketId, resolved: true }),
    });
    assert.equal(resolvedSupport.response.status, 200);
    assert.equal(resolvedSupport.body.ticket.status, 'resolved');

    const trialRequest = await api(base, '/support/request', {
      method: 'POST',
      body: JSON.stringify({
        type: 'account',
        email: 'trial@example.com',
        message: 'I would like to apply for a one-day trial account.',
      }),
    });
    assert.equal(trialRequest.response.status, 200);

    const anonymousApproval = await api(base, '/admin/support/approve-trial', {
      method: 'POST', body: JSON.stringify({ id: trialRequest.body.ticketId }),
    });
    assert.equal(anonymousApproval.response.status, 401);

    const approvedTrial = await api(base, '/admin/support/approve-trial', {
      method: 'POST',
      headers: { Authorization: 'Bearer ' + adminLogin.body.token },
      body: JSON.stringify({ id: trialRequest.body.ticketId }),
    });
    assert.equal(approvedTrial.response.status, 200);
    assert.equal(approvedTrial.body.ticket.trialStatus, 'approved');
    assert.equal(approvedTrial.body.ticket.trialExpiresAt, 1700000000000 + 86400000);
    assert.equal(Object.hasOwn(approvedTrial.body.ticket, 'credentialCipher'), false);

    const wrongClaim = await api(base, '/support/status', {
      method: 'POST',
      body: JSON.stringify({ ticketId: trialRequest.body.ticketId, email: 'wrong@example.com' }),
    });
    assert.equal(wrongClaim.response.status, 404);

    const claimedTrial = await api(base, '/support/status', {
      method: 'POST',
      body: JSON.stringify({ ticketId: trialRequest.body.ticketId, email: 'trial@example.com' }),
    });
    assert.equal(claimedTrial.response.status, 200);
    assert.equal(claimedTrial.body.status, 'approved');
    assert.equal(claimedTrial.body.credentials.email, 'trial@example.com');
    assert.ok(claimedTrial.body.credentials.password.length >= 10);

    const trialLogin = await api(base, '/auth/login', {
      method: 'POST',
      body: JSON.stringify({ email: 'trial@example.com', password: claimedTrial.body.credentials.password }),
    });
    assert.equal(trialLogin.response.status, 200);

    const secondClaim = await api(base, '/support/status', {
      method: 'POST',
      body: JSON.stringify({ ticketId: trialRequest.body.ticketId, email: 'trial@example.com' }),
    });
    assert.equal(secondClaim.response.status, 200);
    assert.equal(secondClaim.body.status, 'claimed');
    assert.equal(Object.hasOwn(secondClaim.body, 'credentials'), false);

    const created = await api(base, '/admin/accounts/create', {
      method: 'POST',
      headers: { Authorization: 'Bearer ' + adminLogin.body.token },
      body: JSON.stringify({ email: 'customer@example.com', password: 'customer-password', months: 3 }),
    });
    assert.equal(created.response.status, 200);
    assert.equal(created.body.account.email, 'customer@example.com');
    assert.equal(Object.hasOwn(created.body.account, 'password'), false);

    const login = await api(base, '/auth/login', {
      method: 'POST', body: JSON.stringify({ email: 'customer@example.com', password: 'customer-password' }),
    });
    assert.equal(login.response.status, 200);
    assert.ok(login.body.idToken);

    const anonymousAi = await api(base, '/ai', {
      method: 'POST', body: JSON.stringify({ messages: [{ role: 'user', content: 'hello' }] }),
    });
    assert.equal(anonymousAi.response.status, 401);

    const authenticatedAi = await api(base, '/ai', {
      method: 'POST',
      headers: { Authorization: 'Bearer ' + login.body.idToken },
      body: JSON.stringify({ messages: [{ role: 'user', content: 'hello' }] }),
    });
    assert.equal(authenticatedAi.response.status, 503);
    assert.equal(authenticatedAi.body.error, 'AI_NOT_CONFIGURED');

    const accountIndex = storage.values.get('/admin/accounts.json');
    accountIndex.accounts.find(account => account.email === 'customer@example.com').expiresAt = 1700000000000 - 1;
    storage.values.set('/admin/accounts.json', accountIndex);
    setNow(1700000000000);
    const expiredLogin = await api(base, '/auth/login', {
      method: 'POST', body: JSON.stringify({ email: 'customer@example.com', password: 'customer-password' }),
    });
    assert.equal(expiredLogin.response.status, 403);
    assert.equal(expiredLogin.body.error, 'USER_EXPIRED');
  });
});
