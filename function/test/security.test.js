'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

process.env.JWT_SECRET = 'test-secret-that-is-long-enough';

const {
  accountError,
  createRateLimiter,
  encodeAdminPassword,
  isAllowedOrigin,
  makePasswordRecord,
  makeToken,
  validEmail,
  validateMessages,
  verifyAdminPassword,
  verifyPassword,
  verifyToken,
} = require('../index');

test('new passwords use scrypt and verify safely', () => {
  const record = makePasswordRecord('correct horse battery staple');
  assert.equal(record.hashAlg, 'scrypt-v1');
  assert.equal(verifyPassword('correct horse battery staple', record), true);
  assert.equal(verifyPassword('wrong password', record), false);
});

test('legacy password records remain compatible for migration', () => {
  const crypto = require('crypto');
  const salt = 'legacy-salt';
  const hash = crypto.createHmac('sha256', salt).update('old-password').digest('hex');
  assert.equal(verifyPassword('old-password', { salt, hash }), true);
  assert.equal(verifyPassword('wrong', { salt, hash }), false);
});

test('admin password hashes do not contain plaintext', () => {
  const encoded = encodeAdminPassword('a-long-admin-password');
  assert.equal(encoded.includes('a-long-admin-password'), false);
  assert.equal(verifyAdminPassword('a-long-admin-password', encoded), true);
  assert.equal(verifyAdminPassword('incorrect', encoded), false);
});

test('tokens are signed, typed, and expire', () => {
  const token = makeToken('u1', 'user@example.com', 'user', 1000);
  assert.equal(verifyToken(token, 'user', 1001).uid, 'u1');
  assert.equal(verifyToken(token, 'admin', 1001), null);
  assert.equal(verifyToken(token, 'user', 1000 + 8 * 86400000), null);
  assert.equal(verifyToken(token + 'x', 'user', 1001), null);
});

test('account expiration and disable state are enforced', () => {
  assert.equal(accountError(null, 1000), null);
  assert.equal(accountError({ expiresAt: 2000, disabled: false }, 1000), null);
  assert.equal(accountError({ expiresAt: 999, disabled: false }, 1000), 'USER_EXPIRED');
  assert.equal(accountError({ expiresAt: 2000, disabled: true }, 1000), 'USER_DISABLED');
});

test('rate limiter resets after its window', () => {
  let now = 1000;
  const allow = createRateLimiter(() => now);
  assert.equal(allow('key', 2, 100), true);
  assert.equal(allow('key', 2, 100), true);
  assert.equal(allow('key', 2, 100), false);
  now = 1100;
  assert.equal(allow('key', 2, 100), true);
});

test('origin, email, and AI message validation reject unsafe input', () => {
  assert.equal(isAllowedOrigin('https://vin78999.github.io'), true);
  assert.equal(isAllowedOrigin('https://evil.example'), false);
  assert.equal(validEmail('person@example.com'), true);
  assert.equal(validEmail('not-an-email'), false);
  assert.equal(validateMessages([{ role: 'user', content: 'hello' }]), true);
  assert.equal(validateMessages([{ role: 'tool', content: 'hello' }]), false);
  assert.equal(validateMessages([{ role: 'user', content: 'x'.repeat(12001) }]), false);
});
