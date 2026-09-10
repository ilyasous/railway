'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const http = require('node:http');
const os = require('node:os');
const path = require('node:path');
const { spawn } = require('node:child_process');
const { after, before, test } = require('node:test');

let child;
let baseUrl;
let dataDirectory;

async function waitForServer(url, timeoutMs = 15000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const response = await fetch(url + '/health');
      if (response.ok) return;
    } catch (error) { /* server is still starting */ }
    await new Promise((resolve) => { setTimeout(resolve, 100); });
  }
  throw new Error('test web server did not become ready');
}

before(async () => {
  dataDirectory = fs.mkdtempSync(path.join(os.tmpdir(), 'serveur-railway-test-'));
  const requestedPort = 19000 + Math.floor(Math.random() * 1000);
  baseUrl = 'http://127.0.0.1:' + requestedPort;
  const childEnvironment = {
    ...process.env,
    PORT: String(requestedPort),
    APP_DATA_DIR: dataDirectory,
    ALLOWED_HOSTS: '127.0.0.1',
    WEB_ADMIN_USER: 'ci-admin',
    WEB_ADMIN_PASSWORD: 'integration-only-password'
  };
  delete childEnvironment.TURNSTILE_SITE_KEY;
  delete childEnvironment.TURNSTILE_SECRET_KEY;
  child = spawn(process.execPath, [path.join(__dirname, 'fixtures', 'web-server.js')], {
    env: childEnvironment,
    stdio: ['ignore', 'pipe', 'pipe']
  });
  await waitForServer(baseUrl);
});

after(async () => {
  if (child && !child.killed) child.kill('SIGTERM');
  await new Promise((resolve) => {
    if (!child || child.exitCode !== null) resolve();
    else child.once('exit', resolve);
  });
  fs.rmSync(dataDirectory, { recursive: true, force: true });
});

test('health endpoint is available without authentication', async () => {
  const response = await fetch(baseUrl + '/health');
  assert.equal(response.status, 200);
  const body = await response.json();
  assert.equal(body.ok, true);
});

test('security headers are applied', async () => {
  const response = await fetch(baseUrl + '/');
  assert.equal(response.headers.get('x-content-type-options'), 'nosniff');
  assert.equal(response.headers.get('x-frame-options'), 'DENY');
  assert.match(response.headers.get('content-security-policy') || '', /frame-ancestors 'none'/);
  assert.match(response.headers.get('permissions-policy') || '', /camera=\(\)/);
  assert.equal(response.headers.get('x-powered-by'), null);
});

test('unknown host headers are rejected', async () => {
  const statusCode = await new Promise((resolve, reject) => {
    const request = http.get(baseUrl + '/health', { headers: { host: 'attacker.example' } }, (response) => {
      response.resume();
      response.once('end', () => resolve(response.statusCode));
    });
    request.once('error', reject);
  });
  assert.equal(statusCode, 404);
});

test('protected API rejects anonymous requests', async () => {
  const response = await fetch(baseUrl + '/api/speedtest');
  assert.equal(response.status, 401);
  assert.equal((await response.json()).message, 'Authentication required.');
});

test('login rejects a missing CSRF token', async () => {
  const response = await fetch(baseUrl + '/login', {
    method: 'POST',
    redirect: 'manual',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: 'name=ci-admin&password=integration-only-password'
  });
  assert.equal(response.status, 403);
});

test('login is available with only the two web credential variables', async () => {
  const loginResponse = await fetch(baseUrl + '/login');
  const loginPage = await loginResponse.text();
  assert.equal(loginResponse.status, 200);
  assert.doesNotMatch(loginPage, /cf-turnstile|challenges\.cloudflare\.com/);

  const csrfToken = loginPage.match(/name="_csrf" value="([^"]+)"/)?.[1];
  assert.ok(csrfToken);
  const response = await fetch(baseUrl + '/login', {
    method: 'POST',
    redirect: 'manual',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      name: 'ci-admin',
      password: 'wrong-password',
      _csrf: csrfToken
    })
  });
  assert.equal(response.status, 401);
});

test('oversized form bodies are rejected', async () => {
  const response = await fetch(baseUrl + '/login', {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: 'name=' + 'a'.repeat(12000)
  });
  assert.equal(response.status, 413);
});
