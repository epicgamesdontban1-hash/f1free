#!/usr/bin/env node
'use strict';

const assert = require('assert');
const { spawn } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const root = path.resolve(__dirname, '..');
const port = 34567 + Math.floor(Math.random() * 1000);
const siteDir = fs.mkdtempSync(path.join(os.tmpdir(), 'freef1-site-'));
fs.writeFileSync(path.join(siteDir, 'index.html'), '<!doctype html><title>FreeF1 Smoke</title><h1>OK</h1>');

const env = {
  ...process.env,
  PORT: String(port),
  DEV_DIR: siteDir,
  ADMIN_DIR: path.join(root, 'admin'),
  ADMIN_USER: 'admin',
  ADMIN_PASS: 'admin',
  ADMIN_SECRET: 'smoke-test-secret',
  VISITOR_SECRET: 'smoke-visitor-secret',
  GEO_API: 'http://127.0.0.1:9',
  NODE_ENV: 'test'
};

const child = spawn(process.execPath, ['server.js'], {
  cwd: root,
  env,
  stdio: ['ignore', 'pipe', 'pipe']
});

let output = '';
child.stdout.on('data', chunk => { output += chunk.toString(); });
child.stderr.on('data', chunk => { output += chunk.toString(); });

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

async function request(url, options = {}) {
  const response = await fetch(url, options);
  const text = await response.text();
  let body = text;
  try { body = JSON.parse(text); } catch (_) {}
  return { response, body, text };
}

async function waitForServer() {
  const deadline = Date.now() + 7000;
  while (Date.now() < deadline) {
    try {
      const { response } = await request(`http://127.0.0.1:${port}/healthz`);
      if (response.ok) return;
    } catch (_) {
      await sleep(150);
    }
  }
  throw new Error(`Server did not start. Output:\n${output}`);
}

(async () => {
  try {
    await waitForServer();

    const health = await request(`http://127.0.0.1:${port}/healthz`);
    assert.equal(health.response.status, 200);
    assert.equal(health.body.ok, true);

    const home = await request(`http://127.0.0.1:${port}/`);
    assert.equal(home.response.status, 200);
    assert.match(home.text, /FreeF1 Smoke|OK/);

    const heartbeat = await request(`http://127.0.0.1:${port}/api/visitors/heartbeat`, {
      headers: {
        'x-visitor-secret': 'smoke-visitor-secret',
        'x-user-id': 'smoke-user',
        referer: `http://127.0.0.1:${port}/watch`
      }
    });
    assert.equal(heartbeat.response.status, 200);
    assert.equal(heartbeat.body.active, 1);

    const login = await request(`http://127.0.0.1:${port}/admin/api/login`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        origin: `http://127.0.0.1:${port}`
      },
      body: JSON.stringify({ username: 'admin', password: 'admin' })
    });
    assert.equal(login.response.status, 200);
    assert.equal(login.body.success, true);

    const cookie = login.response.headers.get('set-cookie')?.split(';')[0];
    assert.ok(cookie, 'login should set a session cookie');

    const visitors = await request(`http://127.0.0.1:${port}/admin/api/visitors`, {
      headers: { cookie }
    });
    assert.equal(visitors.response.status, 200);
    assert.equal(visitors.body.onlineCount, 1);
    assert.ok(Array.isArray(visitors.body.visitors));
    assert.equal(typeof visitors.body.visitors[0], 'object');
    assert.equal(visitors.body.visitors[0].page, '/watch');

    const override = await request(`http://127.0.0.1:${port}/admin/api/stream/override`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', cookie },
      body: JSON.stringify({ url: 'https://youtu.be/dQw4w9WgXcQ?t=1' })
    });
    assert.equal(override.response.status, 200);
    assert.equal(override.body.success, true);
    assert.equal(override.body.override.type, 'youtube');
    assert.match(override.body.override.url, /youtube-nocookie\.com\/embed\/dQw4w9WgXcQ/);

    const rejected = await request(`http://127.0.0.1:${port}/admin/api/login`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        origin: 'https://evil.example'
      },
      body: JSON.stringify({ username: 'admin', password: 'admin' })
    });
    assert.equal(rejected.response.status, 403);

    console.log('Smoke tests passed');
  } finally {
    child.kill('SIGTERM');
    await sleep(100);
    fs.rmSync(siteDir, { recursive: true, force: true });
  }
})().catch(err => {
  child.kill('SIGTERM');
  console.error(output);
  console.error(err);
  process.exit(1);
});
