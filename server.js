'use strict';

const express = require('express');
const session = require('express-session');
const fs      = require('fs');
const path    = require('path');

const app    = express();

const PORT           = process.env.PORT          || 3000;
const ADMIN_USER     = process.env.ADMIN_USER    || 'admin';
const ADMIN_PASS     = process.env.ADMIN_PASS    || 'admin';
const ADMIN_SECRET   = process.env.ADMIN_SECRET  || 'freef1-admin-secret-change-me';
const VISITOR_SECRET = process.env.VISITOR_SECRET || 'doggomc';
const ALLOWED_ORIGIN = (process.env.ALLOWED_ORIGIN || 'https://freef1.netlify.app').replace(/\/$/, '');
const AUTHORIZED_DOMAIN = 'freef1.netlify.app';

// Site root — set DEV_DIR to the folder containing your index.html
// Render example: DEV_DIR=/opt/render/project/Development-FreeF1
const DEV_DIR = resolveDir(process.env.DEV_DIR, [
  path.join(__dirname, '..', 'Development - FreeF1'),
  path.join(__dirname, 'Development - FreeF1'),
  path.join(__dirname, '..', '..', 'Development - FreeF1'),
  path.join(process.cwd(), 'Development - FreeF1'),
  path.join(process.cwd(), '..', 'Development - FreeF1'),
  path.join('/opt', 'render', 'project', 'Development - FreeF1'),
  path.join('/opt', 'render', 'project', 'development-freef1'),
  path.join('/opt', 'render', 'project', 'site'),
  path.join(process.cwd(), 'public'),
  path.join(process.cwd(), 'site'),
  process.cwd()
]);

const ADMIN_DIR = resolveDir(process.env.ADMIN_DIR, [
  path.join(__dirname, 'admin'),
  path.join(process.cwd(), 'admin'),
  path.join('/opt', 'render', 'project', 'admin')
]);

function resolveDir(envValue, candidates) {
  if (envValue && fs.existsSync(envValue)) return envValue;
  for (const candidate of candidates) {
    if (fs.existsSync(candidate)) return candidate;
  }
  return envValue || candidates[0];
}

function findIndexHtml(dir) {
  if (!dir) return null;
  const direct = path.join(dir, 'index.html');
  if (fs.existsSync(direct)) return direct;
  // Search one level deep for any index.html
  try {
    const entries = fs.readdirSync(dir, { withFileTypes: true });
    for (const entry of entries) {
      if (entry.isDirectory()) {
        const nested = path.join(dir, entry.name, 'index.html');
        if (fs.existsSync(nested)) return nested;
      }
    }
  } catch (_) {}
  return direct;
}

// ─────────────────────────────────────────────
// DATA STORES
// ─────────────────────────────────────────────

// visitorId -> { ip, country, city, browser, os, deviceType, page, connectedAt, lastSeen, online }
const activeUsers = new Map();

// Stream override state
const streamOverride = {
  active: false,
  url: null,
  type: null, // 'youtube' | 'mp4' | 'embed' | null
  startedAt: null
};

// SSE clients for admin dashboard
const sseClients = new Set();

// Heartbeat / cleanup settings
const HEARTBEAT_TIMEOUT  = 60_000;
const CLEANUP_INTERVAL   = 30_000;
const GEO_API            = 'http://ip-api.com/json';

// ─────────────────────────────────────────────
// MIDDLEWARE
// ─────────────────────────────────────────────

app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', ALLOWED_ORIGIN);
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-Visitor-Secret, X-User-Id');
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  if (req.headers.origin && req.headers.origin.replace(/\/$/, '') !== ALLOWED_ORIGIN) {
    return res.status(403).json({ error: 'Forbidden' });
  }
  next();
});

app.use(express.json());

// Session for admin (memory store; cleared on server restart)
const sessionMiddleware = session({
  secret: ADMIN_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: 'lax',
    maxAge: 24 * 60 * 60 * 1000 // 24 hours
  }
});

// ─────────────────────────────────────────────
// UTILITY — User-Agent Parsing
// ─────────────────────────────────────────────

function parseUA(ua) {
  if (!ua) return { browser: 'Unknown', os: 'Unknown', deviceType: 'Desktop' };
  const lower = ua.toLowerCase();

  const osMatch =
    /windows nt (\d+\.?\d*)/.exec(lower)   ? { os: 'Windows ' + RegExp.$1 } :
    /mac os x (\d+[._]\d+[._]?\d*)/.exec(lower) ? { os: 'macOS ' + RegExp.$1.replace(/_/g, '.') } :
    /iphone os (\d+[._]\d+)/.exec(lower)   ? { os: 'iOS ' + RegExp.$1.replace(/_/g, '.') } :
    /ipad.*os (\d+[._]\d+)/.exec(lower)    ? { os: 'iPadOS ' + RegExp.$1.replace(/_/g, '.') } :
    /android (\d+[./]\d+)/.exec(lower)     ? { os: 'Android ' + RegExp.$1.replace(/\//, '.') } :
    /linux/.test(lower)                     ? { os: 'Linux' } :
    /cros/.test(lower)                      ? { os: 'ChromeOS' } :
                                             { os: 'Unknown' };

  const browserMatch =
    /edg\/(\d+[\.\d]*)/.exec(lower)         ? { browser: 'Edge ' + RegExp.$1.split('.')[0] } :
    /opr\/(\d+[\.\d]*)/.exec(lower)         ? { browser: 'Opera ' + RegExp.$1.split('.')[0] } :
    /chrome\/(\d+[\.\d]*)/.exec(lower) && !/edg|opr/.test(lower)
                                              ? { browser: 'Chrome ' + RegExp.$1.split('.')[0] } :
    /firefox\/(\d+[\.\d]*)/.exec(lower)     ? { browser: 'Firefox ' + RegExp.$1.split('.')[0] } :
    /safari\/(\d+[\.\d]*)/.exec(lower) && !/chrome/.test(lower)
                                              ? { browser: 'Safari ' + RegExp.$1.split('.')[0] } :
    /samsungbrowser\/(\d+)/.exec(lower)      ? { browser: 'Samsung ' + RegExp.$1 } :
    /micromessenger\/(\d+)/.exec(lower)      ? { browser: 'WeChat ' + RegExp.$1 } :
    /instagram/.test(lower)                   ? { browser: 'Instagram' } :
    /tiktok/.test(lower)                     ? { browser: 'TikTok' } :
                                              { browser: 'Unknown' };

  const deviceType =
    /mobile|android|iphone|ipod|blackberry|mini|windows\s+phone|silk/.test(lower) ? 'Mobile' :
    /tablet|ipad|playbook|silk|(android(?!.*mobile))/.test(lower)             ? 'Tablet' :
                                                                                 'Desktop';

  return { ...osMatch, ...browserMatch, deviceType };
}

// ─────────────────────────────────────────────
// UTILITY — Stream URL Classification
// ─────────────────────────────────────────────

function classifyStreamURL(url) {
  if (!url) return { type: null, embedUrl: null };
  const trimmed = url.trim();

  if (/^https?:\/\/(www\.)?youtube\.com\/watch\?v=([A-Za-z0-9_-]+)/.test(trimmed) ||
      /^https?:\/\/youtu\.be\/([A-Za-z0-9_-]+)/.test(trimmed)) {
    const id = (trimmed.match(/[?&]v=([A-Za-z0-9_-]+)/) || trimmed.match(/\/([A-Za-z0-9_-]+)$/))?.[1];
    return { type: 'youtube', embedUrl: id ? `https://www.youtube-nocookie.com/embed/${id}?autoplay=1&rel=0&modestbranding=1` : null };
  }
  if (/\.mp4(\?.*)?$/i.test(trimmed)) return { type: 'mp4', embedUrl: trimmed };
  if (/\.webm(\?.*)?$/i.test(trimmed)) return { type: 'mp4', embedUrl: trimmed };

  // Attempt generic embed fallback
  return { type: 'embed', embedUrl: trimmed };
}

// ─────────────────────────────────────────────
// UTILITY — SSE Broadcast
// ─────────────────────────────────────────────

function broadcastSSE(event, data) {
  const payload = `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
  for (const res of sseClients) {
    try { res.write(payload); } catch (_) { sseClients.delete(res); }
  }
}

// ─────────────────────────────────────────────
// GEO LOOKUP (async, fire-and-forget)
// ─────────────────────────────────────────────

async function lookupGeo(ip) {
  try {
    const res = await fetch(`${GEO_API}/${ip}?fields=status,city,country,countryCode,lat,lon,query&timeout=3000`);
    if (!res.ok) return;
    const d = await res.json();
    if (d.status === 'success') return d;
  } catch (_) { /* silently skip geo if API unreachable */ }
  return null;
}

// ─────────────────────────────────────────────
// VISITOR TRACKING MIDDLEWARE
// Applied to all site-serving routes (non-admin, non-API)
// ─────────────────────────────────────────────

function visitorTracking(req, res, next) {
  // Skip admin routes, API routes that don't need tracking, and static assets
  if (req.path.startsWith('/admin') || req.path.startsWith('/api/admin')) return next();

  const ip       = (req.headers['x-forwarded-for'] || req.ip || req.connection.remoteAddress || 'unknown').split(',')[0].trim();
  const ua       = req.headers['user-agent'] || '';
  const { browser, os, deviceType } = parseUA(ua);
  const page     = req.path;
  const now      = Date.now();

  // Check if this IP already has a session
  let entry = activeUsers.get(ip);
  if (!entry) {
    entry = {
      ip,
      country: null,
      city: null,
      countryCode: null,
      browser,
      os,
      deviceType,
      page,
      connectedAt: now,
      lastSeen: now,
      online: true
    };
    activeUsers.set(ip, entry);
    lookupGeo(ip).then(geo => {
      if (!geo || !activeUsers.has(ip)) return;
      const e = activeUsers.get(ip);
      e.country     = geo.country  || null;
      e.city        = geo.city     || null;
      e.countryCode = geo.countryCode || null;
      broadcastSSE('visitor_update', { type: 'geo', visitor: sanitizeVisitor(e) });
    });
  } else {
    entry.lastSeen = now;
    entry.browser  = browser;
    entry.os       = os;
    entry.deviceType = deviceType;
    entry.page     = page;
    entry.online   = true;
  }
  next();
}

app.use(visitorTracking);

// ─────────────────────────────────────────────
// CLEANUP LOOP
// ─────────────────────────────────────────────

setInterval(() => {
  const now = Date.now();
  for (const [id, v] of activeUsers) {
    if (now - v.lastSeen > HEARTBEAT_TIMEOUT) {
      v.online = false;
      broadcastSSE('visitor_update', { type: 'offline', visitor: sanitizeVisitor(v) });
      activeUsers.delete(id);
    }
  }
  broadcastSSE('stats', getStats());
}, CLEANUP_INTERVAL);

function sanitizeVisitor(v) {
  return {
    ip: v.ip,
    country: v.country,
    city: v.city,
    countryCode: v.countryCode,
    browser: v.browser,
    os: v.os,
    deviceType: v.deviceType,
    page: v.page,
    connectedAt: v.connectedAt,
    lastSeen: v.lastSeen,
    online: v.online
  };
}

function getStats() {
  const now = Date.now();
  let onlineCount = 0;
  const visitors = [];
  for (const v of activeUsers.values()) {
    const online = now - v.lastSeen <= HEARTBEAT_TIMEOUT;
    if (online) onlineCount++;
    visitors.push(sanitizeVisitor(v));
  }
  return {
    onlineCount,
    totalUnique: activeUsers.size,
    visitors,
    override: streamOverride.active ? {
      active: true,
      url: streamOverride.url,
      type: streamOverride.type,
      startedAt: streamOverride.startedAt
    } : { active: false }
  };
}

// ─────────────────────────────────────────────
// STATIC FILES — Main site
// ─────────────────────────────────────────────

console.log(`[Config] DEV_DIR   = ${DEV_DIR}`);
console.log(`[Config] ADMIN_DIR = ${ADMIN_DIR}`);
console.log(`[Config] DEV_DIR exists: ${fs.existsSync(DEV_DIR)}`);
console.log(`[Config] ADMIN_DIR exists: ${fs.existsSync(ADMIN_DIR)}`);

app.use(express.static(DEV_DIR, { index: false }));

app.get('/', (req, res) => {
  const indexPath = findIndexHtml(DEV_DIR);
  if (!fs.existsSync(indexPath)) {
    return res.status(404).send(
      `<h1>404 — Site not found</h1>
       <p>index.html not found under: ${DEV_DIR}</p>
       <p>Resolved path: ${indexPath}</p>
       <p>Set the <strong>DEV_DIR</strong> environment variable on Render to the folder containing your index.html</p>`
    );
  }
  res.sendFile(indexPath);
});

// Auth verification (existing, kept intact)
app.get('/api/auth/verify', (req, res) => {
  const host    = req.headers.host    || '';
  const origin  = req.headers.origin  || '';
  const referer = req.headers.referer || '';
  const isAuthorized =
    origin.includes(AUTHORIZED_DOMAIN) ||
    referer.includes(AUTHORIZED_DOMAIN)  ||
    host.includes('localhost') ||
    host.includes('127.0.0.1');
  if (isAuthorized) return res.json({ authorized: true, domain: AUTHORIZED_DOMAIN });
  res.status(403).json({ authorized: false, error: 'Unauthorized', message: 'Access only from ' + AUTHORIZED_DOMAIN });
});

// Visitor heartbeat (existing, kept intact)
app.get('/api/visitors/heartbeat', (req, res) => {
  const secret = req.headers['x-visitor-secret'];
  if (secret !== VISITOR_SECRET) return res.status(403).json({ error: 'Forbidden' });
  const userId = req.headers['x-user-id'];
  if (!userId) return res.status(400).json({ error: 'Missing user ID' });
  activeUsers.set(userId, Date.now());
  res.json({ active: activeUsers.size });
});

app.get('/api/visitors/active', (req, res) => {
  const secret = req.headers['x-visitor-secret'];
  if (secret !== VISITOR_SECRET) return res.status(403).json({ error: 'Forbidden' });
  const now = Date.now();
  let count = 0;
  for (const lastSeen of activeUsers.values()) {
    if (now - lastSeen <= HEARTBEAT_TIMEOUT) count++;
  }
  res.json({ active: count });
});

// ─────────────────────────────────────────────
// ADMIN — STATIC FILES & AUTHENTICATION
// ─────────────────────────────────────────────

app.use('/admin', express.static(ADMIN_DIR, { index: false }));

app.use('/admin/api/login', sessionMiddleware);
app.post('/admin/api/login', (req, res) => {
  const { username, password } = req.body || {};
  if (username === ADMIN_USER && password === ADMIN_PASS) {
    req.session.isAdmin = true;
    req.session.loginAt = Date.now();
    return res.json({ success: true });
  }
  res.status(401).json({ success: false, error: 'Invalid credentials' });
});

app.use('/admin/api/*', sessionMiddleware, (req, res, next) => {
  if (!req.session.isAdmin) return res.status(401).json({ error: 'Not authenticated' });
  next();
});

app.post('/admin/api/logout', (req, res) => {
  req.session.destroy(() => res.json({ success: true }));
});

app.get('/admin/api/status', (req, res) => {
  res.json({ authenticated: !!req.session.isAdmin });
});

// ─────────────────────────────────────────────
// ADMIN — API ENDPOINTS
// ─────────────────────────────────────────────

app.get('/admin/api/visitors', (req, res) => {
  res.json(getStats());
});

app.get('/admin/api/stream/status', (req, res) => {
  res.json({
    active: streamOverride.active,
    url:    streamOverride.url,
    type:   streamOverride.type,
    startedAt: streamOverride.startedAt
  });
});

app.post('/admin/api/stream/override', (req, res) => {
  const { url } = req.body || {};
  if (!url || !url.trim()) {
    return res.status(400).json({ error: 'Stream URL is required' });
  }
  const { type, embedUrl } = classifyStreamURL(url.trim());
  if (!embedUrl) return res.status(400).json({ error: 'Unsupported URL format' });

  streamOverride.active   = true;
  streamOverride.url      = embedUrl;
  streamOverride.type     = type;
  streamOverride.startedAt = Date.now();

  broadcastSSE('stream_override', {
    active: true,
    url: embedUrl,
    type,
    startedAt: streamOverride.startedAt
  });
  broadcastSSE('stream_update', { active: true, url: embedUrl, type });

  res.json({ success: true, override: { active: true, url: embedUrl, type, startedAt: streamOverride.startedAt } });
});

app.post('/admin/api/stream/stop', (req, res) => {
  streamOverride.active   = false;
  streamOverride.url      = null;
  streamOverride.type     = null;
  streamOverride.startedAt = null;

  broadcastSSE('stream_override', { active: false, url: null, type: null });
  broadcastSSE('stream_update', { active: false, url: null, type: null });

  res.json({ success: true, override: { active: false } });
});

app.post('/admin/api/stream/normal', (req, res) => {
  // Alias for /stop — explicitly return to normal stream
  streamOverride.active   = false;
  streamOverride.url      = null;
  streamOverride.type     = null;
  streamOverride.startedAt = null;

  broadcastSSE('stream_override', { active: false, url: null, type: null });
  broadcastSSE('stream_update', { active: false, url: null, type: null });

  res.json({ success: true, message: 'Returned to normal stream', override: { active: false } });
});

// ─────────────────────────────────────────────
// ADMIN — SSE ENDPOINT
// ─────────────────────────────────────────────

app.get('/admin/api/events', (req, res) => {
  if (!req.session.isAdmin) {
    res.status(401).write('data: {"error":"Not authenticated"}\n\n');
    return res.end();
  }

  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.setHeader('X-Accel-Buffering', 'no');

  sseClients.add(res);

  // Send initial snapshot
  const payload = `event: init\ndata: ${JSON.stringify(getStats())}\n\n`;
  res.write(payload);

  const heartbeat = setInterval(() => {
    try { res.write(':\n\n'); } catch (_) { /* client disconnected */ }
  }, 15_000);

  req.on('close', () => {
    clearInterval(heartbeat);
    sseClients.delete(res);
  });
});

// ─────────────────────────────────────────────
// ADMIN — SPA FALLBACK
// ─────────────────────────────────────────────

app.get('/admin', (req, res) => {
  const p = path.join(ADMIN_DIR, 'index.html');
  if (!fs.existsSync(p)) return res.status(404).send(`<h1>404</h1><p>admin/index.html not found at: ${p}</p>`);
  res.sendFile(p);
});
app.get('/admin/login', (req, res) => {
  const p = path.join(ADMIN_DIR, 'index.html');
  if (!fs.existsSync(p)) return res.status(404).send(`<h1>404</h1><p>admin/index.html not found at: ${p}</p>`);
  res.sendFile(p);
});

// ─────────────────────────────────────────────
// SERVER STARTUP
// ─────────────────────────────────────────────

app.listen(PORT, () => {
  console.log(`[Server] Running on http://localhost:${PORT}`);
  console.log(`[Main]  Site:  http://localhost:${PORT}/  (${DEV_DIR})`);
  console.log(`[Admin] Panel: http://localhost:${PORT}/admin  (${ADMIN_DIR})`);
  console.log(`[Admin] Login: ${ADMIN_USER} / ${ADMIN_PASS}`);
});
