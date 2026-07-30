'use strict';

const crypto = require('crypto');
const express = require('express');
const session = require('express-session');
const fs = require('fs');
const path = require('path');

const app = express();

app.disable('x-powered-by');
app.set('trust proxy', 1);

const SERVER_STARTED_AT = Date.now();
const PORT = process.env.PORT || 3000;
const ADMIN_USER = process.env.ADMIN_USER || 'admin';
const ADMIN_PASS = process.env.ADMIN_PASS || 'admin';
const ADMIN_SECRET = process.env.ADMIN_SECRET || 'freef1-admin-secret-change-me';
const VISITOR_SECRET = process.env.VISITOR_SECRET || 'doggomc';
const AUTHORIZED_DOMAIN = process.env.AUTHORIZED_DOMAIN || 'freef1.netlify.app';
const ALLOWED_ORIGINS = parseOrigins(process.env.ALLOWED_ORIGIN || 'https://freef1.netlify.app');

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

  // Search one level deep for any index.html. This keeps deploys working even
  // when the static site is wrapped in one extra folder by the host/build step.
  try {
    const entries = fs.readdirSync(dir, { withFileTypes: true });
    for (const entry of entries) {
      if (entry.isDirectory()) {
        const nested = path.join(dir, entry.name, 'index.html');
        if (fs.existsSync(nested)) return nested;
      }
    }
  } catch (_) {
    // The caller reports the final missing path in the HTTP response.
  }

  return direct;
}

function parseOrigins(value) {
  return String(value || '')
    .split(',')
    .map(origin => normalizeOrigin(origin.trim()))
    .filter(Boolean);
}

function normalizeOrigin(value) {
  if (!value) return '';
  try {
    return new URL(value).origin.replace(/\/$/, '');
  } catch (_) {
    return String(value).replace(/\/$/, '');
  }
}

function getRequestOrigin(req) {
  const origin = normalizeOrigin(req.headers.origin || '');
  if (origin) return origin;

  const host = req.headers.host;
  if (!host) return '';
  const proto = String(req.headers['x-forwarded-proto'] || req.protocol || 'http').split(',')[0].trim();
  return `${proto}://${host}`;
}

function isLocalOrigin(origin) {
  try {
    const { hostname } = new URL(origin);
    return hostname === 'localhost' || hostname === '127.0.0.1' || hostname === '::1';
  } catch (_) {
    return false;
  }
}

function isSameOriginRequest(req, origin) {
  if (!origin || !req.headers.host) return false;
  const host = req.headers.host;
  const forwardedProto = String(req.headers['x-forwarded-proto'] || '').split(',')[0].trim();
  const protocolCandidates = new Set([req.protocol || 'http', 'http', 'https']);
  if (forwardedProto) protocolCandidates.add(forwardedProto);
  return [...protocolCandidates].some(proto => normalizeOrigin(`${proto}://${host}`) === origin);
}

function isAllowedOrigin(req, origin) {
  if (!origin) return true;
  return (
    ALLOWED_ORIGINS.includes(origin) ||
    isSameOriginRequest(req, origin) ||
    isLocalOrigin(origin)
  );
}

function safeEqual(a, b) {
  const left = Buffer.from(String(a || ''));
  const right = Buffer.from(String(b || ''));
  return left.length === right.length && crypto.timingSafeEqual(left, right);
}

// ─────────────────────────────────────────────
// DATA STORES
// ─────────────────────────────────────────────

// visitorKey -> { id, ip, country, city, browser, os, deviceType, page, connectedAt, lastSeen, online, source }
const activeUsers = new Map();
const visitorKeysSeen = new Set();

// Stream override state
const streamOverride = {
  active: false,
  url: null,
  type: null, // 'youtube' | 'mp4' | 'embed' | null
  startedAt: null
};

// SSE clients for admin dashboard
const sseClients = new Set();
// SSE clients for public site (stream override only)
const publicSseClients = new Set();

// Heartbeat / cleanup settings
const HEARTBEAT_TIMEOUT = Number(process.env.HEARTBEAT_TIMEOUT_MS || 60_000);
const CLEANUP_INTERVAL = Number(process.env.CLEANUP_INTERVAL_MS || 30_000);
const GEO_API = process.env.GEO_API || 'http://ip-api.com/json';

// ─────────────────────────────────────────────
// MIDDLEWARE
// ─────────────────────────────────────────────

app.use((req, res, next) => {
  const origin = normalizeOrigin(req.headers.origin || '');

  res.setHeader('Vary', 'Origin');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-Visitor-Secret, X-User-Id');
  res.setHeader('Access-Control-Allow-Credentials', 'true');

  if (origin && !isAllowedOrigin(req, origin)) {
    return res.status(403).json({ error: 'Forbidden' });
  }

  if (origin) {
    res.setHeader('Access-Control-Allow-Origin', origin);
  } else if (ALLOWED_ORIGINS[0]) {
    res.setHeader('Access-Control-Allow-Origin', ALLOWED_ORIGINS[0]);
  }

  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

app.use(express.json({ limit: '64kb' }));

// Session for admin (memory store; cleared on server restart)
const sessionMiddleware = session({
  secret: ADMIN_SECRET,
  name: 'freef1.sid',
  resave: false,
  saveUninitialized: false,
  proxy: true,
  cookie: {
    httpOnly: true,
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production' ? 'auto' : false,
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
    /windows nt (\d+\.?\d*)/.exec(lower) ? { os: 'Windows ' + RegExp.$1 } :
    /mac os x (\d+[._]\d+[._]?\d*)/.exec(lower) ? { os: 'macOS ' + RegExp.$1.replace(/_/g, '.') } :
    /iphone os (\d+[._]\d+)/.exec(lower) ? { os: 'iOS ' + RegExp.$1.replace(/_/g, '.') } :
    /ipad.*os (\d+[._]\d+)/.exec(lower) ? { os: 'iPadOS ' + RegExp.$1.replace(/_/g, '.') } :
    /android (\d+[./]\d+)/.exec(lower) ? { os: 'Android ' + RegExp.$1.replace(/\//, '.') } :
    /cros/.test(lower) ? { os: 'ChromeOS' } :
    /linux/.test(lower) ? { os: 'Linux' } :
    { os: 'Unknown' };

  const browserMatch =
    /edg\/(\d+[\.\d]*)/.exec(lower) ? { browser: 'Edge ' + RegExp.$1.split('.')[0] } :
    /opr\/(\d+[\.\d]*)/.exec(lower) ? { browser: 'Opera ' + RegExp.$1.split('.')[0] } :
    /samsungbrowser\/(\d+)/.exec(lower) ? { browser: 'Samsung ' + RegExp.$1 } :
    /firefox\/(\d+[\.\d]*)/.exec(lower) ? { browser: 'Firefox ' + RegExp.$1.split('.')[0] } :
    /chrome\/(\d+[\.\d]*)/.exec(lower) && !/edg|opr/.test(lower) ? { browser: 'Chrome ' + RegExp.$1.split('.')[0] } :
    /safari\/(\d+[\.\d]*)/.exec(lower) && !/chrome/.test(lower) ? { browser: 'Safari ' + RegExp.$1.split('.')[0] } :
    /micromessenger\/(\d+)/.exec(lower) ? { browser: 'WeChat ' + RegExp.$1 } :
    /instagram/.test(lower) ? { browser: 'Instagram' } :
    /tiktok/.test(lower) ? { browser: 'TikTok' } :
    { browser: 'Unknown' };

  const deviceType =
    /tablet|ipad|playbook|silk|(android(?!.*mobile))/.test(lower) ? 'Tablet' :
    /mobile|android|iphone|ipod|blackberry|mini|windows\s+phone|silk/.test(lower) ? 'Mobile' :
    'Desktop';

  return { ...osMatch, ...browserMatch, deviceType };
}

// ─────────────────────────────────────────────
// UTILITY — Stream URL Classification
// ─────────────────────────────────────────────

function getYouTubeId(parsedUrl) {
  const host = parsedUrl.hostname.replace(/^www\./, '').toLowerCase();
  if (host === 'youtu.be') return parsedUrl.pathname.split('/').filter(Boolean)[0] || null;
  if (host !== 'youtube.com' && host !== 'youtube-nocookie.com' && host !== 'm.youtube.com') return null;

  if (parsedUrl.pathname === '/watch') return parsedUrl.searchParams.get('v');

  const parts = parsedUrl.pathname.split('/').filter(Boolean);
  if (['embed', 'shorts', 'live'].includes(parts[0])) return parts[1] || null;

  return null;
}

function classifyStreamURL(url) {
  if (!url) return { type: null, embedUrl: null };
  const trimmed = url.trim();

  let parsedUrl;
  try {
    parsedUrl = new URL(trimmed);
  } catch (_) {
    return { type: null, embedUrl: null };
  }

  if (!['http:', 'https:'].includes(parsedUrl.protocol)) {
    return { type: null, embedUrl: null };
  }

  const youtubeId = getYouTubeId(parsedUrl);
  if (youtubeId && /^[A-Za-z0-9_-]{6,}$/.test(youtubeId)) {
    return {
      type: 'youtube',
      embedUrl: `https://www.youtube-nocookie.com/embed/${youtubeId}?autoplay=1&rel=0&modestbranding=1`
    };
  }

  if (/\.(mp4|webm)(\?.*)?$/i.test(parsedUrl.pathname + parsedUrl.search)) {
    return { type: 'mp4', embedUrl: parsedUrl.href };
  }

  // Generic HTTP(S) embed fallback.
  return { type: 'embed', embedUrl: parsedUrl.href };
}

// ─────────────────────────────────────────────
// UTILITY — SSE Broadcast
// ─────────────────────────────────────────────

function broadcastSSE(event, data) {
  const payload = `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
  for (const res of sseClients) {
    try {
      res.write(payload);
    } catch (_) {
      sseClients.delete(res);
    }
  }
}

function broadcastPublicSSE(event, data) {
  const payload = `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
  for (const res of publicSseClients) {
    try {
      res.write(payload);
    } catch (_) {
      publicSseClients.delete(res);
    }
  }
}

function broadcastVisitorChange(type, visitor) {
  broadcastSSE('visitor_update', { type, visitor: sanitizeVisitor(visitor) });
  broadcastSSE('stats', getStats());
}

// ─────────────────────────────────────────────
// GEO LOOKUP (async, fire-and-forget)
// ─────────────────────────────────────────────

function isPublicIp(ip) {
  if (!ip || ip === 'unknown') return false;
  if (ip === '127.0.0.1' || ip === '::1') return false;
  if (/^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/.test(ip)) return false;
  if (/^(fc00:|fd00:|fe80:)/i.test(ip)) return false;
  return true;
}

async function lookupGeo(ip) {
  if (!isPublicIp(ip) || typeof fetch !== 'function') return null;

  try {
    const res = await fetch(`${GEO_API}/${encodeURIComponent(ip)}?fields=status,city,country,countryCode,lat,lon,query&timeout=3000`);
    if (!res.ok) return null;
    const d = await res.json();
    if (d.status === 'success') return d;
  } catch (_) {
    // Silently skip geo if API is unreachable/rate-limited.
  }
  return null;
}

// ─────────────────────────────────────────────
// VISITOR TRACKING
// ─────────────────────────────────────────────

function getClientIp(req) {
  const raw = String(req.headers['x-forwarded-for'] || req.ip || req.socket?.remoteAddress || req.connection?.remoteAddress || 'unknown')
    .split(',')[0]
    .trim();
  if (raw === '::1') return '127.0.0.1';
  return raw.replace(/^::ffff:/, '') || 'unknown';
}

function normalizeVisitorId(value) {
  return String(value || '')
    .trim()
    .replace(/[^A-Za-z0-9_.:@-]/g, '')
    .slice(0, 128);
}

function findVisitorKeyByIp(ip) {
  for (const [key, visitor] of activeUsers) {
    if (visitor.ip === ip) return key;
  }
  return null;
}

function pageFromReferer(req, fallback = '/') {
  const referer = req.headers.referer || req.headers.referrer || '';
  if (!referer) return fallback;
  try {
    const parsed = new URL(referer);
    return parsed.pathname + parsed.search;
  } catch (_) {
    return fallback;
  }
}

function isStaticAssetPath(requestPath) {
  return /\.(?:css|js|mjs|map|png|jpe?g|gif|webp|svg|ico|avif|bmp|webmanifest|json|txt|xml|woff2?|ttf|otf|eot|mp4|webm|mp3|wav|ogg|m4a)$/i.test(requestPath);
}

function getVisitorRouteKey(req) {
  const ip = getClientIp(req);
  const suppliedId = normalizeVisitorId(req.headers['x-user-id']);
  return suppliedId || ip;
}

function upsertVisitor(key, req, options = {}) {
  const now = Date.now();
  const ip = getClientIp(req);
  const ua = req.headers['user-agent'] || '';
  const { browser, os, deviceType } = parseUA(ua);
  const page = options.page || req.path || '/';

  let entry = activeUsers.get(key);
  const isNew = !entry;

  if (!entry) {
    entry = {
      id: key,
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
      online: true,
      source: options.source || 'page'
    };
    activeUsers.set(key, entry);
    visitorKeysSeen.add(key);

    lookupGeo(ip).then(geo => {
      if (!geo || !activeUsers.has(key)) return;
      const current = activeUsers.get(key);
      current.country = geo.country || null;
      current.city = geo.city || null;
      current.countryCode = geo.countryCode || null;
      broadcastVisitorChange('geo', current);
    });
  } else {
    entry.ip = entry.ip || ip;
    entry.browser = browser || entry.browser;
    entry.os = os || entry.os;
    entry.deviceType = deviceType || entry.deviceType;
    entry.page = options.keepExistingPage ? (entry.page || page) : page;
    entry.lastSeen = now;
    entry.online = true;
    entry.source = options.source || entry.source || 'page';
  }

  return { entry, isNew };
}

// Applied to site-serving routes only (not admin, APIs, health checks, or assets).
function visitorTracking(req, res, next) {
  if (
    req.path.startsWith('/admin') ||
    req.path.startsWith('/api/') ||
    req.path === '/healthz' ||
    req.path === '/favicon.ico' ||
    isStaticAssetPath(req.path)
  ) {
    return next();
  }

  const key = getVisitorRouteKey(req);
  const { entry, isNew } = upsertVisitor(key, req, {
    page: req.originalUrl || req.path || '/',
    source: 'page'
  });

  broadcastVisitorChange(isNew ? 'online' : 'update', entry);
  next();
}

app.use(visitorTracking);

// ─────────────────────────────────────────────
// CLEANUP LOOP
// ─────────────────────────────────────────────

function cleanupInactiveVisitors() {
  const now = Date.now();
  for (const [id, v] of activeUsers) {
    if (now - v.lastSeen > HEARTBEAT_TIMEOUT) {
      v.online = false;
      broadcastSSE('visitor_update', { type: 'offline', visitor: sanitizeVisitor(v) });
      activeUsers.delete(id);
    }
  }
  broadcastSSE('stats', getStats());
}

setInterval(cleanupInactiveVisitors, CLEANUP_INTERVAL).unref?.();

function sanitizeVisitor(v) {
  const now = Date.now();
  const lastSeen = Number(v.lastSeen || v.connectedAt || now);
  return {
    id: v.id,
    ip: v.ip,
    country: v.country,
    city: v.city,
    countryCode: v.countryCode,
    browser: v.browser,
    os: v.os,
    deviceType: v.deviceType,
    page: v.page,
    connectedAt: v.connectedAt,
    lastSeen,
    online: now - lastSeen <= HEARTBEAT_TIMEOUT,
    source: v.source
  };
}

function getStats() {
  const now = Date.now();
  let onlineCount = 0;
  const visitors = [];

  for (const visitor of activeUsers.values()) {
    const sanitized = sanitizeVisitor(visitor);
    if (sanitized.online) onlineCount++;
    visitors.push(sanitized);
  }

  visitors.sort((a, b) => b.lastSeen - a.lastSeen);

  return {
    onlineCount,
    activeSessions: activeUsers.size,
    totalUnique: visitorKeysSeen.size,
    visitors,
    override: streamOverride.active ? {
      active: true,
      url: streamOverride.url,
      type: streamOverride.type,
      startedAt: streamOverride.startedAt
    } : { active: false },
    server: {
      startedAt: SERVER_STARTED_AT,
      uptimeMs: now - SERVER_STARTED_AT,
      nodeEnv: process.env.NODE_ENV || 'development'
    }
  };
}

// ─────────────────────────────────────────────
// STATIC FILES — Main site
// ─────────────────────────────────────────────

console.log(`[Config] DEV_DIR   = ${DEV_DIR}`);
console.log(`[Config] ADMIN_DIR = ${ADMIN_DIR}`);
console.log(`[Config] DEV_DIR exists: ${fs.existsSync(DEV_DIR)}`);
console.log(`[Config] ADMIN_DIR exists: ${fs.existsSync(ADMIN_DIR)}`);
console.log(`[Config] Allowed origins: ${ALLOWED_ORIGINS.join(', ') || '(same-origin/local only)'}`);

app.use(express.static(DEV_DIR, {
  index: false,
  fallthrough: true,
  maxAge: process.env.NODE_ENV === 'production' ? '1h' : 0
}));

app.get('/healthz', (req, res) => {
  res.json({ ok: true, uptimeMs: Date.now() - SERVER_STARTED_AT });
});

function sendSiteIndex(req, res) {
  const indexPath = findIndexHtml(DEV_DIR);
  if (!indexPath || !fs.existsSync(indexPath)) {
    return res.status(404).send(
      `<h1>404 — Site not found</h1>
       <p>index.html not found under: ${escapeServerHtml(DEV_DIR)}</p>
       <p>Resolved path: ${escapeServerHtml(indexPath || '(none)')}</p>
       <p>Set the <strong>DEV_DIR</strong> environment variable on Render to the folder containing your index.html.</p>`
    );
  }
  res.sendFile(indexPath);
}

app.get('/', sendSiteIndex);

// Auth verification (existing public endpoint, with same-origin/local support)
app.get('/api/auth/verify', (req, res) => {
  const host = req.headers.host || '';
  const origin = req.headers.origin || '';
  const referer = req.headers.referer || '';
  const sourceOrigin = normalizeOrigin(origin || referer || '');
  const requestOrigin = getRequestOrigin(req);

  const isAuthorized =
    origin.includes(AUTHORIZED_DOMAIN) ||
    referer.includes(AUTHORIZED_DOMAIN) ||
    host.includes('localhost') ||
    host.includes('127.0.0.1') ||
    isLocalOrigin(requestOrigin) ||
    (sourceOrigin && (
      ALLOWED_ORIGINS.includes(sourceOrigin) ||
      isSameOriginRequest(req, sourceOrigin) ||
      isLocalOrigin(sourceOrigin)
    ));

  if (isAuthorized) return res.json({ authorized: true, domain: AUTHORIZED_DOMAIN });
  res.status(403).json({ authorized: false, error: 'Unauthorized', message: 'Access only from ' + AUTHORIZED_DOMAIN });
});

// Visitor heartbeat used by the public site. It now updates the same object shape
// as page tracking instead of corrupting the admin visitor map with raw numbers.
app.get('/api/visitors/heartbeat', (req, res) => {
  const secret = req.headers['x-visitor-secret'];
  if (secret !== VISITOR_SECRET) return res.status(403).json({ error: 'Forbidden' });

  const suppliedUserId = normalizeVisitorId(req.headers['x-user-id']);
  if (!suppliedUserId) return res.status(400).json({ error: 'Missing user ID' });

  const ip = getClientIp(req);
  const existingIpKey = findVisitorKeyByIp(ip);
  const key = activeUsers.has(suppliedUserId) ? suppliedUserId : (existingIpKey || suppliedUserId);
  const { entry, isNew } = upsertVisitor(key, req, {
    page: pageFromReferer(req, activeUsers.get(key)?.page || '/'),
    source: 'heartbeat',
    keepExistingPage: !req.headers.referer
  });

  broadcastVisitorChange(isNew ? 'online' : 'heartbeat', entry);
  res.json({ active: getStats().onlineCount });
});

app.get('/api/visitors/active', (req, res) => {
  const secret = req.headers['x-visitor-secret'];
  if (secret !== VISITOR_SECRET) return res.status(403).json({ error: 'Forbidden' });
  res.json({ active: getStats().onlineCount });
});

// ─────────────────────────────────────────────
// PUBLIC — Stream status & SSE (no auth needed)
// ─────────────────────────────────────────────

// Public endpoint for the Netlify site to poll stream status
app.get('/api/stream/status', (req, res) => {
  res.json({
    active: streamOverride.active,
    url: streamOverride.url,
    type: streamOverride.type,
    startedAt: streamOverride.startedAt
  });
});

// Public SSE endpoint — only sends stream_override / stream_update events (no visitor data)
app.get('/api/events', (req, res) => {
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache, no-transform');
  res.setHeader('Connection', 'keep-alive');
  res.setHeader('X-Accel-Buffering', 'no');
  res.flushHeaders?.();

  publicSseClients.add(res);

  // Send initial stream state
  const initPayload = JSON.stringify(streamOverride.active ? {
    active: streamOverride.active,
    url: streamOverride.url,
    type: streamOverride.type,
    startedAt: streamOverride.startedAt
  } : { active: false, url: null, type: null, startedAt: null });

  res.write(`event: stream_override\ndata: ${initPayload}\n\n`);
  res.write(`event: stream_update\ndata: ${initPayload}\n\n`);

  const heartbeat = setInterval(() => {
    try {
      res.write(': heartbeat\n\n');
    } catch (_) {
      publicSseClients.delete(res);
    }
  }, 15_000);

  req.on('close', () => {
    clearInterval(heartbeat);
    publicSseClients.delete(res);
  });
});

// ─────────────────────────────────────────────
// ADMIN — STATIC FILES & AUTHENTICATION
// ─────────────────────────────────────────────

app.use('/admin', express.static(ADMIN_DIR, { index: false, fallthrough: true }));

app.use('/admin/api/login', sessionMiddleware);
app.post('/admin/api/login', (req, res) => {
  const { username, password } = req.body || {};
  if (safeEqual(username, ADMIN_USER) && safeEqual(password, ADMIN_PASS)) {
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
  res.json({ authenticated: !!req.session.isAdmin, loginAt: req.session.loginAt || null });
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
    url: streamOverride.url,
    type: streamOverride.type,
    startedAt: streamOverride.startedAt
  });
});

app.post('/admin/api/stream/override', (req, res) => {
  const { url } = req.body || {};
  if (!url || !String(url).trim()) {
    return res.status(400).json({ error: 'Stream URL is required' });
  }

  const { type, embedUrl } = classifyStreamURL(String(url).trim());
  if (!embedUrl) return res.status(400).json({ error: 'Unsupported URL format' });

  streamOverride.active = true;
  streamOverride.url = embedUrl;
  streamOverride.type = type;
  streamOverride.startedAt = Date.now();

  const payload = {
    active: true,
    url: embedUrl,
    type,
    startedAt: streamOverride.startedAt
  };

  broadcastSSE('stream_override', payload);
  broadcastSSE('stream_update', payload);
  broadcastSSE('stats', getStats());
  broadcastPublicSSE('stream_override', payload);
  broadcastPublicSSE('stream_update', payload);

  res.json({ success: true, override: payload });
});

function stopStreamOverride(message) {
  streamOverride.active = false;
  streamOverride.url = null;
  streamOverride.type = null;
  streamOverride.startedAt = null;

  const payload = { active: false, url: null, type: null, startedAt: null };
  broadcastSSE('stream_override', payload);
  broadcastSSE('stream_update', payload);
  broadcastSSE('stats', getStats());
  broadcastPublicSSE('stream_override', payload);
  broadcastPublicSSE('stream_update', payload);

  return { success: true, message, override: { active: false } };
}

app.post('/admin/api/stream/stop', (req, res) => {
  res.json(stopStreamOverride('Stream override stopped'));
});

app.post('/admin/api/stream/normal', (req, res) => {
  res.json(stopStreamOverride('Returned to normal stream'));
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
  res.setHeader('Cache-Control', 'no-cache, no-transform');
  res.setHeader('Connection', 'keep-alive');
  res.setHeader('X-Accel-Buffering', 'no');
  res.flushHeaders?.();

  sseClients.add(res);

  // Send initial snapshot
  const payload = `event: init\ndata: ${JSON.stringify(getStats())}\n\n`;
  res.write(payload);

  const heartbeat = setInterval(() => {
    try {
      res.write(': heartbeat\n\n');
    } catch (_) {
      sseClients.delete(res);
    }
  }, 15_000);

  req.on('close', () => {
    clearInterval(heartbeat);
    sseClients.delete(res);
  });
});

// ─────────────────────────────────────────────
// ADMIN — SPA FALLBACK
// ─────────────────────────────────────────────

function sendAdminIndex(req, res) {
  const adminIndex = path.join(ADMIN_DIR, 'index.html');
  if (!fs.existsSync(adminIndex)) {
    return res.status(404).send(`<h1>404</h1><p>admin/index.html not found at: ${escapeServerHtml(adminIndex)}</p>`);
  }
  res.sendFile(adminIndex);
}

app.get(['/admin', '/admin/', '/admin/login'], sendAdminIndex);

// Main-site SPA fallback for deep links. API/admin routes are defined above and
// static assets have already had a chance to resolve through express.static().
app.get(/^\/(?!admin(?:\/|$)|api(?:\/|$)|healthz$).*/, (req, res, next) => {
  if (req.method !== 'GET' || isStaticAssetPath(req.path)) return next();
  sendSiteIndex(req, res);
});

app.use((req, res) => {
  res.status(404).json({ error: 'Not found' });
});

app.use((err, req, res, next) => {
  console.error('[Error]', err);
  if (res.headersSent) return next(err);
  res.status(500).json({ error: 'Internal server error' });
});

function escapeServerHtml(value) {
  return String(value == null ? '' : value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

// ─────────────────────────────────────────────
// SERVER STARTUP
// ─────────────────────────────────────────────

app.listen(PORT, () => {
  console.log(`[Server] Running on http://localhost:${PORT}`);
  console.log(`[Main]  Site:  http://localhost:${PORT}/  (${DEV_DIR})`);
  console.log(`[Admin] Panel: http://localhost:${PORT}/admin  (${ADMIN_DIR})`);
  console.log(`[Admin] User:  ${ADMIN_USER}`);

  if (ADMIN_USER === 'admin' && ADMIN_PASS === 'admin') {
    console.warn('[Security] ADMIN_USER/ADMIN_PASS are still the defaults. Set strong values in production.');
  }
  if (ADMIN_SECRET === 'freef1-admin-secret-change-me') {
    console.warn('[Security] ADMIN_SECRET is still the default. Set a long random value in production.');
  }
  if (VISITOR_SECRET === 'doggomc') {
    console.warn('[Security] VISITOR_SECRET is still the default. Set a private value in production.');
  }
});
