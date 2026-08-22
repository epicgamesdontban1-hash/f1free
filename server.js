'use strict';

const crypto = require('crypto');
const compression = require('compression');
const express = require('express');
const session = require('express-session');
const MemoryStore = require('memorystore')(session);
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
const AUTHORIZED_HOSTNAME = String(AUTHORIZED_DOMAIN).replace(/^https?:\/\//i, '').split('/')[0].split(':')[0].toLowerCase();
const ALLOWED_ORIGINS = parseOrigins(process.env.ALLOWED_ORIGIN || 'https://freef1.netlify.app');

// Durable unique-visitor storage. Upstash's REST API is intentionally used
// directly so this stays dependency-free and works on every Render plan.
const UNIQUE_VISITOR_BASELINE = Math.max(0, Number.parseInt(process.env.UNIQUE_VISITOR_BASELINE || '0', 10) || 0);
const UNIQUE_VISITOR_REDIS_KEY = process.env.UNIQUE_VISITOR_REDIS_KEY || 'freef1:unique-visitors:v1';
const MAINTENANCE_REDIS_KEY = process.env.MAINTENANCE_REDIS_KEY || 'freef1:maintenance:v1';
const UNIQUE_VISITOR_HASH_SECRET = process.env.UNIQUE_VISITOR_HASH_SECRET || ADMIN_SECRET;
const UPSTASH_REDIS_REST_URL = String(process.env.UPSTASH_REDIS_REST_URL || '').replace(/\/+$/, '');
const UPSTASH_REDIS_REST_TOKEN = String(process.env.UPSTASH_REDIS_REST_TOKEN || '');
const UNIQUE_VISITOR_REMOTE_ENABLED = Boolean(UPSTASH_REDIS_REST_URL && UPSTASH_REDIS_REST_TOKEN);

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

function hostnameFromUrl(value) {
  if (!value) return '';
  try { return new URL(value).hostname.toLowerCase(); } catch (_) { return ''; }
}

function isAuthorizedHostname(value) {
  const hostname = String(value || '').split(':')[0].toLowerCase();
  return hostname === AUTHORIZED_HOSTNAME;
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
// Only keyed hashes are retained for unique counting; raw browser IDs/IPs are
// never sent to the durable store.
const visitorKeysSeen = new Set();
const persistedVisitorHashes = new Set();
const pendingUniqueWrites = new Map();
let persistentUniqueCount = 0;
let uniqueVisitorStoreReady = !UNIQUE_VISITOR_REMOTE_ENABLED;
let lastUniqueStoreWarningAt = 0;
// O(1) IP lookups avoid scanning every active visitor on each heartbeat.
const visitorKeyByIp = new Map();
// Geo responses are reused and concurrent lookups for one IP are deduplicated.
const geoCache = new Map();
const pendingGeoLookups = new Map();
const loginAttempts = new Map();
const GEO_CACHE_TTL = Number(process.env.GEO_CACHE_TTL_MS || 6 * 60 * 60 * 1000);

// Stream override state
const streamOverride = {
  active: false,
  url: null,
  type: null, // 'youtube' | 'mp4' | 'embed' | null
  startedAt: null
};

const DEFAULT_MAINTENANCE_MESSAGE = "We'll be back before the race.";
const maintenanceMode = {
  active: false,
  message: DEFAULT_MAINTENANCE_MESSAGE,
  startedAt: null,
  updatedAt: null
};
let maintenanceStoreReady = !UNIQUE_VISITOR_REMOTE_ENABLED;
let maintenanceInitPromise = Promise.resolve(false);

// SSE clients for admin dashboard
const sseClients = new Set();
// SSE clients for public site (stream override only)
const publicSseClients = new Set();

// One shared timer scales better than allocating a timer per connected SSE client.
const sseHeartbeatTimer = setInterval(() => {
  const heartbeat = ': heartbeat\n\n';
  writeSSE(sseClients, heartbeat);
  writeSSE(publicSseClients, heartbeat);
}, 15_000);
sseHeartbeatTimer.unref?.();

// Heartbeat / cleanup settings
const HEARTBEAT_TIMEOUT = Number(process.env.HEARTBEAT_TIMEOUT_MS || 60_000);
const CLEANUP_INTERVAL = Number(process.env.CLEANUP_INTERVAL_MS || 30_000);
const GEO_API = process.env.GEO_API || 'http://ip-api.com/json';

// ─────────────────────────────────────────────
// MIDDLEWARE
// ─────────────────────────────────────────────

app.use(compression({
  threshold: 1024,
  filter(req, res) {
    // Streaming responses must never be buffered by a compressor.
    if (req.path.endsWith('/events') || String(req.headers.accept || '').includes('text/event-stream')) return false;
    return compression.filter(req, res);
  }
}));

app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=(), usb=()');
  if (req.path.startsWith('/api/') || req.path.startsWith('/admin/api/') || req.path === '/healthz') {
    res.setHeader('Cache-Control', 'no-store');
  }
  next();
});

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

// Expiring in-memory store suits a single Render instance without the leak warning
// of express-session's default store. Set up a shared store when scaling to many instances.
const sessionStore = new MemoryStore({ checkPeriod: 15 * 60 * 1000 });
const sessionMiddleware = session({
  store: sessionStore,
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

function writeSSE(clients, payload) {
  for (const res of clients) {
    if (res.destroyed || res.writableEnded) { clients.delete(res); continue; }
    try { res.write(payload); } catch (_) { clients.delete(res); }
  }
}

function broadcastSSE(event, data) {
  if (!sseClients.size) return;
  writeSSE(sseClients, `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);
}

function broadcastPublicSSE(event, data) {
  if (!publicSseClients.size) return;
  writeSSE(publicSseClients, `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);
}

let statsBroadcastTimer = null;
function scheduleStatsBroadcast(delay = 80) {
  if (!sseClients.size || statsBroadcastTimer) return;
  statsBroadcastTimer = setTimeout(() => {
    statsBroadcastTimer = null;
    broadcastSSE('stats', getStats());
  }, delay);
  statsBroadcastTimer.unref?.();
}

function broadcastVisitorChange(type, visitor, includeStats = true) {
  broadcastSSE('visitor_update', { type, visitor: sanitizeVisitor(visitor) });
  if (includeStats) scheduleStatsBroadcast();
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

function pruneGeoCache() {
  const now = Date.now();
  for (const [ip, cached] of geoCache) if (cached.expiresAt <= now) geoCache.delete(ip);
  while (geoCache.size > 5000) geoCache.delete(geoCache.keys().next().value);
}

async function lookupGeo(ip) {
  if (!isPublicIp(ip) || typeof fetch !== 'function') return null;
  const cached = geoCache.get(ip);
  if (cached && cached.expiresAt > Date.now()) return cached.value;
  if (pendingGeoLookups.has(ip)) return pendingGeoLookups.get(ip);

  const lookup = (async () => {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 3500);
    timeout.unref?.();
    try {
      const res = await fetch(`${GEO_API}/${encodeURIComponent(ip)}?fields=status,city,country,countryCode,lat,lon,query&timeout=3000`, { signal: controller.signal });
      if (!res.ok) return null;
      const data = await res.json();
      if (data.status !== 'success') return null;
      geoCache.set(ip, { value: data, expiresAt: Date.now() + GEO_CACHE_TTL });
      if (geoCache.size > 5000) pruneGeoCache();
      return data;
    } catch (_) {
      return null;
    } finally {
      clearTimeout(timeout);
      pendingGeoLookups.delete(ip);
    }
  })();

  pendingGeoLookups.set(ip, lookup);
  return lookup;
}

// ─────────────────────────────────────────────
// DURABLE UNIQUE-VISITOR COUNT
// ─────────────────────────────────────────────

function hashVisitorKey(key) {
  return crypto
    .createHmac('sha256', UNIQUE_VISITOR_HASH_SECRET)
    .update(String(key || 'unknown'))
    .digest('hex');
}

function warnUniqueStore(error) {
  const now = Date.now();
  if (now - lastUniqueStoreWarningAt < 60_000) return;
  lastUniqueStoreWarningAt = now;
  console.warn(`[Visitors] Durable store unavailable; keeping the last confirmed total. ${error?.message || error}`);
}

async function upstashRequest(commands) {
  if (!UNIQUE_VISITOR_REMOTE_ENABLED) throw new Error('Upstash is not configured');
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 3500);
  timeout.unref?.();

  try {
    const isPipeline = Array.isArray(commands[0]);
    const response = await fetch(`${UPSTASH_REDIS_REST_URL}${isPipeline ? '/pipeline' : ''}`, {
      method: 'POST',
      headers: {
        authorization: `Bearer ${UPSTASH_REDIS_REST_TOKEN}`,
        'content-type': 'application/json'
      },
      body: JSON.stringify(commands),
      cache: 'no-store',
      signal: controller.signal
    });

    if (!response.ok) throw new Error(`Upstash HTTP ${response.status}`);
    const payload = await response.json();
    if (payload?.error) throw new Error(payload.error);
    if (Array.isArray(payload)) {
      const failed = payload.find(item => item?.error);
      if (failed) throw new Error(failed.error);
    }
    return payload;
  } finally {
    clearTimeout(timeout);
  }
}

async function syncUniqueVisitorCount() {
  if (!UNIQUE_VISITOR_REMOTE_ENABLED) return false;
  try {
    const payload = await upstashRequest(['SCARD', UNIQUE_VISITOR_REDIS_KEY]);
    const count = Number(payload?.result);
    if (!Number.isFinite(count) || count < 0) throw new Error('Upstash returned an invalid visitor count');
    persistentUniqueCount = count;
    uniqueVisitorStoreReady = true;
    scheduleStatsBroadcast();
    return true;
  } catch (error) {
    warnUniqueStore(error);
    return false;
  }
}

async function trackUniqueVisitor(key) {
  const hash = hashVisitorKey(key);
  const firstSeenThisProcess = !visitorKeysSeen.has(hash);
  visitorKeysSeen.add(hash);

  if (!UNIQUE_VISITOR_REMOTE_ENABLED) return firstSeenThisProcess;
  if (persistedVisitorHashes.has(hash)) return false;
  if (pendingUniqueWrites.has(hash)) return pendingUniqueWrites.get(hash);

  const write = (async () => {
    try {
      // SADD is atomic: two simultaneous requests for one browser can never
      // increment the permanent total twice. SCARD returns the authoritative
      // count after the write, including visitors recorded by another process.
      const payload = await upstashRequest([
        ['SADD', UNIQUE_VISITOR_REDIS_KEY, hash],
        ['SCARD', UNIQUE_VISITOR_REDIS_KEY]
      ]);
      const added = Number(payload?.[0]?.result) === 1;
      const count = Number(payload?.[1]?.result);
      if (!Number.isFinite(count) || count < 0) throw new Error('Upstash returned an invalid visitor count');

      persistedVisitorHashes.add(hash);
      persistentUniqueCount = count;
      uniqueVisitorStoreReady = true;
      if (added) scheduleStatsBroadcast();
      return added;
    } catch (error) {
      warnUniqueStore(error);
      return false;
    } finally {
      pendingUniqueWrites.delete(hash);
    }
  })();

  pendingUniqueWrites.set(hash, write);
  return write;
}

function getTotalUniqueVisitors() {
  if (UNIQUE_VISITOR_REMOTE_ENABLED) {
    return UNIQUE_VISITOR_BASELINE + persistentUniqueCount;
  }
  return UNIQUE_VISITOR_BASELINE + visitorKeysSeen.size;
}

function normalizeMaintenanceMessage(value) {
  const message = String(value || '')
    .replace(/[\u0000-\u001F\u007F]/g, ' ')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, 180);
  return message || DEFAULT_MAINTENANCE_MESSAGE;
}

function publicMaintenanceState() {
  return {
    active: Boolean(maintenanceMode.active),
    message: normalizeMaintenanceMessage(maintenanceMode.message),
    startedAt: maintenanceMode.startedAt || null,
    updatedAt: maintenanceMode.updatedAt || null
  };
}

function applyMaintenanceState(state) {
  const active = Boolean(state?.active);
  maintenanceMode.active = active;
  maintenanceMode.message = normalizeMaintenanceMessage(state?.message);
  maintenanceMode.startedAt = active ? (Number(state?.startedAt) || Date.now()) : null;
  maintenanceMode.updatedAt = Number(state?.updatedAt) || Date.now();
  return publicMaintenanceState();
}

async function syncMaintenanceState() {
  if (!UNIQUE_VISITOR_REMOTE_ENABLED) {
    maintenanceStoreReady = true;
    return false;
  }

  try {
    const payload = await upstashRequest(['GET', MAINTENANCE_REDIS_KEY]);
    if (payload?.result) {
      const stored = JSON.parse(payload.result);
      applyMaintenanceState(stored);
    }
    maintenanceStoreReady = true;
    scheduleStatsBroadcast();
    return true;
  } catch (error) {
    warnUniqueStore(error);
    maintenanceStoreReady = false;
    return false;
  }
}

async function persistMaintenanceState() {
  if (!UNIQUE_VISITOR_REMOTE_ENABLED) return false;
  try {
    const payload = await upstashRequest([
      'SET',
      MAINTENANCE_REDIS_KEY,
      JSON.stringify(publicMaintenanceState())
    ]);
    if (payload?.result !== 'OK') throw new Error('Upstash did not confirm the maintenance update');
    maintenanceStoreReady = true;
    return true;
  } catch (error) {
    warnUniqueStore(error);
    maintenanceStoreReady = false;
    return false;
  }
}

// Keep the local snapshot in sync if the service is ever scaled beyond one
// process. This is a single lightweight request every five minutes.
const uniqueVisitorSyncTimer = UNIQUE_VISITOR_REMOTE_ENABLED
  ? setInterval(syncUniqueVisitorCount, 5 * 60 * 1000)
  : null;
uniqueVisitorSyncTimer?.unref?.();
if (UNIQUE_VISITOR_REMOTE_ENABLED) {
  syncUniqueVisitorCount();
  maintenanceInitPromise = syncMaintenanceState();
} else if (UPSTASH_REDIS_REST_URL || UPSTASH_REDIS_REST_TOKEN) {
  console.warn('[Visitors] Both UPSTASH_REDIS_REST_URL and UPSTASH_REDIS_REST_TOKEN are required; unique totals and maintenance mode are in-memory only.');
} else {
  console.warn('[Visitors] Upstash is not configured; unique totals and maintenance mode will reset when the server restarts.');
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
  const key = visitorKeyByIp.get(ip);
  if (key && activeUsers.has(key)) return key;
  if (key) visitorKeyByIp.delete(ip);
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
    if (ip && ip !== 'unknown') visitorKeyByIp.set(ip, key);

    lookupGeo(ip).then(geo => {
      if (!geo || !activeUsers.has(key)) return;
      const current = activeUsers.get(key);
      current.country = geo.country || null;
      current.city = geo.city || null;
      current.countryCode = geo.countryCode || null;
      broadcastVisitorChange('geo', current, false);
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
    if (entry.ip && entry.ip !== 'unknown') visitorKeyByIp.set(entry.ip, key);
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

  // Never hold up page delivery for remote analytics storage.
  trackUniqueVisitor(key).catch(warnUniqueStore);
  broadcastVisitorChange(isNew ? 'online' : 'update', entry, isNew);
  next();
}

app.use(visitorTracking);

// ─────────────────────────────────────────────
// CLEANUP LOOP
// ─────────────────────────────────────────────

function cleanupInactiveVisitors() {
  const now = Date.now();
  for (const [key, state] of loginAttempts) if (state.resetAt <= now) loginAttempts.delete(key);
  let removed = 0;
  for (const [id, visitor] of activeUsers) {
    if (now - visitor.lastSeen > HEARTBEAT_TIMEOUT) {
      visitor.online = false;
      broadcastSSE('visitor_update', { type: 'offline', visitor: sanitizeVisitor(visitor) });
      activeUsers.delete(id);
      if (visitorKeyByIp.get(visitor.ip) === id) visitorKeyByIp.delete(visitor.ip);
      removed++;
    }
  }
  if (removed) scheduleStatsBroadcast();
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

function countOnlineUsers(now = Date.now()) {
  let count = 0;
  for (const visitor of activeUsers.values()) if (now - visitor.lastSeen <= HEARTBEAT_TIMEOUT) count++;
  return count;
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
    totalUnique: getTotalUniqueVisitors(),
    visitors,
    override: streamOverride.active ? {
      active: true,
      url: streamOverride.url,
      type: streamOverride.type,
      startedAt: streamOverride.startedAt
    } : { active: false },
    maintenance: publicMaintenanceState(),
    server: {
      startedAt: SERVER_STARTED_AT,
      uptimeMs: now - SERVER_STARTED_AT,
      nodeEnv: process.env.NODE_ENV || 'development',
      uniqueVisitorStore: UNIQUE_VISITOR_REMOTE_ENABLED
        ? (uniqueVisitorStoreReady ? 'upstash' : 'upstash-connecting')
        : 'memory',
      maintenanceStore: UNIQUE_VISITOR_REMOTE_ENABLED
        ? (maintenanceStoreReady ? 'upstash' : 'upstash-connecting')
        : 'memory'
    }
  };
}

// ─────────────────────────────────────────────
// STATIC FILES — Main site
// ─────────────────────────────────────────────

const SITE_INDEX_PATH = findIndexHtml(DEV_DIR);
const SITE_INDEX_EXISTS = Boolean(SITE_INDEX_PATH && fs.existsSync(SITE_INDEX_PATH));
const MAINTENANCE_PAGE_PATH = SITE_INDEX_PATH
  ? path.join(path.dirname(SITE_INDEX_PATH), 'maintenance.html')
  : path.join(DEV_DIR, 'maintenance.html');

console.log(`[Config] DEV_DIR   = ${DEV_DIR}`);
console.log(`[Config] ADMIN_DIR = ${ADMIN_DIR}`);
console.log(`[Config] DEV_DIR exists: ${fs.existsSync(DEV_DIR)}`);
console.log(`[Config] ADMIN_DIR exists: ${fs.existsSync(ADMIN_DIR)}`);
console.log(`[Config] Allowed origins: ${ALLOWED_ORIGINS.join(', ') || '(same-origin/local only)'}`);

// Intercept the explicit index path before static middleware so maintenance
// mode cannot be bypassed when this server is also serving the public site.
app.get('/index.html', sendSiteIndex);

app.use(express.static(DEV_DIR, {
  index: false,
  fallthrough: true,
  etag: true,
  lastModified: true,
  maxAge: process.env.NODE_ENV === 'production' ? '7d' : 0,
  setHeaders(res, filePath) {
    if (/\.html?$/i.test(filePath)) res.setHeader('Cache-Control', 'public, max-age=0, must-revalidate');
    else if (/\.(?:css|m?js)$/i.test(filePath)) res.setHeader('Cache-Control', 'public, max-age=3600, must-revalidate');
    else if (filePath.includes(`${path.sep}assets${path.sep}`)) res.setHeader('Cache-Control', 'public, max-age=2592000');
  }
}));

app.get('/healthz', (req, res) => {
  res.json({
    ok: true,
    uptimeMs: Date.now() - SERVER_STARTED_AT,
    uniqueVisitorStore: UNIQUE_VISITOR_REMOTE_ENABLED
      ? (uniqueVisitorStoreReady ? 'upstash' : 'upstash-connecting')
      : 'memory',
    maintenanceStore: UNIQUE_VISITOR_REMOTE_ENABLED
      ? (maintenanceStoreReady ? 'upstash' : 'upstash-connecting')
      : 'memory'
  });
});

async function sendSiteIndex(req, res, next) {
  try {
    await maintenanceInitPromise;
    if (maintenanceMode.active && fs.existsSync(MAINTENANCE_PAGE_PATH)) {
      res.setHeader('Cache-Control', 'no-store');
      res.setHeader('Retry-After', '600');
      return res.status(503).sendFile(MAINTENANCE_PAGE_PATH);
    }
  } catch (error) {
    return next(error);
  }

  if (!SITE_INDEX_EXISTS) {
    return res.status(404).send(
      `<h1>404 — Site not found</h1>
       <p>index.html not found under: ${escapeServerHtml(DEV_DIR)}</p>
       <p>Resolved path: ${escapeServerHtml(SITE_INDEX_PATH || '(none)')}</p>
       <p>Set the <strong>DEV_DIR</strong> environment variable on Render to the folder containing your index.html.</p>`
    );
  }
  res.setHeader('Cache-Control', 'public, max-age=0, must-revalidate');
  res.sendFile(SITE_INDEX_PATH);
}

app.get('/', sendSiteIndex);

// Auth verification (existing public endpoint, with same-origin/local support)
app.get('/api/auth/verify', (req, res) => {
  const origin = normalizeOrigin(req.headers.origin || '');
  const referer = normalizeOrigin(req.headers.referer || '');
  const requestOrigin = getRequestOrigin(req);
  const sourceOrigin = origin || referer;
  const isAuthorized =
    isAuthorizedHostname(req.hostname) ||
    isAuthorizedHostname(hostnameFromUrl(origin)) ||
    isAuthorizedHostname(hostnameFromUrl(referer)) ||
    isLocalOrigin(requestOrigin) ||
    isLocalOrigin(sourceOrigin) ||
    Boolean(sourceOrigin && (ALLOWED_ORIGINS.includes(sourceOrigin) || isSameOriginRequest(req, sourceOrigin)));

  if (isAuthorized) return res.json({ authorized: true, domain: AUTHORIZED_DOMAIN });
  res.status(403).json({ authorized: false, error: 'Unauthorized', message: 'Access only from ' + AUTHORIZED_DOMAIN });
});

// Visitor heartbeat used by the public site. It now updates the same object shape
// as page tracking instead of corrupting the admin visitor map with raw numbers.
app.get('/api/visitors/heartbeat', async (req, res, next) => {
  try {
    const secret = req.headers['x-visitor-secret'];
    if (!safeEqual(secret, VISITOR_SECRET)) return res.status(403).json({ error: 'Forbidden' });

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
    const isGloballyNew = await trackUniqueVisitor(key);

    // Heartbeats update one row in real time; full stats are serialized only
    // for a new live session or a newly confirmed permanent visitor.
    broadcastVisitorChange(isNew ? 'online' : 'heartbeat', entry, isNew || isGloballyNew);
    res.json({ active: countOnlineUsers() });
  } catch (error) {
    next(error);
  }
});

app.get('/api/visitors/active', (req, res) => {
  const secret = req.headers['x-visitor-secret'];
  if (!safeEqual(secret, VISITOR_SECRET)) return res.status(403).json({ error: 'Forbidden' });
  res.json({ active: countOnlineUsers() });
});

// ─────────────────────────────────────────────
// PUBLIC — Site/stream status & SSE (no auth needed)
// ─────────────────────────────────────────────

app.get('/api/site/status', async (req, res, next) => {
  try {
    await maintenanceInitPromise;
    res.json({ maintenance: publicMaintenanceState() });
  } catch (error) {
    next(error);
  }
});

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
app.get('/api/events', async (req, res, next) => {
  try {
    await maintenanceInitPromise;
    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache, no-transform');
    res.setHeader('Connection', 'keep-alive');
    res.setHeader('X-Accel-Buffering', 'no');
    res.flushHeaders?.();

    publicSseClients.add(res);

    // Send initial stream and site state.
    const initPayload = JSON.stringify(streamOverride.active ? {
      active: streamOverride.active,
      url: streamOverride.url,
      type: streamOverride.type,
      startedAt: streamOverride.startedAt
    } : { active: false, url: null, type: null, startedAt: null });

    res.write(`event: stream_override\ndata: ${initPayload}\n\n`);
    res.write(`event: stream_update\ndata: ${initPayload}\n\n`);
    res.write(`event: maintenance_update\ndata: ${JSON.stringify(publicMaintenanceState())}\n\n`);

    req.on('close', () => {
      publicSseClients.delete(res);
    });
  } catch (error) {
    next(error);
  }
});

// ─────────────────────────────────────────────
// ADMIN — STATIC FILES & AUTHENTICATION
// ─────────────────────────────────────────────

app.use('/admin', express.static(ADMIN_DIR, {
  index: false,
  fallthrough: true,
  etag: true,
  maxAge: 0,
  setHeaders(res) {
    // The dashboard HTML, CSS and JS are deployed together and must never get
    // out of sync. Revalidate every admin asset instead of running stale JS
    // against newer controls.
    res.setHeader('Cache-Control', 'private, max-age=0, must-revalidate');
  }
}));

function checkLoginLimit(req, res, next) {
  const key = getClientIp(req);
  const now = Date.now();
  let state = loginAttempts.get(key);
  if (!state || state.resetAt <= now) state = { count: 0, resetAt: now + 15 * 60 * 1000 };
  if (state.count >= 10) {
    res.setHeader('Retry-After', String(Math.max(1, Math.ceil((state.resetAt - now) / 1000))));
    return res.status(429).json({ success: false, error: 'Too many login attempts. Try again later.' });
  }
  req.loginLimitKey = key;
  req.loginLimitState = state;
  next();
}

app.use('/admin/api/login', sessionMiddleware);
app.post('/admin/api/login', checkLoginLimit, (req, res) => {
  const { username, password } = req.body || {};
  if (safeEqual(username, ADMIN_USER) && safeEqual(password, ADMIN_PASS)) {
    loginAttempts.delete(req.loginLimitKey);
    req.session.isAdmin = true;
    req.session.loginAt = Date.now();
    return res.json({ success: true });
  }
  req.loginLimitState.count++;
  loginAttempts.set(req.loginLimitKey, req.loginLimitState);
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

app.get('/admin/api/maintenance', async (req, res, next) => {
  try {
    await maintenanceInitPromise;
    res.json({ maintenance: publicMaintenanceState(), durable: maintenanceStoreReady });
  } catch (error) {
    next(error);
  }
});

app.post('/admin/api/maintenance', async (req, res, next) => {
  try {
    await maintenanceInitPromise;
    const { active, message } = req.body || {};
    if (typeof active !== 'boolean') {
      return res.status(400).json({ error: 'The active field must be true or false.' });
    }

    applyMaintenanceState({
      active,
      message,
      startedAt: active
        ? (maintenanceMode.active && maintenanceMode.startedAt ? maintenanceMode.startedAt : Date.now())
        : null,
      updatedAt: Date.now()
    });

    const durable = await persistMaintenanceState();
    const state = publicMaintenanceState();
    broadcastSSE('maintenance_update', state);
    broadcastPublicSSE('maintenance_update', state);
    scheduleStatsBroadcast(0);

    res.json({ success: true, maintenance: state, durable });
  } catch (error) {
    next(error);
  }
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
  scheduleStatsBroadcast();
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
  scheduleStatsBroadcast();
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

  req.on('close', () => {
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
  res.setHeader('Cache-Control', 'private, max-age=0, must-revalidate');
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

const server = app.listen(PORT, () => {
  console.log(`[Server] Running on http://localhost:${PORT}`);
  console.log(`[Main]  Site:  http://localhost:${PORT}/  (${DEV_DIR})`);
  console.log(`[Admin] Panel: http://localhost:${PORT}/admin  (${ADMIN_DIR})`);
  console.log(`[Admin] User:  ${ADMIN_USER}`);
  console.log(`[Visitors] Unique store: ${UNIQUE_VISITOR_REMOTE_ENABLED ? 'Upstash Redis (durable)' : 'memory (resets on restart)'}`);
  if (UNIQUE_VISITOR_BASELINE) console.log(`[Visitors] Restored baseline: ${UNIQUE_VISITOR_BASELINE}`);

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

// Keep reverse-proxy connections reusable without letting stale sockets linger.
server.keepAliveTimeout = 65_000;
server.headersTimeout = 66_000;
server.requestTimeout = 30_000;

function shutdown(signal) {
  console.log(`[Server] ${signal} received; shutting down gracefully.`);
  clearInterval(sseHeartbeatTimer);
  if (uniqueVisitorSyncTimer) clearInterval(uniqueVisitorSyncTimer);
  clearTimeout(statsBroadcastTimer);
  writeSSE(sseClients, 'event: shutdown\ndata: {}\n\n');
  writeSSE(publicSseClients, 'event: shutdown\ndata: {}\n\n');
  for (const response of [...sseClients, ...publicSseClients]) response.end();
  server.close(async () => {
    await Promise.allSettled([...pendingUniqueWrites.values()]);
    process.exit(0);
  });
  setTimeout(() => process.exit(1), 10_000).unref();
}
process.once('SIGTERM', () => shutdown('SIGTERM'));
process.once('SIGINT', () => shutdown('SIGINT'));
