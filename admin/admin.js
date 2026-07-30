/* ═══════════════════════════════════════════════════════════
   FreeF1 Admin Dashboard — JavaScript
   Auth · SSE · Visitor Table · Stream Controls
   ═══════════════════════════════════════════════════════════ */

'use strict';

// ─────────────────────────────────────────────
// CONFIG
// ─────────────────────────────────────────────
const API_BASE   = '/admin/api';
const SSE_URL    = `${API_BASE}/events`;
const REFRESH_MS = 3000;

// ─────────────────────────────────────────────
// DOM REFS
// ─────────────────────────────────────────────
const $ = id => document.getElementById(id);

const authScreen     = $('authScreen');
const appEl          = $('app');
const loginForm      = $('loginForm');
const usernameInput  = $('username');
const passwordInput  = $('password');
const authError      = $('authError');
const loginBtn       = $('loginBtn');
const logoutBtn      = $('logoutBtn');
const navStatus      = $('navStatus');
const onlineCountEl  = $('onlineCount');
const uniqueCountEl  = $('uniqueCount');
const visitorTableBody = $('visitorTableBody');
const visitorEmpty   = $('visitorEmpty');
const streamStatusEl = $('streamStatus');
const streamTypeLabel = $('streamTypeLabel');
const streamStartedLabel = $('streamStartedLabel');
const streamUrlInput = $('streamUrlInput');
const playOverrideBtn   = $('playOverrideBtn');
const stopOverrideBtn   = $('stopOverrideBtn');
const normalStreamBtn   = $('normalStreamBtn');
const streamPreview     = $('streamPreview');
const sysUptime         = $('sysUptime');
const sysVisitorStore   = $('sysVisitorStore');
const sysOverrideStatus = $('sysOverrideStatus');
const sysNodeEnv        = $('sysNodeEnv');
const toastContainer    = $('toastContainer');
const connBarFill       = $('connBarFill');

// ─────────────────────────────────────────────
// STATE
// ─────────────────────────────────────────────
let isAdmin      = false;
let sse          = null;
let sseConnected = false;
let reconnectTimer = null;
let currentStats = null;
let overrideActive = false;

// ─────────────────────────────────────────────
// AUTH
// ─────────────────────────────────────────────
async function checkAuthStatus() {
  try {
    const r = await fetch(`${API_BASE}/status`);
    const d = await r.json();
    if (d.authenticated) {
      showDashboard();
    } else {
      showLogin();
    }
  } catch (_) {
    showLogin();
  }
}

function showLogin() {
  isAdmin = false;
  authScreen.classList.remove('hidden');
  appEl.classList.remove('open');
  if (sse) { sse.close(); sse = null; sseConnected = false; }
}

function showDashboard() {
  isAdmin = true;
  authScreen.classList.add('hidden');
  appEl.classList.add('open');
  connectSSE();
}

async function handleLogin(e) {
  e.preventDefault();
  const username = usernameInput.value.trim();
  const password = passwordInput.value;
  if (!username || !password) { showAuthError('Enter both username and password.'); return; }

  loginBtn.disabled = true;
  loginBtn.textContent = 'Authenticating…';
  authError.classList.remove('visible');

  try {
    const r = await fetch(`${API_BASE}/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password })
    });
    const d = await r.json();
    if (d.success) {
      showToast('Welcome back, admin.', 'success');
      showDashboard();
      usernameInput.value = '';
      passwordInput.value = '';
    } else {
      showAuthError(d.error || 'Invalid credentials.');
    }
  } catch (_) {
    showAuthError('Network error. Please try again.');
  } finally {
    loginBtn.disabled = false;
    loginBtn.textContent = 'Sign In';
  }
}

async function handleLogout() {
  try { await fetch(`${API_BASE}/logout`, { method: 'POST' }); } catch (_) {}
  showToast('Logged out successfully.', 'info');
  showLogin();
}

function showAuthError(msg) {
  authError.textContent = msg;
  authError.classList.add('visible');
}

loginForm.addEventListener('submit', handleLogin);
logoutBtn.addEventListener('click', handleLogout);

// ─────────────────────────────────────────────
// SSE CONNECTION
// ─────────────────────────────────────────────
function connectSSE() {
  if (sseConnected) return;
  if (sse) { sse.close(); sse = null; }

  sse = new EventSource(SSE_URL);

  sse.addEventListener('open', () => {
    sseConnected = true;
    clearTimeout(reconnectTimer);
    updateConnectionBar(true);
  });

  sse.addEventListener('init', e => {
    const data = JSON.parse(e.data);
    handleStatsUpdate(data);
  });

  sse.addEventListener('stats', e => {
    const data = JSON.parse(e.data);
    handleStatsUpdate(data);
  });

  sse.addEventListener('visitor_update', e => {
    const { type, visitor } = JSON.parse(e.data);
    handleVisitorUpdate(type, visitor);
  });

  sse.addEventListener('stream_update', e => {
    const data = JSON.parse(e.data);
    handleStreamStatusUpdate(data);
  });

  sse.addEventListener('stream_override', e => {
    const data = JSON.parse(e.data);
    handleStreamOverrideUpdate(data);
  });

  sse.addEventListener('error', () => {
    sseConnected = false;
    updateConnectionBar(false);
    sse.close();
    reconnectTimer = setTimeout(() => { if (isAdmin) connectSSE(); }, 4000);
  });
}

function updateConnectionBar(connected) {
  if (!connBarFill) return;
  connBarFill.style.width = connected ? '100%' : '0%';
  connBarFill.classList.toggle('disconnected', !connected);
  if (navStatus) navStatus.textContent = connected ? 'CONNECTED' : 'RECONNECTING…';
}

// ─────────────────────────────────────────────
// STATS HANDLERS
// ─────────────────────────────────────────────
function handleStatsUpdate(data) {
  currentStats = data;
  updateStatCards(data);
  updateVisitorTable(data);
  updateStreamStatus(data.override);
  updateSystemInfo(data);
}

function updateStatCards(data) {
  if (onlineCountEl)  onlineCountEl.textContent  = String(data.onlineCount ?? 0);
  if (uniqueCountEl)  uniqueCountEl.textContent  = String(data.totalUnique ?? 0);
}

function updateStreamStatus(override) {
  if (!streamStatusEl) return;
  if (override?.active) {
    streamStatusEl.className = 'stream-status active-override';
    streamStatusEl.innerHTML = `
      <div class="status-indicator override"></div>
      <div class="status-text">
        <strong style="color:#ff6b62">Stream Override Active</strong>
        <small>${escapeHtml(override.type || 'custom').toUpperCase()} · Started ${formatTimeAgo(override.startedAt)}</small>
      </div>
      <div class="time-ago">LIVE</div>`;
    if (streamTypeLabel) streamTypeLabel.textContent = (override.type || 'custom').toUpperCase();
    if (streamStartedLabel) streamStartedLabel.textContent = formatTimeAgo(override.startedAt);
    overrideActive = true;
    updateStreamButtons(true);
  } else {
    streamStatusEl.className = 'stream-status active-normal';
    streamStatusEl.innerHTML = `
      <div class="status-indicator online"></div>
      <div class="status-text">
        <strong style="color:var(--green)">Normal Stream</strong>
        <small>Default site feed is active · No override in effect</small>
      </div>
      <div class="time-ago">● LIVE</div>`;
    if (streamTypeLabel) streamTypeLabel.textContent = 'NORMAL';
    if (streamStartedLabel) streamStartedLabel.textContent = '—';
    overrideActive = false;
    updateStreamButtons(false);
  }
}

function updateStreamButtons(active) {
  if (playOverrideBtn)  playOverrideBtn.disabled = active;
  if (stopOverrideBtn)  stopOverrideBtn.disabled = !active;
  if (normalStreamBtn)  normalStreamBtn.disabled = !active;
}

function updateSystemInfo(data) {
  if (sysUptime) {
    const elapsed = Math.floor((Date.now() - (data?.override?.startedAt || Date.now())) / 1000);
    sysUptime.textContent = `${Math.floor(elapsed / 60)}m ${elapsed % 60}s`;
  }
  if (sysVisitorStore) sysVisitorStore.textContent = `${data?.totalUnique ?? '—'} unique`;
  if (sysOverrideStatus) {
    sysOverrideStatus.textContent = data?.override?.active ? 'OVERRIDE' : 'NORMAL';
    sysOverrideStatus.style.color = data?.override?.active ? '#ff6b62' : 'var(--green)';
  }
  if (sysNodeEnv) sysNodeEnv.textContent = (import.meta?.env?.MODE || 'production').toUpperCase();
}

// ─────────────────────────────────────────────
// VISITOR TABLE
// ─────────────────────────────────────────────
function updateVisitorTable(data) {
  if (!visitorTableBody || !data?.visitors) return;
  const now = Date.now();
  const visitors = [...data.visitors].sort((a, b) => (b.lastSeen - a.lastSeen));

  if (visitors.length === 0) {
    visitorTableBody.innerHTML = '';
    if (visitorEmpty) visitorEmpty.style.display = '';
    return;
  }
  if (visitorEmpty) visitorEmpty.style.display = 'none';

  // Build a lookup by IP for incremental updates
  const existingRows = new Map();
  visitorTableBody.querySelectorAll('tr').forEach(tr => {
    existingRows.set(tr.dataset.ip, tr);
  });

  const visibleIps = new Set();
  visitors.forEach(v => {
    const ip = v.ip;
    visibleIps.add(ip);
    const online = now - v.lastSeen <= 60000;
    const flag = v.countryCode ? getFlag(v.countryCode) : '🌐';
    const countryDisplay = v.country || v.countryCode || 'Unknown';
    const deviceClass = v.deviceType ? `device-${v.deviceType.toLowerCase()}` : '';

    if (existingRows.has(ip)) {
      // Update existing row
      const tr = existingRows.get(ip);
      tr.querySelector('.status-pill').outerHTML = `
        <td><span class="pill-sm ${online ? 'pill-online' : 'pill-offline'}">
          <span class="${online ? 'dot-online' : 'dot-offline'}"></span>${online ? 'Online' : 'Offline'}
        </span></td>`;
      tr.querySelector('.page-cell').textContent = v.page || '/';
      tr.querySelector('.timestamp-cell').textContent = formatTimeAgo(v.lastSeen);
      tr.dataset.online = online ? '1' : '0';
    } else {
      // Insert new row at top
      const tr = document.createElement('tr');
      tr.dataset.ip = ip;
      tr.dataset.online = online ? '1' : '0';
      tr.className = 'fade-in';
      tr.innerHTML = `
        <td class="ip">${escapeHtml(ip)}</td>
        <td class="country"><span class="flag">${flag}</span>${escapeHtml(countryDisplay)}</td>
        <td>${escapeHtml(v.browser || '—')}</td>
        <td>${escapeHtml(v.os || '—')}</td>
        <td class="${deviceClass}">${escapeHtml(v.deviceType || '—')}</td>
        <td class="page-cell" title="${escapeHtml(v.page || '/')}">${escapeHtml(v.page || '/')}</td>
        <td><span class="pill-sm ${online ? 'pill-online' : 'pill-offline'}">
          <span class="${online ? 'dot-online' : 'dot-offline'}"></span>${online ? 'Online' : 'Offline'}
        </span></td>
        <td class="timestamp-cell">${formatTimeAgo(v.lastSeen)}</td>`;
      visitorTableBody.insertBefore(tr, visitorTableBody.firstChild);
    }
  });

  // Remove rows no longer in visitor list
  existingRows.forEach((tr, ip) => {
    if (!visibleIps.has(ip)) tr.remove();
  });

  // Toggle empty state
  if (visitorEmpty) visitorEmpty.style.display = visitorTableBody.children.length === 0 ? '' : 'none';
}

function handleVisitorUpdate(type, visitor) {
  if (!visitor || !currentStats) return;
  const now = Date.now();
  const idx = currentStats.visitors.findIndex(v => v.ip === visitor.ip);
  if (idx >= 0) {
    currentStats.visitors[idx] = { ...currentStats.visitors[idx], ...visitor };
  } else {
    currentStats.visitors.unshift(visitor);
  }
  updateStatCards(currentStats);
  updateVisitorTable(currentStats);
}

function handleStreamStatusUpdate(data) {
  if (!currentStats) return;
  currentStats.override = data;
  updateStreamStatus(data);
}

function handleStreamOverrideUpdate(data) {
  handleStreamStatusUpdate(data);
  if (data.active && streamPreview) {
    renderStreamPreview(data.url, data.type);
  } else if (!data.active && streamPreview) {
    clearStreamPreview();
  }
  showToast(data.active ? 'Stream override activated.' : 'Stream override deactivated — normal feed restored.', data.active ? 'warning' : 'success');
}

// ─────────────────────────────────────────────
// STREAM CONTROLS
// ─────────────────────────────────────────────
async function activateStreamOverride() {
  const url = streamUrlInput.value.trim();
  if (!url) { showToast('Enter a stream URL first.', 'error'); return; }
  if (!isValidUrl(url)) { showToast('Please enter a valid URL.', 'error'); return; }

  playOverrideBtn.disabled = true;
  playOverrideBtn.textContent = 'Activating…';

  try {
    const r = await fetch(`${API_BASE}/stream/override`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url })
    });
    const d = await r.json();
    if (d.success) {
      showToast('Stream override activated.', 'warning');
      if (d.override?.url && streamPreview) renderStreamPreview(d.override.url, d.override.type);
    } else {
      showToast(d.error || 'Failed to activate override.', 'error');
    }
  } catch (_) {
    showToast('Network error activating override.', 'error');
  } finally {
    playOverrideBtn.disabled = false;
    playOverrideBtn.textContent = '▶ Play Override';
  }
}

async function stopStreamOverride() {
  stopOverrideBtn.disabled = true;
  stopOverrideBtn.textContent = 'Stopping…';
  try {
    const r = await fetch(`${API_BASE}/stream/stop`, { method: 'POST' });
    const d = await r.json();
    if (d.success) {
      showToast('Stream override stopped.', 'success');
      clearStreamPreview();
    }
  } catch (_) {
    showToast('Network error stopping override.', 'error');
  } finally {
    stopOverrideBtn.disabled = false;
    stopOverrideBtn.textContent = '■ Stop Override';
  }
}

async function returnToNormalStream() {
  normalStreamBtn.disabled = true;
  normalStreamBtn.textContent = 'Restoring…';
  try {
    const r = await fetch(`${API_BASE}/stream/normal`, { method: 'POST' });
    const d = await r.json();
    if (d.success) {
      showToast('Returned to normal stream.', 'success');
      clearStreamPreview();
    }
  } catch (_) {
    showToast('Network error restoring stream.', 'error');
  } finally {
    normalStreamBtn.disabled = false;
    normalStreamBtn.textContent = '↩ Return to Normal';
  }
}

function renderStreamPreview(url, type) {
  if (!streamPreview) return;
  if (type === 'youtube' || type === 'embed') {
    streamPreview.innerHTML = `<iframe src="${escapeHtml(url)}" allow="autoplay; fullscreen" allowFullScreen sandbox="allow-scripts allow-same-origin"></iframe>`;
  } else if (type === 'mp4') {
    streamPreview.innerHTML = `<video controls autoplay style="width:100%;height:100%;border-radius:var(--radius-sm)"><source src="${escapeHtml(url)}"></video>`;
  }
}

function clearStreamPreview() {
  if (!streamPreview) return;
  streamPreview.innerHTML = `
    <div class="placeholder">
      <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
        <polygon points="5 3 19 12 5 21 5 3" fill="currentColor" opacity=".3"/>
      </svg>
      <div>No override active</div>
      <div style="font-size:.65rem;margin-top:4px">Normal feed broadcasting</div>
    </div>`;
}

playOverrideBtn?.addEventListener('click', activateStreamOverride);
stopOverrideBtn?.addEventListener('click', stopStreamOverride);
normalStreamBtn?.addEventListener('click', returnToNormalStream);

// ─────────────────────────────────────────────
// POLL FALLBACK (in case SSE stalls)
// ─────────────────────────────────────────────
async function pollStats() {
  if (!isAdmin) return;
  try {
    const r = await fetch(`${API_BASE}/visitors`);
    const data = await r.json();
    handleStatsUpdate(data);
  } catch (_) { /* ignore poll errors */ }
}

setInterval(pollStats, REFRESH_MS);

// ─────────────────────────────────────────────
// UPTIME CLOCK
// ─────────────────────────────────────────────
setInterval(() => {
  if (!isAdmin) return;
  if (currentStats?.override?.startedAt) {
    const elapsed = Math.floor((Date.now() - currentStats.override.startedAt) / 1000);
    if (sysUptime) sysUptime.textContent = `${Math.floor(elapsed / 60)}m ${elapsed % 60}s`;
  }
}, 1000);

// ─────────────────────────────────────────────
// UTILITIES
// ─────────────────────────────────────────────
function escapeHtml(str) {
  if (str == null) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function formatTimeAgo(ts) {
  if (!ts) return '—';
  const diff = Date.now() - ts;
  if (diff < 0) return 'Just now';
  const s = Math.floor(diff / 1000);
  if (s < 5)   return 'Just now';
  if (s < 60)  return `${s}s ago`;
  const m = Math.floor(s / 60);
  if (m < 60)  return `${m}m ${s % 60}s ago`;
  const h = Math.floor(m / 60);
  return `${h}h ${m % 60}m ago`;
}

function getFlag(cc) {
  if (!cc || cc.length !== 2) return '🌐';
  const code = cc.toUpperCase().replace(/[^A-Z]/g, '');
  if (!code) return '🌐';
  return code
    .split('')
    .map(c => String.fromCodePoint(0x1F1E6 - 65 + c.charCodeAt(0)))
    .join('');
}

function isValidUrl(str) {
  try { new URL(str); return true; } catch (_) { return false; }
}

// ─────────────────────────────────────────────
// TOAST NOTIFICATIONS
// ─────────────────────────────────────────────
function showToast(message, type = 'info') {
  if (!toastContainer) return;
  const toast = document.createElement('div');
  toast.className = 'toast';
  const now = new Date();
  const time = now.toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit' });
  toast.innerHTML = `
    <div class="toast-dot ${type}"></div>
    <div class="toast-msg">${escapeHtml(message)}</div>
    <div class="toast-time">${time}</div>`;
  toastContainer.appendChild(toast);
  setTimeout(() => {
    toast.classList.add('removing');
    setTimeout(() => toast.remove(), 300);
  }, 4500);
}

// ─────────────────────────────────────────────
// INIT
// ─────────────────────────────────────────────
checkAuthStatus();

// Auto-refresh stream preview from current state on load
setTimeout(async () => {
  if (!isAdmin) return;
  try {
    const r = await fetch(`${API_BASE}/stream/status`);
    const d = await r.json();
    if (d.active && streamPreview) renderStreamPreview(d.url, d.type);
  } catch (_) {}
}, 800);
