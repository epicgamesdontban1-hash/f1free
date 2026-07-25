const express = require('express');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

const VISITOR_SECRET = process.env.VISITOR_SECRET || 'CHANGE_ME_TO_A_RANDOM_SECRET';
const ALLOWED_ORIGIN = (process.env.ALLOWED_ORIGIN || 'https://freef1.netlify.app').replace(/\/$/, '');

function normalizeOrigin(origin) {
  if (!origin) return origin;
  return origin.replace(/\/$/, '');
}

const activeUsers = new Map();
const HEARTBEAT_TIMEOUT = 60000;
const CLEANUP_INTERVAL = 30000;

setInterval(() => {
  const now = Date.now();
  for (const [userId, lastSeen] of activeUsers.entries()) {
    if (now - lastSeen > HEARTBEAT_TIMEOUT) {
      activeUsers.delete(userId);
    }
  }
}, CLEANUP_INTERVAL);

app.use((req, res, next) => {
  const origin = req.headers.origin;

  res.setHeader('Access-Control-Allow-Origin', ALLOWED_ORIGIN);
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-Visitor-Secret');

  if (req.method === 'OPTIONS') {
    return res.sendStatus(204);
  }

  if (origin && normalizeOrigin(origin) !== ALLOWED_ORIGIN) {
    return res.status(403).json({ error: 'Forbidden' });
  }

  next();
});

app.get('/api/visitors/heartbeat', (req, res) => {
  const secret = req.headers['x-visitor-secret'];
  if (secret !== VISITOR_SECRET) {
    return res.status(403).json({ error: 'Forbidden' });
  }

  const userId = req.headers['x-user-id'];
  if (!userId) {
    return res.status(400).json({ error: 'Missing user ID' });
  }

  activeUsers.set(userId, Date.now());
  res.json({ active: activeUsers.size });
});

app.get('/api/visitors/active', (req, res) => {
  const secret = req.headers['x-visitor-secret'];
  if (secret !== VISITOR_SECRET) {
    return res.status(403).json({ error: 'Forbidden' });
  }

  const now = Date.now();
  let activeCount = 0;
  for (const lastSeen of activeUsers.values()) {
    if (now - lastSeen <= HEARTBEAT_TIMEOUT) {
      activeCount++;
    }
  }

  res.json({ active: activeCount });
});

app.get('/', (req, res) => {
  res.send('<h1>All systems operational</h1><p>Everything is good.</p>');
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
