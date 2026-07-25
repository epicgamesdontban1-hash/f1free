const express = require('express');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

const DATA_FILE = path.join(__dirname, 'visitors.json');
const VISITOR_SECRET = process.env.VISITOR_SECRET || 'CHANGE_ME_TO_A_RANDOM_SECRET';
const ALLOWED_ORIGIN = process.env.ALLOWED_ORIGIN || 'https://freef1.netlify.app';

const rateLimitMap = new Map();

function readCount() {
  try {
    if (fs.existsSync(DATA_FILE)) {
      const data = JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
      return data.count || 0;
    }
  } catch (e) {
    console.error('Error reading count:', e);
  }
  return 0;
}

function writeCount(count) {
  try {
    fs.writeFileSync(DATA_FILE, JSON.stringify({ count }, null, 2));
  } catch (e) {
    console.error('Error writing count:', e);
  }
}

function isRateLimited(ip) {
  const now = Date.now();
  const windowMs = 60000;
  const maxRequests = 10;

  const record = rateLimitMap.get(ip) || { count: 0, resetAt: now + windowMs };

  if (now > record.resetAt) {
    record.count = 0;
    record.resetAt = now + windowMs;
  }

  record.count++;
  rateLimitMap.set(ip, record);

  return record.count > maxRequests;
}

app.use((req, res, next) => {
  const origin = req.headers.origin;

  res.setHeader('Access-Control-Allow-Origin', ALLOWED_ORIGIN);
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-Visitor-Secret');

  if (req.method === 'OPTIONS') {
    return res.sendStatus(204);
  }

  if (origin && origin !== ALLOWED_ORIGIN) {
    return res.status(403).json({ error: 'Forbidden' });
  }

  next();
});

app.use((req, res, next) => {
  const clientIp = req.ip || req.connection.remoteAddress || req.socket.remoteAddress;
  if (isRateLimited(clientIp)) {
    return res.status(429).json({ error: 'Too many requests' });
  }
  next();
});

app.get('/api/visitors', (req, res) => {
  const secret = req.headers['x-visitor-secret'];
  if (secret !== VISITOR_SECRET) {
    return res.status(403).json({ error: 'Forbidden' });
  }

  const count = readCount() + 1;
  writeCount(count);
  res.json({ count });
});

app.get('/', (req, res) => {
  res.send('<h1>All systems operational</h1><p>Everything is good.</p>');
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
