const express = require('express');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

const DATA_FILE = path.join(__dirname, 'visitors.json');

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

app.get('/api/visitors', (req, res) => {
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
