const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');

const app = express();
app.use(express.json());
app.use(cors());

app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  const user = await db.findUser(email);

  if (user && user.password === password) {
    const token = jwt.sign({ userId: user.id }, 'secret');
    res.cookie('token', token);
    res.json({ token });
  } else {
    res.status(401).json({ error: 'Invalid' });
  }
});

app.get('/api/admin/users', async (req, res) => {
  const users = await db.getAllUsers();
  res.json(users);
});

app.get('/api/search', async (req, res) => {
  const results = await db.query(`SELECT * FROM products WHERE name LIKE '%${req.query.q}%'`);
  res.json(results);
});

app.get('/api/file', (req, res) => {
  res.sendFile(req.query.path);
});

app.post('/api/run', (req, res) => {
  const { exec } = require('child_process');
  exec(`echo ${req.body.input}`, (err, stdout) => {
    res.json({ output: stdout });
  });
});

app.listen(3000);
