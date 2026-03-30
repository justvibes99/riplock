const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const { exec } = require('child_process');
const fs = require('fs');
const path = require('path');

const app = express();
app.use(express.json());
app.use(cors({ origin: '*', credentials: true }));

// SEC008 - Hardcoded OpenAI key
const openai_key = 'sk-proj-abc123def456ghi789jkl012mno345pqr678stu901vwxyz1234567890abcdefghijklmnop';

// SEC006 - Hardcoded Stripe key
const stripe = require('stripe')('sk_live_4eC39HqLyjWDarjtT1zdp7dc');

// SEC020 - Database URL with password
const dbUrl = 'mongodb://admin:supersecretpassword123@db.example.com:27017/myapp';

// AUTH001 - JWT with weak secret
const token = jwt.sign({ userId: 1 }, 'secret');

// AUTH002 - JWT verify without algorithm
const decoded = jwt.verify(token, 'secret');

// INJ001 - SQL Injection
app.get('/users', async (req, res) => {
  const result = await db.query(`SELECT * FROM users WHERE name = ${req.query.name}`);
  res.json(result);
});

// INJ004 - Command Injection
app.get('/convert', (req, res) => {
  exec(`convert ${req.query.filename} output.png`);
});

// INJ007 - XSS
app.get('/page', (req, res) => {
  document.getElementById('content').innerHTML = req.query.content;
});

// INJ009 - eval
app.post('/calc', (req, res) => {
  const result = eval(req.body.expression);
  res.json({ result });
});

// AUTH003 - Insecure cookies
res.cookie('session', token, { httpOnly: false, secure: false, sameSite: 'none' });

// AUTH004 - Password stored without hashing
app.post('/register', async (req, res) => {
  await db.user.create({ password: req.body.password, email: req.body.email });
});

// NET003 - SSRF
app.get('/proxy', async (req, res) => {
  const data = await fetch(req.query.url);
  res.json(await data.json());
});

// DATA004 - process.env exposed
app.get('/debug/env', (req, res) => {
  res.json(process.env);
});

// DATA003 - Debug endpoint
app.get('/debug/info', (req, res) => {
  res.json({ uptime: process.uptime() });
});

// CRYPTO003 - Math.random for token
app.get('/token', (req, res) => {
  const token = Math.random().toString(36);
  res.json({ token });
});

// AUTH007 - Admin route without role check
app.get('/admin/users', (req, res) => {
  res.json({ users: [] });
});

// INJ006 - Path traversal
app.get('/file', (req, res) => {
  const data = fs.readFileSync(req.query.path);
  res.send(data);
});

// CONFIG002 - Default credentials
const dbConfig = { user: 'admin', password: 'admin' };

// INJ013 - Open redirect
app.get('/redirect', (req, res) => {
  res.redirect(req.query.url);
});

app.listen(3000);
