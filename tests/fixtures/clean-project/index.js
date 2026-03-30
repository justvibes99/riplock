const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const bcrypt = require('bcrypt');

const app = express();
app.use(express.json({ limit: '1mb' }));
app.use(helmet());
app.use(cors({ origin: ['https://myapp.com'] }));

app.post('/register', async (req, res) => {
  const hashedPassword = await bcrypt.hash(req.body.password, 12);
  await db.user.create({ password: hashedPassword, email: req.body.email });
  res.json({ success: true });
});

const server = app.listen(3000);
server.timeout = 30000;
