const express = require('express');
const mysql = require('mysql2');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');
const cors = require('cors');

const app = express();
app.use(cors());
app.use(bodyParser.json());

// ===== DATABASE CONNECTION =====
const db = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: 'root',
  database: 'eat_and_die'
});

db.connect(err => {
  if (err) throw err;
  console.log('✅ Connected to MySQL database');
});

// ===== JWT SECRET =====
const SECRET = "eatanddie_secret";

// ===== ROUTES =====

// --- REGISTER USER ---
app.post('/api/register', async (req, res) => {
  const { name, email, password } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);

  db.query('INSERT INTO users (name, email, password) VALUES (?, ?, ?)',
    [name, email, hashedPassword],
    (err, result) => {
      if (err) return res.status(400).json({ error: err.message });
      res.json({ message: 'User registered successfully' });
    }
  );
});

// --- LOGIN USER ---
app.post('/api/login', (req, res) => {
  const { email, password } = req.body;

  db.query('SELECT * FROM users WHERE email = ?', [email], async (err, results) => {
    if (err) return res.status(400).json({ error: err.message });
    if (results.length === 0) return res.status(404).json({ error: 'User not found' });

    const user = results[0];
    const isValid = await bcrypt.compare(password, user.password);
    if (!isValid) return res.status(401).json({ error: 'Invalid password' });

    const token = jwt.sign({ id: user.id, email: user.email }, SECRET, { expiresIn: '1h' });
    res.json({ token, user: { id: user.id, name: user.name, email: user.email } });
  });
});

// --- GET RESTAURANTS ---
app.get('/api/restaurants', (req, res) => {
  db.query('SELECT * FROM restaurants', (err, results) => {
    if (err) return res.status(400).json({ error: err.message });
    res.json(results);
  });
});

// --- ADD TO CART ---
app.post('/api/cart', (req, res) => {
  const { user_id, restaurant_id, item_name, quantity, price } = req.body;
  db.query(
    'INSERT INTO cart (user_id, restaurant_id, item_name, quantity, price) VALUES (?, ?, ?, ?, ?)',
    [user_id, restaurant_id, item_name, quantity, price],
    (err, result) => {
      if (err) return res.status(400).json({ error: err.message });
      res.json({ message: 'Item added to cart' });
    }
  );
});

// --- GET CART ITEMS ---
app.get('/api/cart/:userId', (req, res) => {
  const userId = req.params.userId;
  db.query(
    'SELECT * FROM cart WHERE user_id = ?',
    [userId],
    (err, results) => {
      if (err) return res.status(400).json({ error: err.message });
      res.json(results);
    }
  );
});

// --- REMOVE FROM CART ---
app.delete('/api/cart/:id', (req, res) => {
  const id = req.params.id;
  db.query('DELETE FROM cart WHERE id = ?', [id], (err, result) => {
    if (err) return res.status(400).json({ error: err.message });
    res.json({ message: 'Item removed from cart' });
  });
});

// ===== START SERVER =====
const PORT = 5000;
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
