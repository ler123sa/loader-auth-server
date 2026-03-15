const express = require('express');
const bcrypt = require('bcrypt');
const cors = require('cors');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());

const DB_FILE = 'users.json';

function initDB() {
  if (!fs.existsSync(DB_FILE)) {
    fs.writeFileSync(DB_FILE, JSON.stringify({ users: [] }));
  }
}

function readDB() {
  const data = fs.readFileSync(DB_FILE, 'utf8');
  return JSON.parse(data);
}

function writeDB(data) {
  fs.writeFileSync(DB_FILE, JSON.stringify(data, null, 2));
}

initDB();

app.post('/api/register', async (req, res) => {
  try {
    const { username, password, hwid } = req.body;
    if (!username || !password || !hwid) {
      return res.status(400).json({ success: false, message: 'Все поля обязательны' });
    }
    const db = readDB();
    const existing = db.users.find(u => u.username === username);
    if (existing) {
      return res.status(400).json({ success: false, message: 'Пользователь уже существует' });
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = {
      id: db.users.length + 1,
      username,
      password: hashedPassword,
      hwid,
      created_at: new Date().toISOString(),
      last_login: null,
      is_banned: 0,
      subscription_end: null
    };
    db.users.push(newUser);
    writeDB(db);
    res.json({ success: true, message: 'Регистрация успешна' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: 'Ошибка сервера' });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { username, password, hwid } = req.body;
    if (!username || !password || !hwid) {
      return res.status(400).json({ success: false, message: 'Все поля обязательны' });
    }
    const db = readDB();
    const user = db.users.find(u => u.username === username);
    if (!user) {
      return res.status(401).json({ success: false, message: 'Неверный логин или пароль' });
    }
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(401).json({ success: false, message: 'Неверный логин или пароль' });
    }
    if (user.is_banned) {
      return res.status(403).json({ success: false, message: 'Аккаунт заблокирован' });
    }
    if (user.hwid && user.hwid !== hwid) {
      return res.status(403).json({ success: false, message: 'HWID не совпадает' });
    }
    if (!user.hwid) {
      user.hwid = hwid;
    }
    user.last_login = new Date().toISOString();
    writeDB(db);
    res.json({ success: true, message: 'Вход выполнен', user: { username: user.username, subscription_end: user.subscription_end }});
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: 'Ошибка сервера' });
  }
});

app.post('/api/admin/reset-hwid', (req, res) => {
  try {
    const { username, admin_key } = req.body;
    if (admin_key !== 'YOUR_SECRET_ADMIN_KEY') {
      return res.status(403).json({ success: false, message: 'Неверный админ-ключ' });
    }
    const db = readDB();
    const user = db.users.find(u => u.username === username);
    if (user) {
      user.hwid = null;
      writeDB(db);
    }
    res.json({ success: true, message: 'HWID сброшен' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: 'Ошибка сервера' });
  }
});

app.get('/api/admin/users', (req, res) => {
  try {
    const db = readDB();
    const users = db.users.map(u => ({ id: u.id, username: u.username, hwid: u.hwid, is_banned: u.is_banned, subscription_end: u.subscription_end, last_login: u.last_login }));
    res.json({ success: true, users });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: 'Ошибка сервера' });
  }
});

app.listen(PORT, () => {
  console.log(`Сервер запущен на порту ${PORT}`);
});
