const express = require('express');
const sqlite3 = require('better-sqlite3');
const bcrypt = require('bcrypt');
const cors = require('cors');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());

// Инициализация БД (для Render используем /opt/render/project/src)
const dbPath = process.env.NODE_ENV === 'production' 
  ? '/opt/render/project/src/users.db' 
  : 'users.db';
const db = sqlite3(dbPath);

// Создание таблицы пользователей
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    hwid TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_login DATETIME,
    is_banned INTEGER DEFAULT 0,
    subscription_end DATETIME
  )
`);

// Регистрация
app.post('/api/register', async (req, res) => {
  try {
    const { username, password, hwid } = req.body;

    if (!username || !password || !hwid) {
      return res.status(400).json({ success: false, message: 'Все поля обязательны' });
    }

    // Проверка существования пользователя
    const existing = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
    if (existing) {
      return res.status(400).json({ success: false, message: 'Пользователь уже существует' });
    }

    // Хеширование пароля
    const hashedPassword = await bcrypt.hash(password, 10);

    // Создание пользователя
    const stmt = db.prepare('INSERT INTO users (username, password, hwid) VALUES (?, ?, ?)');
    stmt.run(username, hashedPassword, hwid);

    res.json({ success: true, message: 'Регистрация успешна' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: 'Ошибка сервера' });
  }
});

// Логин
app.post('/api/login', async (req, res) => {
  try {
    const { username, password, hwid } = req.body;

    if (!username || !password || !hwid) {
      return res.status(400).json({ success: false, message: 'Все поля обязательны' });
    }

    // Поиск пользователя
    const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
    
    if (!user) {
      return res.status(401).json({ success: false, message: 'Неверный логин или пароль' });
    }

    // Проверка пароля
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(401).json({ success: false, message: 'Неверный логин или пароль' });
    }

    // Проверка бана
    if (user.is_banned) {
      return res.status(403).json({ success: false, message: 'Аккаунт заблокирован' });
    }

    // Проверка HWID
    if (user.hwid && user.hwid !== hwid) {
      return res.status(403).json({ 
        success: false, 
        message: 'HWID не совпадает. Обратитесь к администратору для сброса.' 
      });
    }

    // Если HWID не был установлен, устанавливаем
    if (!user.hwid) {
      db.prepare('UPDATE users SET hwid = ? WHERE id = ?').run(hwid, user.id);
    }

    // Обновление времени последнего входа
    db.prepare('UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?').run(user.id);

    res.json({ 
      success: true, 
      message: 'Вход выполнен',
      user: {
        username: user.username,
        subscription_end: user.subscription_end
      }
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: 'Ошибка сервера' });
  }
});

// Проверка подписки
app.post('/api/check-subscription', (req, res) => {
  try {
    const { username } = req.body;
    
    const user = db.prepare('SELECT subscription_end FROM users WHERE username = ?').get(username);
    
    if (!user) {
      return res.status(404).json({ success: false, message: 'Пользователь не найден' });
    }

    const now = new Date();
    const subEnd = user.subscription_end ? new Date(user.subscription_end) : null;
    
    const hasSubscription = subEnd && subEnd > now;

    res.json({ 
      success: true, 
      has_subscription: hasSubscription,
      subscription_end: user.subscription_end
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: 'Ошибка сервера' });
  }
});

// Сброс HWID (для админа)
app.post('/api/admin/reset-hwid', (req, res) => {
  try {
    const { username, admin_key } = req.body;
    
    // Простая проверка админ-ключа (в продакшене используй более безопасный метод)
    if (admin_key !== 'YOUR_SECRET_ADMIN_KEY') {
      return res.status(403).json({ success: false, message: 'Неверный админ-ключ' });
    }

    db.prepare('UPDATE users SET hwid = NULL WHERE username = ?').run(username);
    
    res.json({ success: true, message: 'HWID сброшен' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: 'Ошибка сервера' });
  }
});

// Бан/разбан пользователя
app.post('/api/admin/ban-user', (req, res) => {
  try {
    const { username, is_banned } = req.body;
    
    db.prepare('UPDATE users SET is_banned = ? WHERE username = ?').run(is_banned, username);
    
    res.json({ success: true, message: is_banned ? 'Пользователь забанен' : 'Пользователь разбанен' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: 'Ошибка сервера' });
  }
});

// Установка подписки
app.post('/api/admin/set-subscription', (req, res) => {
  try {
    const { username, days } = req.body;
    
    if (days === 0) {
      db.prepare('UPDATE users SET subscription_end = NULL WHERE username = ?').run(username);
      res.json({ success: true, message: 'Подписка удалена' });
    } else {
      const endDate = new Date();
      endDate.setDate(endDate.getDate() + days);
      
      db.prepare('UPDATE users SET subscription_end = ? WHERE username = ?')
        .run(endDate.toISOString(), username);
      
      res.json({ success: true, message: `Подписка установлена до ${endDate.toLocaleDateString('ru-RU')}` });
    }
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: 'Ошибка сервера' });
  }
});

// Получение списка всех пользователей
app.get('/api/admin/users', (req, res) => {
  try {
    const users = db.prepare('SELECT id, username, hwid, is_banned, subscription_end, last_login, created_at FROM users ORDER BY id DESC').all();
    
    res.json({ success: true, users });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: 'Ошибка сервера' });
  }
});

app.listen(PORT, () => {
  console.log(`Сервер запущен на порту ${PORT}`);
});
