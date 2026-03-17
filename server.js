const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const path = require('path');
const fs = require('fs');

// HTML Interface Routes - загружаем полные интерфейсы с сервера для безопасности
const loginHtmlPath = path.join(__dirname, 'auth_interface', 'login.html');
const profileHtmlPath = path.join(__dirname, 'auth_interface', 'profile.html');

app.get('/interface/login', (req, res) => {
  try {
    if (fs.existsSync(loginHtmlPath)) {
      const loginHtml = fs.readFileSync(loginHtmlPath, 'utf8');
      res.setHeader('Content-Type', 'text/html; charset=utf-8');
      res.send(loginHtml);
    } else {
      res.status(404).send('Login page not found');
    }
  } catch (error) {
    console.error('Error serving login page:', error);
    res.status(500).send('Internal Server Error');
  }
});

app.get('/interface/profile', (req, res) => {
  try {
    if (fs.existsSync(profileHtmlPath)) {
      const profileHtml = fs.readFileSync(profileHtmlPath, 'utf8');
      res.setHeader('Content-Type', 'text/html; charset=utf-8');
      res.send(profileHtml);
    } else {
      res.status(404).send('Profile page not found');
    }
  } catch (error) {
    console.error('Error serving profile page:', error);
    res.status(500).send('Internal Server Error');
  }
});


const app = express();
const PORT = process.env.PORT || 3000;
const ADMIN_KEY = process.env.ADMIN_KEY || 'CHANGE_THIS_ADMIN_KEY_2025';

// Middleware
app.use(helmet({
  contentSecurityPolicy: false, // Отключаем CSP для админ-панели
}));
app.use(cors({
  origin: '*', // Разрешаем все домены для лоадера
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));
app.use(express.json());
app.use(express.static('public'));

// Rate limiting
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10, // limit each IP to 10 requests per windowMs (увеличено для тестирования)
  message: { error: 'Too many authentication attempts, try again later' },
  standardHeaders: true,
  legacyHeaders: false,
});

const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 200 // limit each IP to 200 requests per windowMs
});

app.use('/api/auth', authLimiter);
app.use('/api', generalLimiter);

// Database setup
const db = new sqlite3.Database('./users.db');

// Initialize database
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    hwid TEXT,
    is_banned INTEGER DEFAULT 0,
    subscription_end DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_login DATETIME,
    login_count INTEGER DEFAULT 0
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS login_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    hwid TEXT,
    ip_address TEXT,
    success INTEGER,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users (id)
  )`);

  // Создаем тестового пользователя если его нет
  db.get('SELECT id FROM users WHERE username = ?', ['testuser'], (err, row) => {
    if (!row) {
      bcrypt.hash('testpass', 12, (err, hash) => {
        if (!err) {
          const subscriptionEnd = new Date();
          subscriptionEnd.setDate(subscriptionEnd.getDate() + 365); // 1 год подписки
          
          db.run(
            'INSERT INTO users (username, password_hash, subscription_end) VALUES (?, ?, ?)',
            ['testuser', hash, subscriptionEnd.toISOString()],
            function(err) {
              if (!err) {
                console.log('✅ Test user created: testuser / testpass');
              }
            }
          );
        }
      });
    }
  });
});

// Helper functions
function isValidHWID(hwid) {
  return hwid && typeof hwid === 'string' && hwid.length > 10;
}

function isValidUsername(username) {
  return username && /^[a-zA-Z0-9_]{3,20}$/.test(username);
}

function isValidPassword(password) {
  return password && password.length >= 3 && password.length <= 50;
}

function hasValidSubscription(subscriptionEnd) {
  if (!subscriptionEnd) return false;
  return new Date(subscriptionEnd) > new Date();
}

function getClientIP(req) {
  return req.headers['x-forwarded-for'] || 
         req.headers['x-real-ip'] || 
         req.connection.remoteAddress || 
         req.socket.remoteAddress ||
         (req.connection.socket ? req.connection.socket.remoteAddress : null) ||
         req.ip ||
         'unknown';
}

// Root endpoint
app.get('/', (req, res) => {
  res.json({
    message: '🚀 MegaSelf Auth Server is running!',
    version: '1.0.0',
    endpoints: {
      health: '/api/health',
      admin: '/admin',
      register: 'POST /api/auth/register',
      login: 'POST /api/auth/login'
    }
  });
});

// Authentication endpoints
app.post('/api/auth/register', async (req, res) => {
  try {
    const { username, password, hwid } = req.body;

    // Validation
    if (!isValidUsername(username)) {
      return res.status(400).json({ error: 'Invalid username format (3-20 chars, letters/numbers/underscore only)' });
    }

    if (!isValidPassword(password)) {
      return res.status(400).json({ error: 'Invalid password format (3-50 characters)' });
    }

    if (!isValidHWID(hwid)) {
      return res.status(400).json({ error: 'Invalid HWID' });
    }

    // Check if username already exists
    db.get('SELECT id FROM users WHERE username = ?', [username], async (err, row) => {
      if (err) {
        console.error('Database error:', err);
        return res.status(500).json({ error: 'Database error' });
      }

      if (row) {
        return res.status(400).json({ error: 'Username already exists' });
      }

      try {
        // Hash password
        const passwordHash = await bcrypt.hash(password, 12);

        // Create user WITHOUT subscription (admin will add manually)
        db.run(
          'INSERT INTO users (username, password_hash, hwid) VALUES (?, ?, ?)',
          [username, passwordHash, hwid],
          function(err) {
            if (err) {
              console.error('Database error:', err);
              return res.status(500).json({ error: 'Failed to create user' });
            }

            // Log registration
            db.run(
              'INSERT INTO login_logs (user_id, hwid, ip_address, success) VALUES (?, ?, ?, 1)',
              [this.lastID, hwid, getClientIP(req)]
            );

            console.log(`✅ New user registered: ${username} (NO SUBSCRIPTION - admin must add)`);
            res.json({ 
              success: true, 
              message: 'Registration successful! Contact administrator for subscription activation.'
            });
          }
        );
      } catch (hashError) {
        console.error('Hash error:', hashError);
        res.status(500).json({ error: 'Internal server error' });
      }
    });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password, hwid } = req.body;

    if (!isValidUsername(username) || !isValidPassword(password) || !isValidHWID(hwid)) {
      return res.status(400).json({ error: 'Invalid credentials format' });
    }

    db.get(
      'SELECT * FROM users WHERE username = ?',
      [username],
      async (err, user) => {
        if (err) {
          console.error('Database error:', err);
          return res.status(500).json({ error: 'Database error' });
        }

        // Log failed attempt
        const logFailedAttempt = () => {
          db.run(
            'INSERT INTO login_logs (user_id, hwid, ip_address, success) VALUES (?, ?, ?, 0)',
            [user ? user.id : null, hwid, getClientIP(req)]
          );
        };

        if (!user) {
          logFailedAttempt();
          return res.status(401).json({ error: 'Invalid credentials' });
        }

        // Check if user is banned
        if (user.is_banned) {
          logFailedAttempt();
          return res.status(403).json({ error: 'Account is banned' });
        }

        try {
          // Verify password
          const passwordValid = await bcrypt.compare(password, user.password_hash);
          if (!passwordValid) {
            logFailedAttempt();
            return res.status(401).json({ error: 'Invalid credentials' });
          }

          // Check HWID
          if (user.hwid && user.hwid !== hwid) {
            logFailedAttempt();
            return res.status(403).json({ 
              error: 'HWID mismatch. Contact administrator to reset HWID.' 
            });
          }

          // Update HWID if not set
          if (!user.hwid) {
            db.run('UPDATE users SET hwid = ? WHERE id = ?', [hwid, user.id]);
          }

          // Check subscription
          const hasSubscription = hasValidSubscription(user.subscription_end);
          if (!hasSubscription) {
            logFailedAttempt();
            return res.status(403).json({ 
              error: 'Subscription expired',
              subscription_end: user.subscription_end 
            });
          }

          // Update login info
          db.run(
            'UPDATE users SET last_login = CURRENT_TIMESTAMP, login_count = login_count + 1 WHERE id = ?',
            [user.id]
          );

          // Log successful login
          db.run(
            'INSERT INTO login_logs (user_id, hwid, ip_address, success) VALUES (?, ?, ?, 1)',
            [user.id, hwid, getClientIP(req)]
          );

          console.log(`✅ User logged in: ${username}`);
          res.json({
            success: true,
            user: {
              id: user.id,
              username: user.username,
              subscription_end: user.subscription_end,
              login_count: user.login_count + 1
            }
          });
        } catch (bcryptError) {
          console.error('Bcrypt error:', bcryptError);
          logFailedAttempt();
          res.status(500).json({ error: 'Internal server error' });
        }
      }
    );
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Admin endpoints
app.get('/api/admin/users', (req, res) => {
  const { admin_key } = req.query;
  
  if (admin_key !== ADMIN_KEY) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  db.all(
    'SELECT id, username, hwid, is_banned, subscription_end, created_at, last_login, login_count FROM users ORDER BY created_at DESC',
    (err, rows) => {
      if (err) {
        console.error('Database error:', err);
        return res.status(500).json({ error: 'Database error' });
      }
      res.json(rows);
    }
  );
});

app.post('/api/admin/ban', (req, res) => {
  const { admin_key, user_id, banned } = req.body;
  
  if (admin_key !== ADMIN_KEY) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  db.run(
    'UPDATE users SET is_banned = ? WHERE id = ?',
    [banned ? 1 : 0, user_id],
    function(err) {
      if (err) {
        console.error('Database error:', err);
        return res.status(500).json({ error: 'Database error' });
      }
      console.log(`👮 User ${user_id} ${banned ? 'banned' : 'unbanned'}`);
      res.json({ success: true, message: `User ${banned ? 'banned' : 'unbanned'}` });
    }
  );
});

app.post('/api/admin/reset-hwid', (req, res) => {
  const { admin_key, user_id } = req.body;
  
  if (admin_key !== ADMIN_KEY) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  db.run(
    'UPDATE users SET hwid = NULL WHERE id = ?',
    [user_id],
    function(err) {
      if (err) {
        console.error('Database error:', err);
        return res.status(500).json({ error: 'Database error' });
      }
      console.log(`🔄 HWID reset for user ${user_id}`);
      res.json({ success: true, message: 'HWID reset successfully' });
    }
  );
});

app.post('/api/admin/extend-subscription', (req, res) => {
  const { admin_key, user_id, days } = req.body;
  
  if (admin_key !== ADMIN_KEY) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  db.get('SELECT subscription_end FROM users WHERE id = ?', [user_id], (err, user) => {
    if (err) {
      console.error('Database error:', err);
      return res.status(500).json({ error: 'Database error' });
    }

    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    const currentEnd = user.subscription_end ? new Date(user.subscription_end) : new Date();
    const newEnd = new Date(Math.max(currentEnd.getTime(), Date.now()));
    newEnd.setDate(newEnd.getDate() + parseInt(days));

    db.run(
      'UPDATE users SET subscription_end = ? WHERE id = ?',
      [newEnd.toISOString(), user_id],
      function(err) {
        if (err) {
          console.error('Database error:', err);
          return res.status(500).json({ error: 'Database error' });
        }
        console.log(`💳 Subscription extended for user ${user_id} by ${days} days`);
        res.json({ 
          success: true, 
          message: `Subscription extended by ${days} days`,
          new_end: newEnd.toISOString()
        });
      }
    );
  });
});

app.get('/api/admin/logs', (req, res) => {
  const { admin_key } = req.query;
  
  if (admin_key !== ADMIN_KEY) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  db.all(
    `SELECT l.*, u.username 
     FROM login_logs l 
     LEFT JOIN users u ON l.user_id = u.id 
     ORDER BY l.timestamp DESC 
     LIMIT 100`,
    (err, rows) => {
      if (err) {
        console.error('Database error:', err);
        return res.status(500).json({ error: 'Database error' });
      }
      res.json(rows);
    }
  );
});

// Health check
app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'OK', 
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    version: '1.0.0'
  });
});

// Serve admin panel
app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({ error: 'Endpoint not found' });
});

// Error handler
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({ error: 'Internal server error' });
});

// Start server
app.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 MegaSelf Auth Server running on port ${PORT}`);
  console.log(`📊 Admin panel: http://localhost:${PORT}/admin`);
  console.log(`🔑 Admin key: ${ADMIN_KEY}`);
  console.log(`🌐 Health check: http://localhost:${PORT}/api/health`);
  
  if (ADMIN_KEY === 'CHANGE_THIS_ADMIN_KEY_2025') {
    console.log('⚠️  WARNING: Please change the default admin key!');
  }
});

// Graceful shutdown
process.on('SIGINT', () => {
  console.log('\n🛑 Shutting down server...');
  db.close((err) => {
    if (err) {
      console.error('Error closing database:', err);
    } else {
      console.log('✅ Database connection closed');
    }
    process.exit(0);
  });
});

process.on('SIGTERM', () => {
  console.log('🛑 Received SIGTERM, shutting down gracefully...');
  db.close((err) => {
    if (err) {
      console.error('Error closing database:', err);
    } else {
      console.log('✅ Database connection closed');
    }
    process.exit(0);
  });
});
