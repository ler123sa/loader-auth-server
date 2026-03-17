const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const path = require('path');
const fs = require('fs');

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
      login: 'POST /api/auth/login',
      interface_login: '/interface/login',
      interface_profile: '/interface/profile'
    }
  });
});

// HTML Interface Routes - загружаем полные интерфейсы с сервера для безопасности
const loginHtmlPath = path.join(__dirname, 'auth_interface', 'login.html');
const profileHtmlPath = path.join(__dirname, 'auth_interface', 'profile.html');

app.get('/interface/login', (req, res) => {
  try {
    if (fs.existsSync(loginHtmlPath)) {
      const loginHtml = fs.readFileSync(loginHtmlPath, 'utf8');
      res.setHeader('Content-Type', 'text/html; charset=utf-8');
      res.send(loginHtml);
      console.log('✅ Served login.html from file');
    } else {
      // Fallback на упрощенную версию если файл не найден
      console.log('⚠️ login.html not found, serving fallback');
      const fallbackHtml = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MegaSelf Login</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Roboto', 'Helvetica Neue', Arial, sans-serif;
            background: #0d0d1a;
            color: white;
            margin: 0;
            padding: 0;
            display: flex;
            align-items: center;
            justify-content: center;
            min-height: 100vh;
            overflow: hidden;
        }
        .login-container {
            background: rgba(255,255,255,0.05);
            padding: 40px;
            border-radius: 12px;
            width: 320px;
            border: 1px solid rgba(255,255,255,0.1);
        }
        .login-title {
            text-align: center;
            font-size: 24px;
            font-weight: 600;
            margin-bottom: 30px;
        }
        .form-group {
            margin-bottom: 20px;
        }
        .form-input {
            width: 100%;
            padding: 12px;
            background: rgba(255,255,255,0.05);
            border: 1px solid rgba(255,255,255,0.1);
            border-radius: 8px;
            color: white;
            font-size: 14px;
            box-sizing: border-box;
        }
        .form-input:focus {
            outline: none;
            border-color: rgba(255,255,255,0.3);
        }
        .form-input::placeholder {
            color: rgba(255,255,255,0.4);
        }
        .login-btn {
            width: 100%;
            padding: 12px;
            background: white;
            color: #0d0d1a;
            border: none;
            border-radius: 8px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            margin-bottom: 10px;
        }
        .login-btn:hover {
            background: #e0e0e0;
        }
        .register-btn {
            width: 100%;
            padding: 12px;
            background: rgba(255,255,255,0.1);
            color: white;
            border: 1px solid rgba(255,255,255,0.1);
            border-radius: 8px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
        }
        .register-btn:hover {
            background: rgba(255,255,255,0.15);
        }
        .notification {
            position: fixed;
            top: 20px;
            right: 20px;
            padding: 12px 16px;
            border-radius: 8px;
            font-size: 14px;
            font-weight: 500;
            z-index: 1000;
            transform: translateX(400px);
            transition: all 0.3s ease;
        }
        .notification.show {
            transform: translateX(0);
        }
        .notification.success {
            background: rgba(34, 197, 94, 0.1);
            border: 1px solid rgba(34, 197, 94, 0.3);
            color: #22c55e;
        }
        .notification.error {
            background: rgba(239, 68, 68, 0.1);
            border: 1px solid rgba(239, 68, 68, 0.3);
            color: #ef4444;
        }
        .loading-overlay {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0,0,0,0.8);
            display: flex;
            align-items: center;
            justify-content: center;
            z-index: 2000;
            opacity: 0;
            visibility: hidden;
            transition: all 0.3s ease;
        }
        .loading-overlay.show {
            opacity: 1;
            visibility: visible;
        }
        .spinner {
            width: 40px;
            height: 40px;
            border: 3px solid rgba(255,255,255,0.1);
            border-top: 3px solid white;
            border-radius: 50%;
            animation: spin 1s linear infinite;
        }
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
    </style>
</head>
<body>
    <div class="login-container">
        <h1 class="login-title">MegaSelf Login</h1>
        <div class="form-group">
            <input type="text" class="form-input" id="username" placeholder="Username" required>
        </div>
        <div class="form-group">
            <input type="password" class="form-input" id="password" placeholder="Password" required>
        </div>
        <button class="login-btn" onclick="login()">Login</button>
        <button class="register-btn" onclick="register()">Register</button>
    </div>
    
    <div class="loading-overlay" id="loadingOverlay">
        <div class="spinner"></div>
    </div>
    
    <div class="notification" id="notification"></div>
    
    <script>
        function showNotification(message, type = 'success') {
            const notification = document.getElementById('notification');
            notification.textContent = message;
            notification.className = 'notification ' + type;
            
            setTimeout(() => {
                notification.classList.add('show');
            }, 10);
            
            setTimeout(() => {
                notification.classList.remove('show');
            }, 5000);
        }
        
        function showLoading(show = true) {
            const overlay = document.getElementById('loadingOverlay');
            if (show) {
                overlay.classList.add('show');
            } else {
                overlay.classList.remove('show');
            }
        }
        
        async function getHWID() {
            return new Promise((resolve) => {
                window.chrome.webview.postMessage('get_hwid');
                
                window.addEventListener('message', function handler(event) {
                    if (event.data.startsWith('hwid:')) {
                        window.removeEventListener('message', handler);
                        resolve(event.data.substring(5));
                    }
                });
                
                // Fallback timeout
                setTimeout(() => {
                    resolve('HWID-FALLBACK-' + Date.now());
                }, 5000);
            });
        }
        
        async function login() {
            const username = document.getElementById('username').value;
            const password = document.getElementById('password').value;
            
            if (!username || !password) {
                showNotification('Please fill in all fields', 'error');
                return;
            }
            
            showLoading(true);
            
            try {
                const hwid = await getHWID();
                
                const response = await fetch('/api/auth/login', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({ username, password, hwid })
                });
                
                const result = await response.json();
                
                if (response.ok) {
                    showNotification('Login successful!', 'success');
                    localStorage.setItem('userData', JSON.stringify(result.user));
                    
                    setTimeout(() => {
                        window.chrome.webview.postMessage('navigate_to_profile');
                    }, 1000);
                } else {
                    showNotification(result.error || 'Login failed', 'error');
                }
            } catch (error) {
                showNotification('Server is starting up, please wait 30 seconds and try again.', 'error');
            } finally {
                showLoading(false);
            }
        }
        
        async function register() {
            const username = document.getElementById('username').value;
            const password = document.getElementById('password').value;
            
            if (!username || !password) {
                showNotification('Please fill in all fields', 'error');
                return;
            }
            
            showLoading(true);
            
            try {
                const hwid = await getHWID();
                
                const response = await fetch('/api/auth/register', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({ username, password, hwid })
                });
                
                const result = await response.json();
                
                if (response.ok) {
                    showNotification('Registration successful! Please login.', 'success');
                    document.getElementById('username').value = '';
                    document.getElementById('password').value = '';
                } else {
                    showNotification(result.error || 'Registration failed', 'error');
                }
            } catch (error) {
                showNotification('Server is starting up, please wait 30 seconds and try again.', 'error');
            } finally {
                showLoading(false);
            }
        }
        
        document.addEventListener('keypress', function(e) {
            if (e.key === 'Enter') {
                login();
            }
        });
        
        // Initialize immediately
        (function() {
            setTimeout(() => {
                showLoading(false);
            }, 100);
        })();
    </script>
</body>
</html>`;
      res.setHeader('Content-Type', 'text/html; charset=utf-8');
      res.send(fallbackHtml);
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
      console.log('✅ Served profile.html from file');
    } else {
      // Fallback на упрощенную версию если файл не найден
      console.log('⚠️ profile.html not found, serving fallback');
      const fallbackHtml = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MegaSelf Profile</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Roboto', 'Helvetica Neue', Arial, sans-serif;
            background: #0d0d1a;
            color: white;
            margin: 0;
            padding: 20px;
            min-height: 100vh;
            overflow: hidden;
        }
        .profile-container {
            max-width: 600px;
            margin: 0 auto;
            background: rgba(255,255,255,0.05);
            padding: 30px;
            border-radius: 12px;
            border: 1px solid rgba(255,255,255,0.1);
        }
        .profile-header {
            text-align: center;
            margin-bottom: 30px;
        }
        .profile-title {
            font-size: 24px;
            font-weight: 600;
            margin-bottom: 10px;
        }
        .user-info {
            background: rgba(255,255,255,0.05);
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 20px;
        }
        .launch-btn {
            width: 100%;
            padding: 15px;
            background: white;
            color: #0d0d1a;
            border: none;
            border-radius: 8px;
            font-size: 18px;
            font-weight: 600;
            cursor: pointer;
            margin-bottom: 20px;
        }
        .launch-btn:hover {
            background: #e0e0e0;
        }
        .logout-btn {
            width: 100%;
            padding: 12px;
            background: rgba(239, 68, 68, 0.1);
            color: #ef4444;
            border: 1px solid rgba(239, 68, 68, 0.3);
            border-radius: 8px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
        }
        .logout-btn:hover {
            background: rgba(239, 68, 68, 0.2);
        }
    </style>
</head>
<body>
    <div class="profile-container">
        <div class="profile-header">
            <h1 class="profile-title">MegaSelf Profile</h1>
        </div>
        
        <div class="user-info" id="userInfo">
            <p><strong>Username:</strong> <span id="username">Loading...</span></p>
            <p><strong>Subscription:</strong> <span id="subscription">Loading...</span></p>
        </div>
        
        <button class="launch-btn" onclick="launchGame()">Launch Game</button>
        <button class="logout-btn" onclick="logout()">Logout</button>
    </div>
    
    <script>
        const userData = JSON.parse(localStorage.getItem('userData') || '{}');
        
        if (userData.username) {
            document.getElementById('username').textContent = userData.username;
            
            const subscriptionEnd = new Date(userData.subscription_end);
            const now = new Date();
            const isActive = subscriptionEnd > now;
            
            if (isActive) {
                document.getElementById('subscription').textContent = 'Active until ' + subscriptionEnd.toLocaleDateString();
            } else {
                document.getElementById('subscription').textContent = 'Expired';
                document.querySelector('.launch-btn').disabled = true;
                document.querySelector('.launch-btn').textContent = 'Subscription Expired';
            }
        } else {
            window.chrome.webview.postMessage('navigate_to_login');
        }
        
        function launchGame() {
            window.chrome.webview.postMessage('action_button');
        }
        
        function logout() {
            localStorage.removeItem('userData');
            window.chrome.webview.postMessage('navigate_to_login');
        }
        
        // Initialize immediately
        (function() {
            setTimeout(() => {
                // Profile loaded
            }, 100);
        })();
    </script>
</body>
</html>`;
      res.setHeader('Content-Type', 'text/html; charset=utf-8');
      res.send(fallbackHtml);
    }
  } catch (error) {
    console.error('Error serving profile page:', error);
    res.status(500).send('Internal Server Error');
  }
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
  console.log(`🔗 Interface login: http://localhost:${PORT}/interface/login`);
  console.log(`👤 Interface profile: http://localhost:${PORT}/interface/profile`);
  
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
