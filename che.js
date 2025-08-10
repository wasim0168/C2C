require('dotenv').config();
const express = require('express');
const session = require('express-session');
const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const Razorpay = require('razorpay');
const crypto = require('crypto');
const app = express();
const port = process.env.PORT || 3000;
const http = require('http');
const { Server } = require('socket.io');
const categoryUpload = multer({ dest: 'public/uploads/categories/' });
const { body, validationResult } = require('express-validator');
const sanitizeHtml = require('sanitize-html');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const RedisStore = require('rate-limit-redis');
const redisClient = require('redis').createClient();
const passwordValidator = require('password-validator');
const { v4: uuidv4 } = require('uuid');
const morgan = require('morgan');
const { createWriteStream } = require('fs');

// Security scanning tools (would be in package.json)
// "dependencies": {
//   "snyk": "^1.1000.0",
//   "npm-audit-resolver": "^3.0.0"
// }

// Initialize security logging
const securityLogStream = createWriteStream(path.join(__dirname, 'security.log'), { flags: 'a' });

// Enhanced password policy schema
const passwordSchema = new passwordValidator();
passwordSchema
  .is().min(10)
  .is().max(100)
  .has().uppercase()
  .has().lowercase()
  .has().digits()
  .has().symbols()
  .has().not().spaces();

// Initialize Razorpay
const razorpay = new Razorpay({
  key_id: process.env.RAZORPAY_KEY_ID,
  key_secret: process.env.RAZORPAY_KEY_SECRET
});

// Database connection
const db = mysql.createPool({
  host: process.env.DB_HOST || 'localhost',
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || '',
  database: process.env.DB_NAME || 'olx_clone',
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

// Security middleware setup
app.use(morgan('combined', {
  stream: securityLogStream,
  skip: (req) => req.path.includes('/public/') // Skip static files
}));

// Enhanced session configuration
app.use(session({
  secret: process.env.SESSION_SECRET || crypto.randomBytes(64).toString('hex'),
  name: '__Secure-sessionId', // Secure cookie name
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,
    sameSite: 'strict',
    domain: process.env.COOKIE_DOMAIN || undefined,
    maxAge: 24 * 60 * 60 * 1000, // 24 hours
    path: '/'
  },
  rolling: true, // Reset maxAge on every request
  genid: () => uuidv4() // Use UUIDs for session IDs
}));

// Enhanced CSP configuration
const cspConfig = {
  directives: {
    defaultSrc: ["'self'"],
    scriptSrc: [
      "'self'",
      "'strict-dynamic'",
      `'nonce-${crypto.randomBytes(16).toString('hex')}'`,
      "https://cdn.jsdelivr.net",
      "https://checkout.razorpay.com"
    ],
    styleSrc: [
      "'self'",
      "'unsafe-inline'", // Still needed for some libs
      "https://cdn.jsdelivr.net",
      "https://cdnjs.cloudflare.com",
      "https://fonts.googleapis.com"
    ],
    imgSrc: ["'self'", "data:", "https:"],
    fontSrc: [
      "'self'",
      "https://cdn.jsdelivr.net",
      "https://cdnjs.cloudflare.com",
      "https://fonts.gstatic.com"
    ],
    connectSrc: [
      "'self'",
      "https://api.razorpay.com",
      "https://lumberjack.razorpay.com"
    ],
    frameSrc: [
      "https://checkout.razorpay.com",
      "https://api.razorpay.com"
    ],
    objectSrc: ["'none'"],
    baseUri: ["'self'"],
    formAction: ["'self'"],
    frameAncestors: ["'none'"],
    upgradeInsecureRequests: []
  }
};

// Apply security middleware
app.use(helmet({
  contentSecurityPolicy: cspConfig,
  hsts: {
    maxAge: 63072000,
    includeSubDomains: true,
    preload: true
  },
  referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
  noSniff: true,
  xssFilter: true,
  frameguard: { action: 'deny' }
}));

// Enhanced rate limiting
const globalLimiter = rateLimit({
  windowMs: 1 * 60 * 1000, // 1 minute
  max: 300,
  message: 'Too many requests, please try again later',
  standardHeaders: true,
  skip: (req) => req.path.startsWith('/public/'),
  handler: (req, res) => {
    securityLogStream.write(`[RATE LIMIT] IP: ${req.ip} Path: ${req.path}\n`);
    res.status(429).json({ error: 'Too many requests' });
  }
});

// Apply rate limiting
app.use(globalLimiter);

// Security event logging middleware
app.use((req, res, next) => {
  // Log authentication attempts
  if (req.path.includes('/auth/login') || req.path.includes('/auth/register')) {
    securityLogStream.write(`[AUTH ATTEMPT] ${req.method} ${req.path} from IP: ${req.ip}\n`);
  }

  // Log admin actions
  if (req.path.startsWith('/admin/') && req.session.admin) {
    securityLogStream.write(`[ADMIN ACTION] ${req.session.admin.email} - ${req.method} ${req.path}\n`);
  }

  // Log payment attempts
  if (req.path.includes('/payment') || req.path.includes('/verify-payment')) {
    securityLogStream.write(`[PAYMENT ATTEMPT] ${req.method} ${req.path}\n`);
  }

  next();
});

// Account lockout mechanism
const failedAttempts = new Map();
const MAX_FAILED_ATTEMPTS = 5;
const LOCKOUT_TIME = 15 * 60 * 1000; // 15 minutes

app.post('/auth/login', [
  body('email').isEmail().normalizeEmail(),
  body('password').isLength({ min: 1 })
], async (req, res, next) => {
  const ip = req.ip;
  const now = Date.now();
  
  // Check if IP is locked out
  if (failedAttempts.has(ip) && failedAttempts.get(ip).count >= MAX_FAILED_ATTEMPTS) {
    const lockoutTime = failedAttempts.get(ip).time;
    if (now - lockoutTime < LOCKOUT_TIME) {
      securityLogStream.write(`[LOCKED OUT] IP: ${ip} attempted login while locked out\n`);
      return res.status(429).render('auth/login', { 
        error: 'Account temporarily locked. Try again later.' 
      });
    } else {
      // Lockout period expired
      failedAttempts.delete(ip);
    }
  }

  try {
    const [users] = await db.query('SELECT * FROM users WHERE email = ?', [req.body.email]);
    
    if (users.length === 0) {
      recordFailedAttempt(ip);
      return res.render('auth/login', { error: 'Invalid credentials' });
    }

    const user = users[0];
    const match = await bcrypt.compare(req.body.password, user.password);

    if (!match) {
      recordFailedAttempt(ip);
      return res.render('auth/login', { error: 'Invalid credentials' });
    }

    // Successful login - reset failed attempts
    failedAttempts.delete(ip);
    
    // Rest of your login logic...
    
  } catch (error) {
    securityLogStream.write(`[LOGIN ERROR] ${error.message}\n`);
    next(error);
  }
});

function recordFailedAttempt(ip) {
  const now = Date.now();
  if (!failedAttempts.has(ip)) {
    failedAttempts.set(ip, { count: 1, time: now });
  } else {
    const attempt = failedAttempts.get(ip);
    attempt.count += 1;
    attempt.time = now;
  }
  
  securityLogStream.write(`[FAILED LOGIN] IP: ${ip} Attempt: ${failedAttempts.get(ip).count}\n`);
}

// Enhanced password validation middleware
const validatePassword = (req, res, next) => {
  const password = req.body.password;
  const errors = passwordSchema.validate(password, { list: true });

  if (errors.length > 0) {
    const errorMessages = {
      min: 'Password must be at least 10 characters',
      max: 'Password must be less than 100 characters',
      uppercase: 'Password must contain uppercase letters',
      lowercase: 'Password must contain lowercase letters',
      digits: 'Password must contain numbers',
      symbols: 'Password must contain special characters',
      spaces: 'Password must not contain spaces'
    };

    const messages = errors.map(err => errorMessages[err]);
    return res.status(400).render('auth/register', {
      error: messages.join(', '),
      formData: req.body
    });
  }

  next();
};

// Apply to registration route
app.post('/auth/register', [
  // Existing validations...
], validatePassword, async (req, res) => {
  // Registration logic...
});

// Nonce-based CSP middleware
app.use((req, res, next) => {
  res.locals.cspNonce = crypto.randomBytes(16).toString('hex');
  next();
});

// In your views, use the nonce:
// <script nonce="<%= cspNonce %>">...</script>

// ... [Rest of your existing application code] ...

// Error handling with security logging
app.use((err, req, res, next) => {
  securityLogStream.write(`[ERROR] ${err.stack || err.message}\n`);
  
  const statusCode = err.statusCode || 500;
  const message = statusCode === 500 ? 'Something went wrong!' : err.message;
  
  res.status(statusCode).render('error', {
    status: statusCode,
    message: message,
    user: req.session.user || null
  });
});

// Security headers verification middleware (for testing)
app.get('/security-headers', (req, res) => {
  const headers = res.getHeaders();
  res.json({
    csp: headers['content-security-policy'],
    hsts: headers['strict-transport-security'],
    xss: headers['x-xss-protection'],
    frameOptions: headers['x-frame-options'],
    contentType: headers['x-content-type-options'],
    referrerPolicy: headers['referrer-policy']
  });
});

// Start server with security checks
function startServer() {
  // Verify required environment variables
  const requiredEnvVars = ['SESSION_SECRET', 'DB_HOST', 'DB_USER', 'DB_PASSWORD', 'DB_NAME'];
  const missingVars = requiredEnvVars.filter(v => !process.env[v]);
  
  if (missingVars.length > 0) {
    console.error('Missing required environment variables:', missingVars.join(', '));
    process.exit(1);
  }

  // Verify password policy
  if (!passwordSchema.validate('Sample1@Password')) {
    console.error('Password policy validation failed');
    process.exit(1);
  }

  server.listen(port, () => {
    console.log(`Server running securely on port ${port}`);
    securityLogStream.write(`[SERVER START] ${new Date().toISOString()}\n`);
  });
}

startServer();