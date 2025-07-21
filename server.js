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
const cookieParser = require('cookie-parser');
const csrf = require('csurf');
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

// chat server
const server = http.createServer(app);
const io = new Server(server);

// Socket.io connection
// Socket.io Setup (add to your existing code)
io.on('connection', (socket) => {
  console.log('New client connected:', socket.id);

  // Join user to their personal room
  socket.on('register', (userId) => {
    socket.join(`user_${userId}`);
    console.log(`User ${userId} registered with socket ${socket.id}`);
  });

  // Handle new messages
  socket.on('sendMessage', async (data) => {
    try {
      const { senderId, receiverId, productId, message } = data;
      
      // Save message to database
      const [result] = await db.query(
        `INSERT INTO messages 
        (sender_id, receiver_id, product_id, message) 
        VALUES (?, ?, ?, ?)`,
        [senderId, receiverId, productId, message]
      );

      // Get sender details
      const [sender] = await db.query(
        'SELECT id, name FROM users WHERE id = ?', 
        [senderId]
      );

      // Construct message object
      const messageObj = {
        id: result.insertId,
        senderId,
        senderName: sender[0].name,
        productId,
        message,
        timestamp: new Date()
      };

      // Emit to receiver
      io.to(`user_${receiverId}`).emit('newMessage', messageObj);
      
      // Also emit back to sender (for their own UI update)
      io.to(`user_${senderId}`).emit('newMessage', messageObj);

    } catch (error) {
      console.error('Error sending message:', error);
    }
  });

  // Handle disconnection
  socket.on('disconnect', () => {
    console.log('Client disconnected:', socket.id);
  });
});


// Middleware
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(session({
  secret: process.env.SESSION_SECRET || 'your-secret-key',
  resave: false,
  saveUninitialized: true,
  cookie: { secure: false }
}));

// After session middleware
app.use(cookieParser());

// CSRF middleware setup
const csrfProtection = csrf({ cookie: true });
app.use(csrfProtection);

// Make CSRF token available to all views
app.use((req, res, next) => {
  res.locals.csrfToken = req.csrfToken();
  next();
});
// block access to admin routes for non-admin users

const checkBlocked = (req, res, next) => {
  if (req.session.user?.is_blocked) {
    req.session.destroy();
    return res.render('auth/login', {
      error: 'Your account has been blocked. Please contact support.'
    });
  }
  next();
};

// Apply to all authenticated routes
app.use(['/profile', '/products', '/messages'], checkBlocked);
app.use(express.static("public"));
// Static files
app.use(express.static(path.join(__dirname, 'public')));
app.use('/uploads', express.static(path.join(__dirname, 'public', 'uploads')));
// Set view engine
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');


const upload = multer({ 
  dest: 'public/uploads/',
  limits: { 
    fileSize: 5 * 1024 * 1024, // 5MB per file
    files: 3 // Maximum 3 files
  },
  fileFilter: (req, file, cb) => {
    if (file.mimetype.startsWith('image/')) {
      cb(null, true);
    } else {
      cb(new Error('Only image files are allowed'), false);
    }
  }
});

// Authentication middleware
const isAuthenticated = (req, res, next) => {
  if (req.session.user) {
    next();
  } else {
    req.session.returnTo = req.originalUrl;
    res.redirect('/auth/login');
  }
};

// Admin middleware
const isAdmin = (req, res, next) => {
  // Check if admin session exists
  if (!req.session.admin) {
    return res.redirect('/admin/login');
  }
  
  // Additional role checks if needed
  if (req.path.startsWith('/admin/super') && req.session.admin.role !== 'super') {
    return res.status(403).send('Access denied');
  }
  
  return next();
};

// Product ID validation middleware (updated)
const validateProductId = (req, res, next) => {
  const productId = req.params.id;
  
  if (!productId || !/^\d+$/.test(productId)) {
    return res.status(400).render('error', {
      user: req.session.user,
      status: 400,
      message: 'Invalid product ID format',
      showSearch: true
    });
  }
  
  req.productId = parseInt(productId, 10);
  next();
};

// Product ownership validation middleware
const validateProductOwner = async (req, res, next) => {
  try {
    const [products] = await db.query(
      'SELECT * FROM products WHERE id = ? AND user_id = ?',
      [req.productId, req.session.user?.id]
    );
    
    if (products.length === 0) {
      return res.status(404).render('error', {
        user: req.session.user,
        status: 404,
        message: 'Product not found or you don\'t have permission',
        showSearch: true
      });
    }
    
    req.product = products[0];
    next();
  } catch (error) {
    console.error('Product validation error:', error);
    res.status(500).render('error', {
      user: req.session.user,
      status: 500,
      message: 'Server error during product validation'
    });
  }
};

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(`ERROR (${err.statusCode || 500}): ${err.message}`);
  
  const statusCode = err.statusCode || 500;
  const message = err.message || 'Something went wrong!';
  
  res.status(statusCode).render('error', {
    title: `Error ${statusCode}`,
    status: statusCode,
    message: message,
    user: req.session.user || null,
    showSearch: statusCode === 404
  });
});

// Routes

// Home page with pagination
app.get('/', async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = 8; // 9 products per page
    const offset = (page - 1) * limit;

    // Get total count of products
    const [countResult] = await db.query(
      'SELECT COUNT(*) as total FROM products WHERE is_active = TRUE'
    );
    const totalProducts = countResult[0].total;
    const totalPages = Math.ceil(totalProducts / limit);

    // Get paginated products
    const [products] = await db.query(`
      SELECT p.*, u.name as user_name 
      FROM products p
      JOIN users u ON p.user_id = u.id
      WHERE p.is_active = TRUE
      ORDER BY p.created_at DESC
      LIMIT ? OFFSET ?
    `, [limit, offset]);
    
    res.render('home', { 
      user: req.session.user || null,
      products: products || [],
      searchQuery: null,
      selectedCategory: null,
      categories: ['Electronics', 'Furniture', 'Cars', 'Bikes', 'Fashion', 'Books', 'Others'],
      message: null,
      pagination: {
        page,
        limit,
        totalPages,
        totalProducts
      }
    });
  } catch (error) {
    console.error(error);
    res.status(500).send('Server error');
  }
});

// Search products with pagination
app.get('/search', async (req, res) => {
  const { q, category, page = 1 } = req.query;
  const limit = 9;
  const offset = (page - 1) * limit;
  
  let baseQuery = `
    SELECT p.*, u.name as user_name 
    FROM products p
    JOIN users u ON p.user_id = u.id
    WHERE p.is_active = TRUE
  `;
  
  let countQuery = `
    SELECT COUNT(*) as total 
    FROM products p
    WHERE p.is_active = TRUE
  `;
  
  const params = [];
  const countParams = [];

  if (q) {
    baseQuery += ' AND (p.title LIKE ? OR p.description LIKE ?)';
    countQuery += ' AND (p.title LIKE ? OR p.description LIKE ?)';
    params.push(`%${q}%`, `%${q}%`);
    countParams.push(`%${q}%`, `%${q}%`);
  }

  if (category) {
    baseQuery += ' AND p.category = ?';
    countQuery += ' AND p.category = ?';
    params.push(category);
    countParams.push(category);
  }

  baseQuery += ' ORDER BY p.created_at DESC LIMIT ? OFFSET ?';
  params.push(limit, offset);

  try {
    const [[count]] = await db.query(countQuery, countParams);
    const totalPages = Math.ceil(count.total / limit);
    
    const [products] = await db.query(baseQuery, params);
    
    res.render('home', { 
      user: req.session.user || null,
      products,
      searchQuery: q,
      selectedCategory: category,
      categories: ['Electronics', 'Furniture', 'Cars', 'Bikes', 'Fashion', 'Books', 'Others'],
      message: null,
      pagination: {
        page: parseInt(page),
        limit,
        totalPages,
        totalProducts: count.total
      }
    });
  } catch (error) {
    console.error(error);
    res.status(500).send('Server error');
  }
});

// Product Creation Routes (should come before ID routes)
app.get('/products/create', isAuthenticated, csrfProtection ,  async (req, res) => {
  try {
    if (!req.session.user.plan_id) {
      req.session.message = {
        type: 'warning',
        text: 'Please select a plan before posting products'
      };
      return res.redirect('/plans/select');
    }

    const [count] = await db.query(
      'SELECT COUNT(*) as count FROM products WHERE user_id = ?',
      [req.session.user.id]
    );
    
    if (count[0].count >= req.session.user.product_limit) {
      req.session.message = {
        type: 'danger',
        text: `You've reached your limit of ${req.session.user.product_limit} products. Please upgrade your plan.`
      };
      return res.redirect('/profile');
    }

    res.render('products/create', {
      user: req.session.user,
      categories: ['Electronics', 'Furniture', 'Cars', 'Bikes', 'Fashion', 'Books', 'Others'],
      message: req.session.message || null
    });

    delete req.session.message;
  } catch (error) {
    console.error('Product create page error:', error);
    res.status(500).render('error', {
      user: req.session.user,
      status: 500,
      message: 'Error loading product creation page'
    });
  }
});

app.post('/products/create', 
  isAuthenticated, 
  csrfProtection,
  upload.array('images', 3), // Handle up to 3 files with field name 'images'
  async (req, res) => {
    try {
      if (!req.session.user.plan_id) {
        req.session.message = { type: 'danger', text: 'Please select a plan before posting products' };
        return res.redirect('/plans/select');
      }

      const [count] = await db.query(
        'SELECT COUNT(*) as count FROM products WHERE user_id = ?',
        [req.session.user.id]
      );
      
      if (count[0].count >= req.session.user.product_limit) {
        req.session.message = { 
          type: 'warning', 
          text: `You've reached your limit of ${req.session.user.product_limit} products. Please upgrade your plan.`
        };
        return res.redirect('/profile');
      }

      const { title, description, price, category } = req.body;
      
      if (!title || !description || !price || !category || !req.files || req.files.length === 0) {
        req.session.message = { type: 'danger', text: 'All required fields are missing' };
        return res.redirect('/products/create');
      }

      // Get the filenames of uploaded images
      const images = req.files.map(file => file.filename);
      
      // Insert product with first image as primary
      const [result] = await db.query(
        'INSERT INTO products (user_id, title, description, price, image, category, additional_images) VALUES (?, ?, ?, ?, ?, ?, ?)',
        [
          req.session.user.id, 
          title, 
          description, 
          parseFloat(price), 
          images[0], // Primary image
          category,
          JSON.stringify(images.slice(1)) // Store additional images as JSON array
        ]
      );
      
      req.session.message = { type: 'success', text: 'Product posted successfully!' };
      return res.redirect('/profile');
      
    } catch (error) {
      console.error('Product creation error:', error);
      
      // Clean up uploaded files if error occurs
      if (req.files) {
        req.files.forEach(file => {
          const filePath = path.join(__dirname, 'public', 'uploads', file.filename);
          if (fs.existsSync(filePath)) {
            fs.unlinkSync(filePath);
          }
        });
      }
      
      req.session.message = { type: 'danger', text: 'Error creating product. Please try again.' };
      return res.redirect('/products/create');
    }
  }
);

// In your product show route
app.get('/products/:id', validateProductId, async (req, res) => {
  try {
    const [products] = await db.query(`
      SELECT p.*, u.name as user_name, u.email as user_email, u.phone as user_phone
      FROM products p
      JOIN users u ON p.user_id = u.id
      WHERE p.id = ? AND p.is_active = TRUE
    `, [req.productId]);

    if (products.length === 0) {
      return res.status(404).render('error', {
        user: req.session.user,
        status: 404,
        message: 'Product not found or has been removed',
        showSearch: true
      });
    }

    const product = products[0];
    // Parse additional images if they exist
    product.additionalImages = product.additional_images ? JSON.parse(product.additional_images) : [];

    res.render('products/show', { 
      user: req.session.user,
      product: product,
      similarProducts: await getSimilarProducts(product.category, product.id)
    });
  } catch (error) {
    console.error('Product view error:', error);
    res.status(500).render('error', {
      user: req.session.user,
      status: 500,
      message: 'Server error while loading product'
    });
  }
});

app.get('/products/:id/edit', 
  isAuthenticated, 
  validateProductId, 
  validateProductOwner, 
  async (req, res) => {
    res.render('products/edit', { 
      user: req.session.user,
      product: req.product,
      categories: ['Electronics', 'Furniture', 'Cars', 'Bikes', 'Fashion', 'Books', 'Others']
    });
  }
);

app.post('/products/:id/update', 
  isAuthenticated, 
  validateProductId, 
  validateProductOwner, 
  upload.single('image'), 
  async (req, res) => {
    const { title, description, price, category } = req.body;
    
    try {
      const updateData = {
        title,
        description,
        price: parseFloat(price),
        category
      };
      
      if (req.file) {
        const oldImage = path.join(__dirname, 'public', 'uploads', req.product.image);
        if (fs.existsSync(oldImage)) {
          fs.unlinkSync(oldImage);
        }
        updateData.image = req.file.filename;
      }
      
      await db.query(
        'UPDATE products SET ? WHERE id = ?',
        [updateData, req.productId]
      );
      
      req.session.message = {
        type: 'success',
        text: 'Product updated successfully'
      };
      res.redirect('/profile');
    } catch (error) {
      console.error(error);
      req.session.message = {
        type: 'danger',
        text: 'Error updating product'
      };
      res.redirect(`/products/${req.productId}/edit`);
    }
  }
);

app.post('/products/:id/delete', 
  isAuthenticated, 
  validateProductId, 
  validateProductOwner, 
  async (req, res) => {
    try {
      const imagePath = path.join(__dirname, 'public', 'uploads', req.product.image);
      if (fs.existsSync(imagePath)) {
        fs.unlinkSync(imagePath);
      }
      
      await db.query('DELETE FROM products WHERE id = ?', [req.productId]);
      
      req.session.message = {
        type: 'success',
        text: 'Product deleted successfully'
      };
      res.redirect('/profile');
    } catch (error) {
      console.error(error);
      req.session.message = {
        type: 'danger',
        text: 'Error deleting product'
      };
      res.redirect('/profile');
    }
  }
);

// Helper function to get similar products
async function getSimilarProducts(category, excludeId) {
  try {
    const [products] = await db.query(`
      SELECT p.*, u.name as user_name 
      FROM products p
      JOIN users u ON p.user_id = u.id
      WHERE p.category = ? AND p.id != ? AND p.is_active = TRUE
      ORDER BY p.created_at DESC
      LIMIT 4
    `, [category, excludeId]);
    return products;
  } catch (error) {
    console.error('Error fetching similar products:', error);
    return [];
  }
}

// admin login

// Admin Login Route
app.get('/admin/login', (req, res) => {
 if (req.session.admin) return res.redirect('/admin/dashboard');
  res.render('admin/login', { 
    error: null,
    success: req.query.registered ? 'Registration successful! Please login.' : null
  });
});
app.post('/admin/login', async (req, res) => {
  const { email, password } = req.body;
  
  try {
    const [admins] = await db.query(
      'SELECT * FROM admins WHERE email = ? AND is_active = TRUE',
      [email]
    );
    
    if (admins.length === 0) {
      return res.render('admin/login', { error: 'Invalid credentials' });
    }

    const admin = admins[0];
    const match = await bcrypt.compare(password, admin.password);

    if (!match) {
      return res.render('admin/login', { error: 'Invalid credentials' });
    }

    req.session.admin = {
      id: admin.id,
      name: admin.name,
      email: admin.email,
      role: admin.role
    };

    // Save session before redirect
    req.session.save(() => {
      res.redirect('/admin/dashboard');
    });
  } catch (error) {
    console.error('Admin login error:', error);
    res.render('admin/login', { error: 'Server error' });
  }
});

// Admin Logout
app.get('/admin/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/admin/login');
});

// Login page
app.get('/auth/login', (req, res) => {
  if (req.session.user) {
    return res.redirect('/');
  }
  res.render('auth/login', { error: null });
});

// Login handler
app.post('/auth/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    const [users] = await db.query('SELECT * FROM users WHERE email = ?', [email]);
    
    if (users.length === 0) {
      return res.render('auth/login', { error: 'Invalid email or password' });
    }

    const user = users[0];
    const match = await bcrypt.compare(password, user.password);

    if (!match) {
      return res.render('auth/login', { error: 'Invalid email or password' });
    }

    req.session.user = {
      id: user.id,
      name: user.name,
      email: user.email,
      plan_id: user.plan_id,
      product_limit: user.product_limit,
      is_admin: user.is_admin,
      is_blocked: user.is_blocked
    };

    const redirectTo = req.session.returnTo || '/';
    delete req.session.returnTo;
    res.redirect(redirectTo);

  } catch (error) {
    console.error(error);
    res.status(500).send('Server error');
  }
});

// Register page
app.get('/auth/register', (req, res) => {
  if (req.session.user) {
    return res.redirect('/');
  }
  res.render('auth/register', { error: null });
});

// chat message
// Add this route to your app.js
app.get('/api/messages', isAuthenticated, async (req, res) => {
  try {
    const { productId, otherUserId } = req.query;
    const currentUserId = req.session.user.id;

    const [messages] = await db.query(`
      SELECT m.*, u.name as sender_name 
      FROM messages m
      JOIN users u ON m.sender_id = u.id
      WHERE product_id = ? AND (
        (sender_id = ? AND receiver_id = ?) OR 
        (sender_id = ? AND receiver_id = ?)
      )
      ORDER BY created_at ASC
    `, [productId, currentUserId, otherUserId, otherUserId, currentUserId]);

    res.json(messages);
  } catch (error) {
    console.error('Error fetching messages:', error);
    res.status(500).json({ error: 'Failed to load messages' });
  }
});
// inbox message
// Get all conversations for the current user
app.get('/messages', isAuthenticated, async (req, res) => {
  try {
    const userId = req.session.user.id;
    
    // Get distinct conversations (grouped by product and other user)
    const [conversations] = await db.query(`
      SELECT 
        p.id as product_id,
        p.title as product_title,
        p.image as product_image,
        p.price as product_price,
        u.id as other_user_id,
        u.name as other_user_name,
        MAX(m.created_at) as last_message_time,
        (
          SELECT message 
          FROM messages 
          WHERE (
            (sender_id = ? AND receiver_id = u.id AND product_id = p.id) OR
            (sender_id = u.id AND receiver_id = ? AND product_id = p.id)
          )
          ORDER BY created_at DESC 
          LIMIT 1
        ) as last_message,
        SUM(CASE WHEN m.receiver_id = ? AND m.is_read = FALSE THEN 1 ELSE 0 END) as unread_count
      FROM messages m
      JOIN products p ON m.product_id = p.id
      JOIN users u ON (u.id = CASE 
        WHEN m.sender_id = ? THEN m.receiver_id 
        ELSE m.sender_id 
      END)
      WHERE m.sender_id = ? OR m.receiver_id = ?
      GROUP BY p.id, u.id
      ORDER BY last_message_time DESC
    `, [userId, userId, userId, userId, userId, userId]);

    res.render('messages/inbox', {
      user: req.session.user,
      conversations,
      activeTab: 'inbox'
    });
  } catch (error) {
    console.error('Error fetching conversations:', error);
    res.status(500).render('error', {
      user: req.session.user,
      status: 500,
      message: 'Failed to load messages'
    });
  }
});

// Mark messages as read
app.post('/messages/mark-as-read', isAuthenticated, async (req, res) => {
  try {
    const { productId, senderId } = req.body;
    await db.query(
      'UPDATE messages SET is_read = TRUE WHERE product_id = ? AND sender_id = ? AND receiver_id = ?',
      [productId, senderId, req.session.user.id]
    );
    res.json({ success: true });
  } catch (error) {
    console.error('Error marking messages as read:', error);
    res.status(500).json({ success: false });
  }
});

// Get specific conversation
app.get('/messages/:productId/:userId', isAuthenticated, async (req, res) => {
  try {
    const { productId, userId } = req.params;
    const currentUserId = req.session.user.id;
    
    // Get product details
    const [products] = await db.query('SELECT * FROM products WHERE id = ?', [productId]);
    if (products.length === 0) {
      return res.status(404).render('error', {
        user: req.session.user,
        status: 404,
        message: 'Product not found'
      });
    }
    
    // Get other user details
    const [users] = await db.query('SELECT id, name FROM users WHERE id = ?', [userId]);
    if (users.length === 0) {
      return res.status(404).render('error', {
        user: req.session.user,
        status: 404,
        message: 'User not found'
      });
    }
    
    // Get messages
    const [messages] = await db.query(`
      SELECT m.*, u.name as sender_name 
      FROM messages m
      JOIN users u ON m.sender_id = u.id
      WHERE product_id = ? AND (
        (sender_id = ? AND receiver_id = ?) OR 
        (sender_id = ? AND receiver_id = ?)
      )
      ORDER BY created_at ASC
    `, [productId, currentUserId, userId, userId, currentUserId]);
    
    res.render('messages/conversation', {
      user: req.session.user,
      product: products[0],
      otherUser: users[0],
      messages
    });
  } catch (error) {
    console.error('Error fetching conversation:', error);
    res.status(500).render('error', {
      user: req.session.user,
      status: 500,
      message: 'Failed to load conversation'
    });
  }
});

// Register handler
app.post('/auth/register', async (req, res) => {
  const { name, email, password, confirm_password } = req.body;

  if (password !== confirm_password) {
    return res.render('auth/register', { error: 'Passwords do not match' });
  }

  try {
    const [existingUsers] = await db.query('SELECT id FROM users WHERE email = ?', [email]);
    
    if (existingUsers.length > 0) {
      return res.render('auth/register', { error: 'Email already registered' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    
    await db.query(
      'INSERT INTO users (name, email, password) VALUES (?, ?, ?)',
      [name, email, hashedPassword]
    );

    res.redirect('/auth/login');
  } catch (error) {
    console.error(error);
    res.status(500).send('Server error');
  }
});

// Logout
app.get('/auth/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/');
});


app.get('/profile', isAuthenticated, async (req, res) => {
  try {
    const userId = req.session.user.id;
    
    // Get user's products
    const [products] = await db.query(
      'SELECT * FROM products WHERE user_id = ? ORDER BY created_at DESC',
      [userId]
    );
    
    // Get available plans
    const [plans] = await db.query('SELECT * FROM plans');
    
    // Get unread message count
    const [unreadResult] = await db.query(
      'SELECT COUNT(*) as unreadCount FROM messages WHERE receiver_id = ? AND is_read = FALSE',
      [userId]
    );
    const unreadCount = unreadResult[0].unreadCount || 0;
    
    res.render('profile', {
      user: req.session.user,
      products,
      plans,
      message: req.session.message,
      unreadCount: unreadCount // Make sure this is passed to the template
    });
    
    delete req.session.message;
  } catch (error) {
    console.error('Profile error:', error);
    res.status(500).render('error', {
      user: req.session.user,
      status: 500,
      message: 'Error loading profile'
    });
  }
});
// Plan Selection
app.get('/plans/select', isAuthenticated, (req, res) => {
  if (req.session.user.plan_id) {
    return res.redirect('/profile');
  }
  
  db.query('SELECT * FROM plans')
    .then(([plans]) => {
      res.render('plans/select', { plans, user: req.session.user });
    })
    .catch(error => {
      console.error(error);
      res.status(500).send('Server error');
    });
});

// Razorpay Integration

// Create Razorpay order
app.post('/create-razorpay-order', isAuthenticated, async (req, res) => {
  const { plan_id } = req.body;

  try {
    const [plans] = await db.query('SELECT * FROM plans WHERE id = ?', [plan_id]);
    if (plans.length === 0) {
      return res.status(400).json({ error: 'Invalid plan selected' });
    }

    const plan = plans[0];
    const amount = plan.price * 100;

    const options = {
      amount: amount.toString(),
      currency: 'INR',
      receipt: `plan_${plan.id}_user_${req.session.user.id}_${Date.now()}`,
      payment_capture: 1,
      notes: {
        plan_id: plan.id,
        user_id: req.session.user.id
      }
    };

    razorpay.orders.create(options, (err, order) => {
      if (err) {
        console.error('Razorpay create order error:', err);
        return res.status(500).json({ error: err.error.description });
      }
      
      res.json({
        id: order.id,
        currency: order.currency,
        amount: order.amount,
        plan_id: plan.id
      });
    });
    
  } catch (error) {
    console.error('Server error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Verify payment and update plan
app.post('/verify-payment', isAuthenticated, async (req, res) => {
  try {
    const { razorpay_payment_id, razorpay_order_id, razorpay_signature, plan_id } = req.body;

    if (!razorpay_payment_id || !razorpay_order_id || !razorpay_signature || !plan_id) {
      return res.status(400).json({ 
        success: false, 
        message: 'Missing payment verification fields' 
      });
    }

    const hmac = crypto.createHmac('sha256', process.env.RAZORPAY_KEY_SECRET);
    hmac.update(razorpay_order_id + "|" + razorpay_payment_id);
    const generated_signature = hmac.digest('hex');

    if (generated_signature !== razorpay_signature) {
      return res.status(400).json({ 
        success: false, 
        message: 'Payment verification failed - invalid signature' 
      });
    }

    const [plans] = await db.query('SELECT * FROM plans WHERE id = ?', [plan_id]);
    if (plans.length === 0) {
      return res.status(400).json({ 
        success: false, 
        message: 'Invalid plan selected' 
      });
    }

    const plan = plans[0];
    
    await db.query(
      'UPDATE users SET plan_id = ?, product_limit = ? WHERE id = ?',
      [plan.id, plan.max_products, req.session.user.id]
    );

    await db.query(
      'INSERT INTO payments (user_id, plan_id, amount, razorpay_payment_id, razorpay_order_id) VALUES (?, ?, ?, ?, ?)',
      [req.session.user.id, plan.id, plan.price, razorpay_payment_id, razorpay_order_id]
    );

    req.session.user.plan_id = plan.id;
    req.session.user.product_limit = plan.max_products;

    return res.json({ 
      success: true,
      plan_name: plan.name,
      product_limit: plan.max_products,
      redirectUrl: '/profile'
    });

  } catch (error) {
    console.error('Payment verification error:', error);
    return res.status(500).json({ 
      success: false, 
      message: 'Internal server error during payment verification'
    });
  }
});

// Product Management

// Remove product ID validation from create routes
app.get('/products/create', isAuthenticated, async (req, res) => {
  try {
    if (!req.session.user.plan_id) {
      req.session.message = {
        type: 'warning',
        text: 'Please select a plan before posting products'
      };
      return res.redirect('/plans/select');
    }

    const [count] = await db.query(
      'SELECT COUNT(*) as count FROM products WHERE user_id = ?',
      [req.session.user.id]
    );
    
    if (count[0].count >= req.session.user.product_limit) {
      req.session.message = {
        type: 'danger',
        text: `You've reached your limit of ${req.session.user.product_limit} products. Please upgrade your plan.`
      };
      return res.redirect('/profile');
    }

    res.render('products/create', {
      user: req.session.user,
      categories: ['Electronics', 'Furniture', 'Cars', 'Bikes', 'Fashion', 'Books', 'Others'],
      message: req.session.message || null
    });

    delete req.session.message;
  } catch (error) {
    console.error('Product create page error:', error);
    res.status(500).render('error', {
      user: req.session.user,
      status: 500,
      message: 'Error loading product creation page'
    });
  }
});

// Add this with your other routes
app.get('/users/:id/phone', isAuthenticated, async (req, res) => {
  try {
    const [users] = await db.query(
      'SELECT phone FROM users WHERE id = ?',
      [req.params.id]
    );
    
    if (users.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    res.json({ phone: users[0].phone });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/products/create', isAuthenticated, upload.single('image'), async (req, res) => {
  try {
    if (!req.session.user.plan_id) {
      req.session.message = { type: 'danger', text: 'Please select a plan before posting products' };
      return res.redirect('/plans/select');
    }

    const [count] = await db.query(
      'SELECT COUNT(*) as count FROM products WHERE user_id = ?',
      [req.session.user.id]
    );
    
    if (count[0].count >= req.session.user.product_limit) {
      req.session.message = { 
        type: 'warning', 
        text: `You've reached your limit of ${req.session.user.product_limit} products. Please upgrade your plan.`
      };
      return res.redirect('/profile');
    }

    const { title, description, price, category } = req.body;
    if (!title || !description || !price || !category || !req.file) {
      req.session.message = { type: 'danger', text: 'All fields are required' };
      return res.redirect('/products/create');
    }

    const [result] = await db.query(
      'INSERT INTO products (user_id, title, description, price, image, category) VALUES (?, ?, ?, ?, ?, ?)',
      [req.session.user.id, title, description, parseFloat(price), req.file.filename, category]
    );
    
    req.session.message = { type: 'success', text: 'Product posted successfully!' };
    return res.redirect('/profile');
    
  } catch (error) {
    console.error('Product creation error:', error);
    req.session.message = { type: 'danger', text: 'Error creating product. Please try again.' };
    return res.redirect('/products/create');
  }
});

// Edit product page
app.get('/products/:id/edit', 
  isAuthenticated, 
  validateProductId, 
  validateProductOwner, 
  async (req, res) => {
    res.render('products/edit', { 
      user: req.session.user,
      product: req.product,
      categories: ['Electronics', 'Furniture', 'Cars', 'Bikes', 'Fashion', 'Books', 'Others']
    });
  }
);

// Update product handler
app.post('/products/:id/update', 
  isAuthenticated, 
  validateProductId, 
  validateProductOwner, 
  upload.single('image'), 
  async (req, res) => {
    const { title, description, price, category } = req.body;
    
    try {
      const updateData = {
        title,
        description,
        price: parseFloat(price),
        category
      };
      
      if (req.file) {
        const oldImage = path.join(__dirname, 'public', 'uploads', req.product.image);
        if (fs.existsSync(oldImage)) {
          fs.unlinkSync(oldImage);
        }
        updateData.image = req.file.filename;
      }
      
      await db.query(
        'UPDATE products SET ? WHERE id = ?',
        [updateData, req.productId]
      );
      
      req.session.message = {
        type: 'success',
        text: 'Product updated successfully'
      };
      res.redirect('/profile');
    } catch (error) {
      console.error(error);
      req.session.message = {
        type: 'danger',
        text: 'Error updating product'
      };
      res.redirect(`/products/${req.productId}/edit`);
    }
  }
);

// Delete product
app.post('/products/:id/delete', 
  isAuthenticated, 
  validateProductId, 
  validateProductOwner, 
  async (req, res) => {
    try {
      const imagePath = path.join(__dirname, 'public', 'uploads', req.product.image);
      if (fs.existsSync(imagePath)) {
        fs.unlinkSync(imagePath);
      }
      
      await db.query('DELETE FROM products WHERE id = ?', [req.productId]);
      
      req.session.message = {
        type: 'success',
        text: 'Product deleted successfully'
      };
      res.redirect('/profile');
    } catch (error) {
      console.error(error);
      req.session.message = {
        type: 'danger',
        text: 'Error deleting product'
      };
      res.redirect('/profile');
    }
  }
);

// Admin Routes

// Admin dashboard
app.get('/admin/dashboard', isAdmin, async (req, res) => {
  try {
    // Get basic counts with fallbacks
    const getCount = async (query, fallback = 0) => {
      try {
        const [result] = await db.query(query);
        return result[0]?.count || fallback;
      } catch (error) {
        console.error(`Query failed: ${query}`, error);
        return fallback;
      }
    };

    // Get all counts in parallel
    const [
      usersCount,
      activeProductsCount,
      pendingApprovalsCount,
      transactionsCount,
      reportedItemsCount
    ] = await Promise.all([
      getCount('SELECT COUNT(*) as count FROM users'),
      getCount('SELECT COUNT(*) as count FROM products WHERE is_active = TRUE'),
      getCount('SELECT COUNT(*) as count FROM products WHERE is_approved = FALSE'),
      getCount('SELECT COUNT(*) as count FROM transactions'),
      getCount('SELECT COUNT(*) as count FROM reported_items WHERE status = "pending"')
    ]);

    // Get chart data (last 30 days)
    const getChartData = async (table) => {
      try {
        const [data] = await db.query(`
          SELECT DATE(created_at) as date, COUNT(*) as count 
          FROM ${table}
          WHERE created_at >= DATE_SUB(NOW(), INTERVAL 30 DAY)
          GROUP BY DATE(created_at)
          ORDER BY date
        `);
        return data;
      } catch (error) {
        console.error(`Failed to get chart data for ${table}`, error);
        return [];
      }
    };

    const charts = {
      users: await getChartData('users'),
      products: await getChartData('products')
    };

    res.render('admin/dashboard', {
      admin: req.session.admin,
      counts: {
        users: usersCount,
        activeProducts: activeProductsCount,
        pendingApprovals: pendingApprovalsCount,
        transactions: transactionsCount,
        reportedItems: reportedItemsCount
      },
      charts
    });

  } catch (error) {
    console.error('Dashboard error:', error);
    res.status(500).render('admin/error', {
      status: 500,
      message: 'Failed to load dashboard data',
      error: process.env.NODE_ENV === 'development' ? error : null
    });
  }
});

// Admin - List users
// List Users
app.get('/admin/users', isAdmin, async (req, res) => {
  try {
    const [users] = await db.query(`
      SELECT u.*, COUNT(p.id) as product_count 
      FROM users u
      LEFT JOIN products p ON p.user_id = u.id
      GROUP BY u.id
      ORDER BY u.created_at DESC
    `);
    
    res.render('admin/users/list', { 
      admin: req.session.admin,
      users,
      activePage: 'users'  // This highlights the active menu item
    });
  } catch (error) {
    console.error('Users list error:', error);
    res.status(500).render('admin/error', {
      status: 500,
      message: 'Failed to load users',
      admin: req.session.admin
    });
  }
});
// Block/Unblock User
app.post('/admin/users/:id/toggle-status', isAdmin, async (req, res) => {
  try {
    await db.query(
      'UPDATE users SET is_active = NOT is_active WHERE id = ?',
      [req.params.id]
    );
    res.redirect('/admin/users');
  } catch (error) {
    console.error('Toggle user status error:', error);
    res.status(500).render('admin/error', { admin: req.session.admin });
  }
});

// View User's Products
app.get('/admin/users/:id/products', isAdmin, async (req, res) => {
  try {
    // Get user and products in a single query
    const [results] = await db.query(`
      SELECT 
        p.*, 
        u.name as user_name,
        u.email as user_email
      FROM products p
      JOIN users u ON p.user_id = u.id
      WHERE p.user_id = ?
      ORDER BY p.created_at DESC
    `, [req.params.id]);

    if (results.length === 0) {
      // If no products, still get user info
      const [users] = await db.query('SELECT * FROM users WHERE id = ?', [req.params.id]);
      if (users.length === 0) {
        return res.status(404).render('admin/error', {
          status: 404,
          message: 'User not found'
        });
      }
      return res.render('admin/users/products', {
        admin: req.session.admin,
        user: users[0],
        products: []
      });
    }

    res.render('admin/users/products', {
      admin: req.session.admin,
      user: {
        id: req.params.id,
        name: results[0].user_name,
        email: results[0].user_email
      },
      products: results
    });
  } catch (error) {
    console.error('User products error:', error);
    res.status(500).render('admin/error', {
      status: 500,
      message: 'Failed to load user products'
    });
  }
});

// Approve/Reject Product
// Approve product
app.post('/admin/products/:id/approve', isAdmin, async (req, res) => {
  try {
    await db.query(
      'UPDATE products SET is_approved = TRUE, is_active = TRUE WHERE id = ?',
      [req.params.id]
    );
    res.redirect('/admin/products/pending?success=Product+approved+successfully');
  } catch (error) {
    console.error('Approve product error:', error);
    res.redirect('/admin/products/pending?error=Failed+to+approve+product');
  }
});

// Reject product
app.post('/admin/products/:id/reject', isAdmin, async (req, res) => {
  try {
    await db.query(
      'UPDATE products SET is_approved = FALSE, is_active = FALSE WHERE id = ?',
      [req.params.id]
    );
    res.redirect('/admin/products/pending?success=Product+rejected+successfully');
  } catch (error) {
    console.error('Reject product error:', error);
    res.redirect('/admin/products/pending?error=Failed+to+reject+product');
  }
});

// Pending Products
// Admin product approval routes
app.get('/admin/products/pending', isAdmin, async (req, res) => {
  try {
    const [products] = await db.query(`
      SELECT p.*, u.name as user_name, u.email as user_email
      FROM products p
      JOIN users u ON p.user_id = u.id
      WHERE p.is_approved = FALSE
      ORDER BY p.created_at DESC
    `);
    
    res.render('admin/products/pending', {
      admin: req.session.admin,
      products: products || [],
      success: req.query.success,
      error: req.query.error
    });
  } catch (error) {
    console.error('Pending products error:', error);
    res.status(500).render('admin/error', {
      status: 500,
      message: 'Failed to load pending products'
    });
  }
});

// Flagged Products
app.get('/admin/products/flagged', isAdmin, async (req, res) => {
  try {
    const [products] = await db.query(`
      SELECT p.*, u.name as user_name, COUNT(r.id) as report_count
      FROM products p
      JOIN users u ON p.user_id = u.id
      JOIN reports r ON r.product_id = p.id
      WHERE p.is_active = TRUE
      GROUP BY p.id
      HAVING report_count > 0
      ORDER BY report_count DESC
    `);
    
    res.render('admin/products/flagged', { 
      admin: req.session.admin,
      products 
    });
  } catch (error) {
    console.error('Flagged products error:', error);
    res.status(500).render('admin/error', { admin: req.session.admin });
  }
});
app.get('/admin/reports', isAdmin, async (req, res) => {
  try {
    const [reports] = await db.query(`
      SELECT r.*, p.title as product_title, u.name as reporter_name
      FROM reports r
      JOIN products p ON r.product_id = p.id
      JOIN users u ON r.reporter_id = u.id
      WHERE r.status = 'pending'
      ORDER BY r.created_at DESC
    `);
    
    res.render('admin/reports/list', { 
      admin: req.session.admin,
      reports 
    });
  } catch (error) {
    console.error('Reports error:', error);
    res.status(500).render('admin/error', { admin: req.session.admin });
  }
});

app.post('/admin/reports/:id/resolve', isAdmin, async (req, res) => {
  try {
    const { action } = req.body;
    
    await db.query(
      'UPDATE reports SET status = ? WHERE id = ?',
      [action, req.params.id]
    );
    
    if (action === 'remove') {
      await db.query(
        'UPDATE products SET is_active = FALSE WHERE id = (SELECT product_id FROM reports WHERE id = ?)',
        [req.params.id]
      );
    }
    
    res.redirect('/admin/reports');
  } catch (error) {
    console.error('Resolve report error:', error);
    res.status(500).render('admin/error', { admin: req.session.admin });
  }
});
app.get('/admin/transactions', isAdmin, async (req, res) => {
  try {
    const [transactions] = await db.query(`
      SELECT t.*, 
        p.title as product_title,
        u1.name as buyer_name,
        u2.name as seller_name
      FROM transactions t
      JOIN products p ON t.product_id = p.id
      JOIN users u1 ON t.buyer_id = u1.id
      JOIN users u2 ON t.seller_id = u2.id
      ORDER BY t.created_at DESC
    `);
    
    // Calculate totals
    const [[total]] = await db.query(
      'SELECT SUM(amount) as total FROM transactions'
    );
    
    res.render('admin/transactions/list', { 
      admin: req.session.admin,
      transactions,
      total: total.total || 0
    });
  } catch (error) {
    console.error('Transactions error:', error);
    res.status(500).render('admin/error', { admin: req.session.admin });
  }
});
app.get('/admin/feedback', isAdmin, async (req, res) => {
  try {
    const [feedback] = await db.query(`
      SELECT f.*, 
        p.title as product_title,
        u1.name as reviewer_name,
        u2.name as seller_name
      FROM feedback f
      JOIN products p ON f.product_id = p.id
      JOIN users u1 ON f.reviewer_id = u1.id
      JOIN users u2 ON p.user_id = u2.id
      ORDER BY f.created_at DESC
    `);
    
    res.render('admin/feedback/list', { 
      admin: req.session.admin,
      feedback 
    });
  } catch (error) {
    console.error('Feedback error:', error);
    res.status(500).render('admin/error', { admin: req.session.admin });
  }
});

app.post('/admin/feedback/:id/block', isAdmin, async (req, res) => {
  try {
    await db.query(
      'UPDATE feedback SET is_blocked = TRUE WHERE id = ?',
      [req.params.id]
    );
    
    res.redirect('/admin/feedback');
  } catch (error) {
    console.error('Block feedback error:', error);
    res.status(500).render('admin/error', { admin: req.session.admin });
  }
});
// block user
// Block user
app.post('/admin/users/:id/block', isAdmin, async (req, res) => {
  try {
    const { reason } = req.body;
    
    await db.query(
      'UPDATE users SET is_blocked = TRUE, blocked_reason = ?, blocked_at = NOW() WHERE id = ?',
      [reason, req.params.id]
    );
    
    // Destroy the user's session if they're currently logged in
    await destroyUserSessions(req.params.id);
    
    req.session.message = {
      type: 'success',
      text: 'User blocked successfully'
    };
    res.redirect('/admin/users');
    
  } catch (error) {
    console.error('Block user error:', error);
    req.session.message = {
      type: 'danger',
      text: 'Failed to block user'
    };
    res.redirect('/admin/users');
  }
});

// Unblock user
app.post('/admin/users/:id/unblock', isAdmin, async (req, res) => {
  try {
    await db.query(
      'UPDATE users SET is_blocked = FALSE, blocked_reason = NULL, blocked_at = NULL WHERE id = ?',
      [req.params.id]
    );
    
    req.session.message = {
      type: 'success',
      text: 'User unblocked successfully'
    };
    res.redirect('/admin/users');
    
  } catch (error) {
    console.error('Unblock user error:', error);
    req.session.message = {
      type: 'danger',
      text: 'Failed to unblock user'
    };
    res.redirect('/admin/users');
  }
});

// Helper function to destroy all sessions for a user
async function destroyUserSessions(userId) {
  // Implement session destruction logic here
  // This depends on your session store (Redis, database, etc.)
}

app.get('/admin/categories', isAdmin, async (req, res) => {
  try {
    const [categories] = await db.query(`
      SELECT c.*, 
        COUNT(p.id) as product_count,
        (SELECT COUNT(*) FROM categories WHERE parent_id = c.id) as subcategory_count
      FROM categories c
      LEFT JOIN products p ON p.category_id = c.id
      WHERE c.parent_id IS NULL
      GROUP BY c.id
      ORDER BY c.name
    `);
    
    res.render('admin/categories/list', { 
      admin: req.session.admin,
      categories 
    });
  } catch (error) {
    console.error('Categories error:', error);
    res.status(500).render('admin/error', { admin: req.session.admin });
  }
});

app.post('/admin/categories', isAdmin, categoryUpload.single('image'), async (req, res) => {
  try {
    const { name, parent_id } = req.body;
    
    await db.query(
      'INSERT INTO categories (name, parent_id, image) VALUES (?, ?, ?)',
      [name, parent_id || null, req.file?.filename]
    );
    
    res.redirect('/admin/categories');
  } catch (error) {
    console.error('Create category error:', error);
    res.status(500).render('admin/error', { admin: req.session.admin });
  }
});
app.get('/admin/settings', isAdmin, async (req, res) => {
  try {
    const [admin] = await db.query(
      'SELECT * FROM admins WHERE id = ?',
      [req.session.admin.id]
    );
    
    res.render('admin/settings/index', { 
      admin: { ...req.session.admin, ...admin[0] } 
    });
  } catch (error) {
    console.error('Settings error:', error);
    res.status(500).render('admin/error', { admin: req.session.admin });
  }
});

app.post('/admin/settings/change-password', isAdmin, async (req, res) => {
  try {
    const { current_password, new_password } = req.body;
    
    const [admin] = await db.query(
      'SELECT password FROM admins WHERE id = ?',
      [req.session.admin.id]
    );
    
    const match = await bcrypt.compare(current_password, admin[0].password);
    if (!match) {
      return res.render('admin/settings/index', {
        admin: req.session.admin,
        error: 'Current password is incorrect'
      });
    }
    
    const hashedPassword = await bcrypt.hash(new_password, 10);
    await db.query(
      'UPDATE admins SET password = ? WHERE id = ?',
      [hashedPassword, req.session.admin.id]
    );
    
    res.render('admin/settings/index', {
      admin: req.session.admin,
      success: 'Password changed successfully'
    });
  } catch (error) {
    console.error('Change password error:', error);
    res.status(500).render('admin/error', { admin: req.session.admin });
  }
});
app.get('/admin/tickets', isAdmin, async (req, res) => {
  try {
    const [tickets] = await db.query(`
      SELECT t.*, u.name as user_name
      FROM tickets t
      JOIN users u ON t.user_id = u.id
      WHERE t.status != 'closed'
      ORDER BY t.created_at DESC
    `);
    
    res.render('admin/tickets/list', { 
      admin: req.session.admin,
      tickets 
    });
  } catch (error) {
    console.error('Tickets error:', error);
    res.status(500).render('admin/error', { admin: req.session.admin });
  }
});

app.post('/admin/tickets/:id/reply', isAdmin, async (req, res) => {
  try {
    const { reply } = req.body;
    
    await db.query(
      'UPDATE tickets SET reply = ?, status = "replied", replied_at = NOW() WHERE id = ?',
      [reply, req.params.id]
    );
    
    res.redirect('/admin/tickets');
  } catch (error) {
    console.error('Ticket reply error:', error);
    res.status(500).render('admin/error', { admin: req.session.admin });
  }
});
// Admin - List products
app.get('/admin/products', isAdmin, async (req, res) => {
  try {
    const [products] = await db.query(`
      SELECT p.*, u.name as user_name, u.email as user_email
      FROM products p
      JOIN users u ON p.user_id = u.id
      ORDER BY p.created_at DESC
    `);
    
    res.render('admin/products', {
      user: req.session.user,
      products
    });
  } catch (error) {
    console.error(error);
    res.status(500).send('Server error');
  }
});

// Admin - Toggle product status
app.post('/admin/products/:id/toggle', isAdmin, validateProductId, async (req, res) => {
  try {
    await db.query(
      'UPDATE products SET is_active = NOT is_active WHERE id = ?',
      [req.productId]
    );
    
    res.redirect('/admin/products');
  } catch (error) {
    console.error(error);
    res.status(500).send('Server error');
  }
});

// Admin - Delete product
app.post('/admin/products/:id/delete', isAdmin, validateProductId, async (req, res) => {
  try {
    const [products] = await db.query('SELECT * FROM products WHERE id = ?', [req.productId]);
    
    if (products.length > 0) {
      const imagePath = path.join(__dirname, 'public', 'uploads', products[0].image);
      if (fs.existsSync(imagePath)) {
        fs.unlinkSync(imagePath);
      }
    }
    
    await db.query('DELETE FROM products WHERE id = ?', [req.productId]);
    
    res.redirect('/admin/products');
  } catch (error) {
    console.error(error);
    res.status(500).send('Server error');
  }
});

// Admin Registration Routes
app.get('/admin/register', (req, res) => {
  if (req.session.admin) return res.redirect('/admin/dashboard');
  res.render('admin/register', { 
    error: null,
    formData: { name: '', email: '' } // Initialize empty formData
  });
});

app.post('/admin/register', async (req, res) => {
  const { name, email, password, confirm_password, secret_key } = req.body;
  
  if (password !== confirm_password) {
    return res.render('admin/register', { 
      error: 'Passwords do not match',
      formData: { name, email } // Pass back the submitted data
    });
  }

  if (secret_key !== process.env.ADMIN_REGISTER_KEY) {
    return res.render('admin/register', { 
      error: 'Invalid registration key',
      formData: { name, email } // Pass back the submitted data
    });
  }

  try {
    const [existingAdmins] = await db.query(
      'SELECT id FROM admins WHERE email = ?', 
      [email]
    );
    
    if (existingAdmins.length > 0) {
      return res.render('admin/register', { 
        error: 'Admin with this email already exists',
        formData: { name, email } // Pass back the submitted data
      });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    
    await db.query(
      'INSERT INTO admins (name, email, password, role) VALUES (?, ?, ?, ?)',
      [name, email, hashedPassword, 'moderator']
    );

    res.redirect('/admin/login?registered=true');
  } catch (error) {
    console.error('Admin registration error:', error);
    res.render('admin/register', { 
      error: 'Registration failed. Please try again.',
      formData: { name, email } // Pass back the submitted data
    });
  }
});

// One-time setup route (remove after first use)
app.get('/setup-first-admin', async (req, res) => {
  const [admins] = await db.query('SELECT id FROM admins');
  if (admins.length > 0) return res.send('Admin already exists');
  
  const hashedPassword = await bcrypt.hash('admin123', 10);
  console.log(hashedPassword);
  await db.query(
    'INSERT INTO admins (name, email, password, role) VALUES (?, ?, ?, ?)',
    ['Super Admin', 'superadmin@example.com', hashedPassword, 'super']
  );
  
  res.send('First admin created: superadmin@example.com / admin123');
});
// middleware to handle 404 errors

// Error handling middleware (should be near the end of app.js, before the server starts)
app.use((err, req, res, next) => {
  console.error(`ERROR (${err.statusCode || 500}): ${err.message}`);
  
  const statusCode = err.statusCode || 500;
  const message = err.message || 'Something went wrong!';
  
  res.status(statusCode).render('error', {
    title: `Error ${statusCode}`,
    status: statusCode,
    message: message,
    user: req.session.user || null,
    showSearch: statusCode === 404
  });
});

// products rating
// Add to your existing routes
app.post('/api/ratings', isAuthenticated, async (req, res) => {
  try {
    const { productId, rating, comment } = req.body;
    const userId = req.session.user.id;

    // Validate rating (1-5)
    if (![1, 2, 3, 4, 5].includes(parseInt(rating))) {
      return res.status(400).json({ error: 'Invalid rating value' });
    }

    // Check if user already rated this product
    const [existing] = await db.query(
      'SELECT * FROM ratings WHERE user_id = ? AND product_id = ?',
      [userId, productId]
    );

    if (existing.length > 0) {
      // Update existing rating
      await db.query(
        'UPDATE ratings SET rating = ?, comment = ?, updated_at = NOW() WHERE id = ?',
        [rating, comment, existing[0].id]
      );
    } else {
      // Create new rating
      await db.query(
        'INSERT INTO ratings (user_id, product_id, rating, comment) VALUES (?, ?, ?, ?)',
        [userId, productId, rating, comment]
      );
    }

    // Emit rating update to all connected clients
    const [updatedRatings] = await db.query(`
      SELECT r.*, u.name as user_name 
      FROM ratings r
      JOIN users u ON r.user_id = u.id
      WHERE r.product_id = ?
      ORDER BY r.created_at DESC
    `, [productId]);

    const [avgResult] = await db.query(`
      SELECT AVG(rating) as average, COUNT(*) as count 
      FROM ratings 
      WHERE product_id = ?
    `, [productId]);

    io.emit('ratingUpdate', {
      productId,
      ratings: updatedRatings,
      average: parseFloat(avgResult[0].average).toFixed(1),
      count: avgResult[0].count
    });

    res.json({ success: true });
  } catch (error) {
    console.error('Rating error:', error);
    res.status(500).json({ error: 'Failed to submit rating' });
  }
});

app.get('/api/ratings/:productId', async (req, res) => {
  try {
    const { productId } = req.params;

    const [ratings] = await db.query(`
      SELECT r.*, u.name as user_name 
      FROM ratings r
      JOIN users u ON r.user_id = u.id
      WHERE r.product_id = ?
      ORDER BY r.created_at DESC
    `, [productId]);

    const [avgResult] = await db.query(`
      SELECT AVG(rating) as average, COUNT(*) as count 
      FROM ratings 
      WHERE product_id = ?
    `, [productId]);



    res.json({
      ratings,
      average: parseFloat(avgResult[0].average).toFixed(1),
      count: avgResult[0].count
    });
  } catch (error) {
    console.error('Get ratings error:', error);
    res.status(500).json({ error: 'Failed to get ratings' });
  }
});

// Start server
server.listen(port, () => {
  console.log(`Server running on http://localhost:${port}`);
});