const express = require('express');
const router = express.Router();
const Product = require('../models/Product');
const upload = require('../middleware/upload'); // Your multer upload middleware
const AppError = require('../utils/AppError');
const validateProductId = require('../middleware/validateProductId');
router.param('id', validateProductId);
// Create product
router.post('/', upload.single('image'), async (req, res) => {
  try {
    if (!req.session.user?.id) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    const { title, description, price, category } = req.body;
    const image = req.file?.filename;

    const product = await Product.create(req.session.user.id, {
      title,
      description,
      price: parseFloat(price),
      image,
      category
    });

    res.redirect('/profile');
  } catch (error) {
    console.error('Product creation error:', error);
    res.status(500).json({ error: error.message });
  }
});

// Get product by ID
// Example route in routes/products.js
router.get('/:id', async (req, res, next) => {
  try {
    const product = await Product.findById(req.params.id);
    res.render('products/show', {
      product,
      user: req.session.user || null
    });
  } catch (error) {
    next(error);
  }
});

// Update product
router.put('/:id', upload.single('image'), async (req, res) => {
  try {
    if (!req.session.user?.id) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    const updates = {
      title: req.body.title,
      description: req.body.description,
      price: parseFloat(req.body.price),
      category: req.body.category,
      image: req.file?.filename
    };

    const product = await Product.update(
      req.params.id,
      req.session.user.id,
      updates
    );

    res.json(product);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Delete product
router.delete('/:id', async (req, res) => {
  try {
    if (!req.session.user?.id) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    await Product.delete(req.params.id, req.session.user.id);
    res.json({ success: true });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

module.exports = router;