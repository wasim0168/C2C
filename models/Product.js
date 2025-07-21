const db = require('../database'); // Assuming you have a database connection setup
const AppError = require('../utils/AppError');
class Product {
  // Create a new product
  static async create(userId, { title, description, price, image, category }) {
    const [result] = await db.query(
      `INSERT INTO products 
       (user_id, title, description, price, image, category) 
       VALUES (?, ?, ?, ?, ?, ?)`,
      [userId, title, description, price, image, category]
    );
    return this.findById(result.insertId);
  }
static validateId(id) {
    if (!id) return false;
    const num = Number(id);
    return Number.isInteger(num) && num > 0;
  }

  static async findById(id) {
    if (!this.validateId(id)) {
      throw new AppError('Invalid product ID format', 400);
    }

    const [products] = await db.query(
      `SELECT p.*, u.name as user_name 
       FROM products p
       JOIN users u ON p.user_id = u.id
       WHERE p.id = ? AND p.is_active = TRUE`,
      [id]
    );

    if (products.length === 0) {
      throw new AppError('Product not found', 404);
    }

    return products[0];
  }
static async findById(id) {
    // Validate ID format
    if (!id || !Number.isInteger(Number(id)) || Number(id) <= 0) {
      throw new AppError('Invalid product ID format', 400);
    }

    const [products] = await db.query(
      `SELECT p.*, u.name as user_name, u.email as user_email 
       FROM products p
       JOIN users u ON p.user_id = u.id
       WHERE p.id = ? AND p.is_active = TRUE`,
      [id]
    );

    if (products.length === 0) {
      throw new AppError('Product not found', 404);
    }

    return products[0];
  }

  static async getSimilarProducts(category, excludeId, limit = 4) {
    const [products] = await db.query(
      `SELECT p.*, u.name as user_name 
       FROM products p
       JOIN users u ON p.user_id = u.id
       WHERE p.category = ? AND p.id != ? AND p.is_active = TRUE
       ORDER BY p.created_at DESC
       LIMIT ?`,
      [category, excludeId, limit]
    );
    return products;
  }
  // Add other methods with similar error handling
  static async getSimilarProducts(category, excludeId, limit = 4) {
    try {
      const [products] = await db.query(
        `SELECT p.*, u.name as user_name 
         FROM products p
         JOIN users u ON p.user_id = u.id
         WHERE p.category = ? AND p.id != ? AND p.is_active = TRUE
         ORDER BY p.created_at DESC
         LIMIT ?`,
        [category, excludeId, limit]
      );
      return products;
    } catch (error) {
      console.error('Error fetching similar products:', error);
      return []; // Return empty array instead of failing
    }
  }

  // Find all products by user
  static async findByUser(userId) {
    const [products] = await db.query(
      `SELECT * FROM products 
       WHERE user_id = ? AND is_active = TRUE
       ORDER BY created_at DESC`,
      [userId]
    );
    return products;
  }

  // Update product
  static async update(id, userId, updates) {
    // First verify product belongs to user
    const product = await this.findById(id);
    if (!product || product.user_id !== userId) {
      throw new Error('Product not found or unauthorized');
    }

    const { title, description, price, category, image } = updates;
    await db.query(
      `UPDATE products SET
       title = ?, description = ?, price = ?, 
       category = ?, image = COALESCE(?, image)
       WHERE id = ?`,
      [title, description, price, category, image, id]
    );

    return this.findById(id);
  }

  // Delete product (soft delete)
  static async delete(id, userId) {
    // Verify ownership
    const product = await this.findById(id);
    if (!product || product.user_id !== userId) {
      throw new Error('Product not found or unauthorized');
    }

    await db.query(
      `UPDATE products SET is_active = FALSE 
       WHERE id = ?`,
      [id]
    );

    return true;
  }

  // Search products
  static async search({ query = '', category = '', limit = 20, offset = 0 }) {
    let sql = `SELECT p.*, u.name as user_name 
               FROM products p
               JOIN users u ON p.user_id = u.id
               WHERE p.is_active = TRUE`;
    const params = [];

    if (query) {
      sql += ` AND (p.title LIKE ? OR p.description LIKE ?)`;
      params.push(`%${query}%`, `%${query}%`);
    }

    if (category) {
      sql += ` AND p.category = ?`;
      params.push(category);
    }

    sql += ` ORDER BY p.created_at DESC LIMIT ? OFFSET ?`;
    params.push(limit, offset);

    const [products] = await db.query(sql, params);
    return products;
  }

  // Count products for pagination
  static async count({ query = '', category = '' }) {
    let sql = `SELECT COUNT(*) as total 
               FROM products WHERE is_active = TRUE`;
    const params = [];

    if (query) {
      sql += ` AND (title LIKE ? OR description LIKE ?)`;
      params.push(`%${query}%`, `%${query}%`);
    }

    if (category) {
      sql += ` AND category = ?`;
      params.push(category);
    }

    const [[{ total }]] = await db.query(sql, params);
    return total;
  }
}

module.exports = Product;