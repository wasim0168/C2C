class ProductController {
  static async getProductById(id) {
    if (!Number.isInteger(id) || id <= 0) {
      throw new Error('Invalid product ID format');
    }

    const [products] = await db.query(
      'SELECT * FROM products WHERE id = ? AND is_active = TRUE',
      [id]
    );

    if (products.length === 0) {
      throw new Error('Product not found');
    }

    return products[0];
  }

  static async validateProductOwnership(productId, userId) {
    const product = await this.getProductById(productId);
    if (product.user_id !== userId) {
      throw new Error('User does not own this product');
    }
    return product;
  }
}