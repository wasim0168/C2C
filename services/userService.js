// services/userService.js
class UserService {
  static async getUserWithProducts(userId) {
    const [results] = await db.query(`
      SELECT 
        p.*, 
        u.name as user_name,
        u.email as user_email
      FROM products p
      JOIN users u ON p.user_id = u.id
      WHERE p.user_id = ?
      ORDER BY p.created_at DESC
    `, [userId]);

    if (results.length === 0) {
      const [users] = await db.query('SELECT * FROM users WHERE id = ?', [userId]);
      return {
        user: users[0] || null,
        products: []
      };
    }

    return {
      user: {
        id: userId,
        name: results[0].user_name,
        email: results[0].user_email
      },
      products: results
    };
  }
}