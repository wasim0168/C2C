const db = require('../config/database');

class Admin {
  static async findByEmail(email) {
    const [admins] = await db.query('SELECT * FROM admins WHERE email = ?', [email]);
    return admins[0];
  }

  static async create({ name, email, password, role = 'moderator' }) {
    const hashedPassword = await bcrypt.hash(password, 10);
    const [result] = await db.query(
      'INSERT INTO admins (name, email, password, role) VALUES (?, ?, ?, ?)',
      [name, email, hashedPassword, role]
    );
    return result.insertId;
  }

  // Add other methods as needed
}

module.exports = Admin;