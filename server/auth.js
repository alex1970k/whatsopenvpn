import pg from 'pg';
import crypto from 'crypto';
import dotenv from 'dotenv';

dotenv.config();

const pool = new pg.Pool({
  host: 'localhost',
  database: process.env.DB_NAME,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
});

export async function verifyCredentials(username, password) {
  try {
    const passwordHash = crypto.createHash('md5').update(password).digest('hex');
    
    const result = await pool.query(
      'SELECT * FROM admin_users WHERE username = $1 AND password_hash = $2',
      [username, passwordHash]
    );
    
    if (result.rows.length > 0) {
      // Update last login time
      await pool.query(
        'UPDATE admin_users SET last_login = CURRENT_TIMESTAMP WHERE username = $1',
        [username]
      );
      return true;
    }
    
    return false;
  } catch (error) {
    console.error('Error verifying credentials:', error);
    return false;
  }
}

export async function resetCredentials() {
  try {
    const newPassword = crypto.randomBytes(8).toString('hex');
    const passwordHash = crypto.createHash('md5').update(newPassword).digest('hex');
    
    await pool.query(
      'UPDATE admin_users SET password_hash = $1 WHERE username = $2',
      [passwordHash, 'admin']
    );
    
    return {
      username: 'admin',
      password: newPassword
    };
  } catch (error) {
    console.error('Error resetting credentials:', error);
    throw error;
  }
}