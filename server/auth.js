import fs from 'fs-extra';
import crypto from 'crypto';

const HTPASSWD_PATH = '/var/www/vpn-admin/.htpasswd';

export async function verifyCredentials(username, password) {
  try {
    const htpasswdContent = await fs.readFile(HTPASSWD_PATH, 'utf8');
    const [storedUsername, storedHash] = htpasswdContent.split(':');
    
    const inputHash = crypto.createHash('md5').update(password).digest('hex');
    
    return username === storedUsername && inputHash === storedHash;
  } catch (error) {
    console.error('Error verifying credentials:', error);
    return false;
  }
}

export async function resetCredentials() {
  try {
    const newPassword = crypto.randomBytes(8).toString('hex');
    const newHash = crypto.createHash('md5').update(newPassword).digest('hex');
    
    await fs.writeFile(HTPASSWD_PATH, `admin:${newHash}`);
    
    return {
      username: 'admin',
      password: newPassword
    };
  } catch (error) {
    console.error('Error resetting credentials:', error);
    throw error;
  }
}