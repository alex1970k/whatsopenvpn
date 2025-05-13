import express from 'express';
import cors from 'cors';
import { exec } from 'child_process';
import fs from 'fs-extra';
import { promisify } from 'util';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import dotenv from 'dotenv';

const execAsync = promisify(exec);
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());

// Helper functions
const runCommand = async (command) => {
  try {
    const { stdout, stderr } = await execAsync(command);
    return { success: true, output: stdout };
  } catch (error) {
    return { success: false, error: error.message };
  }
};

// Routes
app.get('/api/status', async (req, res) => {
  const status = await runCommand('systemctl is-active openvpn@server');
  res.json({ status: status.success ? 'running' : 'stopped' });
});

app.get('/api/users', async (req, res) => {
  try {
    const { output } = await runCommand('cd /etc/openvpn/easy-rsa && ./easyrsa list-issued');
    const users = output
      .split('\n')
      .filter(line => line && !line.includes('server'))
      .map(line => {
        const [name, , created] = line.trim().split(/\s+/);
        return { name, created };
      });
    res.json(users);
  } catch (error) {
    res.status(500).json({ error: 'Failed to get users' });
  }
});

app.post('/api/users', async (req, res) => {
  const { username } = req.body;
  if (!username) {
    return res.status(400).json({ error: 'Username is required' });
  }

  try {
    await runCommand(`cd /etc/openvpn/easy-rsa && ./easyrsa build-client-full "${username}" nopass`);
    await generateClientConfig(username);
    res.json({ success: true, message: 'User created successfully' });
  } catch (error) {
    res.status(500).json({ error: 'Failed to create user' });
  }
});

app.delete('/api/users/:username', async (req, res) => {
  const { username } = req.params;
  try {
    await runCommand(`cd /etc/openvpn/easy-rsa && ./easyrsa revoke "${username}" && ./easyrsa gen-crl`);
    await fs.remove(`/var/www/vpn-admin/clients/${username}.ovpn`);
    res.json({ success: true, message: 'User revoked successfully' });
  } catch (error) {
    res.status(500).json({ error: 'Failed to revoke user' });
  }
});

app.get('/api/users/:username/config', async (req, res) => {
  const { username } = req.params;
  const configPath = `/var/www/vpn-admin/clients/${username}.ovpn`;

  try {
    if (!await fs.pathExists(configPath)) {
      await generateClientConfig(username);
    }
    res.download(configPath);
  } catch (error) {
    res.status(500).json({ error: 'Failed to download config' });
  }
});

app.post('/api/service/:action', async (req, res) => {
  const { action } = req.params;
  const validActions = ['start', 'stop', 'restart'];
  
  if (!validActions.includes(action)) {
    return res.status(400).json({ error: 'Invalid action' });
  }

  try {
    await runCommand(`systemctl ${action} openvpn@server`);
    res.json({ success: true, message: `Service ${action}ed successfully` });
  } catch (error) {
    res.status(500).json({ error: `Failed to ${action} service` });
  }
});

app.get('/api/logs', async (req, res) => {
  try {
    const logs = await fs.readFile('/etc/openvpn/openvpn-status.log', 'utf8');
    const lastLines = logs.split('\n').slice(-100).join('\n');
    res.json({ logs: lastLines });
  } catch (error) {
    res.status(500).json({ error: 'Failed to get logs' });
  }
});

// Start server
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

// Helper function to generate client config
async function generateClientConfig(username) {
  const serverIp = await fs.readFile('/var/www/vpn-admin/server_ip.txt', 'utf8');
  const serverProtocol = await fs.readFile('/var/www/vpn-admin/server_protocol.txt', 'utf8');
  const serverPort = await fs.readFile('/var/www/vpn-admin/server_port.txt', 'utf8');

  const ca = await fs.readFile('/etc/openvpn/ca.crt', 'utf8');
  const ta = await fs.readFile('/etc/openvpn/ta.key', 'utf8');
  const cert = await fs.readFile(`/etc/openvpn/easy-rsa/pki/issued/${username}.crt`, 'utf8');
  const key = await fs.readFile(`/etc/openvpn/easy-rsa/pki/private/${username}.key`, 'utf8');

  const certMatch = cert.match(/-----BEGIN CERTIFICATE-----(.+?)-----END CERTIFICATE-----/s);
  const clientCert = certMatch ? certMatch[0] : '';

  const config = `
client
dev tun
proto ${serverProtocol}
remote ${serverIp} ${serverPort}
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
cipher AES-256-GCM
auth SHA256
verb 3
key-direction 1

<ca>
${ca}
</ca>

<cert>
${clientCert}
</cert>

<key>
${key}
</key>

<tls-auth>
${ta}
</tls-auth>
`;

  await fs.outputFile(`/var/www/vpn-admin/clients/${username}.ovpn`, config);
}