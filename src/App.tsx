import React, { useState, useEffect } from 'react';
import { Settings, Users, Activity } from 'lucide-react';

interface User {
  name: string;
  created: string;
}

function App() {
  const [activeTab, setActiveTab] = useState('users');
  const [users, setUsers] = useState<User[]>([]);
  const [serviceStatus, setServiceStatus] = useState('unknown');
  const [logs, setLogs] = useState('');
  const [newUsername, setNewUsername] = useState('');

  const API_URL = 'http://localhost:3000/api';

  useEffect(() => {
    fetchUsers();
    fetchStatus();
    fetchLogs();
  }, []);

  const fetchUsers = async () => {
    try {
      const response = await fetch(`${API_URL}/users`);
      const data = await response.json();
      setUsers(data);
    } catch (error) {
      console.error('Failed to fetch users:', error);
    }
  };

  const fetchStatus = async () => {
    try {
      const response = await fetch(`${API_URL}/status`);
      const data = await response.json();
      setServiceStatus(data.status);
    } catch (error) {
      console.error('Failed to fetch status:', error);
    }
  };

  const fetchLogs = async () => {
    try {
      const response = await fetch(`${API_URL}/logs`);
      const data = await response.json();
      setLogs(data.logs);
    } catch (error) {
      console.error('Failed to fetch logs:', error);
    }
  };

  const handleAddUser = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      await fetch(`${API_URL}/users`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: newUsername }),
      });
      setNewUsername('');
      fetchUsers();
    } catch (error) {
      console.error('Failed to add user:', error);
    }
  };

  const handleDeleteUser = async (username: string) => {
    if (!confirm('Are you sure you want to delete this user?')) return;
    try {
      await fetch(`${API_URL}/users/${username}`, { method: 'DELETE' });
      fetchUsers();
    } catch (error) {
      console.error('Failed to delete user:', error);
    }
  };

  const handleDownloadConfig = async (username: string) => {
    try {
      window.location.href = `${API_URL}/users/${username}/config`;
    } catch (error) {
      console.error('Failed to download config:', error);
    }
  };

  const handleServiceAction = async (action: string) => {
    try {
      await fetch(`${API_URL}/service/${action}`, { method: 'POST' });
      fetchStatus();
    } catch (error) {
      console.error(`Failed to ${action} service:`, error);
    }
  };

  return (
    <div className="min-h-screen bg-gray-100">
      <div className="container mx-auto px-4 py-8">
        <header className="mb-8 pb-4 border-b border-gray-200">
          <h1 className="text-3xl font-bold text-gray-900">OpenVPN Management Interface</h1>
          <div className="mt-4 flex flex-wrap gap-4">
            <p><strong>Status:</strong> <span className={`font-semibold ${serviceStatus === 'running' ? 'text-green-600' : 'text-red-600'}`}>
              {serviceStatus.charAt(0).toUpperCase() + serviceStatus.slice(1)}
            </span></p>
          </div>
        </header>

        <nav className="mb-8">
          <ul className="flex space-x-4 border-b border-gray-200">
            <li>
              <button
                onClick={() => setActiveTab('users')}
                className={`flex items-center px-4 py-2 border-b-2 ${activeTab === 'users' ? 'border-blue-500 text-blue-600' : 'border-transparent text-gray-500'}`}
              >
                <Users className="w-5 h-5 mr-2" />
                Users
              </button>
            </li>
            <li>
              <button
                onClick={() => setActiveTab('service')}
                className={`flex items-center px-4 py-2 border-b-2 ${activeTab === 'service' ? 'border-blue-500 text-blue-600' : 'border-transparent text-gray-500'}`}
              >
                <Settings className="w-5 h-5 mr-2" />
                Service
              </button>
            </li>
            <li>
              <button
                onClick={() => setActiveTab('logs')}
                className={`flex items-center px-4 py-2 border-b-2 ${activeTab === 'logs' ? 'border-blue-500 text-blue-600' : 'border-transparent text-gray-500'}`}
              >
                <Activity className="w-5 h-5 mr-2" />
                Logs
              </button>
            </li>
          </ul>
        </nav>

        <main>
          {activeTab === 'users' && (
            <div className="bg-white rounded-lg shadow p-6">
              <h2 className="text-xl font-semibold mb-4">VPN Users</h2>
              <form onSubmit={handleAddUser} className="mb-6 flex gap-4">
                <input
                  type="text"
                  value={newUsername}
                  onChange={(e) => setNewUsername(e.target.value)}
                  placeholder="Enter username"
                  className="flex-1 px-4 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                  required
                />
                <button
                  type="submit"
                  className="px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-blue-500"
                >
                  Add User
                </button>
              </form>
              <div className="overflow-x-auto">
                <table className="min-w-full divide-y divide-gray-200">
                  <thead>
                    <tr>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Username</th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Created</th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Actions</th>
                    </tr>
                  </thead>
                  <tbody className="bg-white divide-y divide-gray-200">
                    {users.map((user) => (
                      <tr key={user.name}>
                        <td className="px-6 py-4 whitespace-nowrap">{user.name}</td>
                        <td className="px-6 py-4 whitespace-nowrap">{user.created}</td>
                        <td className="px-6 py-4 whitespace-nowrap">
                          <div className="flex space-x-2">
                            <button
                              onClick={() => handleDownloadConfig(user.name)}
                              className="px-3 py-1 bg-blue-600 text-white rounded hover:bg-blue-700"
                            >
                              Download
                            </button>
                            <button
                              onClick={() => handleDeleteUser(user.name)}
                              className="px-3 py-1 bg-red-600 text-white rounded hover:bg-red-700"
                            >
                              Delete
                            </button>
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {activeTab === 'service' && (
            <div className="bg-white rounded-lg shadow p-6">
              <h2 className="text-xl font-semibold mb-4">Service Control</h2>
              <div className="flex space-x-4">
                <button
                  onClick={() => handleServiceAction('start')}
                  disabled={serviceStatus === 'running'}
                  className="px-4 py-2 bg-green-600 text-white rounded-md hover:bg-green-700 disabled:opacity-50"
                >
                  Start
                </button>
                <button
                  onClick={() => handleServiceAction('stop')}
                  disabled={serviceStatus === 'stopped'}
                  className="px-4 py-2 bg-red-600 text-white rounded-md hover:bg-red-700 disabled:opacity-50"
                >
                  Stop
                </button>
                <button
                  onClick={() => handleServiceAction('restart')}
                  className="px-4 py-2 bg-yellow-600 text-white rounded-md hover:bg-yellow-700"
                >
                  Restart
                </button>
              </div>
            </div>
          )}

          {activeTab === 'logs' && (
            <div className="bg-white rounded-lg shadow p-6">
              <h2 className="text-xl font-semibold mb-4">Server Logs</h2>
              <pre className="bg-gray-900 text-gray-100 p-4 rounded-md overflow-x-auto whitespace-pre-wrap">
                {logs || 'No logs available'}
              </pre>
            </div>
          )}
        </main>
      </div>
    </div>
  );
}

export default App;