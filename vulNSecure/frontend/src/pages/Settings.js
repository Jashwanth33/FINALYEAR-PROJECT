import React, { useState, useEffect } from 'react';
import toast from 'react-hot-toast';
import {
  Settings as SettingsIcon, Moon, Sun, Shield, Key, Download,
  Clock, Users, Activity, Lock, RefreshCw, FileText, Globe
} from 'lucide-react';

const Settings = () => {
  const [activeTab, setActiveTab] = useState('general');
  const [darkMode, setDarkMode] = useState(false);
  const [auditLogs, setAuditLogs] = useState([]);
  const [rateLimits, setRateLimits] = useState({
    api: { windowMs: 60000, max: 100 },
    scans: { windowMs: 3600000, max: 10 },
    login: { windowMs: 900000, max: 5 }
  });

  const getToken = () => localStorage.getItem('token');

  // Toggle dark mode
  const toggleDarkMode = () => {
    const newMode = !darkMode;
    setDarkMode(newMode);
    
    if (newMode) {
      document.documentElement.classList.add('dark');
      localStorage.setItem('theme', 'dark');
      toast.success('Dark mode enabled');
    } else {
      document.documentElement.classList.remove('dark');
      localStorage.setItem('theme', 'light');
      toast.success('Light mode enabled');
    }
  };

  // Load theme on mount
  useEffect(() => {
    const savedTheme = localStorage.getItem('theme');
    if (savedTheme === 'dark') {
      setDarkMode(true);
      document.documentElement.classList.add('dark');
    } else {
      setDarkMode(false);
      document.documentElement.classList.remove('dark');
    }
  }, []);

  // Fetch audit logs
  const fetchAuditLogs = async () => {
    try {
      const resp = await fetch('http://localhost:5001/api/final/audit?limit=20', {
        headers: { Authorization: 'Bearer ' + getToken() }
      });
      const data = await resp.json();
      if (data.success) {
        setAuditLogs(data.data.logs || []);
      }
    } catch (e) {}
  };

  // Setup 2FA
  const setup2FA = async () => {
    try {
      const resp = await fetch('http://localhost:5001/api/final/2fa/setup', {
        method: 'POST',
        headers: { Authorization: 'Bearer ' + getToken() }
      });
      const data = await resp.json();
      if (data.success) {
        toast.success('2FA setup initiated');
      }
    } catch (e) {
      toast.error('2FA setup failed');
    }
  };

  // Update rate limit
  const updateRateLimit = async (type, config) => {
    try {
      const resp = await fetch('http://localhost:5001/api/final/rate-limit', {
        method: 'PUT',
        headers: {
          'Authorization': 'Bearer ' + getToken(),
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ type, config })
      });
      const data = await resp.json();
      if (data.success) {
        toast.success('Rate limit updated');
        setRateLimits(data.data);
      }
    } catch (e) {
      toast.error('Failed to update');
    }
  };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold text-gray-900">Settings</h1>
        <p className="text-gray-600">Configure application settings and preferences</p>
      </div>

      {/* Tabs */}
      <div className="bg-white rounded-lg shadow-sm border border-gray-200">
        <div className="border-b border-gray-200">
          <nav className="flex space-x-4 px-6">
            {[
              { id: 'general', name: 'General', icon: SettingsIcon },
              { id: 'security', name: 'Security', icon: Shield },
              { id: 'audit', name: 'Audit Log', icon: Activity },
              { id: 'rate', name: 'Rate Limits', icon: Clock },
              { id: 'export', name: 'Export', icon: Download }
            ].map(tab => {
              const Icon = tab.icon;
              return (
                <button
                  key={tab.id}
                  onClick={() => {
                    setActiveTab(tab.id);
                    if (tab.id === 'audit') fetchAuditLogs();
                  }}
                  className={`flex items-center px-3 py-4 text-sm font-medium border-b-2 ${
                    activeTab === tab.id
                      ? 'border-blue-500 text-blue-600'
                      : 'border-transparent text-gray-500 hover:text-gray-700'
                  }`}
                >
                  <Icon className="h-4 w-4 mr-2" />
                  {tab.name}
                </button>
              );
            })}
          </nav>
        </div>

        <div className="p-6">
          {/* General Tab */}
          {activeTab === 'general' && (
            <div className="space-y-6">
              <h2 className="text-lg font-semibold">General Settings</h2>
              
              {/* Dark Mode */}
              <div className="flex items-center justify-between p-4 bg-gray-50 rounded-lg">
                <div className="flex items-center space-x-3">
                  {darkMode ? <Moon className="h-5 w-5 text-blue-600" /> : <Sun className="h-5 w-5 text-yellow-500" />}
                  <div>
                    <p className="font-medium">Dark Mode</p>
                    <p className="text-sm text-gray-500">Toggle dark/light theme</p>
                  </div>
                </div>
                <button
                  onClick={toggleDarkMode}
                  className={`w-12 h-6 rounded-full ${darkMode ? 'bg-blue-600' : 'bg-gray-300'} relative`}
                >
                  <span className={`absolute top-1 w-4 h-4 bg-white rounded-full transition-all ${darkMode ? 'left-7' : 'left-1'}`} />
                </button>
              </div>
              
              {/* Notifications */}
              <div className="p-4 bg-gray-50 rounded-lg">
                <p className="font-medium mb-3">Notification Preferences</p>
                <div className="space-y-2">
                  <label className="flex items-center space-x-2">
                    <input type="checkbox" defaultChecked className="rounded" />
                    <span>Email notifications for critical vulnerabilities</span>
                  </label>
                  <label className="flex items-center space-x-2">
                    <input type="checkbox" defaultChecked className="rounded" />
                    <span>Scan completion alerts</span>
                  </label>
                  <label className="flex items-center space-x-2">
                    <input type="checkbox" className="rounded" />
                    <span>Weekly summary reports</span>
                  </label>
                </div>
              </div>
            </div>
          )}

          {/* Security Tab */}
          {activeTab === 'security' && (
            <div className="space-y-6">
              <h2 className="text-lg font-semibold">Security Settings</h2>
              
              {/* 2FA */}
              <div className="flex items-center justify-between p-4 bg-gray-50 rounded-lg">
                <div className="flex items-center space-x-3">
                  <Key className="h-5 w-5 text-blue-600" />
                  <div>
                    <p className="font-medium">Two-Factor Authentication</p>
                    <p className="text-sm text-gray-500">Add an extra layer of security</p>
                  </div>
                </div>
                <button
                  onClick={setup2FA}
                  className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700"
                >
                  Setup 2FA
                </button>
              </div>
              
              {/* Change Password */}
              <div className="p-4 bg-gray-50 rounded-lg">
                <div className="flex items-center space-x-3 mb-4">
                  <Lock className="h-5 w-5 text-blue-600" />
                  <div>
                    <p className="font-medium">Change Password</p>
                    <p className="text-sm text-gray-500">Update your account password</p>
                  </div>
                </div>
                <div className="space-y-3">
                  <input type="password" placeholder="Current password" className="w-full px-3 py-2 border rounded-lg" />
                  <input type="password" placeholder="New password" className="w-full px-3 py-2 border rounded-lg" />
                  <input type="password" placeholder="Confirm new password" className="w-full px-3 py-2 border rounded-lg" />
                  <button className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700">
                    Update Password
                  </button>
                </div>
              </div>
              
              {/* Password Reset */}
              <div className="p-4 bg-gray-50 rounded-lg">
                <div className="flex items-center space-x-3 mb-4">
                  <RefreshCw className="h-5 w-5 text-blue-600" />
                  <div>
                    <p className="font-medium">Password Reset</p>
                    <p className="text-sm text-gray-500">Generate a password reset token</p>
                  </div>
                </div>
                <button className="px-4 py-2 bg-yellow-600 text-white rounded-lg hover:bg-yellow-700">
                  Generate Reset Token
                </button>
              </div>
            </div>
          )}

          {/* Audit Log Tab */}
          {activeTab === 'audit' && (
            <div className="space-y-4">
              <h2 className="text-lg font-semibold">Audit Log</h2>
              <p className="text-gray-600">Track all user activities and system events</p>
              
              {auditLogs.length === 0 ? (
                <div className="text-center py-8 text-gray-500">
                  <Activity className="h-12 w-12 mx-auto mb-3 text-gray-300" />
                  <p>No audit logs yet</p>
                </div>
              ) : (
                <div className="space-y-2">
                  {auditLogs.map((log, i) => (
                    <div key={i} className="flex items-center justify-between p-3 bg-gray-50 rounded">
                      <div>
                        <p className="font-medium text-sm">{log.action}</p>
                        <p className="text-xs text-gray-500">{log.details}</p>
                      </div>
                      <span className="text-xs text-gray-400">
                        {new Date(log.timestamp).toLocaleString()}
                      </span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {/* Rate Limits Tab */}
          {activeTab === 'rate' && (
            <div className="space-y-4">
              <h2 className="text-lg font-semibold">Rate Limiting</h2>
              <p className="text-gray-600">Configure API rate limits to prevent abuse</p>
              
              <div className="space-y-4">
                {Object.entries(rateLimits).map(([type, config]) => (
                  <div key={type} className="p-4 bg-gray-50 rounded-lg">
                    <div className="flex items-center justify-between mb-3">
                      <p className="font-medium capitalize">{type} Rate Limit</p>
                    </div>
                    <div className="grid grid-cols-2 gap-4">
                      <div>
                        <label className="text-sm text-gray-600">Window (ms)</label>
                        <input
                          type="number"
                          value={config.windowMs}
                          onChange={(e) => updateRateLimit(type, { windowMs: parseInt(e.target.value) })}
                          className="w-full px-3 py-2 border rounded"
                        />
                      </div>
                      <div>
                        <label className="text-sm text-gray-600">Max Requests</label>
                        <input
                          type="number"
                          value={config.max}
                          onChange={(e) => updateRateLimit(type, { max: parseInt(e.target.value) })}
                          className="w-full px-3 py-2 border rounded"
                        />
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Export Tab */}
          {activeTab === 'export' && (
            <div className="space-y-4">
              <h2 className="text-lg font-semibold">Export Options</h2>
              <p className="text-gray-600">Export data in various formats</p>
              
              <div className="grid grid-cols-2 gap-4">
                <div className="p-4 bg-gray-50 rounded-lg">
                  <FileText className="h-8 w-8 text-blue-600 mb-3" />
                  <p className="font-medium">Export CSV</p>
                  <p className="text-sm text-gray-500 mb-3">Export vulnerabilities to CSV format</p>
                  <button className="px-4 py-2 bg-blue-600 text-white rounded hover:bg-blue-700">
                    Export CSV
                  </button>
                </div>
                
                <div className="p-4 bg-gray-50 rounded-lg">
                  <FileText className="h-8 w-8 text-green-600 mb-3" />
                  <p className="font-medium">Export JSON</p>
                  <p className="text-sm text-gray-500 mb-3">Export scan data to JSON format</p>
                  <button className="px-4 py-2 bg-green-600 text-white rounded hover:bg-green-700">
                    Export JSON
                  </button>
                </div>
                
                <div className="p-4 bg-gray-50 rounded-lg">
                  <FileText className="h-8 w-8 text-orange-600 mb-3" />
                  <p className="font-medium">Export Excel</p>
                  <p className="text-sm text-gray-500 mb-3">Export to Excel-compatible format</p>
                  <button className="px-4 py-2 bg-orange-600 text-white rounded hover:bg-orange-700">
                    Export Excel
                  </button>
                </div>
                
                <div className="p-4 bg-gray-50 rounded-lg">
                  <FileText className="h-8 w-8 text-red-600 mb-3" />
                  <p className="font-medium">Export PDF</p>
                  <p className="text-sm text-gray-500 mb-3">Generate professional PDF report</p>
                  <button className="px-4 py-2 bg-red-600 text-white rounded hover:bg-red-700">
                    Export PDF
                  </button>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default Settings;
