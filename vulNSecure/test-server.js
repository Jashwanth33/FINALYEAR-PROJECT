const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 5001;

// In-memory user storage for testing
const registeredUsers = [
  {
    id: '1',
    username: 'admin',
    email: 'admin@vulnsecure.com',
    password: 'admin123',
    firstName: 'Admin',
    lastName: 'User',
    role: 'admin',
    isActive: true
  },
  {
    id: '2',
    username: 'rkvamsi84',
    email: 'rkvamsi84@gmail.com',
    password: 'Ramakoti@9848',
    firstName: 'Ramakoti',
    lastName: 'RK',
    role: 'analyst',
    isActive: true
  }
];

// Basic middleware
app.use(helmet());
app.use(cors({
  origin: ['http://localhost:3000', 'http://127.0.0.1:3000'],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));
app.use(morgan('combined'));
app.use(express.json());

// Health check endpoint
app.get('/health', (req, res) => {
  res.status(200).json({ 
    status: 'OK', 
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    environment: process.env.NODE_ENV || 'development'
  });
});

// Test API endpoints
app.get('/api/test', (req, res) => {
  res.json({
    success: true,
    message: 'vulNSecure API is working!',
    timestamp: new Date().toISOString(),
    version: '1.0.0'
  });
});

// Mock authentication endpoints
app.post('/api/auth/login', (req, res) => {
  const { email, password } = req.body;
  
  console.log('Login attempt:', { email, password });
  
  // Find user in registered users
  const user = registeredUsers.find(u => u.email === email && u.password === password);
  
  if (user) {
    console.log('Login successful for:', email);
    res.json({
      success: true,
      message: 'Login successful',
      data: {
        user: {
          id: user.id,
          username: user.username,
          email: user.email,
          firstName: user.firstName,
          lastName: user.lastName,
          role: user.role,
          isActive: user.isActive
        },
        token: 'mock-jwt-token-' + Date.now()
      }
    });
  } else {
    console.log('Login failed - invalid credentials for:', email);
    res.status(401).json({
      success: false,
      message: 'Invalid credentials'
    });
  }
});

app.post('/api/auth/register', (req, res) => {
  const { username, email, password, firstName, lastName } = req.body;
  
  console.log('Registration attempt:', { username, email, firstName, lastName });
  
  // Simple validation
  if (!username || !email || !password || !firstName || !lastName) {
    return res.status(400).json({
      success: false,
      message: 'All fields are required'
    });
  }
  
  // Check if user already exists
  const existingUser = registeredUsers.find(u => u.email === email || u.username === username);
  if (existingUser) {
    return res.status(409).json({
      success: false,
      message: 'User with this email or username already exists'
    });
  }
  
  // Create new user
  const newUser = {
    id: (registeredUsers.length + 1).toString(),
    username,
    email,
    password, // In production, this should be hashed
    firstName,
    lastName,
    role: 'viewer',
    isActive: true
  };
  
  // Add to registered users
  registeredUsers.push(newUser);
  
  console.log('User registered successfully:', email);
  console.log('Total registered users:', registeredUsers.length);
  
  // Return success response
  res.status(201).json({
    success: true,
    message: 'User registered successfully',
    data: {
      user: {
        id: newUser.id,
        username: newUser.username,
        email: newUser.email,
        firstName: newUser.firstName,
        lastName: newUser.lastName,
        role: newUser.role,
        isActive: newUser.isActive
      },
      token: 'mock-jwt-token-' + Date.now()
    }
  });
});

app.get('/api/auth/me', (req, res) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

  if (!token) {
    return res.status(401).json({
      success: false,
      message: 'Access token required'
    });
  }

  // For our mock server, any token is valid
  // In production, you would validate the JWT token here
  res.json({
    success: true,
    data: {
      user: {
        id: '1',
        username: 'admin',
        email: 'admin@vulnsecure.com',
        firstName: 'Admin',
        lastName: 'User',
        role: 'admin',
        isActive: true
      }
    }
  });
});

// Mock dashboard stats
app.get('/api/dashboard/stats', (req, res) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

  if (!token) {
    return res.status(401).json({
      success: false,
      message: 'Access token required'
    });
  }

  // For our mock server, any token is valid
  // In production, you would validate the JWT token here
  res.json({
    success: true,
    data: {
      scans: {
        total: 15,
        completed: 12,
        running: 2,
        failed: 1
      },
      vulnerabilities: {
        critical: 3,
        high: 8,
        medium: 15,
        low: 25,
        info: 10
      },
      leaks: {
        critical: 2,
        high: 5,
        medium: 12,
        low: 8
      },
      recentScans: [
        {
          id: '1',
          name: 'Network Scan - Office Network',
          target: '192.168.1.0/24',
          status: 'completed',
          createdAt: new Date().toISOString(),
          user: { username: 'admin', firstName: 'Admin', lastName: 'User' }
        },
        {
          id: '2',
          name: 'Web App Scan - Company Website',
          target: 'https://company.com',
          status: 'running',
          createdAt: new Date(Date.now() - 3600000).toISOString(),
          user: { username: 'analyst', firstName: 'Security', lastName: 'Analyst' }
        }
      ],
      criticalVulnerabilities: [
        {
          id: '1',
          title: 'SQL Injection in Login Form',
          description: 'Critical SQL injection vulnerability found in the login form',
          severity: 'critical',
          createdAt: new Date().toISOString()
        },
        {
          id: '2',
          title: 'Remote Code Execution',
          description: 'RCE vulnerability in file upload functionality',
          severity: 'critical',
          createdAt: new Date(Date.now() - 1800000).toISOString()
        }
      ],
      unreadNotifications: 5
    }
  });
});

// Mock scans endpoint with enhanced functionality
let mockScans = [
  {
    id: '1',
    name: 'Network Scan - Office Network',
    type: 'network',
    target: '192.168.1.0/24',
    status: 'completed',
    progress: 100,
    createdAt: new Date().toISOString(),
    user: { username: 'admin', firstName: 'Admin', lastName: 'User' },
    results: { critical: 2, high: 5, medium: 8, low: 12 },
    description: 'Comprehensive network security scan of office infrastructure'
  },
  {
    id: '2',
    name: 'Web App Scan - Company Website',
    type: 'web',
    target: 'https://company.com',
    status: 'running',
    progress: 65,
    createdAt: new Date(Date.now() - 3600000).toISOString(),
    user: { username: 'analyst', firstName: 'Security', lastName: 'Analyst' },
    description: 'Security assessment of main company website'
  },
  {
    id: '3',
    name: 'Dark Web Monitoring',
    type: 'darkweb',
    target: 'company.com',
    status: 'completed',
    progress: 100,
    createdAt: new Date(Date.now() - 7200000).toISOString(),
    user: { username: 'admin', firstName: 'Admin', lastName: 'User' },
    results: { critical: 0, high: 1, medium: 3, low: 2 },
    description: 'Monitoring for company data on dark web marketplaces'
  },
  {
    id: '4',
    name: 'API Security Scan',
    type: 'web',
    target: 'https://api.company.com',
    status: 'failed',
    progress: 0,
    createdAt: new Date(Date.now() - 10800000).toISOString(),
    user: { username: 'admin', firstName: 'Admin', lastName: 'User' },
    description: 'Security scan of REST API endpoints'
  },
  {
    id: '5',
    name: 'Infrastructure Scan',
    type: 'network',
    target: '10.0.0.0/16',
    status: 'pending',
    progress: 0,
    createdAt: new Date(Date.now() - 14400000).toISOString(),
    user: { username: 'analyst', firstName: 'Security', lastName: 'Analyst' },
    description: 'Full infrastructure security assessment'
  }
];

app.get('/api/scans', (req, res) => {
  const { search, status, type, sortBy = 'createdAt', sortOrder = 'desc', page = 1, limit = 10 } = req.query;
  
  let filteredScans = [...mockScans];
  
  // Apply filters
  if (search) {
    filteredScans = filteredScans.filter(scan => 
      scan.name.toLowerCase().includes(search.toLowerCase()) ||
      scan.target.toLowerCase().includes(search.toLowerCase())
    );
  }
  
  if (status && status !== 'all') {
    filteredScans = filteredScans.filter(scan => scan.status === status);
  }
  
  if (type && type !== 'all') {
    filteredScans = filteredScans.filter(scan => scan.type === type);
  }
  
  // Apply sorting
  filteredScans.sort((a, b) => {
    let aValue = a[sortBy];
    let bValue = b[sortBy];
    
    if (sortBy === 'createdAt') {
      aValue = new Date(aValue);
      bValue = new Date(bValue);
    }
    
    if (sortOrder === 'asc') {
      return aValue > bValue ? 1 : -1;
    } else {
      return aValue < bValue ? 1 : -1;
    }
  });
  
  // Apply pagination
  const startIndex = (page - 1) * limit;
  const endIndex = startIndex + parseInt(limit);
  const paginatedScans = filteredScans.slice(startIndex, endIndex);
  
  res.json({
    success: true,
    data: {
      scans: paginatedScans,
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total: filteredScans.length,
        pages: Math.ceil(filteredScans.length / limit)
      }
    }
  });
});

// Create new scan
app.post('/api/scans', (req, res) => {
  const { name, type, target, description } = req.body;
  
  if (!name || !type || !target) {
    return res.status(400).json({
      success: false,
      message: 'Name, type, and target are required'
    });
  }
  
  const newScan = {
    id: (mockScans.length + 1).toString(),
    name,
    type,
    target,
    description: description || '',
    status: 'pending',
    progress: 0,
    createdAt: new Date().toISOString(),
    user: { username: 'admin', firstName: 'Admin', lastName: 'User' }
  };
  
  mockScans.unshift(newScan);
  
  // Simulate scan starting after a delay
  setTimeout(() => {
    const scan = mockScans.find(s => s.id === newScan.id);
    if (scan) {
      scan.status = 'running';
      scan.progress = 10;
    }
  }, 2000);
  
  res.status(201).json({
    success: true,
    data: { scan: newScan }
  });
});

// Pause scan
app.post('/api/scans/:id/pause', (req, res) => {
  const { id } = req.params;
  const scan = mockScans.find(s => s.id === id);
  
  if (!scan) {
    return res.status(404).json({
      success: false,
      message: 'Scan not found'
    });
  }
  
  if (scan.status !== 'running') {
    return res.status(400).json({
      success: false,
      message: 'Can only pause running scans'
    });
  }
  
  scan.status = 'paused';
  
  res.json({
    success: true,
    data: { scan }
  });
});

// Delete scan
app.delete('/api/scans/:id', (req, res) => {
  const { id } = req.params;
  const scanIndex = mockScans.findIndex(s => s.id === id);
  
  if (scanIndex === -1) {
    return res.status(404).json({
      success: false,
      message: 'Scan not found'
    });
  }
  
  mockScans.splice(scanIndex, 1);
  
  res.json({
    success: true,
    message: 'Scan deleted successfully'
  });
});

// Mock vulnerabilities endpoint with enhanced functionality
let mockVulnerabilities = [
  {
    id: '1',
    title: 'SQL Injection in Login Form',
    description: 'The login form is vulnerable to SQL injection attacks through the username parameter.',
    severity: 'critical',
    cvssScore: 9.8,
    status: 'open',
    port: 443,
    protocol: 'HTTPS',
    service: 'Web Application',
    target: 'https://company.com/login',
    discoveredAt: new Date(Date.now() - 86400000).toISOString(),
    solution: 'Use parameterized queries and input validation to prevent SQL injection attacks.',
    category: 'injection',
    remediation: {
      effort: 'medium',
      priority: 'critical',
      assignedTo: 'dev-team',
      dueDate: new Date(Date.now() + 604800000).toISOString()
    }
  },
  {
    id: '2',
    title: 'Cross-Site Scripting (XSS)',
    description: 'Reflected XSS vulnerability in search functionality allows execution of malicious scripts.',
    severity: 'high',
    cvssScore: 7.4,
    status: 'in_progress',
    port: 80,
    protocol: 'HTTP',
    service: 'Web Application',
    target: 'https://company.com/search',
    discoveredAt: new Date(Date.now() - 172800000).toISOString(),
    solution: 'Implement proper input sanitization and output encoding.',
    category: 'xss',
    remediation: {
      effort: 'low',
      priority: 'high',
      assignedTo: 'security-team',
      dueDate: new Date(Date.now() + 259200000).toISOString()
    }
  },
  {
    id: '3',
    title: 'Weak SSL/TLS Configuration',
    description: 'Server supports weak cipher suites and outdated TLS versions.',
    severity: 'medium',
    cvssScore: 5.3,
    status: 'open',
    port: 443,
    protocol: 'HTTPS',
    service: 'Web Server',
    target: 'company.com',
    discoveredAt: new Date(Date.now() - 259200000).toISOString(),
    solution: 'Update SSL/TLS configuration to use strong cipher suites and disable weak protocols.',
    category: 'crypto',
    remediation: {
      effort: 'medium',
      priority: 'medium',
      assignedTo: 'infrastructure-team',
      dueDate: new Date(Date.now() + 1209600000).toISOString()
    }
  },
  {
    id: '4',
    title: 'Information Disclosure',
    description: 'Server headers reveal sensitive information about the technology stack.',
    severity: 'low',
    cvssScore: 3.1,
    status: 'resolved',
    port: 80,
    protocol: 'HTTP',
    service: 'Web Server',
    target: 'company.com',
    discoveredAt: new Date(Date.now() - 345600000).toISOString(),
    solution: 'Configure server to hide version information and sensitive headers.',
    category: 'info_disclosure',
    remediation: {
      effort: 'low',
      priority: 'low',
      assignedTo: 'infrastructure-team',
      dueDate: new Date(Date.now() - 86400000).toISOString(),
      resolvedAt: new Date(Date.now() - 86400000).toISOString()
    }
  },
  {
    id: '5',
    title: 'Unencrypted Data Transmission',
    description: 'Sensitive data is transmitted over unencrypted HTTP connections.',
    severity: 'high',
    cvssScore: 7.5,
    status: 'open',
    port: 80,
    protocol: 'HTTP',
    service: 'Web Application',
    target: 'api.company.com',
    discoveredAt: new Date(Date.now() - 432000000).toISOString(),
    solution: 'Implement HTTPS for all sensitive data transmission and redirect HTTP to HTTPS.',
    category: 'crypto',
    remediation: {
      effort: 'high',
      priority: 'high',
      assignedTo: 'dev-team',
      dueDate: new Date(Date.now() + 432000000).toISOString()
    }
  }
];

app.get('/api/vulnerabilities', (req, res) => {
  const { search, severity, status, category, sortBy = 'discoveredAt', sortOrder = 'desc', page = 1, limit = 10 } = req.query;
  
  let filteredVulns = [...mockVulnerabilities];
  
  // Apply filters
  if (search) {
    filteredVulns = filteredVulns.filter(vuln => 
      vuln.title.toLowerCase().includes(search.toLowerCase()) ||
      vuln.description.toLowerCase().includes(search.toLowerCase()) ||
      vuln.target.toLowerCase().includes(search.toLowerCase())
    );
  }
  
  if (severity && severity !== 'all') {
    filteredVulns = filteredVulns.filter(vuln => vuln.severity === severity);
  }
  
  if (status && status !== 'all') {
    filteredVulns = filteredVulns.filter(vuln => vuln.status === status);
  }
  
  if (category && category !== 'all') {
    filteredVulns = filteredVulns.filter(vuln => vuln.category === category);
  }
  
  // Apply sorting
  filteredVulns.sort((a, b) => {
    let aValue = a[sortBy];
    let bValue = b[sortBy];
    
    if (sortBy === 'discoveredAt') {
      aValue = new Date(aValue);
      bValue = new Date(bValue);
    } else if (sortBy === 'cvssScore') {
      aValue = parseFloat(aValue);
      bValue = parseFloat(bValue);
    }
    
    if (sortOrder === 'asc') {
      return aValue > bValue ? 1 : -1;
    } else {
      return aValue < bValue ? 1 : -1;
    }
  });
  
  // Apply pagination
  const startIndex = (page - 1) * limit;
  const endIndex = startIndex + parseInt(limit);
  const paginatedVulns = filteredVulns.slice(startIndex, endIndex);
  
  res.json({
    success: true,
    data: {
      vulnerabilities: paginatedVulns,
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total: filteredVulns.length,
        pages: Math.ceil(filteredVulns.length / limit)
      },
      stats: {
        critical: mockVulnerabilities.filter(v => v.severity === 'critical').length,
        high: mockVulnerabilities.filter(v => v.severity === 'high').length,
        medium: mockVulnerabilities.filter(v => v.severity === 'medium').length,
        low: mockVulnerabilities.filter(v => v.severity === 'low').length,
        open: mockVulnerabilities.filter(v => v.status === 'open').length,
        in_progress: mockVulnerabilities.filter(v => v.status === 'in_progress').length,
        resolved: mockVulnerabilities.filter(v => v.status === 'resolved').length
      }
    }
  });
});

// Update vulnerability status
app.patch('/api/vulnerabilities/:id', (req, res) => {
  const { id } = req.params;
  const { status, assignedTo, dueDate, notes } = req.body;
  
  const vuln = mockVulnerabilities.find(v => v.id === id);
  
  if (!vuln) {
    return res.status(404).json({
      success: false,
      message: 'Vulnerability not found'
    });
  }
  
  if (status) vuln.status = status;
  if (assignedTo) vuln.remediation.assignedTo = assignedTo;
  if (dueDate) vuln.remediation.dueDate = dueDate;
  if (notes) vuln.remediation.notes = notes;
  
  if (status === 'resolved') {
    vuln.remediation.resolvedAt = new Date().toISOString();
  }
  
  res.json({
    success: true,
    data: { vulnerability: vuln }
  });
});

// Get vulnerability details
app.get('/api/vulnerabilities/:id', (req, res) => {
  const { id } = req.params;
  const vuln = mockVulnerabilities.find(v => v.id === id);
  
  if (!vuln) {
    return res.status(404).json({
      success: false,
      message: 'Vulnerability not found'
    });
  }
  
  res.json(vuln);
});

// Mock leaks endpoint with enhanced functionality
let mockLeaks = [
  {
    id: '1',
    title: 'Credit Card Information Exposed',
    content: 'Found exposed credit card numbers: 4532-****-****-1234, 5555-****-****-4444 in database dump from company.com',
    severity: 'critical',
    classification: 'financial',
    source: 'Dark Web Forum',
    confidence: 0.95,
    organization: 'Company Corp',
    discoveredAt: new Date(Date.now() - 86400000).toISOString(),
    status: 'active',
    entities: {
      credit_cards: ['4532-****-****-1234', '5555-****-****-4444'],
      emails: ['admin@company.com'],
      domains: ['company.com']
    },
    location: 'https://darkweb-forum.onion/thread/12345',
    alertSent: true,
    remediation: {
      status: 'in_progress',
      assignedTo: 'security-team',
      actions: ['Contacted card issuers', 'Notified affected customers']
    }
  },
  {
    id: '2',
    title: 'Employee Credentials Leaked',
    content: 'Database containing employee usernames and hashed passwords discovered on paste site',
    severity: 'high',
    classification: 'credentials',
    source: 'Pastebin',
    confidence: 0.88,
    organization: 'Company Corp',
    discoveredAt: new Date(Date.now() - 172800000).toISOString(),
    status: 'active',
    entities: {
      usernames: 156,
      passwords: 156,
      emails: ['hr@company.com', 'admin@company.com']
    },
    location: 'https://pastebin.com/xyz123',
    alertSent: true,
    remediation: {
      status: 'completed',
      assignedTo: 'it-team',
      actions: ['Forced password reset', 'Enabled 2FA', 'Removed paste']
    }
  },
  {
    id: '3',
    title: 'Customer PII Database Breach',
    content: 'Personal information including names, addresses, and phone numbers found in underground marketplace',
    severity: 'critical',
    classification: 'pii',
    source: 'Underground Marketplace',
    confidence: 0.92,
    organization: 'Company Corp',
    discoveredAt: new Date(Date.now() - 259200000).toISOString(),
    status: 'mitigated',
    entities: {
      names: 2500,
      addresses: 2500,
      phone_numbers: 2500,
      emails: 2500
    },
    location: 'Dark Web Marketplace',
    alertSent: true,
    remediation: {
      status: 'completed',
      assignedTo: 'legal-team',
      actions: ['Regulatory notification', 'Customer notification', 'Legal action initiated']
    }
  },
  {
    id: '4',
    title: 'API Keys Exposed in GitHub',
    content: 'AWS API keys and database credentials found in public GitHub repository',
    severity: 'high',
    classification: 'credentials',
    source: 'GitHub',
    confidence: 0.99,
    organization: 'Company Corp',
    discoveredAt: new Date(Date.now() - 345600000).toISOString(),
    status: 'resolved',
    entities: {
      api_keys: ['AKIA****', 'sk-****'],
      repositories: ['company/backend-api']
    },
    location: 'https://github.com/company/backend-api/commit/abc123',
    alertSent: true,
    remediation: {
      status: 'completed',
      assignedTo: 'dev-team',
      actions: ['Keys rotated', 'Repository cleaned', 'Secrets scanning enabled']
    }
  },
  {
    id: '5',
    title: 'Internal Documents Leaked',
    content: 'Confidential business documents and strategic plans found on file sharing site',
    severity: 'medium',
    classification: 'corporate',
    source: 'File Sharing Site',
    confidence: 0.75,
    organization: 'Company Corp',
    discoveredAt: new Date(Date.now() - 432000000).toISOString(),
    status: 'active',
    entities: {
      documents: 25,
      emails: ['ceo@company.com', 'strategy@company.com']
    },
    location: 'https://fileshare.com/folder/xyz',
    alertSent: false,
    remediation: {
      status: 'pending',
      assignedTo: 'legal-team',
      actions: []
    }
  }
];

app.get('/api/leaks', (req, res) => {
  const { search, severity, classification, status, source, sortBy = 'discoveredAt', sortOrder = 'desc', page = 1, limit = 10 } = req.query;
  
  let filteredLeaks = [...mockLeaks];
  
  // Apply filters
  if (search) {
    filteredLeaks = filteredLeaks.filter(leak => 
      leak.title.toLowerCase().includes(search.toLowerCase()) ||
      leak.content.toLowerCase().includes(search.toLowerCase()) ||
      leak.organization.toLowerCase().includes(search.toLowerCase())
    );
  }
  
  if (severity && severity !== 'all') {
    filteredLeaks = filteredLeaks.filter(leak => leak.severity === severity);
  }
  
  if (classification && classification !== 'all') {
    filteredLeaks = filteredLeaks.filter(leak => leak.classification === classification);
  }
  
  if (status && status !== 'all') {
    filteredLeaks = filteredLeaks.filter(leak => leak.status === status);
  }
  
  if (source && source !== 'all') {
    filteredLeaks = filteredLeaks.filter(leak => leak.source.toLowerCase().includes(source.toLowerCase()));
  }
  
  // Apply sorting
  filteredLeaks.sort((a, b) => {
    let aValue = a[sortBy];
    let bValue = b[sortBy];
    
    if (sortBy === 'discoveredAt') {
      aValue = new Date(aValue);
      bValue = new Date(bValue);
    } else if (sortBy === 'confidence') {
      aValue = parseFloat(aValue);
      bValue = parseFloat(bValue);
    }
    
    if (sortOrder === 'asc') {
      return aValue > bValue ? 1 : -1;
    } else {
      return aValue < bValue ? 1 : -1;
    }
  });
  
  // Apply pagination
  const startIndex = (page - 1) * limit;
  const endIndex = startIndex + parseInt(limit);
  const paginatedLeaks = filteredLeaks.slice(startIndex, endIndex);
  
  res.json({
    success: true,
    data: {
      leaks: paginatedLeaks,
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total: filteredLeaks.length,
        pages: Math.ceil(filteredLeaks.length / limit)
      },
      stats: {
        critical: mockLeaks.filter(l => l.severity === 'critical').length,
        high: mockLeaks.filter(l => l.severity === 'high').length,
        medium: mockLeaks.filter(l => l.severity === 'medium').length,
        low: mockLeaks.filter(l => l.severity === 'low').length,
        active: mockLeaks.filter(l => l.status === 'active').length,
        mitigated: mockLeaks.filter(l => l.status === 'mitigated').length,
        resolved: mockLeaks.filter(l => l.status === 'resolved').length,
        total_entities: mockLeaks.reduce((sum, leak) => {
          return sum + Object.values(leak.entities || {}).reduce((entitySum, entity) => {
            return entitySum + (Array.isArray(entity) ? entity.length : (typeof entity === 'number' ? entity : 1));
          }, 0);
        }, 0)
      }
    }
  });
});

// Update leak status
app.patch('/api/leaks/:id', (req, res) => {
  const { id } = req.params;
  const { status, assignedTo, actions, notes } = req.body;
  
  const leak = mockLeaks.find(l => l.id === id);
  
  if (!leak) {
    return res.status(404).json({
      success: false,
      message: 'Leak not found'
    });
  }
  
  if (status) leak.status = status;
  if (assignedTo) leak.remediation.assignedTo = assignedTo;
  if (actions) leak.remediation.actions = actions;
  if (notes) leak.remediation.notes = notes;
  
  leak.remediation.status = status === 'resolved' ? 'completed' : (status === 'mitigated' ? 'completed' : 'in_progress');
  
  res.json({
    success: true,
    data: { leak }
  });
});

// Send alert for leak
app.post('/api/leaks/:id/alert', (req, res) => {
  const { id } = req.params;
  const { recipients, message } = req.body;
  
  const leak = mockLeaks.find(l => l.id === id);
  
  if (!leak) {
    return res.status(404).json({
      success: false,
      message: 'Leak not found'
    });
  }
  
  leak.alertSent = true;
  leak.alertDetails = {
    sentAt: new Date().toISOString(),
    recipients: recipients || ['security-team@company.com'],
    message: message || 'Data leak detected and requires immediate attention'
  };
  
  res.json({
    success: true,
    message: 'Alert sent successfully',
    data: { leak }
  });
});

// Get leak details
app.get('/api/leaks/:id', (req, res) => {
  const { id } = req.params;
  const leak = mockLeaks.find(l => l.id === id);
  
  if (!leak) {
    return res.status(404).json({
      success: false,
      message: 'Leak not found'
    });
  }
  
  res.json({
    success: true,
    data: { leak }
  });
});

// Mock reports data
let mockReports = [
  {
    id: 1,
    title: 'Monthly Security Report',
    type: 'combined',
    format: 'pdf',
    status: 'completed',
    progress: 100,
    size: '2.4 MB',
    createdAt: new Date().toISOString(),
    completedAt: new Date().toISOString(),
    user: { id: 1, username: 'admin', firstName: 'Admin', lastName: 'User' },
    summary: {
      generatedAt: new Date().toISOString(),
      reportType: 'combined',
      total_findings: 45,
      critical_issues: 3,
      high_issues: 8,
      medium_issues: 15,
      low_issues: 19
    },
    config: {
      includeCharts: true,
      includeDetails: true,
      dateRange: 'last_30_days'
    }
  },
  {
    id: 2,
    title: 'Vulnerability Assessment Report',
    type: 'vulnerability',
    format: 'pdf',
    status: 'generating',
    progress: 65,
    size: null,
    createdAt: new Date(Date.now() - 1800000).toISOString(),
    completedAt: null,
    user: { id: 2, username: 'analyst', firstName: 'Security', lastName: 'Analyst' },
    config: {
      includeCharts: false,
      includeDetails: true,
      dateRange: 'last_7_days'
    }
  },
  {
    id: 3,
    title: 'Data Leak Monitoring Report',
    type: 'leak',
    format: 'csv',
    status: 'completed',
    progress: 100,
    size: '1.2 MB',
    createdAt: new Date(Date.now() - 86400000).toISOString(),
    completedAt: new Date(Date.now() - 82800000).toISOString(),
    user: { id: 1, username: 'admin', firstName: 'Admin', lastName: 'User' },
    summary: {
      generatedAt: new Date(Date.now() - 82800000).toISOString(),
      reportType: 'leak',
      total_findings: 12,
      critical_issues: 2,
      high_issues: 3,
      medium_issues: 4,
      low_issues: 3
    },
    config: {
      includeCharts: true,
      includeDetails: false,
      dateRange: 'last_14_days'
    }
  },
  {
    id: 4,
    title: 'Scheduled Weekly Report',
    type: 'combined',
    format: 'pdf',
    status: 'scheduled',
    progress: 0,
    size: null,
    createdAt: new Date(Date.now() - 172800000).toISOString(),
    completedAt: null,
    user: { id: 1, username: 'admin', firstName: 'Admin', lastName: 'User' },
    config: {
      includeCharts: true,
      includeDetails: true,
      dateRange: 'last_7_days'
    },
    schedule: {
      frequency: 'weekly',
      dayOfWeek: 'monday',
      time: '09:00',
      recipients: ['admin@company.com', 'security@company.com'],
      enabled: true,
      nextRun: new Date(Date.now() + 86400000).toISOString()
    }
  },
  {
    id: 5,
    title: 'Network Scan Report',
    type: 'scan',
    format: 'pdf',
    status: 'failed',
    progress: 25,
    size: null,
    createdAt: new Date(Date.now() - 259200000).toISOString(),
    completedAt: null,
    user: { id: 2, username: 'analyst', firstName: 'Security', lastName: 'Analyst' },
    config: {
      includeCharts: true,
      includeDetails: true,
      dateRange: 'last_24_hours'
    },
    error: 'Insufficient data available for report generation'
  }
];

// Reports endpoint with comprehensive functionality
app.get('/api/reports', (req, res) => {
  const { search, type, format, status, dateRange, sortBy = 'createdAt', sortOrder = 'desc', page = 1, limit = 10 } = req.query;
  
  let filteredReports = mockReports.filter(report => {
    if (search && !report.title.toLowerCase().includes(search.toLowerCase()) && 
        !report.type.toLowerCase().includes(search.toLowerCase())) {
      return false;
    }
    if (type && type !== 'all' && report.type !== type) return false;
    if (format && format !== 'all' && report.format !== format) return false;
    if (status && status !== 'all' && report.status !== status) return false;
    if (dateRange && dateRange !== 'all') {
      const reportDate = new Date(report.createdAt);
      const now = new Date();
      switch (dateRange) {
        case 'today':
          if (reportDate.toDateString() !== now.toDateString()) return false;
          break;
        case 'week':
          const weekAgo = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
          if (reportDate < weekAgo) return false;
          break;
        case 'month':
          const monthAgo = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);
          if (reportDate < monthAgo) return false;
          break;
      }
    }
    return true;
  });

  // Sort reports
  filteredReports.sort((a, b) => {
    let aVal = a[sortBy];
    let bVal = b[sortBy];
    
    if (sortBy === 'createdAt' || sortBy === 'completedAt') {
      aVal = new Date(aVal);
      bVal = new Date(bVal);
    }
    
    if (sortOrder === 'asc') {
      return aVal > bVal ? 1 : -1;
    } else {
      return aVal < bVal ? 1 : -1;
    }
  });

  // Pagination
  const startIndex = (page - 1) * limit;
  const endIndex = startIndex + parseInt(limit);
  const paginatedReports = filteredReports.slice(startIndex, endIndex);

  // Calculate stats
  const stats = {
    total: mockReports.length,
    completed: mockReports.filter(r => r.status === 'completed').length,
    generating: mockReports.filter(r => r.status === 'generating').length,
    scheduled: mockReports.filter(r => r.status === 'scheduled').length,
    failed: mockReports.filter(r => r.status === 'failed').length
  };

  res.json({
    success: true,
    data: {
      reports: paginatedReports,
      stats,
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total: filteredReports.length,
        pages: Math.ceil(filteredReports.length / limit)
      }
    }
  });
});

app.post('/api/reports/generate', (req, res) => {
  const { title, type, format, dateRange, includeCharts, includeDetails, filters } = req.body;
  
  const newReport = {
    id: mockReports.length + 1,
    title: title || `${type.replace('_', ' ')} Report`,
    type,
    format,
    status: 'generating',
    progress: 0,
    dateRange,
    size: null,
    createdAt: new Date().toISOString(),
    completedAt: null,
    user: { id: 1, username: 'admin' },
    config: {
      includeCharts,
      includeDetails,
      filters
    }
  };
  
  mockReports.unshift(newReport);
  
  // Simulate report generation
  setTimeout(() => {
    const report = mockReports.find(r => r.id === newReport.id);
    if (report) {
      report.status = 'completed';
      report.progress = 100;
      report.completedAt = new Date().toISOString();
      report.size = '2.4 MB';
      report.summary = {
        total_findings: Math.floor(Math.random() * 50) + 10,
        critical_issues: Math.floor(Math.random() * 5),
        high_issues: Math.floor(Math.random() * 10) + 5,
        medium_issues: Math.floor(Math.random() * 20) + 10,
        low_issues: Math.floor(Math.random() * 15) + 5
      };
    }
  }, 3000);
  
  res.json({
    success: true,
    data: { report: newReport }
  });
});

app.post('/api/reports/schedule', (req, res) => {
  const { frequency, dayOfWeek, time, recipients, enabled, reportConfig } = req.body;
  
  const scheduledReport = {
    id: mockReports.length + 1,
    title: `Scheduled ${reportConfig.type.replace('_', ' ')} Report`,
    type: reportConfig.type,
    format: reportConfig.format,
    status: 'scheduled',
    progress: 0,
    dateRange: reportConfig.dateRange,
    size: null,
    createdAt: new Date().toISOString(),
    completedAt: null,
    user: { id: 1, username: 'admin' },
    config: reportConfig,
    schedule: {
      frequency,
      dayOfWeek,
      time,
      recipients: recipients.split(',').map(email => email.trim()),
      enabled,
      nextRun: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString() // Next day
    }
  };
  
  mockReports.unshift(scheduledReport);
  
  res.json({
    success: true,
    data: { report: scheduledReport }
  });
});

app.get('/api/reports/:id/download', (req, res) => {
  const { id } = req.params;
  const { format = 'pdf' } = req.query;
  
  const report = mockReports.find(r => r.id === parseInt(id));
  if (!report || report.status !== 'completed') {
    return res.status(404).json({ success: false, message: 'Report not found or not ready' });
  }
  
  // Simulate file download
  const content = format === 'pdf' 
    ? `Mock PDF content for report: ${report.title}`
    : `Mock CSV content for report: ${report.title}\nColumn1,Column2,Column3\nValue1,Value2,Value3`;
  
  res.setHeader('Content-Type', format === 'pdf' ? 'application/pdf' : 'text/csv');
  res.setHeader('Content-Disposition', `attachment; filename="report_${id}.${format}"`);
  res.send(content);
});

app.delete('/api/reports/:id', (req, res) => {
  const { id } = req.params;
  const reportIndex = mockReports.findIndex(r => r.id === parseInt(id));
  
  if (reportIndex === -1) {
    return res.status(404).json({ success: false, message: 'Report not found' });
  }
  
  mockReports.splice(reportIndex, 1);
  
  res.json({
    success: true,
    message: 'Report deleted successfully'
  });
});

app.get('/api/reports/:id', (req, res) => {
  const { id } = req.params;
  const report = mockReports.find(r => r.id === parseInt(id));
  
  if (!report) {
    return res.status(404).json({ success: false, message: 'Report not found' });
  }
  
  res.json({
    success: true,
    data: { report }
  });
});

// Mock users data
let mockUsers = [
  {
    id: 1,
    username: 'admin',
    email: 'admin@vulnsecure.com',
    firstName: 'Admin',
    lastName: 'User',
    role: 'admin',
    isActive: true,
    createdAt: new Date().toISOString(),
    lastLogin: new Date().toISOString(),
    phone: '+1-555-0123',
    location: 'New York, NY',
    bio: 'System Administrator with 10+ years of experience in cybersecurity.',
    twoFactorEnabled: true,
    loginNotifications: true
  },
  {
    id: 2,
    username: 'analyst',
    email: 'analyst@vulnsecure.com',
    firstName: 'Security',
    lastName: 'Analyst',
    role: 'analyst',
    isActive: true,
    createdAt: new Date(Date.now() - 86400000).toISOString(),
    lastLogin: new Date(Date.now() - 3600000).toISOString(),
    phone: '+1-555-0124',
    location: 'San Francisco, CA',
    bio: 'Cybersecurity analyst specializing in threat detection and incident response.',
    twoFactorEnabled: false,
    loginNotifications: true
  },
  {
    id: 3,
    username: 'viewer',
    email: 'viewer@vulnsecure.com',
    firstName: 'John',
    lastName: 'Viewer',
    role: 'viewer',
    isActive: true,
    createdAt: new Date(Date.now() - 172800000).toISOString(),
    lastLogin: new Date(Date.now() - 7200000).toISOString(),
    phone: null,
    location: 'Chicago, IL',
    bio: 'Security team member with read-only access to security reports.',
    twoFactorEnabled: false,
    loginNotifications: false
  },
  {
    id: 4,
    username: 'manager',
    email: 'manager@vulnsecure.com',
    firstName: 'Sarah',
    lastName: 'Manager',
    role: 'analyst',
    isActive: false,
    createdAt: new Date(Date.now() - 259200000).toISOString(),
    lastLogin: new Date(Date.now() - 86400000).toISOString(),
    phone: '+1-555-0125',
    location: 'Austin, TX',
    bio: 'Security manager overseeing vulnerability assessment programs.',
    twoFactorEnabled: true,
    loginNotifications: true
  },
  {
    id: 5,
    username: 'consultant',
    email: 'consultant@vulnsecure.com',
    firstName: 'Mike',
    lastName: 'Consultant',
    role: 'viewer',
    isActive: true,
    createdAt: new Date(Date.now() - 345600000).toISOString(),
    lastLogin: new Date(Date.now() - 14400000).toISOString(),
    phone: '+1-555-0126',
    location: 'Remote',
    bio: 'External security consultant providing specialized expertise.',
    twoFactorEnabled: true,
    loginNotifications: false
  }
];

// Users endpoint with comprehensive functionality
app.get('/api/users', (req, res) => {
  const { search, role, status, sortBy = 'createdAt', sortOrder = 'desc', page = 1, limit = 10 } = req.query;
  
  let filteredUsers = mockUsers.filter(user => {
    if (search && !user.firstName.toLowerCase().includes(search.toLowerCase()) && 
        !user.lastName.toLowerCase().includes(search.toLowerCase()) &&
        !user.username.toLowerCase().includes(search.toLowerCase()) &&
        !user.email.toLowerCase().includes(search.toLowerCase())) {
      return false;
    }
    if (role && role !== 'all' && user.role !== role) return false;
    if (status && status !== 'all') {
      const isActive = status === 'active';
      if (user.isActive !== isActive) return false;
    }
    return true;
  });

  // Sort users
  filteredUsers.sort((a, b) => {
    let aVal = a[sortBy];
    let bVal = b[sortBy];
    
    if (sortBy === 'createdAt' || sortBy === 'lastLogin') {
      aVal = new Date(aVal);
      bVal = new Date(bVal);
    }
    
    if (sortOrder === 'asc') {
      return aVal > bVal ? 1 : -1;
    } else {
      return aVal < bVal ? 1 : -1;
    }
  });

  // Pagination
  const startIndex = (page - 1) * limit;
  const endIndex = startIndex + parseInt(limit);
  const paginatedUsers = filteredUsers.slice(startIndex, endIndex);

  // Calculate stats
  const stats = {
    total: mockUsers.length,
    active: mockUsers.filter(u => u.isActive).length,
    inactive: mockUsers.filter(u => !u.isActive).length,
    admins: mockUsers.filter(u => u.role === 'admin').length,
    analysts: mockUsers.filter(u => u.role === 'analyst').length,
    viewers: mockUsers.filter(u => u.role === 'viewer').length
  };

  res.json({
    success: true,
    data: {
      users: paginatedUsers,
      stats,
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total: filteredUsers.length,
        pages: Math.ceil(filteredUsers.length / limit)
      }
    }
  });
});

app.get('/api/users/:id', (req, res) => {
  const { id } = req.params;
  const user = mockUsers.find(u => u.id === parseInt(id));
  
  if (!user) {
    return res.status(404).json({ success: false, message: 'User not found' });
  }
  
  res.json({
    success: true,
    data: { user }
  });
});

app.post('/api/users', (req, res) => {
  const { firstName, lastName, username, email, role, password } = req.body;
  
  const newUser = {
    id: mockUsers.length + 1,
    firstName,
    lastName,
    username,
    email,
    role: role || 'viewer',
    isActive: true,
    createdAt: new Date().toISOString(),
    lastLogin: null,
    phone: null,
    location: null,
    bio: null,
    twoFactorEnabled: false,
    loginNotifications: true
  };
  
  mockUsers.push(newUser);
  
  res.json({
    success: true,
    data: { user: newUser }
  });
});

app.put('/api/users/:id', (req, res) => {
  const { id } = req.params;
  const userIndex = mockUsers.findIndex(u => u.id === parseInt(id));
  
  if (userIndex === -1) {
    return res.status(404).json({ success: false, message: 'User not found' });
  }
  
  mockUsers[userIndex] = { ...mockUsers[userIndex], ...req.body };
  
  res.json({
    success: true,
    data: { user: mockUsers[userIndex] }
  });
});

app.delete('/api/users/:id', (req, res) => {
  const { id } = req.params;
  const userIndex = mockUsers.findIndex(u => u.id === parseInt(id));
  
  if (userIndex === -1) {
    return res.status(404).json({ success: false, message: 'User not found' });
  }
  
  mockUsers.splice(userIndex, 1);
  
  res.json({
    success: true,
    message: 'User deleted successfully'
  });
});

app.get('/api/users/:id/activity', (req, res) => {
  const { id } = req.params;
  const user = mockUsers.find(u => u.id === parseInt(id));
  
  if (!user) {
    return res.status(404).json({ success: false, message: 'User not found' });
  }
  
  const activities = [
    {
      id: 1,
      type: 'login',
      description: 'Logged in to the system',
      timestamp: new Date(Date.now() - 3600000).toISOString(),
      ipAddress: '192.168.1.100',
      deviceType: 'desktop',
      userAgent: 'Chrome 120.0.0.0'
    },
    {
      id: 2,
      type: 'scan_created',
      description: 'Created a new network scan',
      timestamp: new Date(Date.now() - 7200000).toISOString(),
      ipAddress: '192.168.1.100',
      deviceType: 'desktop',
      userAgent: 'Chrome 120.0.0.0'
    },
    {
      id: 3,
      type: 'report_generated',
      description: 'Generated vulnerability report',
      timestamp: new Date(Date.now() - 10800000).toISOString(),
      ipAddress: '192.168.1.100',
      deviceType: 'desktop',
      userAgent: 'Chrome 120.0.0.0'
    },
    {
      id: 4,
      type: 'profile_update',
      description: 'Updated profile information',
      timestamp: new Date(Date.now() - 86400000).toISOString(),
      ipAddress: '192.168.1.100',
      deviceType: 'mobile',
      userAgent: 'Safari Mobile'
    },
    {
      id: 5,
      type: 'password_change',
      description: 'Changed account password',
      timestamp: new Date(Date.now() - 172800000).toISOString(),
      ipAddress: '192.168.1.100',
      deviceType: 'desktop',
      userAgent: 'Chrome 120.0.0.0'
    }
  ];
  
  res.json({
    success: true,
    data: { activities }
  });
});

app.get('/api/users/:id/sessions', (req, res) => {
  const { id } = req.params;
  const user = mockUsers.find(u => u.id === parseInt(id));
  
  if (!user) {
    return res.status(404).json({ success: false, message: 'User not found' });
  }
  
  const sessions = [
    {
      id: 1,
      deviceType: 'desktop',
      ipAddress: '192.168.1.100',
      location: 'New York, NY',
      lastActivity: new Date().toISOString(),
      isCurrent: true
    },
    {
      id: 2,
      deviceType: 'mobile',
      ipAddress: '192.168.1.101',
      location: 'New York, NY',
      lastActivity: new Date(Date.now() - 3600000).toISOString(),
      isCurrent: false
    },
    {
      id: 3,
      deviceType: 'desktop',
      ipAddress: '10.0.0.50',
      location: 'San Francisco, CA',
      lastActivity: new Date(Date.now() - 86400000).toISOString(),
      isCurrent: false
    }
  ];
  
  res.json({
    success: true,
    data: { sessions }
  });
});

app.delete('/api/users/:id/sessions/:sessionId', (req, res) => {
  const { id, sessionId } = req.params;
  
  res.json({
    success: true,
    message: 'Session revoked successfully'
  });
});

app.patch('/api/users/:id/role', (req, res) => {
  const { id } = req.params;
  const { role } = req.body;
  const userIndex = mockUsers.findIndex(u => u.id === parseInt(id));
  
  if (userIndex === -1) {
    return res.status(404).json({ success: false, message: 'User not found' });
  }
  
  mockUsers[userIndex].role = role;
  
  res.json({
    success: true,
    data: { user: mockUsers[userIndex] }
  });
});

app.patch('/api/users/:id/status', (req, res) => {
  const { id } = req.params;
  const userIndex = mockUsers.findIndex(u => u.id === parseInt(id));
  
  if (userIndex === -1) {
    return res.status(404).json({ success: false, message: 'User not found' });
  }
  
  mockUsers[userIndex].isActive = !mockUsers[userIndex].isActive;
  
  res.json({
    success: true,
    data: { user: mockUsers[userIndex] }
  });
});

// Analytics endpoint
app.get('/api/analytics', (req, res) => {
  const { timeRange = '7d', metric = 'all' } = req.query;
  
  // Calculate date range
  const now = new Date();
  let startDate;
  switch (timeRange) {
    case '24h':
      startDate = new Date(now.getTime() - 24 * 60 * 60 * 1000);
      break;
    case '7d':
      startDate = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
      break;
    case '30d':
      startDate = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);
      break;
    case '90d':
      startDate = new Date(now.getTime() - 90 * 24 * 60 * 60 * 1000);
      break;
    default:
      startDate = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
  }

  const analytics = {
    overview: {
      totalScans: 156,
      totalVulnerabilities: 89,
      totalLeaks: 23,
      totalReports: 45,
      activeUsers: 12,
      systemUptime: '99.8%'
    },
    trends: {
      scans: generateTrendData(startDate, now, 'scans'),
      vulnerabilities: generateTrendData(startDate, now, 'vulnerabilities'),
      leaks: generateTrendData(startDate, now, 'leaks'),
      reports: generateTrendData(startDate, now, 'reports')
    },
    vulnerabilityBreakdown: {
      critical: 12,
      high: 23,
      medium: 34,
      low: 20,
      info: 15
    },
    leakSeverity: {
      critical: 5,
      high: 8,
      medium: 7,
      low: 3
    },
    scanTypes: {
      network: 45,
      web: 38,
      database: 28,
      api: 25,
      mobile: 20
    },
    topVulnerabilities: [
      { name: 'SQL Injection', count: 15, severity: 'critical' },
      { name: 'Cross-Site Scripting (XSS)', count: 12, severity: 'high' },
      { name: 'Insecure Direct Object References', count: 10, severity: 'medium' },
      { name: 'Security Misconfiguration', count: 8, severity: 'high' },
      { name: 'Sensitive Data Exposure', count: 7, severity: 'critical' }
    ],
    userActivity: {
      totalLogins: 234,
      uniqueUsers: 18,
      avgSessionDuration: '45m',
      mostActiveUsers: [
        { name: 'Admin User', actions: 156 },
        { name: 'Security Analyst', actions: 89 },
        { name: 'John Viewer', actions: 45 }
      ]
    },
    systemHealth: {
      cpuUsage: 45,
      memoryUsage: 62,
      diskUsage: 38,
      networkLatency: 12,
      errorRate: 0.2
    }
  };

  res.json({
    success: true,
    data: analytics
  });
});

// Helper function to generate trend data
function generateTrendData(startDate, endDate, type) {
  const data = [];
  const daysDiff = Math.ceil((endDate - startDate) / (1000 * 60 * 60 * 24));
  
  for (let i = 0; i < daysDiff; i++) {
    const date = new Date(startDate.getTime() + i * 24 * 60 * 60 * 1000);
    let value;
    
    switch (type) {
      case 'scans':
        value = Math.floor(Math.random() * 10) + 5;
        break;
      case 'vulnerabilities':
        value = Math.floor(Math.random() * 15) + 3;
        break;
      case 'leaks':
        value = Math.floor(Math.random() * 5) + 1;
        break;
      case 'reports':
        value = Math.floor(Math.random() * 8) + 2;
        break;
      default:
        value = Math.floor(Math.random() * 10);
    }
    
    data.push({
      date: date.toISOString().split('T')[0],
      value
    });
  }
  
  return data;
}

// Search endpoint for global search
app.get('/api/search', (req, res) => {
  const { q: query, type = 'all', limit = 20 } = req.query;
  
  if (!query) {
    return res.status(400).json({
      success: false,
      message: 'Search query is required'
    });
  }

  const results = {
    scans: [],
    vulnerabilities: [],
    leaks: [],
    reports: [],
    users: []
  };

  // Search in scans
  if (type === 'all' || type === 'scans') {
    results.scans = mockScans.filter(scan => 
      scan.name.toLowerCase().includes(query.toLowerCase()) ||
      scan.target.toLowerCase().includes(query.toLowerCase()) ||
      scan.type.toLowerCase().includes(query.toLowerCase())
    ).slice(0, limit);
  }

  // Search in vulnerabilities
  if (type === 'all' || type === 'vulnerabilities') {
    results.vulnerabilities = mockVulnerabilities.filter(vuln => 
      vuln.title.toLowerCase().includes(query.toLowerCase()) ||
      vuln.description.toLowerCase().includes(query.toLowerCase()) ||
      vuln.severity.toLowerCase().includes(query.toLowerCase())
    ).slice(0, limit);
  }

  // Search in leaks
  if (type === 'all' || type === 'leaks') {
    results.leaks = mockLeaks.filter(leak => 
      leak.title.toLowerCase().includes(query.toLowerCase()) ||
      leak.content.toLowerCase().includes(query.toLowerCase()) ||
      leak.source.toLowerCase().includes(query.toLowerCase())
    ).slice(0, limit);
  }

  // Search in reports
  if (type === 'all' || type === 'reports') {
    results.reports = mockReports.filter(report => 
      report.title.toLowerCase().includes(query.toLowerCase()) ||
      report.type.toLowerCase().includes(query.toLowerCase())
    ).slice(0, limit);
  }

  // Search in users
  if (type === 'all' || type === 'users') {
    results.users = mockUsers.filter(user => 
      user.firstName.toLowerCase().includes(query.toLowerCase()) ||
      user.lastName.toLowerCase().includes(query.toLowerCase()) ||
      user.username.toLowerCase().includes(query.toLowerCase()) ||
      user.email.toLowerCase().includes(query.toLowerCase())
    ).slice(0, limit);
  }

  const totalResults = Object.values(results).reduce((sum, arr) => sum + arr.length, 0);

  res.json({
    success: true,
    data: {
      query,
      totalResults,
      results
    }
  });
});

// System health endpoint
app.get('/api/system/health', (req, res) => {
  const health = {
    status: 'healthy',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    version: '1.0.0',
    services: {
      database: { status: 'healthy', responseTime: 12 },
      cache: { status: 'healthy', responseTime: 3 },
      storage: { status: 'healthy', responseTime: 8 },
      notifications: { status: 'healthy', responseTime: 15 }
    },
    metrics: {
      cpuUsage: Math.floor(Math.random() * 30) + 20,
      memoryUsage: Math.floor(Math.random() * 40) + 40,
      diskUsage: Math.floor(Math.random() * 20) + 30,
      activeConnections: Math.floor(Math.random() * 50) + 10
    },
    lastChecked: new Date().toISOString()
  };

  res.json({
    success: true,
    data: health
  });
});

// Notifications endpoint
app.get('/api/notifications', (req, res) => {
  const { unread = false, limit = 50 } = req.query;
  
  let notifications = [
    {
      id: 1,
      type: 'vulnerability',
      title: 'Critical Vulnerability Detected',
      message: 'SQL Injection vulnerability found in web application',
      severity: 'critical',
      isRead: false,
      createdAt: new Date(Date.now() - 3600000).toISOString(),
      actionUrl: '/vulnerabilities/1'
    },
    {
      id: 2,
      type: 'scan',
      title: 'Scan Completed',
      message: 'Network scan of 192.168.1.0/24 completed successfully',
      severity: 'info',
      isRead: false,
      createdAt: new Date(Date.now() - 7200000).toISOString(),
      actionUrl: '/scans/1'
    },
    {
      id: 3,
      type: 'leak',
      title: 'Data Leak Detected',
      message: 'Sensitive data exposure detected in application logs',
      severity: 'high',
      isRead: true,
      createdAt: new Date(Date.now() - 10800000).toISOString(),
      actionUrl: '/leaks/1'
    },
    {
      id: 4,
      type: 'report',
      title: 'Report Generated',
      message: 'Monthly security report has been generated',
      severity: 'info',
      isRead: true,
      createdAt: new Date(Date.now() - 86400000).toISOString(),
      actionUrl: '/reports/1'
    },
    {
      id: 5,
      type: 'system',
      title: 'System Update',
      message: 'Security definitions updated successfully',
      severity: 'info',
      isRead: false,
      createdAt: new Date(Date.now() - 172800000).toISOString(),
      actionUrl: null
    }
  ];

  if (unread === 'true') {
    notifications = notifications.filter(n => !n.isRead);
  }

  notifications = notifications.slice(0, parseInt(limit));

  res.json({
    success: true,
    data: {
      notifications,
      unreadCount: notifications.filter(n => !n.isRead).length
    }
  });
});

app.patch('/api/notifications/:id/read', (req, res) => {
  const { id } = req.params;
  
  res.json({
    success: true,
    message: 'Notification marked as read'
  });
});

app.patch('/api/notifications/mark-all-read', (req, res) => {
  res.json({
    success: true,
    message: 'All notifications marked as read'
  });
});

// Start server
app.listen(PORT, () => {
  console.log(`🚀 vulNSecure Test Server running on port ${PORT}`);
  console.log(`📊 Health check: http://localhost:${PORT}/health`);
  console.log(`🔧 API test: http://localhost:${PORT}/api/test`);
  console.log(`🔐 Login test: POST http://localhost:${PORT}/api/auth/login`);
  console.log(`📈 Dashboard: http://localhost:${PORT}/api/dashboard/stats`);
});

module.exports = app;
