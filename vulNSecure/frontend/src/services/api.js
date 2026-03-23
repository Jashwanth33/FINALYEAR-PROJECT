import axios from 'axios';
import toast from 'react-hot-toast';

const API_BASE_URL = process.env.REACT_APP_API_URL || 'http://localhost:5001/api';

// Create axios instance
export const api = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Request interceptor to add auth token
api.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('token');
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => {
    return Promise.reject(error);
  }
);

// Response interceptor to handle errors
api.interceptors.response.use(
  (response) => {
    return response;
  },
  async (error) => {
    const originalRequest = error.config;
    
    // Handle network errors
    if (!error.response) {
      console.error('Network error:', error.message);
      toast.error('Network error. Please check your connection.');
      return Promise.reject(error);
    }
    
    // Handle 401 Unauthorized errors
    if (error.response?.status === 401 && !originalRequest._retry) {
      originalRequest._retry = true;
      
      // Only redirect if we're not already on login/register pages
      const currentPath = window.location.pathname;
      const isAuthPage = currentPath.includes('/login') || currentPath.includes('/register');
      
      if (!isAuthPage) {
        localStorage.removeItem('token');
        toast.error('Session expired. Please log in again.');
        window.location.href = '/login';
      }
    }
    
    // Handle 429 Rate Limit errors with retry
    if (error.response?.status === 429) {
      const retryAfter = error.response.headers['retry-after'] || 2;
      console.log(`Rate limited, retrying after ${retryAfter}s`);
      
      // Wait and retry
      await new Promise(resolve => setTimeout(resolve, retryAfter * 1000));
      return api(originalRequest);
    }
    
    // Handle other HTTP errors
    if (error.response?.status >= 500) {
      toast.error('Server error. Please try again later.');
    } else if (error.response?.status === 403) {
      toast.error('Access denied. You do not have permission to perform this action.');
    } else if (error.response?.status === 404) {
      toast.error('Resource not found.');
    }
    
    return Promise.reject(error);
  }
);

// Auth API
export const authAPI = {
  login: (email, password) => api.post('/auth/login', { email, password }),
  register: (userData) => api.post('/auth/register', userData),
  getMe: () => api.get('/auth/me'),
  updateProfile: (profileData) => api.put('/auth/profile', profileData),
  changePassword: (currentPassword, newPassword) => 
    api.put('/auth/change-password', { currentPassword, newPassword }),
  logout: () => api.post('/auth/logout'),
};

// Scans API
export const scansAPI = {
  getScans: (params) => api.get('/scans', { params }),
  getScan: (id) => api.get(`/scans/${id}`),
  createScan: (scanData) => api.post('/scans', scanData),
  updateScan: (id, scanData) => api.put(`/scans/${id}`, scanData),
  deleteScan: (id) => api.delete(`/scans/${id}`),
  cancelScan: (id) => api.post(`/scans/${id}/cancel`),
};

// Vulnerabilities API
export const vulnerabilitiesAPI = {
  getVulnerabilities: (params = {}) => api.get('/vulnerabilities', { params }),
  getVulnerability: (id) => api.get(`/vulnerabilities/${id}`),
  updateVulnerability: (id, data) => api.put(`/vulnerabilities/${id}`, data),
};

// Leaks API
export const leaksAPI = {
  getLeaks: (params = {}) => {
    const queryParams = new URLSearchParams();
    
    if (params.search) queryParams.append('search', params.search);
    if (params.severity && params.severity !== 'all') queryParams.append('severity', params.severity);
    if (params.classification && params.classification !== 'all') queryParams.append('classification', params.classification);
    if (params.status && params.status !== 'all') queryParams.append('status', params.status);
    if (params.source && params.source !== 'all') queryParams.append('source', params.source);
    if (params.sortBy) queryParams.append('sortBy', params.sortBy);
    if (params.sortOrder) queryParams.append('sortOrder', params.sortOrder);
    
    const queryString = queryParams.toString();
    return api.get(`/leaks${queryString ? `?${queryString}` : ''}`);
  },
  updateLeak: (id, data) => api.patch(`/leaks/${id}`, data),
  sendAlert: (id, data) => api.post(`/leaks/${id}/alert`, data),
  getLeakDetails: (id) => api.get(`/leaks/${id}`)
};

// CVEs API
export const cvesAPI = {
  getCVEs: (params) => api.get('/cves', { params }),
  getCVE: (id) => api.get(`/cves/${id}`),
  getCVEById: (cveId) => api.get(`/cves/cve/${cveId}`),
};

// Reports API
export const reportsAPI = {
  getReports: (params = {}) => {
    const queryParams = new URLSearchParams();
    if (params.search) queryParams.append('search', params.search);
    if (params.type && params.type !== 'all') queryParams.append('type', params.type);
    if (params.format && params.format !== 'all') queryParams.append('format', params.format);
    if (params.status && params.status !== 'all') queryParams.append('status', params.status);
    if (params.dateRange && params.dateRange !== 'all') queryParams.append('dateRange', params.dateRange);
    if (params.sortBy) queryParams.append('sortBy', params.sortBy);
    if (params.sortOrder) queryParams.append('sortOrder', params.sortOrder);
    
    const queryString = queryParams.toString();
    return api.get(`/reports${queryString ? `?${queryString}` : ''}`);
  },
  generateReport: (data) => api.post('/reports/generate', data),
  scheduleReport: (data) => api.post('/reports/schedule', data),
  downloadReport: (id, format = 'pdf') => api.get(`/reports/${id}/download?format=${format}`, { responseType: 'blob' }),
  exportScan: (scanId, format = 'json') => api.get(`/reports/export/${scanId}?format=${format}`, { responseType: 'blob' }),
  deleteReport: (id) => api.delete(`/reports/${id}`),
  getReportDetails: (id) => api.get(`/reports/${id}`)
};

// Dashboard API
export const dashboardAPI = {
  getStats: () => api.get('/dashboard/stats'),
  getVulnerabilityCharts: (params) => api.get('/dashboard/charts/vulnerabilities', { params }),
  getLeakCharts: (params) => api.get('/dashboard/charts/leaks', { params }),
  getActivity: (params) => api.get('/dashboard/activity', { params }),
};

// Users API
export const usersAPI = {
  getUsers: (params = {}) => {
    const queryString = new URLSearchParams(params).toString();
    return api.get(`/users${queryString ? `?${queryString}` : ''}`);
  },
  getUser: (id) => api.get(`/users/${id}`),
  createUser: (data) => api.post('/users', data),
  updateUser: (id, data) => api.put(`/users/${id}`, data),
  deleteUser: (id) => api.delete(`/users/${id}`),
  getUserActivity: (id) => api.get(`/users/${id}/activity`),
  getUserSessions: (id) => api.get(`/users/${id}/sessions`),
  revokeSession: (userId, sessionId) => api.delete(`/users/${userId}/sessions/${sessionId}`),
  updateUserRole: (id, role) => api.patch(`/users/${id}/role`, { role }),
  toggleUserStatus: (id) => api.patch(`/users/${id}/status`)
};

// Analytics API
export const analyticsAPI = {
  getAnalytics: (params = {}) => {
    const queryString = new URLSearchParams(params).toString();
    return api.get(`/analytics${queryString ? `?${queryString}` : ''}`);
  }
};

// Search API
export const searchAPI = {
  search: (query, type = 'all', limit = 20) => {
    const params = new URLSearchParams({ q: query, type, limit }).toString();
    return api.get(`/search?${params}`);
  }
};

// System API
export const systemAPI = {
  getHealth: () => api.get('/system/health')
};

// Notifications API
export const notificationsAPI = {
  getNotifications: (params = {}) => {
    const queryString = new URLSearchParams(params).toString();
    return api.get(`/notifications${queryString ? `?${queryString}` : ''}`);
  },
  markAsRead: (id) => api.patch(`/notifications/${id}/read`),
  markAllAsRead: () => api.patch('/notifications/mark-all-read')
};

export default api;
