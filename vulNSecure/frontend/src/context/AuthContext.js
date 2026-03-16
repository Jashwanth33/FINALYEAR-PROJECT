import React, { createContext, useContext, useState, useEffect } from 'react';
import { authAPI } from '../services/api';
import toast from 'react-hot-toast';

const AuthContext = createContext();

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};

export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);
  const [token, setToken] = useState(null);
  const [initialized, setInitialized] = useState(false);

  // Initialize token from localStorage on mount
  useEffect(() => {
    const storedToken = localStorage.getItem('token');
    if (storedToken) {
      setToken(storedToken);
    }
    setInitialized(true);
  }, []);

  // Fetch user when token is available and context is initialized
  useEffect(() => {
    const initializeAuth = async () => {
      if (initialized && token && !user) {
        console.log('🔐 AUTH CONTEXT - Initializing auth with token, fetching user');
        await fetchUser();
      } else if (initialized && !token) {
        console.log('🔐 AUTH CONTEXT - No token found, setting loading to false');
        setLoading(false);
      } else if (initialized && user) {
        console.log('🔐 AUTH CONTEXT - User already exists, setting loading to false');
        setLoading(false);
      }
    };

    initializeAuth();
  }, [initialized, token, user]); // Include user to properly handle state changes

  const fetchUser = async () => {
    console.log('🔐 AUTH CONTEXT - Fetching user data');
    setLoading(true); // Ensure loading is true while fetching
    try {
      const response = await authAPI.getMe();
      console.log('🔐 AUTH CONTEXT - User data received:', response.data?.data?.user);
      setUser(response.data?.data?.user);
    } catch (error) {
      console.error('🔐 AUTH CONTEXT - Failed to fetch user:', error);
      // Only logout on 401 errors, not network errors
      if (error.response?.status === 401) {
        console.log('🔐 AUTH CONTEXT - 401 error, logging out');
        logout();
      } else {
        // For network errors, just set loading to false
        console.log('🔐 AUTH CONTEXT - Network error, keeping user logged in');
      }
    } finally {
      setLoading(false);
    }
  };

  const login = async (email, password) => {
    try {
      console.log('🔐 AUTH CONTEXT - Login attempt:', email);
      const response = await authAPI.login(email, password);
      console.log('🔐 AUTH CONTEXT - API response:', response.data);
      
      const { user: userData, token: authToken } = response.data.data;
      console.log('🔐 AUTH CONTEXT - Extracted data:', { userData, authToken });
      
      // Update state in correct order
      setToken(authToken);
      localStorage.setItem('token', authToken);
      setUser(userData);
      
      console.log('🔐 AUTH CONTEXT - State updated, user:', userData);
      toast.success('Login successful');
      
      // Wait a brief moment for state to propagate
      await new Promise(resolve => setTimeout(resolve, 50));
      
      return { success: true };
    } catch (error) {
      console.error('🔐 AUTH CONTEXT - Login error:', error);
      const message = error.response?.data?.message || 'Login failed';
      toast.error(message);
      return { success: false, error: message };
    }
  };

  const register = async (userData) => {
    try {
      const response = await authAPI.register(userData);
      const { user: newUser, token: authToken } = response.data.data;
      
      setUser(newUser);
      setToken(authToken);
      localStorage.setItem('token', authToken);
      
      toast.success('Registration successful');
      return { success: true };
    } catch (error) {
      const message = error.response?.data?.message || 'Registration failed';
      toast.error(message);
      return { success: false, error: message };
    }
  };

  const logout = () => {
    console.log('🔐 AUTH CONTEXT - Logging out user');
    setUser(null);
    setToken(null);
    localStorage.removeItem('token');
    setLoading(false); // Ensure loading is false after logout
    toast.success('Logged out successfully');
  };

  const updateProfile = async (profileData) => {
    try {
      const response = await authAPI.updateProfile(profileData);
      setUser(response.data?.data?.user);
      toast.success('Profile updated successfully');
      return { success: true };
    } catch (error) {
      const message = error.response?.data?.message || 'Profile update failed';
      toast.error(message);
      return { success: false, error: message };
    }
  };

  const changePassword = async (currentPassword, newPassword) => {
    try {
      await authAPI.changePassword(currentPassword, newPassword);
      toast.success('Password changed successfully');
      return { success: true };
    } catch (error) {
      const message = error.response?.data?.message || 'Password change failed';
      toast.error(message);
      return { success: false, error: message };
    }
  };

  const value = {
    user,
    token,
    loading,
    login,
    register,
    logout,
    updateProfile,
    changePassword,
    isAuthenticated: !!user,
    isAdmin: user?.role === 'admin',
    isAnalyst: user?.role === 'analyst' || user?.role === 'admin',
  };

  return (
    <AuthContext.Provider value={value}>
      {children}
    </AuthContext.Provider>
  );
};
