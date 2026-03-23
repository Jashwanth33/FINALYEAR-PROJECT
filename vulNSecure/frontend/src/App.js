import React, { useEffect } from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from 'react-query';
import { ReactQueryDevtools } from 'react-query/devtools';
import { Toaster } from 'react-hot-toast';
import { AuthProvider } from './context/AuthContext';
import { SidebarProvider } from './context/SidebarContext';
import ErrorBoundary from './components/ErrorBoundary';
import Layout from './components/Layout';
import Login from './pages/Login';
import Register from './pages/Register';
import Dashboard from './pages/Dashboard';
import Vulnerabilities from './pages/Vulnerabilities';
import VulnerabilityDetail from './pages/VulnerabilityDetail';
import Scans from './pages/Scans';
import CreateScan from './pages/CreateScan';
import ScanDetail from './pages/ScanDetail';
import Leaks from './pages/Leaks';
import Reports from './pages/Reports';
import Users from './pages/Users';
import Profile from './pages/Profile';
import BinaryAnalysis from './pages/BinaryAnalysis';
import NetworkScanner from './pages/NetworkScanner';
import AllFeatures from './pages/AllFeatures';
import ScheduledScans from './pages/ScheduledScans';
import Settings from './pages/Settings';
import ProtectedRoute from './components/ProtectedRoute';

// Create a client with error handling and retry logic
const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: (failureCount, error) => {
        // Don't retry on 4xx errors (client errors)
        if (error?.response?.status >= 400 && error?.response?.status < 500) {
          return false;
        }
        // Retry up to 3 times for other errors
        return failureCount < 3;
      },
      retryDelay: (attemptIndex) => Math.min(1000 * 2 ** attemptIndex, 30000),
      staleTime: 5 * 60 * 1000, // 5 minutes
      cacheTime: 10 * 60 * 1000, // 10 minutes
      refetchOnWindowFocus: false,
      onError: (error) => {
        console.error('Query error:', error);
        // You could show a toast notification here
      }
    },
    mutations: {
      retry: false,
      onError: (error) => {
        console.error('Mutation error:', error);
        // You could show a toast notification here
      }
    }
  }
});

function App() {
  // Global error handler to filter out WebSocket errors
  useEffect(() => {
    const originalConsoleError = console.error;
    
    // Override console.error to filter WebSocket errors
    console.error = (...args) => {
      const message = args.join(' ');
      
      // Filter out WebSocket connection errors
      if (
        message.includes('WebSocket connection') ||
        message.includes('ws://') ||
        message.includes('wss://') ||
        message.includes('WebSocket is closed') ||
        message.includes('ERR_CONNECTION_REFUSED') ||
        message.includes('socket')
      ) {
        // Silent - don't show WebSocket errors to users
        return;
      }
      
      originalConsoleError.apply(console, args);
    };
    
    // Handle uncaught WebSocket errors
    window.addEventListener('error', (event) => {
      if (
        event.message?.includes?.('WebSocket') ||
        event.message?.includes?.('ws://') ||
        event.error?.message?.includes?.('WebSocket')
      ) {
        event.preventDefault();
        return false;
      }
    });
    
    return () => {
      console.error = originalConsoleError;
    };
  }, []);

  return (
    <ErrorBoundary>
      <QueryClientProvider client={queryClient}>
        <AuthProvider>
          <SidebarProvider>
            <Toaster 
              position="top-right"
              toastOptions={{
                duration: 4000,
                style: {
                  background: '#363636',
                  color: '#fff',
                },
              }}
            />
            <Router
              future={{
                v7_startTransition: true,
                v7_relativeSplatPath: true,
              }}
            >
              <div className="App">
                <Routes>
                  <Route path="/login" element={<Login />} />
                  <Route path="/register" element={<Register />} />
                  <Route path="/" element={
                    <ProtectedRoute>
                      <Layout />
                    </ProtectedRoute>
                  }>
                    <Route index element={<Navigate to="/dashboard" replace />} />
                    <Route path="dashboard" element={<Dashboard />} />
                    <Route path="vulnerabilities" element={<Vulnerabilities />} />
                    <Route path="vulnerabilities/:id" element={<VulnerabilityDetail />} />
                    <Route path="scans" element={<Scans />} />
                    <Route path="scans/create" element={<CreateScan />} />
                    <Route path="scans/:id" element={<ScanDetail />} />
                    <Route path="scheduled" element={<ScheduledScans />} />
                    <Route path="settings" element={<Settings />} />
                    <Route path="leaks" element={<Leaks />} />
                    <Route path="reports" element={<Reports />} />
                    <Route path="binary" element={<BinaryAnalysis />} />
                    <Route path="network" element={<NetworkScanner />} />
                    <Route path="features" element={<AllFeatures />} />
                    <Route path="compliance" element={<AllFeatures />} />
                    <Route path="darkweb" element={<AllFeatures />} />
                    <Route path="supplychain" element={<AllFeatures />} />
                    <Route path="cicd" element={<AllFeatures />} />
                    <Route path="team" element={<AllFeatures />} />
                    <Route path="users" element={<Users />} />
                    <Route path="profile" element={<Profile />} />
                  </Route>
                  <Route path="*" element={<Navigate to="/dashboard" replace />} />
                </Routes>
              </div>
            </Router>
          </SidebarProvider>
        </AuthProvider>
        {process.env.NODE_ENV === 'development' && <ReactQueryDevtools initialIsOpen={false} />}
      </QueryClientProvider>
    </ErrorBoundary>
  );
}

export default App;
