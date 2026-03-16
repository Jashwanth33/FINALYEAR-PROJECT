import React from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from 'react-query';
import { ReactQueryDevtools } from 'react-query/devtools';
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
  return (
    <ErrorBoundary>
      <QueryClientProvider client={queryClient}>
        <AuthProvider>
          <SidebarProvider>
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
                    <Route path="leaks" element={<Leaks />} />
                    <Route path="reports" element={<Reports />} />
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
