import React from 'react';
import { useQuery } from 'react-query';
import { dashboardAPI } from '../services/api';
import { 
  Activity, 
  AlertTriangle, 
  Shield, 
  CheckCircle,
  Bell
} from 'lucide-react';
import { ResponsiveContainer, PieChart, Pie, Cell, Tooltip } from 'recharts';

const Dashboard = () => {
  const { data: stats, isLoading: statsLoading, error: statsError, refetch } = useQuery(
    'dashboard-stats', 
    dashboardAPI.getStats,
    {
      retry: 1,
      refetchOnWindowFocus: true,
      refetchOnMount: true,
      staleTime: 0, // Always refetch
      onError: (error) => {
        console.error('📊 DASHBOARD - Query error:', error);
        console.error('📊 DASHBOARD - Error response:', error.response);
      }
    }
  );
  
  // Debug logging
  console.log('📊 DASHBOARD - Stats loading:', statsLoading);
  console.log('📊 DASHBOARD - Stats error:', statsError);
  console.log('📊 DASHBOARD - Stats data:', stats);
  console.log('📊 DASHBOARD - Extracted data:', stats?.data);
  console.log('📊 DASHBOARD - Token in localStorage:', localStorage.getItem('token'));
  
  // Check if we have an authentication error
  if (statsError?.response?.status === 401) {
    console.log('📊 DASHBOARD - Authentication error detected, token may be expired');
  }
  
  // Force refetch if we have a token but no data
  React.useEffect(() => {
    const token = localStorage.getItem('token');
    if (token && !stats && !statsLoading && !statsError) {
      console.log('📊 DASHBOARD - Have token but no data, forcing refetch');
      refetch();
    }
  }, [stats, statsLoading, statsError, refetch]);
  
  // Chart data queries (commented out for now to avoid unused variable warnings)
  // const { data: vulnCharts, isLoading: vulnLoading } = useQuery('vulnerability-charts', () => 
  //   dashboardAPI.getVulnerabilityCharts({ period: '30d' })
  // );
  // const { data: leakCharts, isLoading: leakLoading } = useQuery('leak-charts', () => 
  //   dashboardAPI.getLeakCharts({ period: '30d' })
  // );

  if (statsLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600"></div>
      </div>
    );
  }

  const { scans, vulnerabilities, leaks, recentScans, criticalVulnerabilities, unreadNotifications } = stats?.data?.data || {};

  // Debug logging
  console.log('Dashboard stats:', stats);
  console.log('Scans data:', scans);
  console.log('Vulnerabilities data:', vulnerabilities);
  console.log('Leaks data:', leaks);
  console.log('Recent scans:', recentScans);
  console.log('Critical vulnerabilities:', criticalVulnerabilities);

  const COLORS = {
    critical: '#ef4444',
    high: '#f97316',
    medium: '#eab308',
    low: '#22c55e',
    info: '#3b82f6'
  };

  const vulnData = [
    { name: 'Critical', value: vulnerabilities?.critical || 0, color: COLORS.critical },
    { name: 'High', value: vulnerabilities?.high || 0, color: COLORS.high },
    { name: 'Medium', value: vulnerabilities?.medium || 0, color: COLORS.medium },
    { name: 'Low', value: vulnerabilities?.low || 0, color: COLORS.low },
    { name: 'Info', value: vulnerabilities?.info || 0, color: COLORS.info },
  ];

  const leakData = [
    { name: 'Critical', value: leaks?.critical || 0, color: COLORS.critical },
    { name: 'High', value: leaks?.high || 0, color: COLORS.high },
    { name: 'Medium', value: leaks?.medium || 0, color: COLORS.medium },
    { name: 'Low', value: leaks?.low || 0, color: COLORS.low },
  ];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <h1 className="text-3xl font-bold text-gray-900">Dashboard</h1>
        <div className="flex items-center space-x-2 text-sm text-gray-500">
          <Bell className="h-4 w-4" />
          <span>{unreadNotifications || 0} unread notifications</span>
        </div>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <div className="card">
          <div className="flex items-center">
            <div className="p-2 bg-blue-100 rounded-lg">
              <Activity className="h-6 w-6 text-blue-600" />
            </div>
            <div className="ml-4">
              <p className="text-sm font-medium text-gray-500">Total Scans</p>
              <p className="text-2xl font-semibold text-gray-900">{scans?.total || 0}</p>
            </div>
          </div>
        </div>

        <div className="card">
          <div className="flex items-center">
            <div className="p-2 bg-red-100 rounded-lg">
              <AlertTriangle className="h-6 w-6 text-red-600" />
            </div>
            <div className="ml-4">
              <p className="text-sm font-medium text-gray-500">Critical Vulnerabilities</p>
              <p className="text-2xl font-semibold text-gray-900">{vulnerabilities?.critical || 0}</p>
            </div>
          </div>
        </div>

        <div className="card">
          <div className="flex items-center">
            <div className="p-2 bg-orange-100 rounded-lg">
              <Shield className="h-6 w-6 text-orange-600" />
            </div>
            <div className="ml-4">
              <p className="text-sm font-medium text-gray-500">High Severity Leaks</p>
              <p className="text-2xl font-semibold text-gray-900">{leaks?.high || 0}</p>
            </div>
          </div>
        </div>

        <div className="card">
          <div className="flex items-center">
            <div className="p-2 bg-green-100 rounded-lg">
              <CheckCircle className="h-6 w-6 text-green-600" />
            </div>
            <div className="ml-4">
              <p className="text-sm font-medium text-gray-500">Completed Scans</p>
              <p className="text-2xl font-semibold text-gray-900">{scans?.completed || 0}</p>
            </div>
          </div>
        </div>
      </div>

      {/* Charts */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Vulnerability Severity Chart */}
        <div className="card">
          <h3 className="text-lg font-semibold text-gray-900 mb-4">Vulnerability Severity Distribution</h3>
          <ResponsiveContainer width="100%" height={300}>
            <PieChart>
              <Pie
                data={vulnData}
                cx="50%"
                cy="50%"
                labelLine={false}
                label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
                outerRadius={80}
                fill="#8884d8"
                dataKey="value"
              >
                {vulnData.map((entry, index) => (
                  <Cell key={`cell-${index}`} fill={entry.color} />
                ))}
              </Pie>
              <Tooltip />
            </PieChart>
          </ResponsiveContainer>
        </div>

        {/* Leak Severity Chart */}
        <div className="card">
          <h3 className="text-lg font-semibold text-gray-900 mb-4">Data Leak Severity Distribution</h3>
          <ResponsiveContainer width="100%" height={300}>
            <PieChart>
              <Pie
                data={leakData}
                cx="50%"
                cy="50%"
                labelLine={false}
                label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
                outerRadius={80}
                fill="#8884d8"
                dataKey="value"
              >
                {leakData.map((entry, index) => (
                  <Cell key={`cell-${index}`} fill={entry.color} />
                ))}
              </Pie>
              <Tooltip />
            </PieChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Recent Activity */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Recent Scans */}
        <div className="card">
          <h3 className="text-lg font-semibold text-gray-900 mb-4">Recent Scans</h3>
          <div className="space-y-3">
            {recentScans?.slice(0, 5).map((scan) => (
              <div key={scan.id} className="flex items-center justify-between p-3 bg-gray-50 rounded-lg">
                <div>
                  <p className="font-medium text-gray-900">{scan.name}</p>
                  <p className="text-sm text-gray-500">{scan.target}</p>
                </div>
                <div className="flex items-center space-x-2">
                  <span className={`badge ${
                    scan.status === 'completed' ? 'badge-success' :
                    scan.status === 'running' ? 'badge-info' :
                    scan.status === 'failed' ? 'badge-danger' : 'badge-secondary'
                  }`}>
                    {scan.status}
                  </span>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Critical Vulnerabilities */}
        <div className="card">
          <h3 className="text-lg font-semibold text-gray-900 mb-4">Critical Vulnerabilities</h3>
          <div className="space-y-3">
            {criticalVulnerabilities?.slice(0, 5).map((vuln) => (
              <div key={vuln.id} className="flex items-center justify-between p-3 bg-red-50 rounded-lg">
                <div>
                  <p className="font-medium text-gray-900">{vuln.title}</p>
                  <p className="text-sm text-gray-500">{vuln.description.substring(0, 100)}...</p>
                </div>
                <span className="badge badge-critical">Critical</span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};

export default Dashboard;
