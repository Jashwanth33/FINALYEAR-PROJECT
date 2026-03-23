import React from 'react';
import { useQuery, useMutation, useQueryClient } from 'react-query';
import { useNavigate } from 'react-router-dom';
import { dashboardAPI, scansAPI } from '../services/api';
import toast from 'react-hot-toast';
import { 
  Activity, 
  AlertTriangle, 
  Shield, 
  CheckCircle,
  Bell,
  Zap,
  Globe,
  Network
} from 'lucide-react';
import { ResponsiveContainer, PieChart, Pie, Cell, Tooltip } from 'recharts';

const Dashboard = () => {
  const navigate = useNavigate();
  const queryClient = useQueryClient();

  const { data: stats, isLoading: statsLoading, error: statsError, refetch } = useQuery(
    'dashboard-stats', 
    dashboardAPI.getStats,
    {
      retry: 1,
      refetchOnWindowFocus: true,
      refetchOnMount: true,
      staleTime: 0
    }
  );
  
  const { scans, vulnerabilities, leaks, recentScans, criticalVulnerabilities, unreadNotifications, securityScore, totalCVEs } = stats?.data?.data || {};

  const quickScanMutation = useMutation(
    (data) => scansAPI.createScan(data),
    {
      onSuccess: (data) => {
        toast.success('Quick scan started!');
        queryClient.invalidateQueries('scans');
        navigate('/scans');
      },
      onError: (error) => {
        toast.error(error.response?.data?.message || 'Failed to start scan');
      }
    }
  );

  const handleQuickScan = (type) => {
    const target = prompt('Enter target URL or IP:');
    if (target) {
      quickScanMutation.mutate({
        name: `Quick ${type} Scan - ${new Date().toLocaleDateString()}`,
        type: type,
        target: target
      });
    }
  };

  const getScoreColor = (score) => {
    if (score >= 80) return 'text-green-600';
    if (score >= 60) return 'text-yellow-600';
    if (score >= 40) return 'text-orange-600';
    return 'text-red-600';
  };

  const getScoreBg = (score) => {
    if (score >= 80) return 'bg-green-100';
    if (score >= 60) return 'bg-yellow-100';
    if (score >= 40) return 'bg-orange-100';
    return 'bg-red-100';
  };

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
    { name: 'Low', value: vulnerabilities?.low || 0, color: COLORS.low }
  ];

  const leakData = [
    { name: 'Critical', value: leaks?.critical || 0, color: COLORS.critical },
    { name: 'High', value: leaks?.high || 0, color: COLORS.high },
    { name: 'Medium', value: leaks?.medium || 0, color: COLORS.medium },
    { name: 'Low', value: leaks?.low || 0, color: COLORS.low }
  ];

  if (statsLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600"></div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-3xl font-bold text-gray-900">Dashboard</h1>
        <div className="flex items-center space-x-2 text-sm text-gray-500">
          <Bell className="h-4 w-4" />
          <span>{unreadNotifications || 0} notifications</span>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <div className={`p-6 rounded-lg ${getScoreBg(securityScore || 0)}`}>
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-gray-600">Security Score</p>
              <p className={`text-4xl font-bold ${getScoreColor(securityScore || 0)}`}>
                {securityScore || 0}
              </p>
              <p className="text-xs text-gray-500 mt-1">out of 100</p>
            </div>
            <Shield className={`h-16 w-16 ${getScoreColor(securityScore || 0)}`} />
          </div>
        </div>

        <div className="bg-gradient-to-br from-blue-500 to-blue-600 p-6 rounded-lg text-white">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-lg font-semibold">Quick Scan</h3>
            <Zap className="h-6 w-6" />
          </div>
          <div className="space-y-2">
            <button
              onClick={() => handleQuickScan('web')}
              disabled={quickScanMutation.isLoading}
              className="w-full bg-white/20 hover:bg-white/30 py-2 px-4 rounded flex items-center justify-center"
            >
              <Globe className="h-4 w-4 mr-2" />
              Web Application
            </button>
            <button
              onClick={() => handleQuickScan('network')}
              disabled={quickScanMutation.isLoading}
              className="w-full bg-white/20 hover:bg-white/30 py-2 px-4 rounded flex items-center justify-center"
            >
              <Activity className="h-4 w-4 mr-2" />
              Network Scan
            </button>
          </div>
        </div>

        <div className="bg-white p-6 rounded-lg border border-gray-200">
          <h3 className="text-lg font-semibold mb-4">Overview</h3>
          <div className="space-y-3">
            <div className="flex justify-between">
              <span className="text-gray-600">Total Scans</span>
              <span className="font-semibold">{scans?.total || 0}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-gray-600">Vulnerabilities</span>
              <span className="font-semibold text-red-600">
                {(vulnerabilities?.critical || 0) + (vulnerabilities?.high || 0)}
              </span>
            </div>
            <div className="flex justify-between">
              <span className="text-gray-600">CVE Database</span>
              <span className="font-semibold">{totalCVEs || 0}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-gray-600">Data Leaks</span>
              <span className="font-semibold">{leaks?.critical || 0}</span>
            </div>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="bg-white p-6 rounded-lg border border-gray-200">
          <h3 className="text-lg font-semibold mb-4">Vulnerability Distribution</h3>
          <ResponsiveContainer width="100%" height={250}>
            <PieChart>
              <Pie
                data={vulnData}
                cx="50%"
                cy="50%"
                innerRadius={60}
                outerRadius={80}
                paddingAngle={5}
                dataKey="value"
              >
                {vulnData.map((entry, index) => (
                  <Cell key={`cell-${index}`} fill={entry.color} />
                ))}
              </Pie>
              <Tooltip />
            </PieChart>
          </ResponsiveContainer>
          <div className="flex justify-center space-x-4 mt-4">
            {vulnData.map((entry) => (
              <div key={entry.name} className="flex items-center">
                <div className="w-3 h-3 rounded-full mr-2" style={{ backgroundColor: entry.color }}></div>
                <span className="text-sm">{entry.name}: {entry.value}</span>
              </div>
            ))}
          </div>
        </div>

        <div className="bg-white p-6 rounded-lg border border-gray-200">
          <h3 className="text-lg font-semibold mb-4">Recent Scans</h3>
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
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="bg-white p-6 rounded-lg border border-gray-200">
          <h3 className="text-lg font-semibold mb-4">Leak Distribution</h3>
          <ResponsiveContainer width="100%" height={200}>
            <PieChart>
              <Pie
                data={leakData}
                cx="50%"
                cy="50%"
                outerRadius={60}
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

        <div className="bg-white p-6 rounded-lg border border-gray-200">
          <h3 className="text-lg font-semibold mb-4">Critical Vulnerabilities</h3>
          <div className="space-y-3">
            {criticalVulnerabilities?.slice(0, 5).map((vuln) => (
              <div key={vuln.id} className="flex items-center justify-between p-3 bg-red-50 rounded-lg">
                <div>
                  <p className="font-medium text-gray-900">{vuln.title}</p>
                  <p className="text-sm text-gray-500">{vuln.description?.substring(0, 60)}...</p>
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
