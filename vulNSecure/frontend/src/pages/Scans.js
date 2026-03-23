import React, { useState, useEffect } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { useQuery, useMutation, useQueryClient } from 'react-query';
import { scansAPI } from '../services/api';
import { 
  Plus, Search, Play, Pause, Trash2, Eye, Filter, 
  SortAsc, SortDesc, RefreshCw, Download, Calendar,
  Network, Globe, Moon, Shield, AlertTriangle
} from 'lucide-react';

const Scans = () => {
  const navigate = useNavigate();
  const [searchTerm, setSearchTerm] = useState('');
  const [statusFilter, setStatusFilter] = useState('all');
  const [typeFilter, setTypeFilter] = useState('all');
  const [sortBy, setSortBy] = useState('desc');
  const [sortOrder, setSortOrder] = useState('desc');
  const [showNewScanModal, setShowNewScanModal] = useState(false);
  
  const queryClient = useQueryClient();
  
  const { data: scansData, isLoading, refetch } = useQuery(
    ['scans', { search: searchTerm, status: statusFilter, type: typeFilter, sortBy, sortOrder }],
    () => scansAPI.getScans({ search: searchTerm, status: statusFilter, type: typeFilter, sortBy, sortOrder }),
    {
      refetchInterval: 5000, // Refresh every 5 seconds for real-time updates
      refetchIntervalInBackground: true
    }
  );
  
  // Add debugging for scans data
  useEffect(() => {
    console.log('🔍 SCANS - Raw API response:', scansData);
    console.log('🔍 SCANS - Response data:', scansData?.data);
    console.log('🔍 SCANS - Extracted scans:', scansData?.data?.data?.scans);
    console.log('🔍 SCANS - Scans length:', scansData?.data?.data?.scans?.length);
  }, [scansData]);
  
  const scans = scansData?.data?.data?.scans || [];
  const pagination = scansData?.data?.data?.pagination || {};

  const deleteScanMutation = useMutation(
    (scanId) => scansAPI.deleteScan(scanId),
    {
      onSuccess: () => {
        toast.success('Scan deleted successfully');
        queryClient.invalidateQueries('scans');
      },
      onError: (error) => {
        toast.error(error.response?.data?.message || 'Failed to delete scan');
      }
    }
  );

  const pauseScanMutation = useMutation(
    (scanId) => scansAPI.pauseScan(scanId),
    {
      onSuccess: () => {
        queryClient.invalidateQueries('scans');
      }
    }
  );

  const getStatusColor = (status) => {
    switch (status) {
      case 'completed': return 'bg-green-100 text-green-800 border-green-200';
      case 'running': return 'bg-blue-100 text-blue-800 border-blue-200';
      case 'failed': return 'bg-red-100 text-red-800 border-red-200';
      case 'pending': return 'bg-yellow-100 text-yellow-800 border-yellow-200';
      case 'paused': return 'bg-gray-100 text-gray-800 border-gray-200';
      default: return 'bg-gray-100 text-gray-800 border-gray-200';
    }
  };

  const getTypeIcon = (type) => {
    switch (type) {
      case 'network': return <Network className="h-5 w-5 text-blue-600" />;
      case 'web': return <Globe className="h-5 w-5 text-green-600" />;
      case 'darkweb': return <Moon className="h-5 w-5 text-purple-600" />;
      default: return <Shield className="h-5 w-5 text-gray-600" />;
    }
  };

  const getSeverityStats = (scan) => {
    if (!scan.results) return null;
    const { critical = 0, high = 0, medium = 0, low = 0 } = scan.results;
    return { critical, high, medium, low, total: critical + high + medium + low };
  };

  const handleSort = (field) => {
    if (sortBy === field) {
      setSortOrder(sortOrder === 'asc' ? 'desc' : 'asc');
    } else {
      setSortBy(field);
      setSortOrder('desc');
    }
  };

  const filteredScans = scans.filter(scan => {
    const matchesSearch = scan.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
                         scan.target.toLowerCase().includes(searchTerm.toLowerCase());
    const matchesStatus = statusFilter === 'all' || scan.status === statusFilter;
    const matchesType = typeFilter === 'all' || scan.type === typeFilter;
    return matchesSearch && matchesStatus && matchesType;
  });

  const NewScanModal = () => {
    const [scanData, setScanData] = useState({
      name: '',
      type: 'network',
      target: '',
      description: ''
    });

    // Add debugging to track state changes
    useEffect(() => {
      console.log('🔍 Scan data state changed:', scanData);
    }, [scanData]);

    const createScanMutation = useMutation(
      (data) => scansAPI.createScan(data),
      {
        onSuccess: (response) => {
          console.log('Scan created successfully:', response);
          // Reset form data first
          setScanData({ name: '', type: 'network', target: '', description: '' });
          // Close modal
          setShowNewScanModal(false);
          // Refresh scans list
          queryClient.invalidateQueries('scans');
        },
        onError: (error) => {
          console.error('Failed to create scan:', error);
          // Don't close modal on error so user can retry
        }
      }
    );

    const handleInputChange = (field, value) => {
      console.log(`🔍 Input change - ${field}:`, value);
      setScanData(prevData => {
        const newData = { ...prevData, [field]: value };
        console.log('🔍 New scan data:', newData);
        return newData;
      });
    };

    const handleSubmit = (e) => {
      e.preventDefault();
      
      // Validate required fields
      if (!scanData.name.trim() || !scanData.target.trim()) {
        alert('Please fill in all required fields (Name and Target)');
        return;
      }
      
      console.log('Submitting scan data:', scanData);
      createScanMutation.mutate(scanData);
    };

    if (!showNewScanModal) return null;

    return (
      <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
        <div className="bg-white rounded-lg p-6 w-full max-w-md">
          <h2 className="text-xl font-bold mb-4">Create New Scan</h2>
          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">Scan Name</label>
              <input
                type="text"
                value={scanData.name}
                onChange={(e) => handleInputChange('name', e.target.value)}
                className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 text-gray-900 bg-white placeholder-gray-400"
                style={{ color: '#111827', backgroundColor: '#ffffff', opacity: 1 }}
                placeholder="Enter scan name"
                required
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">Scan Type</label>
              <select
                value={scanData.type}
                onChange={(e) => handleInputChange('type', e.target.value)}
                className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 text-gray-900 bg-white"
                style={{ color: '#111827', backgroundColor: '#ffffff', opacity: 1 }}
              >
                <option value="network">Network Scan</option>
                <option value="web">Web Application Scan</option>
                <option value="darkweb">Dark Web Monitoring</option>
              </select>
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">Target</label>
              <input
                type="text"
                value={scanData.target}
                onChange={(e) => handleInputChange('target', e.target.value)}
                placeholder="e.g., 192.168.1.0/24, https://example.com, domain.com"
                className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 text-gray-900 bg-white placeholder-gray-400"
                style={{ color: '#111827', backgroundColor: '#ffffff', opacity: 1 }}
                required
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">Description</label>
              <textarea
                value={scanData.description}
                onChange={(e) => handleInputChange('description', e.target.value)}
                className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 text-gray-900 bg-white placeholder-gray-400 resize-none"
                style={{ color: '#111827', backgroundColor: '#ffffff', opacity: 1 }}
                placeholder="Optional description for this scan"
                rows="3"
              />
            </div>
            <div className="flex justify-end space-x-3">
              <button
                type="button"
                onClick={() => setShowNewScanModal(false)}
                className="px-4 py-2 text-gray-600 hover:text-gray-800"
              >
                Cancel
              </button>
              <button
                type="submit"
                disabled={createScanMutation.isLoading}
                className="px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 disabled:opacity-50"
              >
                {createScanMutation.isLoading ? 'Creating...' : 'Create Scan'}
              </button>
            </div>
          </form>
        </div>
      </div>
    );
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <h1 className="text-3xl font-bold text-gray-900">Security Scans</h1>
        <div className="flex items-center space-x-3">
          <button
            onClick={() => refetch()}
            className="flex items-center px-3 py-2 text-gray-600 hover:text-gray-800 border border-gray-300 rounded-md hover:bg-gray-50"
          >
            <RefreshCw className="h-4 w-4 mr-2" />
            Refresh
          </button>
          <button
            onClick={() => navigate('/scans/create')}
            className="flex items-center px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700"
          >
            <Plus className="h-5 w-5 mr-2" />
            New Scan
          </button>
        </div>
      </div>

      {/* Filters and Search */}
      <div className="bg-white p-4 rounded-lg shadow-sm border border-gray-200">
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <div className="relative">
            <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-gray-400" />
            <input
              type="text"
              placeholder="Search scans..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="w-full pl-10 pr-4 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
            />
          </div>
          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
          >
            <option value="all">All Statuses</option>
            <option value="running">Running</option>
            <option value="completed">Completed</option>
            <option value="failed">Failed</option>
            <option value="pending">Pending</option>
            <option value="paused">Paused</option>
          </select>
          <select
            value={typeFilter}
            onChange={(e) => setTypeFilter(e.target.value)}
            className="px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
          >
            <option value="all">All Types</option>
            <option value="network">Network</option>
            <option value="web">Web Application</option>
            <option value="darkweb">Dark Web</option>
          </select>
          <select
            value={`${sortBy}-${sortOrder}`}
            onChange={(e) => {
              const [field, order] = e.target.value.split('-');
              setSortBy(field);
              setSortOrder(order);
            }}
            className="px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
          >
            <option value="createdAt-desc">Newest First</option>
            <option value="createdAt-asc">Oldest First</option>
            <option value="name-asc">Name A-Z</option>
            <option value="name-desc">Name Z-A</option>
            <option value="status-asc">Status A-Z</option>
          </select>
        </div>
      </div>

      {/* Scans List */}
      {isLoading ? (
        <div className="flex items-center justify-center h-64">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600"></div>
        </div>
      ) : filteredScans.length === 0 ? (
        <div className="text-center py-12">
          <Shield className="mx-auto h-12 w-12 text-gray-400" />
          <h3 className="mt-2 text-sm font-medium text-gray-900">No scans found</h3>
          <p className="mt-1 text-sm text-gray-500">
            {searchTerm || statusFilter !== 'all' || typeFilter !== 'all'
              ? 'Try adjusting your filters'
              : 'Get started by creating a new security scan'}
          </p>
        </div>
      ) : (
        <div className="space-y-4">
          {filteredScans.map((scan) => {
            const severityStats = getSeverityStats(scan);
            return (
              <div key={scan.id} className="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
                <div className="flex items-start justify-between">
                  <div className="flex items-start space-x-4 flex-1">
                    <div className="flex-shrink-0 mt-1">
                      {getTypeIcon(scan.type)}
                    </div>
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center space-x-3 mb-2">
                        <h3 className="text-lg font-semibold text-gray-900 truncate">
                          {scan.name}
                        </h3>
                        <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium border ${getStatusColor(scan.status)}`}>
                          {scan.status}
                        </span>
                      </div>
                      <div className="space-y-1 text-sm text-gray-600">
                        <p><span className="font-medium">Target:</span> {scan.target}</p>
                        <p><span className="font-medium">Type:</span> {scan.type.charAt(0).toUpperCase() + scan.type.slice(1)}</p>
                        <p><span className="font-medium">Started:</span> {new Date(scan.createdAt).toLocaleString()}</p>
                        {scan.user && (
                          <p><span className="font-medium">By:</span> {scan.user.firstName} {scan.user.lastName}</p>
                        )}
                      </div>
                      
                      {/* Progress Bar */}
                      {scan.status === 'running' && scan.progress !== undefined && (
                        <div className="mt-4">
                          <div className="flex justify-between text-sm text-gray-600 mb-1">
                            <span>Progress</span>
                            <span>{scan.progress}%</span>
                          </div>
                          <div className="w-full bg-gray-200 rounded-full h-2">
                            <div
                              className="bg-blue-600 h-2 rounded-full transition-all duration-300"
                              style={{ width: `${scan.progress}%` }}
                            ></div>
                          </div>
                        </div>
                      )}

                      {/* Severity Stats */}
                      {severityStats && severityStats.total > 0 && (
                        <div className="mt-4 flex items-center space-x-4 text-sm">
                          <span className="font-medium text-gray-700">Findings:</span>
                          {severityStats.critical > 0 && (
                            <span className="flex items-center text-red-600">
                              <AlertTriangle className="h-3 w-3 mr-1" />
                              {severityStats.critical} Critical
                            </span>
                          )}
                          {severityStats.high > 0 && (
                            <span className="text-orange-600">{severityStats.high} High</span>
                          )}
                          {severityStats.medium > 0 && (
                            <span className="text-yellow-600">{severityStats.medium} Medium</span>
                          )}
                          {severityStats.low > 0 && (
                            <span className="text-blue-600">{severityStats.low} Low</span>
                          )}
                        </div>
                      )}
                    </div>
                  </div>
                  
                  {/* Actions */}
                  <div className="flex items-center space-x-2 ml-4">
                    <Link
                      to={`/scans/${scan.id}`}
                      className="p-2 text-gray-500 hover:text-blue-600 hover:bg-blue-50 rounded-md transition-colors"
                      title="View Details"
                    >
                      <Eye className="h-4 w-4" />
                    </Link>
                    {scan.status === 'running' && (
                      <button
                        onClick={() => pauseScanMutation.mutate(scan.id)}
                        className="p-2 text-gray-500 hover:text-orange-600 hover:bg-orange-50 rounded-md transition-colors"
                        title="Pause Scan"
                        disabled={pauseScanMutation.isLoading}
                      >
                        <Pause className="h-4 w-4" />
                      </button>
                    )}
                    {scan.status === 'completed' && (
                      <button
                        className="p-2 text-gray-500 hover:text-green-600 hover:bg-green-50 rounded-md transition-colors"
                        title="Download Report"
                        onClick={() => {
                          toast.success('Report download started');
                          // Navigate to reports or trigger download
                          navigate('/reports');
                        }}
                      >
                        <Download className="h-4 w-4" />
                      </button>
                    )}
                    <button
                      onClick={() => {
                        if (window.confirm('Are you sure you want to delete this scan?')) {
                          deleteScanMutation.mutate(scan.id);
                        }
                      }}
                      className="p-2 text-gray-500 hover:text-red-600 hover:bg-red-50 rounded-md transition-colors"
                      title="Delete Scan"
                      disabled={deleteScanMutation.isLoading}
                    >
                      <Trash2 className="h-4 w-4" />
                    </button>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      )}

      {/* Pagination */}
      {pagination.pages > 1 && (
        <div className="flex items-center justify-between">
          <div className="text-sm text-gray-700">
            Showing {((pagination.page - 1) * pagination.limit) + 1} to{' '}
            {Math.min(pagination.page * pagination.limit, pagination.total)} of{' '}
            {pagination.total} results
          </div>
          <div className="flex space-x-2">
            {/* Pagination buttons would go here */}
          </div>
        </div>
      )}

      <NewScanModal />
    </div>
  );
};

export default Scans;
