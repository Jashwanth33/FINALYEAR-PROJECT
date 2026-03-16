import React, { useState, useEffect } from 'react';
import { useQuery, useMutation, useQueryClient } from 'react-query';
import { vulnerabilitiesAPI } from '../services/api';
import { 
  Shield, 
  AlertTriangle, 
  Info, 
  CheckCircle, 
  Search, 
  Filter, 
  Calendar,
  User,
  Target,
  Clock,
  TrendingUp,
  Eye,
  Edit3,
  X
} from 'lucide-react';

const Vulnerabilities = () => {
  const [filters, setFilters] = useState({
    search: '',
    severity: 'all',
    status: 'all',
    category: 'all'
  });
  const [sortBy, setSortBy] = useState('discoveredAt');
  const [sortOrder, setSortOrder] = useState('desc');
  const [selectedVuln, setSelectedVuln] = useState(null);
  const [showUpdateModal, setShowUpdateModal] = useState(false);
  const [updateData, setUpdateData] = useState({});

  const queryClient = useQueryClient();

  const { data: vulnsData, isLoading } = useQuery(
    ['vulnerabilities', filters, sortBy, sortOrder], 
    () => vulnerabilitiesAPI.getVulnerabilities({
      ...filters,
      sortBy,
      sortOrder
    })
  );

  const updateVulnMutation = useMutation(
    ({ id, data }) => vulnerabilitiesAPI.updateVulnerability(id, data),
    {
      onSuccess: () => {
        queryClient.invalidateQueries('vulnerabilities');
        setShowUpdateModal(false);
        setSelectedVuln(null);
      }
    }
  );

  // Debug logging
  useEffect(() => {
    console.log('🔍 VULNERABILITIES - Raw API response:', vulnsData);
    console.log('🔍 VULNERABILITIES - Response data:', vulnsData?.data);
    console.log('🔍 VULNERABILITIES - Response data.data:', vulnsData?.data?.data);
    console.log('🔍 VULNERABILITIES - Stats from API:', vulnsData?.data?.data?.stats);
    console.log('🔍 VULNERABILITIES - Vulnerabilities array:', vulnsData?.data?.data?.vulnerabilities);
  }, [vulnsData]);

  const vulnerabilities = vulnsData?.data?.data?.vulnerabilities || [];
  
  // Calculate stats from vulnerabilities if not provided by API
  const stats = vulnsData?.data?.data?.stats || {
    critical: vulnerabilities.filter(v => v.severity === 'critical').length,
    high: vulnerabilities.filter(v => v.severity === 'high').length,
    medium: vulnerabilities.filter(v => v.severity === 'medium').length,
    low: vulnerabilities.filter(v => v.severity === 'low').length
  };
  
  console.log('🔍 VULNERABILITIES - Final stats:', stats);
  console.log('🔍 VULNERABILITIES - Vulnerabilities count:', vulnerabilities.length);

  const getSeverityIcon = (severity) => {
    switch (severity) {
      case 'critical': return <AlertTriangle className="h-5 w-5 text-red-600" />;
      case 'high': return <AlertTriangle className="h-5 w-5 text-orange-600" />;
      case 'medium': return <AlertTriangle className="h-5 w-5 text-yellow-600" />;
      case 'low': return <Info className="h-5 w-5 text-green-600" />;
      default: return <Info className="h-5 w-5 text-blue-600" />;
    }
  };

  const getSeverityBadge = (severity) => {
    switch (severity) {
      case 'critical': return 'bg-red-100 text-red-800 border-red-200';
      case 'high': return 'bg-orange-100 text-orange-800 border-orange-200';
      case 'medium': return 'bg-yellow-100 text-yellow-800 border-yellow-200';
      case 'low': return 'bg-green-100 text-green-800 border-green-200';
      default: return 'bg-blue-100 text-blue-800 border-blue-200';
    }
  };

  const getStatusBadge = (status) => {
    switch (status) {
      case 'open': return 'bg-red-100 text-red-800 border-red-200';
      case 'in_progress': return 'bg-yellow-100 text-yellow-800 border-yellow-200';
      case 'resolved': return 'bg-green-100 text-green-800 border-green-200';
      default: return 'bg-gray-100 text-gray-800 border-gray-200';
    }
  };

  const handleFilterChange = (key, value) => {
    setFilters(prev => ({ ...prev, [key]: value }));
  };

  const handleSort = (field) => {
    if (sortBy === field) {
      setSortOrder(sortOrder === 'asc' ? 'desc' : 'asc');
    } else {
      setSortBy(field);
      setSortOrder('desc');
    }
  };

  const handleUpdateVuln = (vuln) => {
    setSelectedVuln(vuln);
    setUpdateData({
      status: vuln.status,
      assignedTo: vuln.remediation?.assignedTo || '',
      dueDate: vuln.remediation?.dueDate ? new Date(vuln.remediation.dueDate).toISOString().split('T')[0] : '',
      notes: vuln.remediation?.notes || ''
    });
    setShowUpdateModal(true);
  };

  const submitUpdate = () => {
    if (selectedVuln) {
      updateVulnMutation.mutate({
        id: selectedVuln.id,
        data: updateData
      });
    }
  };

  return (
    <div className="space-y-6">
      {/* Header with Stats */}
      <div className="flex items-center justify-between">
        <h1 className="text-3xl font-bold text-gray-900">Vulnerability Management</h1>
        <div className="grid grid-cols-4 gap-4 text-center">
          <div className="bg-red-50 p-3 rounded-lg border border-red-200">
            <div className="text-2xl font-bold text-red-600">{stats.critical || 0}</div>
            <div className="text-sm text-red-600">Critical</div>
          </div>
          <div className="bg-orange-50 p-3 rounded-lg border border-orange-200">
            <div className="text-2xl font-bold text-orange-600">{stats.high || 0}</div>
            <div className="text-sm text-orange-600">High</div>
          </div>
          <div className="bg-yellow-50 p-3 rounded-lg border border-yellow-200">
            <div className="text-2xl font-bold text-yellow-600">{stats.medium || 0}</div>
            <div className="text-sm text-yellow-600">Medium</div>
          </div>
          <div className="bg-green-50 p-3 rounded-lg border border-green-200">
            <div className="text-2xl font-bold text-green-600">{stats.low || 0}</div>
            <div className="text-sm text-green-600">Low</div>
          </div>
        </div>
      </div>

      {/* Filters and Search */}
      <div className="bg-white p-6 rounded-lg shadow-sm border border-gray-200">
        <div className="grid grid-cols-1 md:grid-cols-5 gap-4">
          <div className="relative">
            <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-gray-400" />
            <input
              type="text"
              placeholder="Search vulnerabilities..."
              className="pl-10 pr-4 py-2 w-full border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              value={filters.search}
              onChange={(e) => handleFilterChange('search', e.target.value)}
            />
          </div>
          
          <select
            className="px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
            value={filters.severity}
            onChange={(e) => handleFilterChange('severity', e.target.value)}
          >
            <option value="all">All Severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>

          <select
            className="px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
            value={filters.status}
            onChange={(e) => handleFilterChange('status', e.target.value)}
          >
            <option value="all">All Statuses</option>
            <option value="open">Open</option>
            <option value="in_progress">In Progress</option>
            <option value="resolved">Resolved</option>
          </select>

          <select
            className="px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
            value={filters.category}
            onChange={(e) => handleFilterChange('category', e.target.value)}
          >
            <option value="all">All Categories</option>
            <option value="injection">Injection</option>
            <option value="xss">Cross-Site Scripting</option>
            <option value="crypto">Cryptographic Issues</option>
            <option value="info_disclosure">Information Disclosure</option>
          </select>

          <select
            className="px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
            value={`${sortBy}-${sortOrder}`}
            onChange={(e) => {
              const [field, order] = e.target.value.split('-');
              setSortBy(field);
              setSortOrder(order);
            }}
          >
            <option value="discoveredAt-desc">Newest First</option>
            <option value="discoveredAt-asc">Oldest First</option>
            <option value="cvssScore-desc">Highest CVSS</option>
            <option value="cvssScore-asc">Lowest CVSS</option>
            <option value="severity-desc">Severity (High to Low)</option>
          </select>
        </div>
      </div>

      {/* Vulnerabilities List */}
      {isLoading ? (
        <div className="flex items-center justify-center h-64">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600"></div>
        </div>
      ) : (
        <div className="space-y-4">
          {vulnerabilities.map((vuln) => (
            <div key={vuln.id} className="bg-white p-6 rounded-lg shadow-sm border border-gray-200 hover:shadow-md transition-shadow">
              <div className="flex items-start justify-between">
                <div className="flex items-start space-x-4 flex-1">
                  {getSeverityIcon(vuln.severity)}
                  <div className="flex-1">
                    <div className="flex items-center space-x-3 mb-2">
                      <h3 className="text-lg font-semibold text-gray-900">{vuln.title}</h3>
                      <span className={`px-2 py-1 text-xs font-medium rounded-full border ${getSeverityBadge(vuln.severity)}`}>
                        {vuln.severity.toUpperCase()}
                      </span>
                      <span className={`px-2 py-1 text-xs font-medium rounded-full border ${getStatusBadge(vuln.status)}`}>
                        {vuln.status.replace('_', ' ').toUpperCase()}
                      </span>
                    </div>
                    
                    <p className="text-sm text-gray-600 mb-3">{vuln.description}</p>
                    
                    <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm text-gray-500 mb-3">
                      <div className="flex items-center space-x-1">
                        <Target className="h-4 w-4" />
                        <span>{vuln.target || vuln.scan?.target || 'N/A'}</span>
                      </div>
                      <div className="flex items-center space-x-1">
                        <TrendingUp className="h-4 w-4" />
                        <span>CVSS: {vuln.cvssScore || 'N/A'}</span>
                      </div>
                      <div className="flex items-center space-x-1">
                        <Clock className="h-4 w-4" />
                        <span>{vuln.discoveredAt ? new Date(vuln.discoveredAt).toLocaleDateString() : vuln.createdAt ? new Date(vuln.createdAt).toLocaleDateString() : 'N/A'}</span>
                      </div>
                      {vuln.remediation?.assignedTo && (
                        <div className="flex items-center space-x-1">
                          <User className="h-4 w-4" />
                          <span>{vuln.remediation.assignedTo}</span>
                        </div>
                      )}
                    </div>

                    {vuln.solution && (
                      <div className="bg-blue-50 p-3 rounded-lg border border-blue-200">
                        <h4 className="text-sm font-medium text-blue-900 mb-1">Recommended Solution:</h4>
                        <p className="text-sm text-blue-800">{vuln.solution}</p>
                      </div>
                    )}
                  </div>
                </div>
                
                <div className="flex items-center space-x-2 ml-4">
                  <button
                    onClick={() => handleUpdateVuln(vuln)}
                    className="p-2 text-gray-400 hover:text-blue-600 hover:bg-blue-50 rounded-lg transition-colors"
                    title="Update vulnerability"
                  >
                    <Edit3 className="h-4 w-4" />
                  </button>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Update Modal */}
      {showUpdateModal && selectedVuln && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-white rounded-lg p-6 w-full max-w-md">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-lg font-semibold">Update Vulnerability</h3>
              <button
                onClick={() => setShowUpdateModal(false)}
                className="text-gray-400 hover:text-gray-600"
              >
                <X className="h-5 w-5" />
              </button>
            </div>
            
            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">Status</label>
                <select
                  className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500"
                  value={updateData.status}
                  onChange={(e) => setUpdateData(prev => ({ ...prev, status: e.target.value }))}
                >
                  <option value="open">Open</option>
                  <option value="in_progress">In Progress</option>
                  <option value="resolved">Resolved</option>
                </select>
              </div>
              
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">Assigned To</label>
                <input
                  type="text"
                  className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500"
                  value={updateData.assignedTo}
                  onChange={(e) => setUpdateData(prev => ({ ...prev, assignedTo: e.target.value }))}
                  placeholder="Enter team or person"
                />
              </div>
              
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">Due Date</label>
                <input
                  type="date"
                  className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500"
                  value={updateData.dueDate}
                  onChange={(e) => setUpdateData(prev => ({ ...prev, dueDate: e.target.value }))}
                />
              </div>
              
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">Notes</label>
                <textarea
                  className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500"
                  rows="3"
                  value={updateData.notes}
                  onChange={(e) => setUpdateData(prev => ({ ...prev, notes: e.target.value }))}
                  placeholder="Add notes about remediation progress..."
                />
              </div>
            </div>
            
            <div className="flex justify-end space-x-3 mt-6">
              <button
                onClick={() => setShowUpdateModal(false)}
                className="px-4 py-2 text-gray-600 hover:text-gray-800"
              >
                Cancel
              </button>
              <button
                onClick={submitUpdate}
                disabled={updateVulnMutation.isLoading}
                className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50"
              >
                {updateVulnMutation.isLoading ? 'Updating...' : 'Update'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default Vulnerabilities;
