import React, { useState, useEffect } from 'react';
import { useQuery, useMutation, useQueryClient } from 'react-query';
import { 
  ExclamationTriangleIcon, 
  ShieldExclamationIcon, 
  InformationCircleIcon,
  MagnifyingGlassIcon,
  FunnelIcon,
  BellIcon,
  CheckCircleIcon,
  XCircleIcon,
  ClockIcon,
  EyeIcon,
  ArrowsUpDownIcon
} from '@heroicons/react/24/outline';
import { leaksAPI } from '../services/api';

const Leaks = () => {
  const [searchTerm, setSearchTerm] = useState('');
  const [filters, setFilters] = useState({
    severity: 'all',
    classification: 'all',
    status: 'all',
    source: 'all'
  });
  const [sortBy, setSortBy] = useState('discoveredAt');
  const [sortOrder, setSortOrder] = useState('desc');
  const [selectedLeak, setSelectedLeak] = useState(null);
  const [showFilters, setShowFilters] = useState(false);
  const [showAlertModal, setShowAlertModal] = useState(false);
  const [alertForm, setAlertForm] = useState({ recipients: '', message: '' });

  const queryClient = useQueryClient();

  const { data: leaksData, isLoading, error } = useQuery(
    ['leaks', searchTerm, filters, sortBy, sortOrder],
    () => leaksAPI.getLeaks({ search: searchTerm, ...filters, sortBy, sortOrder }),
    { refetchInterval: 30000 }
  );

  const updateLeakMutation = useMutation(
    ({ id, data }) => leaksAPI.updateLeak(id, data),
    {
      onSuccess: () => {
        queryClient.invalidateQueries(['leaks']);
        setSelectedLeak(null);
      }
    }
  );

  const sendAlertMutation = useMutation(
    ({ id, data }) => leaksAPI.sendAlert(id, data),
    {
      onSuccess: () => {
        queryClient.invalidateQueries(['leaks']);
        setShowAlertModal(false);
        setAlertForm({ recipients: '', message: '' });
      }
    }
  );

  // Debug logging - must be before any early returns
  useEffect(() => {
    console.log('🔍 LEAKS - Raw API response:', leaksData);
    console.log('🔍 LEAKS - Response data:', leaksData?.data);
    console.log('🔍 LEAKS - Response data.data:', leaksData?.data?.data);
    console.log('🔍 LEAKS - Stats from API:', leaksData?.data?.data?.stats);
    console.log('🔍 LEAKS - Leaks array:', leaksData?.data?.data?.leaks);
  }, [leaksData]);

  const getSeverityIcon = (severity) => {
    switch (severity) {
      case 'critical':
        return <ExclamationTriangleIcon className="h-5 w-5 text-red-500" />;
      case 'high':
        return <ShieldExclamationIcon className="h-5 w-5 text-orange-500" />;
      case 'medium':
        return <InformationCircleIcon className="h-5 w-5 text-yellow-500" />;
      case 'low':
        return <InformationCircleIcon className="h-5 w-5 text-blue-500" />;
      default:
        return <InformationCircleIcon className="h-5 w-5 text-gray-500" />;
    }
  };

  const getSeverityBadge = (severity) => {
    const colors = {
      critical: 'bg-red-100 text-red-800',
      high: 'bg-orange-100 text-orange-800',
      medium: 'bg-yellow-100 text-yellow-800',
      low: 'bg-blue-100 text-blue-800'
    };
    return colors[severity] || 'bg-gray-100 text-gray-800';
  };

  const getStatusIcon = (status) => {
    switch (status) {
      case 'active':
        return <ExclamationTriangleIcon className="h-4 w-4 text-red-500" />;
      case 'mitigated':
        return <ClockIcon className="h-4 w-4 text-yellow-500" />;
      case 'resolved':
        return <CheckCircleIcon className="h-4 w-4 text-green-500" />;
      default:
        return <XCircleIcon className="h-4 w-4 text-gray-500" />;
    }
  };

  const getStatusBadge = (status) => {
    const colors = {
      active: 'bg-red-100 text-red-800',
      mitigated: 'bg-yellow-100 text-yellow-800',
      resolved: 'bg-green-100 text-green-800'
    };
    return colors[status] || 'bg-gray-100 text-gray-800';
  };

  const handleStatusUpdate = (leakId, newStatus) => {
    updateLeakMutation.mutate({
      id: leakId,
      data: { status: newStatus }
    });
  };

  const handleSendAlert = (leak) => {
    setSelectedLeak(leak);
    setShowAlertModal(true);
  };

  const submitAlert = () => {
    if (selectedLeak) {
      sendAlertMutation.mutate({
        id: selectedLeak.id,
        data: {
          recipients: alertForm.recipients.split(',').map(r => r.trim()),
          message: alertForm.message
        }
      });
    }
  };

  const formatDate = (dateString) => {
    return new Date(dateString).toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    });
  };

  const formatEntities = (entities) => {
    if (!entities) return 'N/A';
    
    return Object.entries(entities).map(([key, value]) => {
      const count = Array.isArray(value) ? value.length : (typeof value === 'number' ? value : 1);
      return `${count} ${key.replace('_', ' ')}`;
    }).join(', ');
  };

  if (isLoading) {
    return (
      <div className="flex justify-center items-center h-64">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600"></div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="bg-red-50 border border-red-200 rounded-md p-4">
        <div className="flex">
          <XCircleIcon className="h-5 w-5 text-red-400" />
          <div className="ml-3">
            <h3 className="text-sm font-medium text-red-800">Error loading leaks</h3>
            <p className="mt-1 text-sm text-red-700">{error.message}</p>
          </div>
        </div>
      </div>
    );
  }

  const leaks = leaksData?.data?.data?.leaks || [];
  
  // Calculate stats from leaks if not provided by API
  const stats = leaksData?.data?.data?.stats || {
    critical: leaks.filter(l => l.severity === 'critical').length,
    active: leaks.filter(l => !l.isProcessed || !l.isVerified).length,
    resolved: leaks.filter(l => l.isProcessed && l.isVerified).length,
    total_entities: leaks.reduce((sum, leak) => {
      const entities = leak.entities || {};
      if (typeof entities === 'object' && entities !== null) {
        return sum + (entities.total || Object.keys(entities).length || 0);
      }
      return sum;
    }, 0)
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Data Leak Protection</h1>
          <p className="mt-1 text-sm text-gray-500">
            Monitor and respond to data leaks across the web
          </p>
        </div>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="bg-white overflow-hidden shadow rounded-lg">
          <div className="p-5">
            <div className="flex items-center">
              <div className="flex-shrink-0">
                <ExclamationTriangleIcon className="h-6 w-6 text-red-500" />
              </div>
              <div className="ml-5 w-0 flex-1">
                <dl>
                  <dt className="text-sm font-medium text-gray-500 truncate">Critical Leaks</dt>
                  <dd className="text-lg font-medium text-gray-900">{stats.critical || 0}</dd>
                </dl>
              </div>
            </div>
          </div>
        </div>

        <div className="bg-white overflow-hidden shadow rounded-lg">
          <div className="p-5">
            <div className="flex items-center">
              <div className="flex-shrink-0">
                <ClockIcon className="h-6 w-6 text-yellow-500" />
              </div>
              <div className="ml-5 w-0 flex-1">
                <dl>
                  <dt className="text-sm font-medium text-gray-500 truncate">Active Leaks</dt>
                  <dd className="text-lg font-medium text-gray-900">{stats.active || 0}</dd>
                </dl>
              </div>
            </div>
          </div>
        </div>

        <div className="bg-white overflow-hidden shadow rounded-lg">
          <div className="p-5">
            <div className="flex items-center">
              <div className="flex-shrink-0">
                <CheckCircleIcon className="h-6 w-6 text-green-500" />
              </div>
              <div className="ml-5 w-0 flex-1">
                <dl>
                  <dt className="text-sm font-medium text-gray-500 truncate">Resolved</dt>
                  <dd className="text-lg font-medium text-gray-900">{stats.resolved || 0}</dd>
                </dl>
              </div>
            </div>
          </div>
        </div>

        <div className="bg-white overflow-hidden shadow rounded-lg">
          <div className="p-5">
            <div className="flex items-center">
              <div className="flex-shrink-0">
                <ShieldExclamationIcon className="h-6 w-6 text-blue-500" />
              </div>
              <div className="ml-5 w-0 flex-1">
                <dl>
                  <dt className="text-sm font-medium text-gray-500 truncate">Total Entities</dt>
                  <dd className="text-lg font-medium text-gray-900">{stats.total_entities || 0}</dd>
                </dl>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Search and Filters */}
      <div className="bg-white shadow rounded-lg p-6">
        <div className="flex flex-col sm:flex-row gap-4">
          <div className="flex-1">
            <div className="relative">
              <MagnifyingGlassIcon className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-gray-400" />
              <input
                type="text"
                placeholder="Search leaks..."
                className="pl-10 pr-4 py-2 w-full border border-gray-300 rounded-md focus:ring-blue-500 focus:border-blue-500"
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
              />
            </div>
          </div>
          
          <button
            onClick={() => setShowFilters(!showFilters)}
            className="inline-flex items-center px-4 py-2 border border-gray-300 rounded-md shadow-sm text-sm font-medium text-gray-700 bg-white hover:bg-gray-50"
          >
            <FunnelIcon className="h-4 w-4 mr-2" />
            Filters
          </button>

          <div className="flex items-center space-x-2">
            <ArrowsUpDownIcon className="h-4 w-4 text-gray-400" />
            <select
              value={`${sortBy}-${sortOrder}`}
              onChange={(e) => {
                const [field, order] = e.target.value.split('-');
                setSortBy(field);
                setSortOrder(order);
              }}
              className="border border-gray-300 rounded-md px-3 py-2 text-sm"
            >
              <option value="discoveredAt-desc">Latest First</option>
              <option value="discoveredAt-asc">Oldest First</option>
              <option value="severity-desc">Severity High-Low</option>
              <option value="confidence-desc">Confidence High-Low</option>
            </select>
          </div>
        </div>

        {showFilters && (
          <div className="mt-4 grid grid-cols-1 sm:grid-cols-4 gap-4 pt-4 border-t border-gray-200">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">Severity</label>
              <select
                value={filters.severity}
                onChange={(e) => setFilters({ ...filters, severity: e.target.value })}
                className="w-full border border-gray-300 rounded-md px-3 py-2 text-sm"
              >
                <option value="all">All Severities</option>
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
              </select>
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">Classification</label>
              <select
                value={filters.classification}
                onChange={(e) => setFilters({ ...filters, classification: e.target.value })}
                className="w-full border border-gray-300 rounded-md px-3 py-2 text-sm"
              >
                <option value="all">All Types</option>
                <option value="financial">Financial</option>
                <option value="pii">PII</option>
                <option value="credentials">Credentials</option>
                <option value="corporate">Corporate</option>
              </select>
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">Status</label>
              <select
                value={filters.status}
                onChange={(e) => setFilters({ ...filters, status: e.target.value })}
                className="w-full border border-gray-300 rounded-md px-3 py-2 text-sm"
              >
                <option value="all">All Statuses</option>
                <option value="active">Active</option>
                <option value="mitigated">Mitigated</option>
                <option value="resolved">Resolved</option>
              </select>
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">Source</label>
              <select
                value={filters.source}
                onChange={(e) => setFilters({ ...filters, source: e.target.value })}
                className="w-full border border-gray-300 rounded-md px-3 py-2 text-sm"
              >
                <option value="all">All Sources</option>
                <option value="dark web">Dark Web</option>
                <option value="pastebin">Pastebin</option>
                <option value="github">GitHub</option>
                <option value="forum">Forums</option>
              </select>
            </div>
          </div>
        )}
      </div>

      {/* Leaks List */}
      <div className="bg-white shadow overflow-hidden sm:rounded-md">
        {leaks.length === 0 ? (
          <div className="text-center py-12">
            <ShieldExclamationIcon className="mx-auto h-12 w-12 text-gray-400" />
            <h3 className="mt-2 text-sm font-medium text-gray-900">No leaks found</h3>
            <p className="mt-1 text-sm text-gray-500">
              {searchTerm || Object.values(filters).some(f => f !== 'all') 
                ? 'Try adjusting your search or filters.' 
                : 'No data leaks detected at this time.'}
            </p>
          </div>
        ) : (
          <ul className="divide-y divide-gray-200">
            {leaks.map((leak) => (
              <li key={leak.id} className="px-6 py-4 hover:bg-gray-50">
                <div className="flex items-center justify-between">
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center space-x-3">
                      {getSeverityIcon(leak.severity)}
                      <div className="flex-1">
                        <div className="flex items-center space-x-2">
                          <h3 className="text-sm font-medium text-gray-900 truncate">
                            {leak.title}
                          </h3>
                          <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${getSeverityBadge(leak.severity)}`}>
                            {leak.severity}
                          </span>
                          <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${getStatusBadge(leak.status)}`}>
                            {getStatusIcon(leak.status)}
                            <span className="ml-1">{leak.status}</span>
                          </span>
                          {leak.alertSent && (
                            <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-blue-100 text-blue-800">
                              <BellIcon className="h-3 w-3 mr-1" />
                              Alert Sent
                            </span>
                          )}
                        </div>
                        <p className="mt-1 text-sm text-gray-600 line-clamp-2">
                          {leak.content}
                        </p>
                        <div className="mt-2 flex items-center text-xs text-gray-500 space-x-4">
                          <span>Source: {leak.source}</span>
                          <span>Confidence: {(leak.confidence * 100).toFixed(0)}%</span>
                          <span>Entities: {formatEntities(leak.entities)}</span>
                          <span>Discovered: {formatDate(leak.discoveredAt)}</span>
                        </div>
                      </div>
                    </div>
                  </div>
                  
                  <div className="flex items-center space-x-2">
                    {!leak.alertSent && (
                      <button
                        onClick={() => handleSendAlert(leak)}
                        className="inline-flex items-center px-3 py-1 border border-transparent text-xs font-medium rounded text-white bg-red-600 hover:bg-red-700"
                      >
                        <BellIcon className="h-3 w-3 mr-1" />
                        Send Alert
                      </button>
                    )}
                    
                    {leak.status === 'active' && (
                      <button
                        onClick={() => handleStatusUpdate(leak.id, 'mitigated')}
                        className="inline-flex items-center px-3 py-1 border border-transparent text-xs font-medium rounded text-white bg-yellow-600 hover:bg-yellow-700"
                      >
                        Mark Mitigated
                      </button>
                    )}
                    
                    {leak.status === 'mitigated' && (
                      <button
                        onClick={() => handleStatusUpdate(leak.id, 'resolved')}
                        className="inline-flex items-center px-3 py-1 border border-transparent text-xs font-medium rounded text-white bg-green-600 hover:bg-green-700"
                      >
                        Mark Resolved
                      </button>
                    )}
                    
                    <button
                      onClick={() => setSelectedLeak(leak)}
                      className="inline-flex items-center px-3 py-1 border border-gray-300 text-xs font-medium rounded text-gray-700 bg-white hover:bg-gray-50"
                    >
                      <EyeIcon className="h-3 w-3 mr-1" />
                      Details
                    </button>
                  </div>
                </div>
              </li>
            ))}
          </ul>
        )}
      </div>

      {/* Alert Modal */}
      {showAlertModal && selectedLeak && (
        <div className="fixed inset-0 bg-gray-600 bg-opacity-50 overflow-y-auto h-full w-full z-50">
          <div className="relative top-20 mx-auto p-5 border w-96 shadow-lg rounded-md bg-white">
            <div className="mt-3">
              <h3 className="text-lg font-medium text-gray-900 mb-4">
                Send Alert for: {selectedLeak.title}
              </h3>
              
              <div className="space-y-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Recipients (comma-separated emails)
                  </label>
                  <input
                    type="text"
                    value={alertForm.recipients}
                    onChange={(e) => setAlertForm({ ...alertForm, recipients: e.target.value })}
                    placeholder="security-team@company.com, admin@company.com"
                    className="w-full border border-gray-300 rounded-md px-3 py-2 text-sm"
                  />
                </div>
                
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Alert Message
                  </label>
                  <textarea
                    value={alertForm.message}
                    onChange={(e) => setAlertForm({ ...alertForm, message: e.target.value })}
                    placeholder="Data leak detected and requires immediate attention..."
                    rows={3}
                    className="w-full border border-gray-300 rounded-md px-3 py-2 text-sm"
                  />
                </div>
              </div>
              
              <div className="flex justify-end space-x-3 mt-6">
                <button
                  onClick={() => setShowAlertModal(false)}
                  className="px-4 py-2 text-sm font-medium text-gray-700 bg-white border border-gray-300 rounded-md hover:bg-gray-50"
                >
                  Cancel
                </button>
                <button
                  onClick={submitAlert}
                  disabled={sendAlertMutation.isLoading}
                  className="px-4 py-2 text-sm font-medium text-white bg-red-600 border border-transparent rounded-md hover:bg-red-700 disabled:opacity-50"
                >
                  {sendAlertMutation.isLoading ? 'Sending...' : 'Send Alert'}
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Leak Details Modal */}
      {selectedLeak && !showAlertModal && (
        <div className="fixed inset-0 bg-gray-600 bg-opacity-50 overflow-y-auto h-full w-full z-50">
          <div className="relative top-10 mx-auto p-5 border w-4/5 max-w-4xl shadow-lg rounded-md bg-white">
            <div className="flex justify-between items-start mb-4">
              <h3 className="text-lg font-medium text-gray-900">
                Leak Details: {selectedLeak.title}
              </h3>
              <button
                onClick={() => setSelectedLeak(null)}
                className="text-gray-400 hover:text-gray-600"
              >
                <XCircleIcon className="h-6 w-6" />
              </button>
            </div>
            
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <div className="space-y-4">
                <div>
                  <h4 className="text-sm font-medium text-gray-900 mb-2">Basic Information</h4>
                  <div className="bg-gray-50 p-3 rounded-md space-y-2">
                    <div className="flex justify-between">
                      <span className="text-sm text-gray-600">Severity:</span>
                      <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium ${getSeverityBadge(selectedLeak.severity)}`}>
                        {selectedLeak.severity}
                      </span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-sm text-gray-600">Status:</span>
                      <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium ${getStatusBadge(selectedLeak.status)}`}>
                        {selectedLeak.status}
                      </span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-sm text-gray-600">Classification:</span>
                      <span className="text-sm text-gray-900">{selectedLeak.classification}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-sm text-gray-600">Confidence:</span>
                      <span className="text-sm text-gray-900">{(selectedLeak.confidence * 100).toFixed(0)}%</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-sm text-gray-600">Source:</span>
                      <span className="text-sm text-gray-900">{selectedLeak.source}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-sm text-gray-600">Discovered:</span>
                      <span className="text-sm text-gray-900">{formatDate(selectedLeak.discoveredAt)}</span>
                    </div>
                  </div>
                </div>
                
                <div>
                  <h4 className="text-sm font-medium text-gray-900 mb-2">Exposed Entities</h4>
                  <div className="bg-gray-50 p-3 rounded-md">
                    <div className="space-y-1">
                      {Object.entries(selectedLeak.entities || {}).map(([key, value]) => (
                        <div key={key} className="flex justify-between text-sm">
                          <span className="text-gray-600 capitalize">{key.replace('_', ' ')}:</span>
                          <span className="text-gray-900">
                            {Array.isArray(value) ? value.length : (typeof value === 'number' ? value : 1)}
                          </span>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              </div>
              
              <div className="space-y-4">
                <div>
                  <h4 className="text-sm font-medium text-gray-900 mb-2">Content</h4>
                  <div className="bg-gray-50 p-3 rounded-md">
                    <p className="text-sm text-gray-700">{selectedLeak.content}</p>
                  </div>
                </div>
                
                <div>
                  <h4 className="text-sm font-medium text-gray-900 mb-2">Location</h4>
                  <div className="bg-gray-50 p-3 rounded-md">
                    <p className="text-sm text-gray-700 break-all">{selectedLeak.location}</p>
                  </div>
                </div>
                
                {selectedLeak.remediation && (
                  <div>
                    <h4 className="text-sm font-medium text-gray-900 mb-2">Remediation</h4>
                    <div className="bg-gray-50 p-3 rounded-md space-y-2">
                      <div className="flex justify-between">
                        <span className="text-sm text-gray-600">Status:</span>
                        <span className="text-sm text-gray-900">{selectedLeak.remediation.status}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-sm text-gray-600">Assigned To:</span>
                        <span className="text-sm text-gray-900">{selectedLeak.remediation.assignedTo}</span>
                      </div>
                      {selectedLeak.remediation.actions && selectedLeak.remediation.actions.length > 0 && (
                        <div>
                          <span className="text-sm text-gray-600">Actions Taken:</span>
                          <ul className="mt-1 text-sm text-gray-900 list-disc list-inside">
                            {selectedLeak.remediation.actions.map((action, index) => (
                              <li key={index}>{action}</li>
                            ))}
                          </ul>
                        </div>
                      )}
                    </div>
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default Leaks;
