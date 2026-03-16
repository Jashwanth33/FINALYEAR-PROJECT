import React, { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from 'react-query';
import { 
  DocumentTextIcon,
  DocumentArrowDownIcon,
  CalendarIcon,
  UserIcon,
  MagnifyingGlassIcon,
  FunnelIcon,
  PlusIcon,
  ClockIcon,
  CheckCircleIcon,
  XCircleIcon,
  ExclamationTriangleIcon,
  ArrowsUpDownIcon,
  ChartBarIcon,
  TableCellsIcon,
  DocumentIcon,
  EyeIcon,
  TrashIcon,
  PlayIcon,
  PauseIcon
} from '@heroicons/react/24/outline';
import { reportsAPI } from '../services/api';

const Reports = () => {
  const [searchTerm, setSearchTerm] = useState('');
  const [filters, setFilters] = useState({
    type: 'all',
    format: 'all',
    status: 'all',
    dateRange: 'all'
  });
  const [sortBy, setSortBy] = useState('createdAt');
  const [sortOrder, setSortOrder] = useState('desc');
  const [showFilters, setShowFilters] = useState(false);
  const [showNewReportModal, setShowNewReportModal] = useState(false);
  const [showScheduleModal, setShowScheduleModal] = useState(false);
  const [selectedReport, setSelectedReport] = useState(null);
  const [newReportForm, setNewReportForm] = useState({
    title: '',
    type: 'vulnerability_summary',
    format: 'pdf',
    dateRange: 'last_30_days',
    includeCharts: true,
    includeDetails: true,
    filters: {}
  });
  const [scheduleForm, setScheduleForm] = useState({
    frequency: 'weekly',
    dayOfWeek: 'monday',
    time: '09:00',
    recipients: '',
    enabled: true
  });

  const queryClient = useQueryClient();

  const { data: reportsData, isLoading, error } = useQuery(
    ['reports', searchTerm, filters, sortBy, sortOrder],
    () => reportsAPI.getReports({ search: searchTerm, ...filters, sortBy, sortOrder }),
    { refetchInterval: 30000 }
  );

  const generateReportMutation = useMutation(
    (data) => reportsAPI.generateReport(data),
    {
      onSuccess: () => {
        queryClient.invalidateQueries(['reports']);
        setShowNewReportModal(false);
        setNewReportForm({
          title: '',
          type: 'vulnerability_summary',
          format: 'pdf',
          dateRange: 'last_30_days',
          includeCharts: true,
          includeDetails: true,
          filters: {}
        });
      }
    }
  );

  const scheduleReportMutation = useMutation(
    (data) => reportsAPI.scheduleReport(data),
    {
      onSuccess: () => {
        queryClient.invalidateQueries(['reports']);
        setShowScheduleModal(false);
        setScheduleForm({
          frequency: 'weekly',
          dayOfWeek: 'monday',
          time: '09:00',
          recipients: '',
          enabled: true
        });
      }
    }
  );

  const deleteReportMutation = useMutation(
    (id) => reportsAPI.deleteReport(id),
    {
      onSuccess: () => {
        queryClient.invalidateQueries(['reports']);
      }
    }
  );

  const handleDownload = async (reportId, format = 'pdf') => {
    try {
      const response = await reportsAPI.downloadReport(reportId, format);
      const blob = new Blob([response.data], { 
        type: format === 'pdf' ? 'application/pdf' : 'text/csv' 
      });
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `report_${reportId}.${format}`;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);
    } catch (error) {
      console.error('Download failed:', error);
    }
  };

  const getStatusIcon = (status) => {
    switch (status) {
      case 'completed':
        return <CheckCircleIcon className="h-4 w-4 text-green-500" />;
      case 'generating':
        return <ClockIcon className="h-4 w-4 text-blue-500" />;
      case 'failed':
        return <XCircleIcon className="h-4 w-4 text-red-500" />;
      case 'scheduled':
        return <CalendarIcon className="h-4 w-4 text-purple-500" />;
      default:
        return <ClockIcon className="h-4 w-4 text-gray-500" />;
    }
  };

  const getStatusBadge = (status) => {
    const colors = {
      completed: 'bg-green-100 text-green-800',
      generating: 'bg-blue-100 text-blue-800',
      failed: 'bg-red-100 text-red-800',
      scheduled: 'bg-purple-100 text-purple-800',
      pending: 'bg-gray-100 text-gray-800'
    };
    return colors[status] || 'bg-gray-100 text-gray-800';
  };

  const getTypeIcon = (type) => {
    switch (type) {
      case 'vulnerability_summary':
        return <ExclamationTriangleIcon className="h-5 w-5 text-red-500" />;
      case 'scan_report':
        return <ChartBarIcon className="h-5 w-5 text-blue-500" />;
      case 'leak_analysis':
        return <DocumentTextIcon className="h-5 w-5 text-orange-500" />;
      case 'compliance':
        return <CheckCircleIcon className="h-5 w-5 text-green-500" />;
      default:
        return <DocumentIcon className="h-5 w-5 text-gray-500" />;
    }
  };

  const getFormatIcon = (format) => {
    switch (format) {
      case 'pdf':
        return <DocumentIcon className="h-4 w-4 text-red-500" />;
      case 'csv':
        return <TableCellsIcon className="h-4 w-4 text-green-500" />;
      case 'json':
        return <DocumentTextIcon className="h-4 w-4 text-blue-500" />;
      default:
        return <DocumentIcon className="h-4 w-4 text-gray-500" />;
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

  const submitNewReport = () => {
    generateReportMutation.mutate(newReportForm);
  };

  const submitSchedule = () => {
    scheduleReportMutation.mutate({
      ...scheduleForm,
      reportConfig: newReportForm
    });
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
            <h3 className="text-sm font-medium text-red-800">Error loading reports</h3>
            <p className="mt-1 text-sm text-red-700">{error.message}</p>
          </div>
        </div>
      </div>
    );
  }

  const reports = reportsData?.data?.data?.reports || [];
  
  // Calculate stats from reports if not provided by API
  const stats = reportsData?.data?.data?.stats || {
    total: reports.length,
    completed: reports.filter(r => r.status === 'completed').length,
    scheduled: reports.filter(r => r.status === 'scheduled').length,
    generating: reports.filter(r => r.status === 'generating').length
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Reports & Analytics</h1>
          <p className="mt-1 text-sm text-gray-500">
            Generate, schedule, and manage security reports
          </p>
        </div>
        <div className="flex space-x-3">
          <button
            onClick={() => setShowScheduleModal(true)}
            className="inline-flex items-center px-4 py-2 border border-gray-300 rounded-md shadow-sm text-sm font-medium text-gray-700 bg-white hover:bg-gray-50"
          >
            <CalendarIcon className="h-4 w-4 mr-2" />
            Schedule Report
          </button>
          <button
            onClick={() => setShowNewReportModal(true)}
            className="inline-flex items-center px-4 py-2 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-blue-600 hover:bg-blue-700"
          >
            <PlusIcon className="h-4 w-4 mr-2" />
            Generate Report
          </button>
        </div>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="bg-white overflow-hidden shadow rounded-lg">
          <div className="p-5">
            <div className="flex items-center">
              <div className="flex-shrink-0">
                <DocumentTextIcon className="h-6 w-6 text-blue-500" />
              </div>
              <div className="ml-5 w-0 flex-1">
                <dl>
                  <dt className="text-sm font-medium text-gray-500 truncate">Total Reports</dt>
                  <dd className="text-lg font-medium text-gray-900">{stats.total || 0}</dd>
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
                  <dt className="text-sm font-medium text-gray-500 truncate">Completed</dt>
                  <dd className="text-lg font-medium text-gray-900">{stats.completed || 0}</dd>
                </dl>
              </div>
            </div>
          </div>
        </div>

        <div className="bg-white overflow-hidden shadow rounded-lg">
          <div className="p-5">
            <div className="flex items-center">
              <div className="flex-shrink-0">
                <CalendarIcon className="h-6 w-6 text-purple-500" />
              </div>
              <div className="ml-5 w-0 flex-1">
                <dl>
                  <dt className="text-sm font-medium text-gray-500 truncate">Scheduled</dt>
                  <dd className="text-lg font-medium text-gray-900">{stats.scheduled || 0}</dd>
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
                  <dt className="text-sm font-medium text-gray-500 truncate">Generating</dt>
                  <dd className="text-lg font-medium text-gray-900">{stats.generating || 0}</dd>
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
                placeholder="Search reports..."
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
              <option value="createdAt-desc">Latest First</option>
              <option value="createdAt-asc">Oldest First</option>
              <option value="title-asc">Title A-Z</option>
              <option value="status-asc">Status</option>
            </select>
          </div>
        </div>

        {showFilters && (
          <div className="mt-4 grid grid-cols-1 sm:grid-cols-4 gap-4 pt-4 border-t border-gray-200">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">Type</label>
              <select
                value={filters.type}
                onChange={(e) => setFilters({ ...filters, type: e.target.value })}
                className="w-full border border-gray-300 rounded-md px-3 py-2 text-sm"
              >
                <option value="all">All Types</option>
                <option value="vulnerability_summary">Vulnerability Summary</option>
                <option value="scan_report">Scan Report</option>
                <option value="leak_analysis">Leak Analysis</option>
                <option value="compliance">Compliance</option>
              </select>
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">Format</label>
              <select
                value={filters.format}
                onChange={(e) => setFilters({ ...filters, format: e.target.value })}
                className="w-full border border-gray-300 rounded-md px-3 py-2 text-sm"
              >
                <option value="all">All Formats</option>
                <option value="pdf">PDF</option>
                <option value="csv">CSV</option>
                <option value="json">JSON</option>
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
                <option value="completed">Completed</option>
                <option value="generating">Generating</option>
                <option value="scheduled">Scheduled</option>
                <option value="failed">Failed</option>
              </select>
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">Date Range</label>
              <select
                value={filters.dateRange}
                onChange={(e) => setFilters({ ...filters, dateRange: e.target.value })}
                className="w-full border border-gray-300 rounded-md px-3 py-2 text-sm"
              >
                <option value="all">All Time</option>
                <option value="today">Today</option>
                <option value="week">This Week</option>
                <option value="month">This Month</option>
              </select>
            </div>
          </div>
        )}
      </div>

      {/* Reports List */}
      <div className="bg-white shadow overflow-hidden sm:rounded-md">
        {reports.length === 0 ? (
          <div className="text-center py-12">
            <DocumentTextIcon className="mx-auto h-12 w-12 text-gray-400" />
            <h3 className="mt-2 text-sm font-medium text-gray-900">No reports found</h3>
            <p className="mt-1 text-sm text-gray-500">
              {searchTerm || Object.values(filters).some(f => f !== 'all') 
                ? 'Try adjusting your search or filters.' 
                : 'Generate your first report to get started.'}
            </p>
          </div>
        ) : (
          <ul className="divide-y divide-gray-200">
            {reports.map((report) => (
              <li key={report.id} className="px-6 py-4 hover:bg-gray-50">
                <div className="flex items-center justify-between">
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center space-x-3">
                      {getTypeIcon(report.type)}
                      <div className="flex-1">
                        <div className="flex items-center space-x-2">
                          <h3 className="text-sm font-medium text-gray-900 truncate">
                            {report.title}
                          </h3>
                          <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${getStatusBadge(report.status)}`}>
                            {getStatusIcon(report.status)}
                            <span className="ml-1">{report.status}</span>
                          </span>
                          <div className="flex items-center space-x-1">
                            {getFormatIcon(report.format)}
                            <span className="text-xs text-gray-500 uppercase">{report.format}</span>
                          </div>
                        </div>
                        <p className="mt-1 text-sm text-gray-600">
                          Type: {report.type.replace('_', ' ')} • 
                          {report.dateRange && ` Range: ${report.dateRange.replace('_', ' ')} • `}
                          {report.size && ` Size: ${report.size}`}
                        </p>
                        <div className="mt-2 flex items-center text-xs text-gray-500 space-x-4">
                          <div className="flex items-center">
                            <CalendarIcon className="h-3 w-3 mr-1" />
                            Created: {formatDate(report.createdAt)}
                          </div>
                          {report.completedAt && (
                            <div className="flex items-center">
                              <CheckCircleIcon className="h-3 w-3 mr-1" />
                              Completed: {formatDate(report.completedAt)}
                            </div>
                          )}
                          <div className="flex items-center">
                            <UserIcon className="h-3 w-3 mr-1" />
                            {report.user?.username || 'System'}
                          </div>
                        </div>
                      </div>
                    </div>
                  </div>
                  
                  <div className="flex items-center space-x-2">
                    {report.status === 'completed' && (
                      <>
                        <button
                          onClick={() => handleDownload(report.id, 'pdf')}
                          className="inline-flex items-center px-3 py-1 border border-transparent text-xs font-medium rounded text-white bg-red-600 hover:bg-red-700"
                          title="Download PDF"
                        >
                          <DocumentIcon className="h-3 w-3 mr-1" />
                          PDF
                        </button>
                        <button
                          onClick={() => handleDownload(report.id, 'csv')}
                          className="inline-flex items-center px-3 py-1 border border-transparent text-xs font-medium rounded text-white bg-green-600 hover:bg-green-700"
                          title="Download CSV"
                        >
                          <TableCellsIcon className="h-3 w-3 mr-1" />
                          CSV
                        </button>
                      </>
                    )}
                    
                    {report.status === 'generating' && (
                      <div className="flex items-center px-3 py-1 text-xs text-blue-600">
                        <ClockIcon className="h-3 w-3 mr-1 animate-spin" />
                        Generating...
                      </div>
                    )}
                    
                    <button
                      onClick={() => setSelectedReport(report)}
                      className="inline-flex items-center px-3 py-1 border border-gray-300 text-xs font-medium rounded text-gray-700 bg-white hover:bg-gray-50"
                    >
                      <EyeIcon className="h-3 w-3 mr-1" />
                      Details
                    </button>
                    
                    <button
                      onClick={() => deleteReportMutation.mutate(report.id)}
                      disabled={deleteReportMutation.isLoading}
                      className="inline-flex items-center px-3 py-1 border border-transparent text-xs font-medium rounded text-white bg-red-600 hover:bg-red-700 disabled:opacity-50"
                    >
                      <TrashIcon className="h-3 w-3" />
                    </button>
                  </div>
                </div>
              </li>
            ))}
          </ul>
        )}
      </div>

      {/* New Report Modal */}
      {showNewReportModal && (
        <div className="fixed inset-0 bg-gray-600 bg-opacity-50 overflow-y-auto h-full w-full z-50">
          <div className="relative top-10 mx-auto p-5 border w-4/5 max-w-2xl shadow-lg rounded-md bg-white">
            <div className="flex justify-between items-start mb-4">
              <h3 className="text-lg font-medium text-gray-900">Generate New Report</h3>
              <button
                onClick={() => setShowNewReportModal(false)}
                className="text-gray-400 hover:text-gray-600"
              >
                <XCircleIcon className="h-6 w-6" />
              </button>
            </div>
            
            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">Report Title</label>
                <input
                  type="text"
                  value={newReportForm.title}
                  onChange={(e) => setNewReportForm({ ...newReportForm, title: e.target.value })}
                  placeholder="Security Report - Weekly Summary"
                  className="w-full border border-gray-300 rounded-md px-3 py-2 text-sm"
                />
              </div>
              
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">Report Type</label>
                  <select
                    value={newReportForm.type}
                    onChange={(e) => setNewReportForm({ ...newReportForm, type: e.target.value })}
                    className="w-full border border-gray-300 rounded-md px-3 py-2 text-sm"
                  >
                    <option value="vulnerability_summary">Vulnerability Summary</option>
                    <option value="scan_report">Scan Report</option>
                    <option value="leak_analysis">Leak Analysis</option>
                    <option value="compliance">Compliance Report</option>
                  </select>
                </div>
                
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">Format</label>
                  <select
                    value={newReportForm.format}
                    onChange={(e) => setNewReportForm({ ...newReportForm, format: e.target.value })}
                    className="w-full border border-gray-300 rounded-md px-3 py-2 text-sm"
                  >
                    <option value="pdf">PDF</option>
                    <option value="csv">CSV</option>
                    <option value="json">JSON</option>
                  </select>
                </div>
              </div>
              
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">Date Range</label>
                <select
                  value={newReportForm.dateRange}
                  onChange={(e) => setNewReportForm({ ...newReportForm, dateRange: e.target.value })}
                  className="w-full border border-gray-300 rounded-md px-3 py-2 text-sm"
                >
                  <option value="last_7_days">Last 7 Days</option>
                  <option value="last_30_days">Last 30 Days</option>
                  <option value="last_90_days">Last 90 Days</option>
                  <option value="custom">Custom Range</option>
                </select>
              </div>
              
              <div className="space-y-2">
                <label className="flex items-center">
                  <input
                    type="checkbox"
                    checked={newReportForm.includeCharts}
                    onChange={(e) => setNewReportForm({ ...newReportForm, includeCharts: e.target.checked })}
                    className="rounded border-gray-300 text-blue-600 focus:ring-blue-500"
                  />
                  <span className="ml-2 text-sm text-gray-700">Include Charts and Graphs</span>
                </label>
                
                <label className="flex items-center">
                  <input
                    type="checkbox"
                    checked={newReportForm.includeDetails}
                    onChange={(e) => setNewReportForm({ ...newReportForm, includeDetails: e.target.checked })}
                    className="rounded border-gray-300 text-blue-600 focus:ring-blue-500"
                  />
                  <span className="ml-2 text-sm text-gray-700">Include Detailed Findings</span>
                </label>
              </div>
            </div>
            
            <div className="flex justify-end space-x-3 mt-6">
              <button
                onClick={() => setShowNewReportModal(false)}
                className="px-4 py-2 text-sm font-medium text-gray-700 bg-white border border-gray-300 rounded-md hover:bg-gray-50"
              >
                Cancel
              </button>
              <button
                onClick={submitNewReport}
                disabled={generateReportMutation.isLoading || !newReportForm.title}
                className="px-4 py-2 text-sm font-medium text-white bg-blue-600 border border-transparent rounded-md hover:bg-blue-700 disabled:opacity-50"
              >
                {generateReportMutation.isLoading ? 'Generating...' : 'Generate Report'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Schedule Report Modal */}
      {showScheduleModal && (
        <div className="fixed inset-0 bg-gray-600 bg-opacity-50 overflow-y-auto h-full w-full z-50">
          <div className="relative top-10 mx-auto p-5 border w-4/5 max-w-2xl shadow-lg rounded-md bg-white">
            <div className="flex justify-between items-start mb-4">
              <h3 className="text-lg font-medium text-gray-900">Schedule Recurring Report</h3>
              <button
                onClick={() => setShowScheduleModal(false)}
                className="text-gray-400 hover:text-gray-600"
              >
                <XCircleIcon className="h-6 w-6" />
              </button>
            </div>
            
            <div className="space-y-4">
              <div className="grid grid-cols-3 gap-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">Frequency</label>
                  <select
                    value={scheduleForm.frequency}
                    onChange={(e) => setScheduleForm({ ...scheduleForm, frequency: e.target.value })}
                    className="w-full border border-gray-300 rounded-md px-3 py-2 text-sm"
                  >
                    <option value="daily">Daily</option>
                    <option value="weekly">Weekly</option>
                    <option value="monthly">Monthly</option>
                  </select>
                </div>
                
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">Day</label>
                  <select
                    value={scheduleForm.dayOfWeek}
                    onChange={(e) => setScheduleForm({ ...scheduleForm, dayOfWeek: e.target.value })}
                    className="w-full border border-gray-300 rounded-md px-3 py-2 text-sm"
                    disabled={scheduleForm.frequency === 'daily'}
                  >
                    <option value="monday">Monday</option>
                    <option value="tuesday">Tuesday</option>
                    <option value="wednesday">Wednesday</option>
                    <option value="thursday">Thursday</option>
                    <option value="friday">Friday</option>
                    <option value="saturday">Saturday</option>
                    <option value="sunday">Sunday</option>
                  </select>
                </div>
                
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">Time</label>
                  <input
                    type="time"
                    value={scheduleForm.time}
                    onChange={(e) => setScheduleForm({ ...scheduleForm, time: e.target.value })}
                    className="w-full border border-gray-300 rounded-md px-3 py-2 text-sm"
                  />
                </div>
              </div>
              
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">Recipients (comma-separated emails)</label>
                <input
                  type="text"
                  value={scheduleForm.recipients}
                  onChange={(e) => setScheduleForm({ ...scheduleForm, recipients: e.target.value })}
                  placeholder="security-team@company.com, manager@company.com"
                  className="w-full border border-gray-300 rounded-md px-3 py-2 text-sm"
                />
              </div>
              
              <div>
                <label className="flex items-center">
                  <input
                    type="checkbox"
                    checked={scheduleForm.enabled}
                    onChange={(e) => setScheduleForm({ ...scheduleForm, enabled: e.target.checked })}
                    className="rounded border-gray-300 text-blue-600 focus:ring-blue-500"
                  />
                  <span className="ml-2 text-sm text-gray-700">Enable Schedule</span>
                </label>
              </div>
            </div>
            
            <div className="flex justify-end space-x-3 mt-6">
              <button
                onClick={() => setShowScheduleModal(false)}
                className="px-4 py-2 text-sm font-medium text-gray-700 bg-white border border-gray-300 rounded-md hover:bg-gray-50"
              >
                Cancel
              </button>
              <button
                onClick={submitSchedule}
                disabled={scheduleReportMutation.isLoading || !scheduleForm.recipients}
                className="px-4 py-2 text-sm font-medium text-white bg-blue-600 border border-transparent rounded-md hover:bg-blue-700 disabled:opacity-50"
              >
                {scheduleReportMutation.isLoading ? 'Scheduling...' : 'Schedule Report'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Report Details Modal */}
      {selectedReport && (
        <div className="fixed inset-0 bg-gray-600 bg-opacity-50 overflow-y-auto h-full w-full z-50">
          <div className="relative top-10 mx-auto p-5 border w-4/5 max-w-3xl shadow-lg rounded-md bg-white">
            <div className="flex justify-between items-start mb-4">
              <h3 className="text-lg font-medium text-gray-900">
                Report Details: {selectedReport.title}
              </h3>
              <button
                onClick={() => setSelectedReport(null)}
                className="text-gray-400 hover:text-gray-600"
              >
                <XCircleIcon className="h-6 w-6" />
              </button>
            </div>
            
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <div className="space-y-4">
                <div>
                  <h4 className="text-sm font-medium text-gray-900 mb-2">Report Information</h4>
                  <div className="bg-gray-50 p-3 rounded-md space-y-2">
                    <div className="flex justify-between">
                      <span className="text-sm text-gray-600">Type:</span>
                      <span className="text-sm text-gray-900">{selectedReport.type.replace('_', ' ')}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-sm text-gray-600">Format:</span>
                      <span className="text-sm text-gray-900 uppercase">{selectedReport.format}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-sm text-gray-600">Status:</span>
                      <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium ${getStatusBadge(selectedReport.status)}`}>
                        {selectedReport.status}
                      </span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-sm text-gray-600">Created:</span>
                      <span className="text-sm text-gray-900">{formatDate(selectedReport.createdAt)}</span>
                    </div>
                    {selectedReport.completedAt && (
                      <div className="flex justify-between">
                        <span className="text-sm text-gray-600">Completed:</span>
                        <span className="text-sm text-gray-900">{formatDate(selectedReport.completedAt)}</span>
                      </div>
                    )}
                  </div>
                </div>
                
                {selectedReport.summary && (
                  <div>
                    <h4 className="text-sm font-medium text-gray-900 mb-2">Summary</h4>
                    <div className="bg-gray-50 p-3 rounded-md">
                      <div className="space-y-1 text-sm">
                        {Object.entries(selectedReport.summary).map(([key, value]) => (
                          <div key={key} className="flex justify-between">
                            <span className="text-gray-600 capitalize">{key.replace('_', ' ')}:</span>
                            <span className="text-gray-900">{value}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  </div>
                )}
              </div>
              
              <div className="space-y-4">
                {selectedReport.config && (
                  <div>
                    <h4 className="text-sm font-medium text-gray-900 mb-2">Configuration</h4>
                    <div className="bg-gray-50 p-3 rounded-md">
                      <div className="space-y-1 text-sm">
                        {Object.entries(selectedReport.config).map(([key, value]) => (
                          <div key={key} className="flex justify-between">
                            <span className="text-gray-600 capitalize">{key.replace('_', ' ')}:</span>
                            <span className="text-gray-900">
                              {typeof value === 'boolean' ? (value ? 'Yes' : 'No') : value}
                            </span>
                          </div>
                        ))}
                      </div>
                    </div>
                  </div>
                )}
                
                {selectedReport.schedule && (
                  <div>
                    <h4 className="text-sm font-medium text-gray-900 mb-2">Schedule</h4>
                    <div className="bg-gray-50 p-3 rounded-md">
                      <div className="space-y-1 text-sm">
                        <div className="flex justify-between">
                          <span className="text-gray-600">Frequency:</span>
                          <span className="text-gray-900">{selectedReport.schedule.frequency}</span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-gray-600">Next Run:</span>
                          <span className="text-gray-900">{formatDate(selectedReport.schedule.nextRun)}</span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-gray-600">Enabled:</span>
                          <span className="text-gray-900">{selectedReport.schedule.enabled ? 'Yes' : 'No'}</span>
                        </div>
                      </div>
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

export default Reports;
