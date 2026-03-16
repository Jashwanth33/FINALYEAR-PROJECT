import React, { useEffect } from 'react';
import { useParams } from 'react-router-dom';
import { useQuery } from 'react-query';
import { scansAPI } from '../services/api';
import { ArrowLeft, Play, Pause, Trash2, Download } from 'lucide-react';

const ScanDetail = () => {
  const { id } = useParams();
  const { data: scanData, isLoading, error } = useQuery(['scan', id], () => scansAPI.getScan(id));
  
  // Debug logging
  useEffect(() => {
    console.log('🔍 SCAN DETAIL - Scan ID:', id);
    console.log('🔍 SCAN DETAIL - Scan data:', scanData);
    console.log('🔍 SCAN DETAIL - Error:', error);
  }, [id, scanData, error]);
  
  const scan = scanData?.data?.data?.scan;

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600"></div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="text-center py-12">
        <h2 className="text-2xl font-bold text-gray-900">Error loading scan</h2>
        <p className="text-gray-500 mt-2">
          {error.response?.data?.message || error.message || 'Failed to load scan details'}
        </p>
        {error.response?.status === 404 && (
          <p className="text-gray-500 mt-2">The requested scan could not be found.</p>
        )}
      </div>
    );
  }

  if (!scan) {
    return (
      <div className="text-center py-12">
        <h2 className="text-2xl font-bold text-gray-900">Scan not found</h2>
        <p className="text-gray-500 mt-2">The requested scan could not be found.</p>
      </div>
    );
  }

  const getStatusColor = (status) => {
    switch (status) {
      case 'completed': return 'badge-success';
      case 'running': return 'badge-info';
      case 'failed': return 'badge-danger';
      case 'pending': return 'badge-secondary';
      default: return 'badge-secondary';
    }
  };

  const getTypeIcon = (type) => {
    switch (type) {
      case 'network': return '🌐';
      case 'web': return '🕷️';
      case 'darkweb': return '🌑';
      default: return '🔍';
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center space-x-4">
        <button className="btn btn-secondary flex items-center">
          <ArrowLeft className="h-4 w-4 mr-2" />
          Back
        </button>
        <h1 className="text-3xl font-bold text-gray-900">{scan.name}</h1>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2">
          <div className="card">
            <div className="flex items-center justify-between mb-6">
              <div className="flex items-center space-x-4">
                <div className="text-3xl">{getTypeIcon(scan.type)}</div>
                <div>
                  <h2 className="text-xl font-semibold text-gray-900">{scan.name}</h2>
                  <p className="text-gray-500">Target: {scan.target}</p>
                </div>
              </div>
              <div className="flex items-center space-x-2">
                <span className={`badge ${getStatusColor(scan.status)}`}>
                  {scan.status}
                </span>
                {scan.status === 'running' && (
                  <button className="btn btn-secondary flex items-center">
                    <Pause className="h-4 w-4 mr-2" />
                    Cancel
                  </button>
                )}
              </div>
            </div>

            {scan.progress > 0 && (
              <div className="mb-6">
                <div className="flex justify-between text-sm text-gray-600 mb-2">
                  <span>Progress</span>
                  <span>{scan.progress}%</span>
                </div>
                <div className="w-full bg-gray-200 rounded-full h-3">
                  <div
                    className="bg-blue-600 h-3 rounded-full transition-all duration-300"
                    style={{ width: `${scan.progress}%` }}
                  ></div>
                </div>
              </div>
            )}

            <div className="space-y-4">
              <div>
                <h3 className="text-lg font-semibold text-gray-900 mb-2">Scan Details</h3>
                <div className="grid grid-cols-2 gap-4 text-sm">
                  <div>
                    <span className="font-medium text-gray-500">Type:</span>
                    <span className="ml-2 text-gray-900">{scan.type}</span>
                  </div>
                  <div>
                    <span className="font-medium text-gray-500">Target:</span>
                    <span className="ml-2 text-gray-900">{scan.target}</span>
                  </div>
                  <div>
                    <span className="font-medium text-gray-500">Started:</span>
                    <span className="ml-2 text-gray-900">
                      {scan.startTime ? new Date(scan.startTime).toLocaleString() : 'Not started'}
                    </span>
                  </div>
                  <div>
                    <span className="font-medium text-gray-500">Completed:</span>
                    <span className="ml-2 text-gray-900">
                      {scan.endTime ? new Date(scan.endTime).toLocaleString() : 'Not completed'}
                    </span>
                  </div>
                </div>
              </div>

              {scan.summary && (
                <div>
                  <h3 className="text-lg font-semibold text-gray-900 mb-2">Summary</h3>
                  <div className="grid grid-cols-2 gap-4 text-sm">
                    <div>
                      <span className="font-medium text-gray-500">Total Hosts:</span>
                      <span className="ml-2 text-gray-900">{scan.summary.totalHosts || 0}</span>
                    </div>
                    <div>
                      <span className="font-medium text-gray-500">Open Ports:</span>
                      <span className="ml-2 text-gray-900">{scan.summary.openPorts || 0}</span>
                    </div>
                    <div>
                      <span className="font-medium text-gray-500">Vulnerabilities:</span>
                      <span className="ml-2 text-gray-900">{scan.summary.vulnerabilities || 0}</span>
                    </div>
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>

        <div className="lg:col-span-1">
          <div className="card">
            <h3 className="text-lg font-semibold text-gray-900 mb-4">Actions</h3>
            <div className="space-y-3">
              <button className="btn btn-primary w-full flex items-center justify-center">
                <Download className="h-4 w-4 mr-2" />
                Download Report
              </button>
              <button className="btn btn-secondary w-full flex items-center justify-center">
                <Play className="h-4 w-4 mr-2" />
                Restart Scan
              </button>
              <button className="btn btn-danger w-full flex items-center justify-center">
                <Trash2 className="h-4 w-4 mr-2" />
                Delete Scan
              </button>
            </div>
          </div>

          {scan.vulnerabilities && scan.vulnerabilities.length > 0 && (
            <div className="card mt-6">
              <h3 className="text-lg font-semibold text-gray-900 mb-4">Vulnerabilities Found</h3>
              <div className="space-y-2">
                {scan.vulnerabilities.slice(0, 5).map((vuln) => (
                  <div key={vuln.id} className="flex items-center justify-between p-2 bg-gray-50 rounded">
                    <span className="text-sm font-medium text-gray-900">{vuln.title}</span>
                    <span className={`badge ${
                      vuln.severity === 'critical' ? 'badge-critical' :
                      vuln.severity === 'high' ? 'badge-high' :
                      vuln.severity === 'medium' ? 'badge-medium' : 'badge-low'
                    }`}>
                      {vuln.severity}
                    </span>
                  </div>
                ))}
                {scan.vulnerabilities.length > 5 && (
                  <p className="text-sm text-gray-500 text-center">
                    +{scan.vulnerabilities.length - 5} more vulnerabilities
                  </p>
                )}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default ScanDetail;
