import React, { useState, useCallback } from 'react';
import { useQuery, useMutation, useQueryClient } from 'react-query';
import toast from 'react-hot-toast';
import { 
  FileText, Upload, Search, Shield, AlertTriangle, 
  CheckCircle, Clock, Trash2, Download, Eye, 
  File, Database, Lock, Key, Code, Layers
} from 'lucide-react';

const BinaryAnalysis = () => {
  const [selectedFile, setSelectedFile] = useState(null);
  const [isUploading, setIsUploading] = useState(false);
  const [scanResults, setScanResults] = useState(null);
  const [scans, setScans] = useState([]);
  const queryClient = useQueryClient();

  // Fetch previous binary scans
  const { data: scansData, isLoading } = useQuery('binary-scans', async () => {
    const token = localStorage.getItem('token');
    const response = await fetch('http://localhost:5001/api/scans?type=binary&limit=10', {
      headers: { 'Authorization': `Bearer ${token}` }
    });
    return response.json();
  }, {
    onSuccess: (data) => {
      if (data?.data?.scans) {
        setScans(data.data.scans);
      }
    }
  });

  // Handle file selection
  const handleFileSelect = (e) => {
    const file = e.target.files[0];
    if (file) {
      setSelectedFile(file);
      setScanResults(null);
    }
  };

  // Handle file drop
  const handleDrop = useCallback((e) => {
    e.preventDefault();
    const file = e.dataTransfer.files[0];
    if (file) {
      setSelectedFile(file);
      setScanResults(null);
    }
  }, []);

  const handleDragOver = (e) => {
    e.preventDefault();
  };

  // Upload and scan binary
  const handleUpload = async () => {
    if (!selectedFile) {
      toast.error('Please select a file first');
      return;
    }

    setIsUploading(true);
    const formData = new FormData();
    formData.append('file', selectedFile);

    try {
      const token = localStorage.getItem('token');
      const response = await fetch('http://localhost:5001/api/scans/binary', {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${token}` },
        body: formData
      });

      const data = await response.json();
      
      if (data.success) {
        toast.success('Binary scan started!');
        setSelectedFile(null);
        
        // Poll for results
        pollScanResults(data.data.scan.id);
      } else {
        toast.error(data.message || 'Failed to start scan');
      }
    } catch (error) {
      toast.error('Upload failed: ' + error.message);
    } finally {
      setIsUploading(false);
    }
  };

  // Poll for scan results
  const pollScanResults = async (scanId) => {
    const token = localStorage.getItem('token');
    const maxAttempts = 30;
    let attempts = 0;

    const checkStatus = async () => {
      try {
        const response = await fetch(`http://localhost:5001/api/scans/${scanId}`, {
          headers: { 'Authorization': `Bearer ${token}` }
        });
        const data = await response.json();
        
        if (data.data.scan.status === 'completed') {
          // Get vulnerabilities
          const vulnResponse = await fetch(`http://localhost:5001/api/vulnerabilities?scanId=${scanId}`, {
            headers: { 'Authorization': `Bearer ${token}` }
          });
          const vulnData = await vulnResponse.json();
          setScanResults(vulnData.data);
          toast.success('Binary analysis complete!');
          return;
        }
        
        if (data.data.scan.status === 'failed') {
          toast.error('Scan failed: ' + (data.data.scan.errorMessage || 'Unknown error'));
          return;
        }

        attempts++;
        if (attempts < maxAttempts) {
          setTimeout(checkStatus, 2000);
        } else {
          toast.error('Scan timeout');
        }
      } catch (error) {
        toast.error('Error checking scan status');
      }
    };

    checkStatus();
  };

  // View previous scan
  const viewScan = async (scanId) => {
    const token = localStorage.getItem('token');
    try {
      const vulnResponse = await fetch(`http://localhost:5001/api/vulnerabilities?scanId=${scanId}`, {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      const vulnData = await vulnResponse.json();
      setScanResults(vulnData.data);
    } catch (error) {
      toast.error('Failed to load scan results');
    }
  };

  // Get severity color
  const getSeverityColor = (severity) => {
    switch (severity) {
      case 'critical': return 'text-red-600 bg-red-50 border-red-200';
      case 'high': return 'text-orange-600 bg-orange-50 border-orange-200';
      case 'medium': return 'text-yellow-600 bg-yellow-50 border-yellow-200';
      case 'low': return 'text-green-600 bg-green-50 border-green-200';
      default: return 'text-gray-600 bg-gray-50 border-gray-200';
    }
  };

  // Get category icon
  const getCategoryIcon = (category) => {
    switch (category) {
      case 'hardcoded-secrets': return <Key className="h-5 w-5" />;
      case 'unsafe-functions': return <Code className="h-5 w-5" />;
      case 'file-analysis': return <Layers className="h-5 w-5" />;
      default: return <Shield className="h-5 w-5" />;
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-gray-900">Binary Analysis</h1>
          <p className="text-gray-600 mt-1">Upload binary files to detect hardcoded secrets, unsafe functions, and malware indicators</p>
        </div>
      </div>

      {/* Upload Section */}
      <div className="bg-white p-6 rounded-lg shadow-sm border border-gray-200">
        <h2 className="text-lg font-semibold text-gray-900 mb-4">Upload Binary File</h2>
        
        <div 
          className="border-2 border-dashed border-gray-300 rounded-lg p-8 text-center hover:border-blue-500 transition-colors cursor-pointer"
          onDrop={handleDrop}
          onDragOver={handleDragOver}
          onClick={() => document.getElementById('file-input').click()}
        >
          <input
            id="file-input"
            type="file"
            className="hidden"
            accept=".exe,.dll,.so,.bin,.elf,.dylib,.o,.a,.pyc"
            onChange={handleFileSelect}
          />
          
          {selectedFile ? (
            <div className="space-y-3">
              <File className="h-12 w-12 text-blue-500 mx-auto" />
              <div>
                <p className="font-medium text-gray-900">{selectedFile.name}</p>
                <p className="text-sm text-gray-500">
                  {(selectedFile.size / 1024).toFixed(2)} KB | {selectedFile.type || 'Unknown type'}
                </p>
              </div>
              <button
                onClick={(e) => {
                  e.stopPropagation();
                  setSelectedFile(null);
                }}
                className="text-red-500 text-sm hover:underline"
              >
                Remove file
              </button>
            </div>
          ) : (
            <div className="space-y-3">
              <Upload className="h-12 w-12 text-gray-400 mx-auto" />
              <div>
                <p className="font-medium text-gray-700">Drop binary file here or click to browse</p>
                <p className="text-sm text-gray-500">Supports: .exe, .dll, .so, .bin, .elf, .pyc</p>
              </div>
            </div>
          )}
        </div>

        {selectedFile && (
          <div className="mt-4 flex justify-end">
            <button
              onClick={handleUpload}
              disabled={isUploading}
              className="flex items-center px-6 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50"
            >
              {isUploading ? (
                <>
                  <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white mr-2"></div>
                  Analyzing...
                </>
              ) : (
                <>
                  <Search className="h-4 w-4 mr-2" />
                  Analyze Binary
                </>
              )}
            </button>
          </div>
        )}
      </div>

      {/* Results Section */}
      {scanResults && (
        <div className="bg-white p-6 rounded-lg shadow-sm border border-gray-200">
          <h2 className="text-lg font-semibold text-gray-900 mb-4">Analysis Results</h2>
          
          {/* Summary Stats */}
          <div className="grid grid-cols-4 gap-4 mb-6">
            <div className="bg-red-50 p-4 rounded-lg border border-red-200 text-center">
              <p className="text-2xl font-bold text-red-600">
                {scanResults.vulnerabilities?.filter(v => v.severity === 'critical').length || 0}
              </p>
              <p className="text-sm text-red-700">Critical</p>
            </div>
            <div className="bg-orange-50 p-4 rounded-lg border border-orange-200 text-center">
              <p className="text-2xl font-bold text-orange-600">
                {scanResults.vulnerabilities?.filter(v => v.severity === 'high').length || 0}
              </p>
              <p className="text-sm text-orange-700">High</p>
            </div>
            <div className="bg-yellow-50 p-4 rounded-lg border border-yellow-200 text-center">
              <p className="text-2xl font-bold text-yellow-600">
                {scanResults.vulnerabilities?.filter(v => v.severity === 'medium').length || 0}
              </p>
              <p className="text-sm text-yellow-700">Medium</p>
            </div>
            <div className="bg-green-50 p-4 rounded-lg border border-green-200 text-center">
              <p className="text-2xl font-bold text-green-600">
                {scanResults.vulnerabilities?.filter(v => v.severity === 'low').length || 0}
              </p>
              <p className="text-sm text-green-700">Low</p>
            </div>
          </div>

          {/* Findings List */}
          {scanResults.vulnerabilities && scanResults.vulnerabilities.length > 0 ? (
            <div className="space-y-4">
              {scanResults.vulnerabilities.map((vuln, index) => (
                <div key={vuln.id || index} className="border border-gray-200 rounded-lg p-4">
                  <div className="flex items-start justify-between">
                    <div className="flex items-start space-x-3">
                      <div className={`p-2 rounded-lg ${getSeverityColor(vuln.severity)}`}>
                        {getCategoryIcon(vuln.category)}
                      </div>
                      <div>
                        <div className="flex items-center space-x-2">
                          <h3 className="font-medium text-gray-900">{vuln.title}</h3>
                          <span className={`px-2 py-1 text-xs font-medium rounded-full border ${getSeverityColor(vuln.severity)}`}>
                            {vuln.severity.toUpperCase()}
                          </span>
                          {vuln.cveId && (
                            <span className="px-2 py-1 text-xs bg-gray-100 text-gray-700 rounded">
                              {vuln.cveId}
                            </span>
                          )}
                          {vuln.cvssScore && (
                            <span className="px-2 py-1 text-xs bg-blue-100 text-blue-700 rounded">
                              CVSS: {vuln.cvssScore}
                            </span>
                          )}
                        </div>
                        <p className="text-sm text-gray-600 mt-1">{vuln.description}</p>
                        <p className="text-xs text-gray-500 mt-2">
                          <strong>File:</strong> {vuln.url}
                        </p>
                      </div>
                    </div>
                  </div>
                  
                  {/* Evidence */}
                  {vuln.evidence && (
                    <div className="mt-3 bg-gray-50 p-3 rounded border">
                      <p className="text-xs font-medium text-gray-700 mb-1">Evidence:</p>
                      <code className="text-xs text-gray-600">{vuln.evidence}</code>
                    </div>
                  )}
                  
                  {/* Solution */}
                  <div className="mt-3 bg-blue-50 p-3 rounded border border-blue-200">
                    <p className="text-xs font-medium text-blue-700 mb-1">How to Fix:</p>
                    <p className="text-sm text-blue-800">{vuln.solution}</p>
                  </div>
                  
                  {/* POC */}
                  {vuln.poc && (
                    <details className="mt-3">
                      <summary className="cursor-pointer text-sm text-blue-600 hover:underline">
                        View Proof of Concept
                      </summary>
                      <div className="mt-2 bg-gray-900 text-gray-100 p-4 rounded overflow-x-auto">
                        <pre className="text-xs whitespace-pre-wrap">{vuln.poc}</pre>
                      </div>
                    </details>
                  )}
                </div>
              ))}
            </div>
          ) : (
            <div className="text-center py-8">
              <CheckCircle className="h-12 w-12 text-green-500 mx-auto mb-3" />
              <p className="text-lg font-medium text-gray-900">No Issues Found</p>
              <p className="text-gray-600">The binary file appears to be clean</p>
            </div>
          )}
        </div>
      )}

      {/* Previous Scans */}
      {scans.length > 0 && (
        <div className="bg-white p-6 rounded-lg shadow-sm border border-gray-200">
          <h2 className="text-lg font-semibold text-gray-900 mb-4">Previous Binary Scans</h2>
          
          <div className="space-y-3">
            {scans.map((scan) => (
              <div 
                key={scan.id} 
                className="flex items-center justify-between p-3 bg-gray-50 rounded-lg hover:bg-gray-100 cursor-pointer"
                onClick={() => viewScan(scan.id)}
              >
                <div className="flex items-center space-x-3">
                  <FileText className="h-5 w-5 text-gray-400" />
                  <div>
                    <p className="font-medium text-gray-900">{scan.name}</p>
                    <p className="text-xs text-gray-500">
                      {new Date(scan.createdAt).toLocaleString()} | {scan.target}
                    </p>
                  </div>
                </div>
                <div className="flex items-center space-x-2">
                  <span className={`px-2 py-1 text-xs rounded-full ${
                    scan.status === 'completed' ? 'bg-green-100 text-green-700' :
                    scan.status === 'running' ? 'bg-blue-100 text-blue-700' :
                    scan.status === 'failed' ? 'bg-red-100 text-red-700' :
                    'bg-gray-100 text-gray-700'
                  }`}>
                    {scan.status}
                  </span>
                  <Eye className="h-4 w-4 text-gray-400" />
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Feature Info */}
      <div className="bg-blue-50 border border-blue-200 rounded-lg p-6">
        <h3 className="font-semibold text-blue-900 mb-3">What Binary Analysis Detects:</h3>
        <div className="grid grid-cols-3 gap-4">
          <div className="flex items-start space-x-2">
            <Key className="h-5 w-5 text-blue-600 mt-0.5" />
            <div>
              <p className="font-medium text-blue-900">Hardcoded Secrets</p>
              <p className="text-xs text-blue-700">AWS keys, API tokens, passwords, private keys</p>
            </div>
          </div>
          <div className="flex items-start space-x-2">
            <Code className="h-5 w-5 text-blue-600 mt-0.5" />
            <div>
              <p className="font-medium text-blue-900">Unsafe Functions</p>
              <p className="text-xs text-blue-700">strcpy, system, eval, sprintf</p>
            </div>
          </div>
          <div className="flex items-start space-x-2">
            <Layers className="h-5 w-5 text-blue-600 mt-0.5" />
            <div>
              <p className="font-medium text-blue-900">Packed/Malware</p>
              <p className="text-xs text-blue-700">High entropy, packer signatures</p>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default BinaryAnalysis;
