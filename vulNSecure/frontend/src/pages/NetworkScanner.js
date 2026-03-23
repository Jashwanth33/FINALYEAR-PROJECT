import React, { useState } from 'react';
import { useQueryClient } from 'react-query';
import toast from 'react-hot-toast';
import { 
  Globe, Search, Server, Shield, AlertTriangle,
  CheckCircle, Clock, Wifi, Lock, Zap,
  RefreshCw, Eye, Copy, Key, Layers, Code
} from 'lucide-react';

const NetworkScanner = () => {
  const [target, setTarget] = useState('');
  const [activeTab, setActiveTab] = useState('scan');
  const [isScanning, setIsScanning] = useState(false);
  const [results, setResults] = useState(null);
  const [subdomains, setSubdomains] = useState(null);
  const [ports, setPorts] = useState(null);
  const [dns, setDns] = useState(null);
  const [ssl, setSsl] = useState(null);
  const [techs, setTechs] = useState(null);
  const [aiAnalysis, setAiAnalysis] = useState(null);
  const queryClient = useQueryClient();

  const getToken = () => localStorage.getItem('token');

  // Run vulnerability scan
  const startScan = async () => {
    if (!target) { toast.error('Please enter a target'); return; }
    setIsScanning(true);
    setResults(null);

    try {
      const response = await fetch('http://localhost:5001/api/scans', {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${getToken()}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: `Scan - ${target}`, target, type: 'web' })
      });
      const data = await response.json();
      if (data.success) {
        toast.success('Scan started!');
        pollResults(data.data.scan.id);
      } else {
        toast.error(data.message);
        setIsScanning(false);
      }
    } catch (error) {
      toast.error('Scan failed');
      setIsScanning(false);
    }
  };

  // Poll for results
  const pollResults = async (scanId) => {
    for (let i = 0; i < 30; i++) {
      await new Promise(r => setTimeout(r, 2000));
      const response = await fetch(`http://localhost:5001/api/scans/${scanId}`, {
        headers: { 'Authorization': `Bearer ${getToken()}` }
      });
      const data = await response.json();
      
      if (data.data.scan.status === 'completed') {
        const vulnResponse = await fetch(`http://localhost:5001/api/vulnerabilities?scanId=${scanId}`, {
          headers: { 'Authorization': `Bearer ${getToken()}` }
        });
        const vulnData = await vulnResponse.json();
        setResults({ scan: data.data.scan, vulnerabilities: vulnData.data?.vulnerabilities || [] });
        setIsScanning(false);
        toast.success('Scan complete!');
        return;
      }
      if (data.data.scan.status === 'failed') {
        toast.error('Scan failed');
        setIsScanning(false);
        return;
      }
    }
  };

  // Enumerate subdomains
  const enumerateSubdomains = async () => {
    if (!target) { toast.error('Please enter a target'); return; }
    toast.loading('Enumerating subdomains...');
    
    try {
      const response = await fetch('http://localhost:5001/api/pro/subdomains', {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${getToken()}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ domain: target })
      });
      const data = await response.json();
      toast.dismiss();
      
      if (data.success) {
        setSubdomains(data.data);
        toast.success(`Found ${data.data.total} subdomains`);
      }
    } catch (error) {
      toast.dismiss();
      toast.error('Subdomain enumeration failed');
    }
  };

  // Scan ports
  const scanPorts = async () => {
    if (!target) { toast.error('Please enter a target'); return; }
    toast.loading('Scanning ports...');
    
    try {
      const response = await fetch('http://localhost:5001/api/pro/ports', {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${getToken()}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ hostname: target })
      });
      const data = await response.json();
      toast.dismiss();
      
      if (data.success) {
        setPorts(data.data);
        toast.success(`Found ${data.data.openPorts.length} open ports`);
      }
    } catch (error) {
      toast.dismiss();
      toast.error('Port scan failed');
    }
  };

  // DNS enumeration
  const enumerateDNS = async () => {
    if (!target) { toast.error('Please enter a target'); return; }
    toast.loading('Querying DNS records...');
    
    try {
      const response = await fetch('http://localhost:5001/api/pro/dns', {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${getToken()}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ domain: target })
      });
      const data = await response.json();
      toast.dismiss();
      
      if (data.success) {
        setDns(data.data);
        toast.success('DNS records retrieved');
      }
    } catch (error) {
      toast.dismiss();
      toast.error('DNS enumeration failed');
    }
  };

  // SSL analysis
  const analyzeSSL = async () => {
    if (!target) { toast.error('Please enter a target'); return; }
    toast.loading('Analyzing SSL/TLS...');
    
    try {
      const response = await fetch('http://localhost:5001/api/pro/ssl', {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${getToken()}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ hostname: target })
      });
      const data = await response.json();
      toast.dismiss();
      
      if (data.success) {
        setSsl(data.data);
        toast.success('SSL analysis complete');
      }
    } catch (error) {
      toast.dismiss();
      toast.error('SSL analysis failed');
    }
  };

  // Detect technologies
  const detectTechnologies = async () => {
    if (!target) { toast.error('Please enter a target'); return; }
    toast.loading('Detecting technologies...');
    
    const url = target.startsWith('http') ? target : 'https://' + target;
    
    try {
      const response = await fetch('http://localhost:5001/api/pro/technologies', {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${getToken()}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ url })
      });
      const data = await response.json();
      toast.dismiss();
      
      if (data.success) {
        setTechs(data.data);
        toast.success(`Found ${data.data.length} technologies`);
      }
    } catch (error) {
      toast.dismiss();
      toast.error('Technology detection failed');
    }
  };

  // AI analysis for vulnerability
  const runAIAnalysis = async (vulnId) => {
    toast.loading('Running AI analysis...');
    
    try {
      const response = await fetch('http://localhost:5001/api/pro/ai-analyze', {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${getToken()}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ vulnerabilityId: vulnId })
      });
      const data = await response.json();
      toast.dismiss();
      
      if (data.success) {
        setAiAnalysis(data.data);
        toast.success('AI analysis complete');
      }
    } catch (error) {
      toast.dismiss();
      toast.error('AI analysis failed');
    }
  };

  const copyToClipboard = (text) => {
    navigator.clipboard.writeText(text);
    toast.success('Copied!');
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-3xl font-bold text-gray-900">Security Scanner</h1>
        <p className="text-gray-600 mt-1">Comprehensive security analysis with subdomain enumeration, port scanning, and AI analysis</p>
      </div>

      {/* Target Input */}
      <div className="bg-white p-6 rounded-lg shadow-sm border border-gray-200">
        <div className="flex space-x-3">
          <input
            type="text"
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            placeholder="example.com"
            className="flex-1 px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500"
          />
        </div>
      </div>

      {/* Feature Tabs */}
      <div className="bg-white rounded-lg shadow-sm border border-gray-200">
        <div className="border-b border-gray-200">
          <nav className="flex space-x-4 px-6">
            {[
              { id: 'scan', name: 'Vulnerability Scan', icon: Search },
              { id: 'subdomains', name: 'Subdomains', icon: Globe },
              { id: 'ports', name: 'Ports', icon: Server },
              { id: 'dns', name: 'DNS', icon: Wifi },
              { id: 'ssl', name: 'SSL/TLS', icon: Lock },
              { id: 'tech', name: 'Technologies', icon: Code }
            ].map(tab => (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`flex items-center px-3 py-4 text-sm font-medium border-b-2 ${
                  activeTab === tab.id
                    ? 'border-blue-500 text-blue-600'
                    : 'border-transparent text-gray-500 hover:text-gray-700'
                }`}
              >
                <tab.icon className="h-4 w-4 mr-2" />
                {tab.name}
              </button>
            ))}
          </nav>
        </div>

        <div className="p-6">
          {/* Vulnerability Scan Tab */}
          {activeTab === 'scan' && (
            <div>
              <button
                onClick={startScan}
                disabled={isScanning || !target}
                className="flex items-center px-6 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50"
              >
                {isScanning ? <><RefreshCw className="h-4 w-4 mr-2 animate-spin" />Scanning...</> : <><Search className="h-4 w-4 mr-2" />Start Scan</>}
              </button>

              {results && (
                <div className="mt-6 space-y-4">
                  <div className="grid grid-cols-5 gap-4">
                    <div className="bg-gray-50 p-4 rounded text-center">
                      <p className="text-2xl font-bold">{results.vulnerabilities.length}</p>
                      <p className="text-sm text-gray-600">Total</p>
                    </div>
                    <div className="bg-red-50 p-4 rounded text-center">
                      <p className="text-2xl font-bold text-red-600">{results.vulnerabilities.filter(v => v.severity === 'critical').length}</p>
                      <p className="text-sm text-red-700">Critical</p>
                    </div>
                    <div className="bg-orange-50 p-4 rounded text-center">
                      <p className="text-2xl font-bold text-orange-600">{results.vulnerabilities.filter(v => v.severity === 'high').length}</p>
                      <p className="text-sm text-orange-700">High</p>
                    </div>
                    <div className="bg-yellow-50 p-4 rounded text-center">
                      <p className="text-2xl font-bold text-yellow-600">{results.vulnerabilities.filter(v => v.severity === 'medium').length}</p>
                      <p className="text-sm text-yellow-700">Medium</p>
                    </div>
                    <div className="bg-green-50 p-4 rounded text-center">
                      <p className="text-2xl font-bold text-green-600">{results.vulnerabilities.filter(v => v.severity === 'low').length}</p>
                      <p className="text-sm text-green-700">Low</p>
                    </div>
                  </div>

                  {results.vulnerabilities.map((vuln, i) => (
                    <div key={i} className="border border-gray-200 rounded-lg p-4">
                      <div className="flex justify-between items-start">
                        <div>
                          <span className={`px-2 py-1 text-xs rounded-full ${
                            vuln.severity === 'critical' ? 'bg-red-100 text-red-800' :
                            vuln.severity === 'high' ? 'bg-orange-100 text-orange-800' :
                            vuln.severity === 'medium' ? 'bg-yellow-100 text-yellow-800' :
                            'bg-green-100 text-green-800'
                          }`}>
                            {vuln.severity.toUpperCase()}
                          </span>
                          <h4 className="font-medium mt-2">{vuln.title}</h4>
                          <p className="text-sm text-gray-600">{vuln.description}</p>
                          {vuln.cvssScore && <p className="text-xs text-gray-500 mt-1">CVSS: {vuln.cvssScore}</p>}
                        </div>
                        <button
                          onClick={() => runAIAnalysis(vuln.id)}
                          className="px-3 py-1 bg-purple-100 text-purple-700 rounded text-sm hover:bg-purple-200"
                        >
                          <Zap className="h-3 w-3 inline mr-1" />
                          AI Analysis
                        </button>
                      </div>
                      
                      <div className="mt-3 bg-blue-50 p-3 rounded">
                        <p className="text-xs font-medium text-blue-700">Fix:</p>
                        <p className="text-sm text-blue-800">{vuln.solution}</p>
                      </div>

                      {vuln.poc && (
                        <details className="mt-3">
                          <summary className="cursor-pointer text-sm text-blue-600">View POC</summary>
                          <pre className="mt-2 bg-gray-900 text-gray-100 p-4 rounded text-xs overflow-x-auto">{vuln.poc}</pre>
                        </details>
                      )}
                    </div>
                  ))}
                </div>
              )}

              {/* AI Analysis Results */}
              {aiAnalysis && (
                <div className="mt-6 bg-purple-50 border border-purple-200 rounded-lg p-6">
                  <h3 className="font-semibold text-purple-900 mb-4">AI Analysis</h3>
                  <div className="space-y-3">
                    <div>
                      <p className="font-medium text-purple-800">Risk Level:</p>
                      <p className="text-purple-700">{aiAnalysis.analysis.riskLevel}</p>
                    </div>
                    <div>
                      <p className="font-medium text-purple-800">Exploitability:</p>
                      <p className="text-purple-700">{aiAnalysis.analysis.exploitability}</p>
                    </div>
                    <div>
                      <p className="font-medium text-purple-800">Business Impact:</p>
                      <p className="text-purple-700">{aiAnalysis.analysis.businessImpact}</p>
                    </div>
                    <div>
                      <p className="font-medium text-purple-800">Real-World Examples:</p>
                      <ul className="list-disc list-inside text-purple-700">
                        {aiAnalysis.analysis.examples.map((ex, i) => <li key={i}>{ex}</li>)}
                      </ul>
                    </div>
                  </div>
                </div>
              )}
            </div>
          )}

          {/* Subdomains Tab */}
          {activeTab === 'subdomains' && (
            <div>
              <button
                onClick={enumerateSubdomains}
                disabled={!target}
                className="flex items-center px-6 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50"
              >
                <Globe className="h-4 w-4 mr-2" />
                Enumerate Subdomains
              </button>

              {subdomains && (
                <div className="mt-6">
                  <p className="text-sm text-gray-600 mb-3">Found {subdomains.total} subdomains:</p>
                  <div className="grid grid-cols-3 gap-2">
                    {subdomains.found.map((sub, i) => (
                      <div key={i} className="flex items-center justify-between p-2 bg-gray-50 rounded">
                        <span className="text-sm">{sub.subdomain}</span>
                        <button onClick={() => copyToClipboard(sub.subdomain)} className="text-gray-400 hover:text-gray-600">
                          <Copy className="h-3 w-3" />
                        </button>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* Ports Tab */}
          {activeTab === 'ports' && (
            <div>
              <button
                onClick={scanPorts}
                disabled={!target}
                className="flex items-center px-6 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50"
              >
                <Server className="h-4 w-4 mr-2" />
                Scan Ports
              </button>

              {ports && (
                <div className="mt-6">
                  <p className="text-sm text-gray-600 mb-3">Open ports: {ports.openPorts.join(', ')}</p>
                  <div className="space-y-2">
                    {ports.services.map((svc, i) => (
                      <div key={i} className="flex items-center justify-between p-3 bg-gray-50 rounded">
                        <div className="flex items-center space-x-3">
                          <span className="px-2 py-1 bg-green-100 text-green-700 rounded text-xs">OPEN</span>
                          <span className="font-medium">Port {svc.port}</span>
                          <span className="text-gray-500">({svc.service})</span>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* DNS Tab */}
          {activeTab === 'dns' && (
            <div>
              <button
                onClick={enumerateDNS}
                disabled={!target}
                className="flex items-center px-6 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50"
              >
                <Wifi className="h-4 w-4 mr-2" />
                Query DNS
              </button>

              {dns && (
                <div className="mt-6 space-y-3">
                  {Object.entries(dns.records).map(([type, records]) => (
                    <div key={type} className="p-3 bg-gray-50 rounded">
                      <p className="font-medium text-gray-700">{type} Records:</p>
                      {records.map((r, i) => (
                        <p key={i} className="text-sm text-gray-600 ml-4">{r}</p>
                      ))}
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {/* SSL Tab */}
          {activeTab === 'ssl' && (
            <div>
              <button
                onClick={analyzeSSL}
                disabled={!target}
                className="flex items-center px-6 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50"
              >
                <Lock className="h-4 w-4 mr-2" />
                Analyze SSL/TLS
              </button>

              {ssl && (
                <div className="mt-6">
                  <div className={`p-4 rounded ${ssl.valid ? 'bg-green-50' : 'bg-red-50'}`}>
                    <p className={`font-medium ${ssl.valid ? 'text-green-700' : 'text-red-700'}`}>
                      {ssl.valid ? 'SSL Certificate Valid' : 'SSL Issues Found'}
                    </p>
                    {ssl.issues.map((issue, i) => (
                      <p key={i} className="text-sm text-red-600 mt-1">- {issue}</p>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* Technologies Tab */}
          {activeTab === 'tech' && (
            <div>
              <button
                onClick={detectTechnologies}
                disabled={!target}
                className="flex items-center px-6 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50"
              >
                <Code className="h-4 w-4 mr-2" />
                Detect Technologies
              </button>

              {techs && (
                <div className="mt-6 grid grid-cols-4 gap-4">
                  {techs.map((tech, i) => (
                    <div key={i} className="p-3 bg-gray-50 rounded">
                      <p className="text-xs text-gray-500">{tech.type}</p>
                      <p className="font-medium">{tech.name}</p>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default NetworkScanner;
