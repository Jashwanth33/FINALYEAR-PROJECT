import React, { useState, useEffect } from 'react';
import { useLocation } from 'react-router-dom';
import toast from 'react-hot-toast';
import {
  Shield, Search, Globe, File, Download, Copy, Play, Activity, RefreshCw, Code, Layers, Users
} from 'lucide-react';

const AllFeatures = () => {
  const location = useLocation();
  const [activeTab, setActiveTab] = useState('scanning');
  const [results, setResults] = useState(null);
  const [loading, setLoading] = useState(false);
  const [target, setTarget] = useState('https://httpbin.org');
  
  // Team state
  const [teamMembers, setTeamMembers] = useState([
    { id: 1, name: 'Admin User', email: 'admin@vulnsecure.com', role: 'admin' }
  ]);
  const [showAddMember, setShowAddMember] = useState(false);
  const [newMember, setNewMember] = useState({ name: '', email: '', role: 'analyst' });
  const [selectedVuln, setSelectedVuln] = useState('');
  const [selectedMember, setSelectedMember] = useState('');

  const getToken = () => localStorage.getItem('token');

  // Map routes to tabs
  const routeToTab = {
    '/features': 'scanning',
    '/recon': 'recon',
    '/threatintel': 'threatintel',
    '/compliance': 'compliance',
    '/darkweb': 'darkweb',
    '/team': 'team',
    '/cicd': 'cicd'
  };

  // Auto-select tab based on URL
  useEffect(() => {
    const path = location.pathname;
    
    // Check exact matches first
    if (routeToTab[path]) {
      setActiveTab(routeToTab[path]);
      return;
    }
    
    // Check partial matches
    if (path.includes('compliance')) setActiveTab('compliance');
    else if (path.includes('darkweb')) setActiveTab('darkweb');
    else if (path.includes('cicd')) setActiveTab('cicd');
    else if (path.includes('team')) setActiveTab('team');
    else if (path.includes('recon')) setActiveTab('recon');
    else if (path.includes('threat')) setActiveTab('threatintel');
    else setActiveTab('scanning');
  }, [location.pathname]);

  // Run main vulnerability scan
  const runScan = async () => {
    setLoading(true);
    toast.loading('Starting scan...');
    
    try {
      const resp = await fetch('http://localhost:5001/api/scans', {
        method: 'POST',
        headers: { 'Authorization': 'Bearer ' + getToken(), 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: 'Full Scan', target, type: 'web' })
      });
      
      const data = await resp.json();
      toast.dismiss();
      
      if (data.success) {
        toast.success('Scan started!');
        
        // Poll for results
        const scanId = data.data.scan.id;
        for (let i = 0; i < 30; i++) {
          await new Promise(r => setTimeout(r, 2000));
          
          const statusResp = await fetch('http://localhost:5001/api/scans/' + scanId, {
            headers: { 'Authorization': 'Bearer ' + getToken() }
          });
          const statusData = await statusResp.json();
          
          if (statusData.data.scan.status === 'completed') {
            // Get vulnerabilities
            const vulnResp = await fetch('http://localhost:5001/api/vulnerabilities?scanId=' + scanId, {
              headers: { 'Authorization': 'Bearer ' + getToken() }
            });
            const vulnData = await vulnResp.json();
            
            setResults({
              type: 'scan',
              scan: statusData.data.scan,
              vulnerabilities: vulnData.data?.vulnerabilities || []
            });
            toast.success('Scan complete!');
            break;
          }
          
          if (statusData.data.scan.status === 'failed') {
            toast.error('Scan failed: ' + (statusData.data.scan.errorMessage || 'Unknown error'));
            break;
          }
        }
      } else {
        toast.error(data.message || 'Scan failed');
      }
    } catch (e) {
      toast.dismiss();
      toast.error('Scan failed: ' + e.message);
    }
    setLoading(false);
  };

  // Run subdomain enumeration
  const runSubdomains = async () => {
    setLoading(true);
    toast.loading('Finding subdomains...');
    
    try {
      const domain = target.replace(/^(https?:\/\/)?/, '').split('/')[0];
      const resp = await fetch('http://localhost:5001/api/pro/subdomains', {
        method: 'POST',
        headers: { 'Authorization': 'Bearer ' + getToken(), 'Content-Type': 'application/json' },
        body: JSON.stringify({ domain })
      });
      
      const data = await resp.json();
      toast.dismiss();
      
      if (data.success) {
        setResults({ type: 'subdomains', ...data.data });
        toast.success('Found ' + data.data.total + ' subdomains');
      }
    } catch (e) {
      toast.dismiss();
      toast.error('Subdomain scan failed');
    }
    setLoading(false);
  };

  // Run port scan
  const runPorts = async () => {
    setLoading(true);
    toast.loading('Scanning ports...');
    
    try {
      const hostname = target.replace(/^(https?:\/\/)?/, '').split('/')[0];
      const resp = await fetch('http://localhost:5001/api/pro/ports', {
        method: 'POST',
        headers: { 'Authorization': 'Bearer ' + getToken(), 'Content-Type': 'application/json' },
        body: JSON.stringify({ hostname })
      });
      
      const data = await resp.json();
      toast.dismiss();
      
      if (data.success) {
        setResults({ type: 'ports', ...data.data });
        toast.success('Found ' + data.data.openPorts.length + ' open ports');
      }
    } catch (e) {
      toast.dismiss();
      toast.error('Port scan failed');
    }
    setLoading(false);
  };

  // Run DNS scan
  const runDNS = async () => {
    setLoading(true);
    toast.loading('Querying DNS...');
    
    try {
      const domain = target.replace(/^(https?:\/\/)?/, '').split('/')[0];
      const resp = await fetch('http://localhost:5001/api/pro/dns', {
        method: 'POST',
        headers: { 'Authorization': 'Bearer ' + getToken(), 'Content-Type': 'application/json' },
        body: JSON.stringify({ domain })
      });
      
      const data = await resp.json();
      toast.dismiss();
      
      if (data.success) {
        setResults({ type: 'dns', ...data.data });
        toast.success('DNS records retrieved');
      }
    } catch (e) {
      toast.dismiss();
      toast.error('DNS scan failed');
    }
    setLoading(false);
  };

  // Run technology detection
  const runTechnologies = async () => {
    setLoading(true);
    toast.loading('Detecting technologies...');
    
    try {
      const resp = await fetch('http://localhost:5001/api/pro/technologies', {
        method: 'POST',
        headers: { 'Authorization': 'Bearer ' + getToken(), 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: target })
      });
      
      const data = await resp.json();
      toast.dismiss();
      
      if (data.success) {
        setResults({ type: 'technologies', technologies: data.data });
        toast.success('Found ' + data.data.length + ' technologies');
      }
    } catch (e) {
      toast.dismiss();
      toast.error('Technology detection failed');
    }
    setLoading(false);
  };

  // Run SSL scan
  const runSSL = async () => {
    setLoading(true);
    toast.loading('Analyzing SSL...');
    
    try {
      const hostname = target.replace(/^(https?:\/\/)?/, '').split('/')[0];
      const resp = await fetch('http://localhost:5001/api/pro/ssl', {
        method: 'POST',
        headers: { 'Authorization': 'Bearer ' + getToken(), 'Content-Type': 'application/json' },
        body: JSON.stringify({ hostname })
      });
      
      const data = await resp.json();
      toast.dismiss();
      
      if (data.success) {
        setResults({ type: 'ssl', ...data.data });
        toast.success('SSL analysis complete');
      }
    } catch (e) {
      toast.dismiss();
      toast.error('SSL scan failed');
    }
    setLoading(false);
  };

  // Run threat intelligence
  const runThreatIntel = async () => {
    setLoading(true);
    toast.loading('Fetching threat intelligence...');
    
    try {
      const domain = target.replace(/^(https?:\/\/)?/, '').split('/')[0];
      const resp = await fetch('http://localhost:5001/api/advanced/threat-intel', {
        method: 'POST',
        headers: { 'Authorization': 'Bearer ' + getToken(), 'Content-Type': 'application/json' },
        body: JSON.stringify({ domain })
      });
      
      const data = await resp.json();
      toast.dismiss();
      
      if (data.success) {
        setResults({ type: 'threatintel', ...data.data });
        toast.success('Threat intelligence retrieved!');
      }
    } catch (e) {
      toast.dismiss();
      toast.error('Threat intel failed');
    }
    setLoading(false);
  };

  // Run dark web check
  const runDarkWeb = async () => {
    setLoading(true);
    toast.loading('Checking dark web...');
    
    try {
      const domain = target.replace(/^(https?:\/\/)?/, '').split('/')[0];
      const resp = await fetch('http://localhost:5001/api/complete/darkweb', {
        method: 'POST',
        headers: { 'Authorization': 'Bearer ' + getToken(), 'Content-Type': 'application/json' },
        body: JSON.stringify({ domain })
      });
      
      const data = await resp.json();
      toast.dismiss();
      
      if (data.success) {
        setResults({ type: 'darkweb', ...data.data });
        toast.success('Dark web check complete');
      }
    } catch (e) {
      toast.dismiss();
      toast.error('Dark web check failed');
    }
    setLoading(false);
  };

  // Run compliance check
  const runCompliance = async (framework) => {
    setLoading(true);
    toast.loading('Checking ' + framework + ' compliance...');
    
    try {
      // Get latest scan
      const scansResp = await fetch('http://localhost:5001/api/scans?limit=1', {
        headers: { 'Authorization': 'Bearer ' + getToken() }
      });
      const scansData = await scansResp.json();
      
      if (scansData.data?.scans?.length > 0) {
        const resp = await fetch('http://localhost:5001/api/complete/compliance', {
          method: 'POST',
          headers: { 'Authorization': 'Bearer ' + getToken(), 'Content-Type': 'application/json' },
          body: JSON.stringify({ scanId: scansData.data.scans[0].id, framework })
        });
        
        const data = await resp.json();
        toast.dismiss();
        
        if (data.success) {
          setResults({ type: 'compliance', framework, ...data.data });
          toast.success(framework + ' compliance checked!');
        }
      } else {
        toast.dismiss();
        toast.error('Run a scan first to check compliance');
      }
    } catch (e) {
      toast.dismiss();
      toast.error('Compliance check failed');
    }
    setLoading(false);
  };

  // Generate CI/CD config
  const generateCICD = async (platform) => {
    setLoading(true);
    toast.loading('Generating ' + platform + ' config...');
    
    try {
      const resp = await fetch('http://localhost:5001/api/complete/cicd/config', {
        method: 'POST',
        headers: { 'Authorization': 'Bearer ' + getToken(), 'Content-Type': 'application/json' },
        body: JSON.stringify({ platform, target })
      });
      
      const data = await resp.json();
      toast.dismiss();
      
      if (data.success) {
        setResults({ type: 'cicd', platform, config: data.data.config });
        toast.success(platform + ' config generated!');
      }
    } catch (e) {
      toast.dismiss();
      toast.error('Config generation failed');
    }
    setLoading(false);
  };

  const copyToClipboard = (text) => {
    navigator.clipboard.writeText(text);
    toast.success('Copied!');
  };

  // Add team member
  const addMember = () => {
    if (!newMember.name || !newMember.email) {
      toast.error('Please enter name and email');
      return;
    }
    
    const member = {
      id: Date.now(),
      name: newMember.name,
      email: newMember.email,
      role: newMember.role
    };
    
    setTeamMembers([...teamMembers, member]);
    setNewMember({ name: '', email: '', role: 'analyst' });
    setShowAddMember(false);
    toast.success('Team member added!');
  };

  // Remove team member
  const removeMember = (id) => {
    setTeamMembers(teamMembers.filter(m => m.id !== id));
    toast.success('Member removed');
  };

  // Assign vulnerability
  const assignVulnerability = async () => {
    if (!selectedVuln || !selectedMember) {
      toast.error('Please select vulnerability and team member');
      return;
    }
    
    toast.success('Vulnerability assigned to ' + teamMembers.find(m => m.id === parseInt(selectedMember))?.name);
    setSelectedVuln('');
    setSelectedMember('');
  };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold text-gray-900">Security Features</h1>
        <p className="text-gray-600">Comprehensive vulnerability scanning and security testing</p>
      </div>

      {/* Target Input */}
      <div className="bg-white p-4 rounded-lg shadow-sm border border-gray-200">
        <label className="block text-sm font-medium text-gray-700 mb-2">Target URL</label>
        <div className="flex space-x-3">
          <input
            type="text"
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            placeholder="https://example.com"
            className="flex-1 px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500"
          />
        </div>
      </div>

      {/* Tabs */}
      <div className="bg-white rounded-lg shadow-sm border border-gray-200">
        <div className="border-b border-gray-200">
          <nav className="flex space-x-4 px-6 overflow-x-auto">
            {[
              { id: 'scanning', name: 'Vulnerability Scan', icon: Search },
              { id: 'recon', name: 'Reconnaissance', icon: Globe },
              { id: 'threatintel', name: 'Threat Intelligence', icon: Activity },
              { id: 'compliance', name: 'Compliance', icon: File },
              { id: 'darkweb', name: 'Dark Web', icon: Shield },
              { id: 'team', name: 'Team', icon: Users },
              { id: 'cicd', name: 'CI/CD', icon: RefreshCw }
            ].map(tab => {
              const Icon = tab.icon;
              return (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id)}
                  className={`flex items-center px-3 py-4 text-sm font-medium border-b-2 whitespace-nowrap ${
                    activeTab === tab.id
                      ? 'border-blue-500 text-blue-600'
                      : 'border-transparent text-gray-500 hover:text-gray-700'
                  }`}
                >
                  <Icon className="h-4 w-4 mr-2" />
                  {tab.name}
                </button>
              );
            })}
          </nav>
        </div>

        <div className="p-6">
          {/* Vulnerability Scan Tab */}
          {activeTab === 'scanning' && (
            <div className="space-y-4">
              <h2 className="text-lg font-semibold">Vulnerability Detection</h2>
              <p className="text-gray-600">Scan for SQL Injection, XSS, SSRF, Command Injection, XXE, Open Redirect, CORS, SSL issues, and more.</p>
              
              <button
                onClick={runScan}
                disabled={loading}
                className="flex items-center px-6 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50"
              >
                {loading ? 'Scanning...' : <><Play className="h-4 w-4 mr-2" /> Start Full Scan</>}
              </button>

              {results?.type === 'scan' && (
                <div className="mt-4 space-y-4">
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

                  <div className="space-y-3">
                    {results.vulnerabilities.map((vuln, i) => (
                      <div key={i} className="border border-gray-200 rounded-lg p-4">
                        <div className="flex items-center space-x-2">
                          <span className={`px-2 py-1 text-xs font-medium rounded-full ${
                            vuln.severity === 'critical' ? 'bg-red-100 text-red-800' :
                            vuln.severity === 'high' ? 'bg-orange-100 text-orange-800' :
                            vuln.severity === 'medium' ? 'bg-yellow-100 text-yellow-800' :
                            'bg-green-100 text-green-800'
                          }`}>
                            {vuln.severity.toUpperCase()}
                          </span>
                          <h4 className="font-medium">{vuln.title}</h4>
                        </div>
                        <p className="text-sm text-gray-600 mt-2">{vuln.description}</p>
                        {vuln.url && (
                          <div className="mt-2 flex items-center space-x-2">
                            <span className="text-xs text-gray-500">URL:</span>
                            <code className="text-xs bg-gray-100 px-2 py-1 rounded">{vuln.url}</code>
                            <button onClick={() => copyToClipboard(vuln.url)} className="text-gray-400 hover:text-gray-600">
                              <Copy className="h-3 w-3" />
                            </button>
                          </div>
                        )}
                        <div className="mt-2 text-xs text-blue-600">
                          <strong>Fix:</strong> {vuln.solution}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* Reconnaissance Tab */}
          {activeTab === 'recon' && (
            <div className="space-y-4">
              <h2 className="text-lg font-semibold">Reconnaissance</h2>
              <p className="text-gray-600">Subdomain enumeration, port scanning, DNS records, technology detection, SSL analysis</p>
              
              <div className="grid grid-cols-3 gap-4">
                <button onClick={runSubdomains} disabled={loading} className="p-4 bg-gray-50 rounded-lg hover:bg-gray-100 text-left">
                  <Globe className="h-6 w-6 text-blue-600 mb-2" />
                  <p className="font-medium">Subdomains</p>
                  <p className="text-xs text-gray-500">Find all subdomains</p>
                </button>
                
                <button onClick={runPorts} disabled={loading} className="p-4 bg-gray-50 rounded-lg hover:bg-gray-100 text-left">
                  <Search className="h-6 w-6 text-blue-600 mb-2" />
                  <p className="font-medium">Ports</p>
                  <p className="text-xs text-gray-500">Scan open ports</p>
                </button>
                
                <button onClick={runDNS} disabled={loading} className="p-4 bg-gray-50 rounded-lg hover:bg-gray-100 text-left">
                  <Globe className="h-6 w-6 text-blue-600 mb-2" />
                  <p className="font-medium">DNS Records</p>
                  <p className="text-xs text-gray-500">Query DNS</p>
                </button>
                
                <button onClick={runTechnologies} disabled={loading} className="p-4 bg-gray-50 rounded-lg hover:bg-gray-100 text-left">
                  <Shield className="h-6 w-6 text-blue-600 mb-2" />
                  <p className="font-medium">Technologies</p>
                  <p className="text-xs text-gray-500">Detect tech stack</p>
                </button>
                
                <button onClick={runSSL} disabled={loading} className="p-4 bg-gray-50 rounded-lg hover:bg-gray-100 text-left">
                  <Shield className="h-6 w-6 text-blue-600 mb-2" />
                  <p className="font-medium">SSL/TLS</p>
                  <p className="text-xs text-gray-500">Certificate analysis</p>
                </button>
              </div>

              {results?.type === 'subdomains' && (
                <div className="mt-4 p-4 bg-gray-50 rounded-lg">
                  <h3 className="font-medium">Subdomains Found: {results.total}</h3>
                  <div className="mt-2 grid grid-cols-3 gap-2">
                    {results.found?.map((sub, i) => (
                      <div key={i} className="p-2 bg-white rounded text-sm">{sub.subdomain}</div>
                    ))}
                  </div>
                </div>
              )}

              {results?.type === 'ports' && (
                <div className="mt-4 p-4 bg-gray-50 rounded-lg">
                  <h3 className="font-medium">Open Ports: {results.openPorts?.join(', ')}</h3>
                  <div className="mt-2 space-y-1">
                    {results.services?.map((svc, i) => (
                      <div key={i} className="text-sm">{svc.port} - {svc.service}</div>
                    ))}
                  </div>
                </div>
              )}

              {results?.type === 'technologies' && (
                <div className="mt-4 p-4 bg-gray-50 rounded-lg">
                  <h3 className="font-medium">Technologies Detected: {results.technologies?.length}</h3>
                  <div className="mt-2 flex flex-wrap gap-2">
                    {results.technologies?.map((tech, i) => (
                      <span key={i} className="px-2 py-1 bg-blue-100 text-blue-800 rounded text-sm">{tech.name}</span>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* Threat Intelligence Tab */}
          {activeTab === 'threatintel' && (
            <div className="space-y-4">
              <h2 className="text-lg font-semibold">Threat Intelligence</h2>
              <p className="text-gray-600">Get latest threat feeds, IOC matching, reputation scores, and risk indicators</p>
              
              <button
                onClick={runThreatIntel}
                disabled={loading}
                className="flex items-center px-6 py-2 bg-purple-600 text-white rounded-lg hover:bg-purple-700 disabled:opacity-50"
              >
                {loading ? 'Fetching...' : <><Shield className="h-4 w-4 mr-2" /> Get Threat Intelligence</>}
              </button>

              {results?.type === 'threatintel' && (
                <div className="mt-4 space-y-4">
                  {/* Reputation Score */}
                  <div className="grid grid-cols-3 gap-4">
                    <div className="bg-white p-4 rounded-lg border">
                      <p className="text-2xl font-bold text-purple-600">{results.reputationScore}</p>
                      <p className="text-sm text-gray-600">Reputation Score</p>
                    </div>
                    <div className="bg-white p-4 rounded-lg border">
                      <p className="text-2xl font-bold capitalize">{results.reputation}</p>
                      <p className="text-sm text-gray-600">Status</p>
                    </div>
                    <div className="bg-white p-4 rounded-lg border">
                      <p className="text-2xl font-bold">{results.recentThreats?.length || 0}</p>
                      <p className="text-sm text-gray-600">Recent Threats</p>
                    </div>
                  </div>

                  {/* Recent Threats */}
                  {results.recentThreats?.length > 0 && (
                    <div className="bg-red-50 p-4 rounded-lg">
                      <h3 className="font-medium text-red-700 mb-3">Recent Threats</h3>
                      <div className="space-y-2">
                        {results.recentThreats.map((threat, i) => (
                          <div key={i} className="flex items-center justify-between p-2 bg-white rounded">
                            <div>
                              <span className={`px-2 py-1 text-xs rounded ${
                                threat.severity === 'critical' ? 'bg-red-100 text-red-800' :
                                threat.severity === 'high' ? 'bg-orange-100 text-orange-800' :
                                'bg-yellow-100 text-yellow-800'
                              }`}>
                                {threat.severity.toUpperCase()}
                              </span>
                              <span className="ml-2 font-medium">{threat.type}</span>
                            </div>
                            <span className="text-sm text-gray-600">{threat.date}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Risk Indicators */}
                  {results.riskIndicators?.length > 0 && (
                    <div className="bg-yellow-50 p-4 rounded-lg">
                      <h3 className="font-medium text-yellow-700 mb-3">Risk Indicators</h3>
                      <div className="space-y-2">
                        {results.riskIndicators.map((indicator, i) => (
                          <div key={i} className="p-2 bg-white rounded">
                            <p className="font-medium">{indicator.indicator}</p>
                            <p className="text-sm text-gray-600">{indicator.risk}</p>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* IOCs */}
                  {results.iocs?.length > 0 && (
                    <div className="bg-blue-50 p-4 rounded-lg">
                      <h3 className="font-medium text-blue-700 mb-3">Indicators of Compromise (IOCs)</h3>
                      <div className="space-y-2">
                        {results.iocs.map((ioc, i) => (
                          <div key={i} className="flex items-center justify-between p-2 bg-white rounded">
                            <div>
                              <span className="px-2 py-1 text-xs bg-blue-100 text-blue-800 rounded">{ioc.type}</span>
                              <span className="ml-2 font-mono text-sm">{ioc.value}</span>
                            </div>
                            <span className="text-sm text-gray-600">{ioc.threat}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              )}
            </div>
          )}

          {/* Compliance Tab */}
          {activeTab === 'compliance' && (
            <div className="space-y-4">
              <h2 className="text-lg font-semibold">Compliance Frameworks</h2>
              <p className="text-gray-600">Check against PCI-DSS, HIPAA, OWASP, SOC2, GDPR requirements</p>
              
              <div className="grid grid-cols-5 gap-4">
                {['pci-dss', 'hipaa', 'owasp', 'soc2', 'gdpr'].map(fw => (
                  <button
                    key={fw}
                    onClick={() => runCompliance(fw)}
                    disabled={loading}
                    className="p-4 bg-gray-50 rounded-lg hover:bg-gray-100 text-center"
                  >
                    <p className="font-medium uppercase">{fw}</p>
                    <p className="text-xs text-gray-500 mt-1">Check compliance</p>
                  </button>
                ))}
              </div>

              {results?.type === 'compliance' && (
                <div className="mt-4 p-4 bg-gray-50 rounded-lg">
                  <h3 className="font-medium uppercase">{results.framework} Compliance</h3>
                  <div className="mt-2 grid grid-cols-3 gap-4">
                    <div className="bg-white p-3 rounded">
                      <p className="text-2xl font-bold text-blue-600">{results.score}%</p>
                      <p className="text-sm text-gray-600">Score</p>
                    </div>
                    <div className="bg-white p-3 rounded">
                      <p className="text-2xl font-bold text-green-600">{results.passed}</p>
                      <p className="text-sm text-gray-600">Passed</p>
                    </div>
                    <div className="bg-white p-3 rounded">
                      <p className="text-2xl font-bold text-red-600">{results.failed}</p>
                      <p className="text-sm text-gray-600">Failed</p>
                    </div>
                  </div>
                  <div className="mt-4 space-y-2">
                    {results.requirements?.map((req, i) => (
                      <div key={i} className={`p-2 rounded ${req.status === 'passed' ? 'bg-green-50' : 'bg-red-50'}`}>
                        <span className={`text-xs font-medium ${req.status === 'passed' ? 'text-green-700' : 'text-red-700'}`}>
                          {req.status === 'passed' ? 'PASS' : 'FAIL'}
                        </span>
                        <span className="ml-2 text-sm">{req.id}: {req.name}</span>
                        {req.vulnerability && <p className="text-xs text-red-600 ml-12">{req.vulnerability}</p>}
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* Dark Web Tab */}
          {activeTab === 'darkweb' && (
            <div className="space-y-4">
              <h2 className="text-lg font-semibold">Dark Web Monitoring</h2>
              <p className="text-gray-600">Check for data breaches, credential leaks, and dark web mentions</p>
              
              <button
                onClick={runDarkWeb}
                disabled={loading}
                className="flex items-center px-6 py-2 bg-red-600 text-white rounded-lg hover:bg-red-700 disabled:opacity-50"
              >
                {loading ? 'Checking...' : <><Shield className="h-4 w-4 mr-2" /> Check Dark Web</>}
              </button>

              {results?.type === 'darkweb' && (
                <div className="mt-4 space-y-4">
                  <div className="grid grid-cols-3 gap-4">
                    <div className="bg-white p-4 rounded-lg border">
                      <p className="text-2xl font-bold text-red-600">{results.riskScore}</p>
                      <p className="text-sm text-gray-600">Risk Score</p>
                    </div>
                    <div className="bg-white p-4 rounded-lg border">
                      <p className="text-2xl font-bold">{results.breaches?.length || 0}</p>
                      <p className="text-sm text-gray-600">Breaches Found</p>
                    </div>
                    <div className="bg-white p-4 rounded-lg border">
                      <p className="text-2xl font-bold">{results.pasteLeaks?.length || 0}</p>
                      <p className="text-sm text-gray-600">Paste Leaks</p>
                    </div>
                  </div>

                  {results.breaches?.length > 0 && (
                    <div className="bg-red-50 p-4 rounded-lg">
                      <h3 className="font-medium text-red-700">Data Breaches</h3>
                      {results.breaches.map((b, i) => (
                        <div key={i} className="mt-2 p-2 bg-white rounded">
                          <p className="font-medium">{b.name}</p>
                          <p className="text-sm text-gray-600">{b.year} - {b.records} records</p>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}
            </div>
          )}

          {/* Team Tab */}
          {activeTab === 'team' && (
            <div className="space-y-4">
              <h2 className="text-lg font-semibold">Team Collaboration</h2>
              <p className="text-gray-600">Manage team members, assign vulnerabilities, track remediation</p>
              
              <div className="grid grid-cols-2 gap-4">
                <div className="p-4 bg-gray-50 rounded-lg">
                  <div className="flex items-center justify-between mb-3">
                    <h3 className="font-medium">Team Members</h3>
                    <button
                      onClick={() => setShowAddMember(true)}
                      className="px-3 py-1 bg-blue-600 text-white rounded text-sm hover:bg-blue-700"
                    >
                      + Add
                    </button>
                  </div>
                  
                  {showAddMember && (
                    <div className="mb-4 p-3 bg-white rounded border">
                      <input
                        type="text"
                        placeholder="Name"
                        value={newMember.name}
                        onChange={(e) => setNewMember({...newMember, name: e.target.value})}
                        className="w-full px-3 py-2 border rounded mb-2 text-sm"
                      />
                      <input
                        type="email"
                        placeholder="Email"
                        value={newMember.email}
                        onChange={(e) => setNewMember({...newMember, email: e.target.value})}
                        className="w-full px-3 py-2 border rounded mb-2 text-sm"
                      />
                      <select
                        value={newMember.role}
                        onChange={(e) => setNewMember({...newMember, role: e.target.value})}
                        className="w-full px-3 py-2 border rounded mb-2 text-sm"
                      >
                        <option value="analyst">Analyst</option>
                        <option value="viewer">Viewer</option>
                        <option value="admin">Admin</option>
                      </select>
                      <div className="flex space-x-2">
                        <button
                          onClick={addMember}
                          className="flex-1 px-3 py-2 bg-green-600 text-white rounded text-sm"
                        >
                          Add Member
                        </button>
                        <button
                          onClick={() => setShowAddMember(false)}
                          className="px-3 py-2 bg-gray-300 rounded text-sm"
                        >
                          Cancel
                        </button>
                      </div>
                    </div>
                  )}
                  
                  <div className="space-y-2">
                    {teamMembers.map(member => (
                      <div key={member.id} className="flex items-center justify-between p-2 bg-white rounded">
                        <div className="flex items-center space-x-2">
                          <div className={`w-8 h-8 rounded-full flex items-center justify-center text-white text-sm ${
                            member.role === 'admin' ? 'bg-blue-500' : 
                            member.role === 'analyst' ? 'bg-green-500' : 'bg-gray-500'
                          }`}>
                            {member.name.charAt(0).toUpperCase()}
                          </div>
                          <div>
                            <p className="font-medium text-sm">{member.name}</p>
                            <p className="text-xs text-gray-500">{member.email}</p>
                          </div>
                        </div>
                        <div className="flex items-center space-x-2">
                          <span className={`px-2 py-1 rounded text-xs ${
                            member.role === 'admin' ? 'bg-blue-100 text-blue-800' :
                            member.role === 'analyst' ? 'bg-green-100 text-green-800' :
                            'bg-gray-100 text-gray-800'
                          }`}>
                            {member.role}
                          </span>
                          {member.id !== 1 && (
                            <button
                              onClick={() => removeMember(member.id)}
                              className="text-red-500 hover:text-red-700 text-xs"
                            >
                              Remove
                            </button>
                          )}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
                
                <div className="p-4 bg-gray-50 rounded-lg">
                  <h3 className="font-medium mb-3">Assign Vulnerability</h3>
                  <select
                    value={selectedVuln}
                    onChange={(e) => setSelectedVuln(e.target.value)}
                    className="w-full px-3 py-2 border rounded mb-2"
                  >
                    <option value="">Select vulnerability...</option>
                    <option value="1">Missing HSTS Header</option>
                    <option value="2">SQL Injection Found</option>
                    <option value="3">XSS Vulnerability</option>
                    <option value="4">Missing X-Frame-Options</option>
                    <option value="5">CORS Misconfiguration</option>
                  </select>
                  <select
                    value={selectedMember}
                    onChange={(e) => setSelectedMember(e.target.value)}
                    className="w-full px-3 py-2 border rounded mb-2"
                  >
                    <option value="">Assign to team member...</option>
                    {teamMembers.map(member => (
                      <option key={member.id} value={member.id}>{member.name} ({member.role})</option>
                    ))}
                  </select>
                  <button
                    onClick={assignVulnerability}
                    className="w-full px-4 py-2 bg-blue-600 text-white rounded text-sm hover:bg-blue-700"
                  >
                    Assign
                  </button>
                </div>
              </div>

              <div className="p-4 bg-gray-50 rounded-lg">
                <h3 className="font-medium mb-3">Recent Activity</h3>
                <div className="space-y-2">
                  <div className="flex items-center space-x-3 p-2 bg-white rounded">
                    <div className="w-2 h-2 bg-green-500 rounded-full"></div>
                    <span className="text-sm">Scan completed on httpbin.org</span>
                    <span className="text-xs text-gray-500 ml-auto">2 min ago</span>
                  </div>
                  <div className="flex items-center space-x-3 p-2 bg-white rounded">
                    <div className="w-2 h-2 bg-blue-500 rounded-full"></div>
                    <span className="text-sm">New vulnerability found: Missing HSTS</span>
                    <span className="text-xs text-gray-500 ml-auto">5 min ago</span>
                  </div>
                  <div className="flex items-center space-x-3 p-2 bg-white rounded">
                    <div className="w-2 h-2 bg-yellow-500 rounded-full"></div>
                    <span className="text-sm">Admin logged in</span>
                    <span className="text-xs text-gray-500 ml-auto">10 min ago</span>
                  </div>
                </div>
              </div>

              <div className="p-4 bg-gray-50 rounded-lg">
                <h3 className="font-medium mb-3">Remediation Tracking</h3>
                <div className="grid grid-cols-4 gap-4">
                  <div className="p-3 bg-white rounded text-center">
                    <p className="text-2xl font-bold text-red-600">5</p>
                    <p className="text-xs text-gray-600">Open</p>
                  </div>
                  <div className="p-3 bg-white rounded text-center">
                    <p className="text-2xl font-bold text-yellow-600">3</p>
                    <p className="text-xs text-gray-600">In Progress</p>
                  </div>
                  <div className="p-3 bg-white rounded text-center">
                    <p className="text-2xl font-bold text-green-600">12</p>
                    <p className="text-xs text-gray-600">Fixed</p>
                  </div>
                  <div className="p-3 bg-white rounded text-center">
                    <p className="text-2xl font-bold text-gray-600">2</p>
                    <p className="text-xs text-gray-600">Accepted</p>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* CI/CD Tab */}
          {activeTab === 'cicd' && (
            <div className="space-y-4">
              <h2 className="text-lg font-semibold">CI/CD Integration</h2>
              <p className="text-gray-600">Generate configuration for GitHub Actions, GitLab CI, Jenkins</p>
              
              <div className="grid grid-cols-3 gap-4">
                {['github', 'gitlab', 'jenkins'].map(platform => (
                  <button
                    key={platform}
                    onClick={() => generateCICD(platform)}
                    disabled={loading}
                    className="p-4 bg-gray-50 rounded-lg hover:bg-gray-100 text-center"
                  >
                    <p className="font-medium capitalize">{platform}</p>
                    <p className="text-xs text-gray-500">Generate config</p>
                  </button>
                ))}
              </div>

              {results?.type === 'cicd' && (
                <div className="mt-4">
                  <div className="flex items-center justify-between">
                    <h3 className="font-medium capitalize">{results.platform} Configuration</h3>
                    <button
                      onClick={() => copyToClipboard(results.config)}
                      className="text-blue-600 hover:text-blue-800"
                    >
                      <Copy className="h-4 w-4" />
                    </button>
                  </div>
                  <pre className="mt-2 p-4 bg-gray-900 text-green-400 rounded-lg text-xs overflow-auto">{results.config}</pre>
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default AllFeatures;
