import React, { useState, useEffect, useRef } from 'react';
import { MagnifyingGlassIcon, XMarkIcon } from '@heroicons/react/24/outline';
import { searchAPI } from '../services/api';

const GlobalSearch = () => {
  const [isOpen, setIsOpen] = useState(false);
  const [query, setQuery] = useState('');
  const [results, setResults] = useState([]);
  const [loading, setLoading] = useState(false);
  const [selectedType, setSelectedType] = useState('all');
  const searchRef = useRef(null);

  const searchTypes = [
    { value: 'all', label: 'All' },
    { value: 'vulnerabilities', label: 'Vulnerabilities' },
    { value: 'scans', label: 'Scans' },
    { value: 'leaks', label: 'Leaks' },
    { value: 'reports', label: 'Reports' },
    { value: 'users', label: 'Users' }
  ];

  useEffect(() => {
    const handleKeyDown = (e) => {
      if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
        e.preventDefault();
        setIsOpen(true);
      }
      if (e.key === 'Escape') {
        setIsOpen(false);
      }
    };

    document.addEventListener('keydown', handleKeyDown);
    return () => document.removeEventListener('keydown', handleKeyDown);
  }, []);

  useEffect(() => {
    if (isOpen && searchRef.current) {
      searchRef.current.focus();
    }
  }, [isOpen]);

  useEffect(() => {
    const searchTimeout = setTimeout(() => {
      if (query.trim()) {
        performSearch();
      } else {
        setResults([]);
      }
    }, 300);

    return () => clearTimeout(searchTimeout);
  }, [query, selectedType]);

  const performSearch = async () => {
    setLoading(true);
    try {
      const response = await searchAPI.search(query, selectedType);
      setResults(response.data.results || []);
    } catch (error) {
      console.error('Search error:', error);
      setResults([]);
    } finally {
      setLoading(false);
    }
  };

  const handleResultClick = (result) => {
    // Navigate to the result
    window.location.href = result.url;
    setIsOpen(false);
  };

  const getResultIcon = (type) => {
    const icons = {
      vulnerability: '🔓',
      scan: '🔍',
      leak: '💧',
      report: '📊',
      user: '👤'
    };
    return icons[type] || '📄';
  };

  if (!isOpen) {
    return (
      <button
        onClick={() => setIsOpen(true)}
        className="flex items-center space-x-2 px-3 py-2 text-gray-400 hover:text-gray-600 transition-colors"
      >
        <MagnifyingGlassIcon className="h-5 w-5" />
        <span className="hidden md:inline text-sm">Search...</span>
        <kbd className="hidden md:inline-flex items-center px-2 py-1 text-xs font-mono bg-gray-100 text-gray-600 rounded">
          ⌘K
        </kbd>
      </button>
    );
  }

  return (
    <div className="fixed inset-0 z-50 overflow-y-auto">
      <div className="flex min-h-screen items-start justify-center p-4 pt-16">
        <div className="fixed inset-0 bg-black bg-opacity-25" onClick={() => setIsOpen(false)} />
        
        <div className="relative w-full max-w-2xl bg-white rounded-lg shadow-xl">
          <div className="flex items-center border-b border-gray-200 p-4">
            <MagnifyingGlassIcon className="h-5 w-5 text-gray-400 mr-3" />
            <input
              ref={searchRef}
              type="text"
              placeholder="Search vulnerabilities, scans, leaks, reports..."
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              className="flex-1 outline-none text-gray-900 placeholder-gray-500"
            />
            <button
              onClick={() => setIsOpen(false)}
              className="ml-3 text-gray-400 hover:text-gray-600"
            >
              <XMarkIcon className="h-5 w-5" />
            </button>
          </div>

          <div className="flex border-b border-gray-200">
            {searchTypes.map((type) => (
              <button
                key={type.value}
                onClick={() => setSelectedType(type.value)}
                className={`px-4 py-2 text-sm font-medium border-b-2 transition-colors ${
                  selectedType === type.value
                    ? 'border-blue-500 text-blue-600'
                    : 'border-transparent text-gray-500 hover:text-gray-700'
                }`}
              >
                {type.label}
              </button>
            ))}
          </div>

          <div className="max-h-96 overflow-y-auto">
            {loading ? (
              <div className="p-4 text-center text-gray-500">
                <div className="animate-spin rounded-full h-6 w-6 border-b-2 border-blue-500 mx-auto"></div>
                <p className="mt-2">Searching...</p>
              </div>
            ) : results.length > 0 ? (
              <div className="py-2">
                {results.map((result, index) => (
                  <button
                    key={index}
                    onClick={() => handleResultClick(result)}
                    className="w-full px-4 py-3 text-left hover:bg-gray-50 transition-colors"
                  >
                    <div className="flex items-start space-x-3">
                      <span className="text-lg">{getResultIcon(result.type)}</span>
                      <div className="flex-1 min-w-0">
                        <p className="text-sm font-medium text-gray-900 truncate">
                          {result.title}
                        </p>
                        <p className="text-sm text-gray-500 truncate">
                          {result.description}
                        </p>
                        <div className="flex items-center mt-1 space-x-2">
                          <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-gray-100 text-gray-800">
                            {result.type}
                          </span>
                          {result.severity && (
                            <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium ${
                              result.severity === 'Critical' ? 'bg-red-100 text-red-800' :
                              result.severity === 'High' ? 'bg-orange-100 text-orange-800' :
                              result.severity === 'Medium' ? 'bg-yellow-100 text-yellow-800' :
                              'bg-green-100 text-green-800'
                            }`}>
                              {result.severity}
                            </span>
                          )}
                        </div>
                      </div>
                    </div>
                  </button>
                ))}
              </div>
            ) : query.trim() ? (
              <div className="p-8 text-center text-gray-500">
                <MagnifyingGlassIcon className="h-12 w-12 mx-auto text-gray-300 mb-4" />
                <p>No results found for "{query}"</p>
                <p className="text-sm mt-1">Try adjusting your search terms or filters</p>
              </div>
            ) : (
              <div className="p-8 text-center text-gray-500">
                <MagnifyingGlassIcon className="h-12 w-12 mx-auto text-gray-300 mb-4" />
                <p>Start typing to search</p>
                <p className="text-sm mt-1">Search across vulnerabilities, scans, leaks, reports, and users</p>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

export default GlobalSearch;