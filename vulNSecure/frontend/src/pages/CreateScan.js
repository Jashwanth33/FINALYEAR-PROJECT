import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useMutation, useQueryClient } from 'react-query';
import { scansAPI } from '../services/api';
import { ArrowLeft, Save, X } from 'lucide-react';
import toast from 'react-hot-toast';

const CreateScan = () => {
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  
  const [formData, setFormData] = useState({
    name: '',
    type: 'network',
    target: '',
    description: ''
  });

  const [errors, setErrors] = useState({});

  const createScanMutation = useMutation(scansAPI.createScan, {
    onSuccess: async (response) => {
      console.log('Scan created successfully', response);
      toast.success('Scan created successfully!');
      // Reset form
      setFormData({
        name: '',
        type: 'network',
        target: '',
        description: ''
      });
      setErrors({});
      // Invalidate and refetch all scan queries
      await queryClient.invalidateQueries(['scans']);
      // Small delay to ensure query refetches
      setTimeout(() => {
        navigate('/scans');
      }, 100);
    },
    onError: (error) => {
      console.error('Error creating scan:', error);
      const errorMessage = error.response?.data?.message || 'Failed to create scan. Please try again.';
      toast.error(errorMessage);
      setErrors({ submit: errorMessage });
    }
  });

  const handleInputChange = (field, value) => {
    setFormData(prev => ({
      ...prev,
      [field]: value
    }));
    
    // Clear field-specific error when user starts typing
    if (errors[field]) {
      setErrors(prev => ({
        ...prev,
        [field]: ''
      }));
    }
  };

  const validateForm = () => {
    const newErrors = {};
    
    if (!formData.name.trim()) {
      newErrors.name = 'Scan name is required';
    }
    
    if (!formData.target.trim()) {
      newErrors.target = 'Target is required';
    }
    
    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  const handleSubmit = (e) => {
    e.preventDefault();
    
    if (!validateForm()) {
      return;
    }
    
    // Prepare scan data - map description to configuration
    const scanData = {
      name: formData.name,
      type: formData.type,
      target: formData.target,
      configuration: {
        description: formData.description || ''
      }
    };
    
    console.log('Submitting scan:', scanData);
    createScanMutation.mutate(scanData);
  };

  const handleCancel = () => {
    navigate('/scans');
  };

  return (
    <div className="min-h-screen bg-gray-50 py-8">
      <div className="max-w-2xl mx-auto px-4 sm:px-6 lg:px-8">
        {/* Header */}
        <div className="mb-8">
          <button
            onClick={handleCancel}
            className="flex items-center text-gray-600 hover:text-gray-900 mb-4"
          >
            <ArrowLeft className="w-4 h-4 mr-2" />
            Back to Scans
          </button>
          <h1 className="text-3xl font-bold text-gray-900">Create New Scan</h1>
          <p className="mt-2 text-gray-600">Configure and launch a new security scan</p>
        </div>

        {/* Form Card */}
        <div className="bg-white shadow-lg rounded-lg overflow-hidden">
          <form onSubmit={handleSubmit} className="p-6 space-y-6">
            
            {/* Scan Name */}
            <div>
              <label htmlFor="scanName" className="block text-sm font-semibold text-gray-800 mb-2">
                Scan Name *
              </label>
              <input
                id="scanName"
                type="text"
                value={formData.name}
                onChange={(e) => handleInputChange('name', e.target.value)}
                placeholder="Enter a descriptive name for your scan"
                className="block w-full px-4 py-3 text-gray-900 bg-white border-2 border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500 transition-colors"
                style={{
                  color: '#1f2937',
                  backgroundColor: '#ffffff',
                  fontSize: '16px',
                  fontWeight: '400'
                }}
              />
              {errors.name && (
                <p className="mt-1 text-sm text-red-600">{errors.name}</p>
              )}
            </div>

            {/* Scan Type */}
            <div>
              <label htmlFor="scanType" className="block text-sm font-semibold text-gray-800 mb-2">
                Scan Type
              </label>
              <select
                id="scanType"
                value={formData.type}
                onChange={(e) => handleInputChange('type', e.target.value)}
                className="block w-full px-4 py-3 text-gray-900 bg-white border-2 border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500 transition-colors"
                style={{
                  color: '#1f2937',
                  backgroundColor: '#ffffff',
                  fontSize: '16px',
                  fontWeight: '400'
                }}
              >
                <option value="network">Network Scan</option>
                <option value="web">Web Application Scan</option>
                <option value="darkweb">Dark Web Monitoring</option>
              </select>
            </div>

            {/* Target */}
            <div>
              <label htmlFor="scanTarget" className="block text-sm font-semibold text-gray-800 mb-2">
                Target *
              </label>
              <input
                id="scanTarget"
                type="text"
                value={formData.target}
                onChange={(e) => handleInputChange('target', e.target.value)}
                placeholder="e.g., 192.168.1.0/24, https://example.com, domain.com"
                className="block w-full px-4 py-3 text-gray-900 bg-white border-2 border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500 transition-colors"
                style={{
                  color: '#1f2937',
                  backgroundColor: '#ffffff',
                  fontSize: '16px',
                  fontWeight: '400'
                }}
              />
              {errors.target && (
                <p className="mt-1 text-sm text-red-600">{errors.target}</p>
              )}
            </div>

            {/* Description */}
            <div>
              <label htmlFor="scanDescription" className="block text-sm font-semibold text-gray-800 mb-2">
                Description
              </label>
              <textarea
                id="scanDescription"
                value={formData.description}
                onChange={(e) => handleInputChange('description', e.target.value)}
                placeholder="Optional: Add notes or description for this scan"
                rows={4}
                className="block w-full px-4 py-3 text-gray-900 bg-white border-2 border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500 transition-colors resize-none"
                style={{
                  color: '#1f2937',
                  backgroundColor: '#ffffff',
                  fontSize: '16px',
                  fontWeight: '400'
                }}
              />
            </div>

            {/* Error Message */}
            {errors.submit && (
              <div className="bg-red-50 border border-red-200 rounded-lg p-4">
                <p className="text-sm text-red-600">{errors.submit}</p>
              </div>
            )}

            {/* Action Buttons */}
            <div className="flex justify-end space-x-4 pt-6 border-t border-gray-200">
              <button
                type="button"
                onClick={handleCancel}
                className="flex items-center px-6 py-3 text-gray-700 bg-gray-100 hover:bg-gray-200 rounded-lg font-medium transition-colors"
              >
                <X className="w-4 h-4 mr-2" />
                Cancel
              </button>
              <button
                type="submit"
                disabled={createScanMutation.isLoading}
                className="flex items-center px-6 py-3 text-white bg-blue-600 hover:bg-blue-700 disabled:bg-blue-400 rounded-lg font-medium transition-colors"
              >
                <Save className="w-4 h-4 mr-2" />
                {createScanMutation.isLoading ? 'Creating...' : 'Create Scan'}
              </button>
            </div>
          </form>
        </div>
      </div>
    </div>
  );
};

export default CreateScan;