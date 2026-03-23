import React, { useState } from 'react';
import { useQuery } from 'react-query';
import toast from 'react-hot-toast';
import { Calendar, Clock, Play, Trash2, Plus, Globe, RefreshCw } from 'lucide-react';

const ScheduledScans = () => {
  const [showCreate, setShowCreate] = useState(false);
  const [form, setForm] = useState({
    name: '',
    target: '',
    frequency: 'daily',
    dayOfWeek: 'monday',
    time: '02:00',
    type: 'web'
  });

  const getToken = () => localStorage.getItem('token');

  // Fetch schedules
  const { data: schedulesData, refetch } = useQuery('schedules', async () => {
    const resp = await fetch('http://localhost:5001/api/new/schedules', {
      headers: { Authorization: 'Bearer ' + getToken() }
    });
    return resp.json();
  });

  const schedules = schedulesData?.data?.schedules || [];

  // Create schedule
  const createSchedule = async () => {
    if (!form.name || !form.target) {
      toast.error('Please enter name and target');
      return;
    }

    try {
      const resp = await fetch('http://localhost:5001/api/new/schedules', {
        method: 'POST',
        headers: {
          'Authorization': 'Bearer ' + getToken(),
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(form)
      });
      
      const data = await resp.json();
      if (data.success) {
        toast.success('Schedule created!');
        setShowCreate(false);
        setForm({ name: '', target: '', frequency: 'daily', dayOfWeek: 'monday', time: '02:00', type: 'web' });
        refetch();
      }
    } catch (e) {
      toast.error('Failed to create schedule');
    }
  };

  // Delete schedule
  const deleteSchedule = async (id) => {
    try {
      await fetch('http://localhost:5001/api/new/schedules/' + id, {
        method: 'DELETE',
        headers: { Authorization: 'Bearer ' + getToken() }
      });
      toast.success('Schedule deleted');
      refetch();
    } catch (e) {
      toast.error('Failed to delete');
    }
  };

  // Download report
  const downloadReport = async (scanId) => {
    try {
      const resp = await fetch('http://localhost:5001/api/new/report/' + scanId, {
        headers: { Authorization: 'Bearer ' + getToken() }
      });
      
      if (resp.ok) {
        const blob = await resp.blob();
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `report-${scanId}.html`;
        document.body.appendChild(a);
        a.click();
        window.URL.revokeObjectURL(url);
        toast.success('Report downloaded!');
      }
    } catch (e) {
      toast.error('Download failed');
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-gray-900">Scheduled Scans</h1>
          <p className="text-gray-600">Automate vulnerability scanning with scheduled tasks</p>
        </div>
        <button
          onClick={() => setShowCreate(true)}
          className="flex items-center px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700"
        >
          <Plus className="h-4 w-4 mr-2" />
          New Schedule
        </button>
      </div>

      {/* Create Form */}
      {showCreate && (
        <div className="bg-white p-6 rounded-lg shadow-sm border border-gray-200">
          <h2 className="text-lg font-semibold mb-4">Create Scheduled Scan</h2>
          
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">Name</label>
              <input
                type="text"
                value={form.name}
                onChange={(e) => setForm({ ...form, name: e.target.value })}
                placeholder="Daily Security Scan"
                className="w-full px-3 py-2 border rounded-lg"
              />
            </div>
            
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">Target</label>
              <input
                type="text"
                value={form.target}
                onChange={(e) => setForm({ ...form, target: e.target.value })}
                placeholder="https://example.com"
                className="w-full px-3 py-2 border rounded-lg"
              />
            </div>
            
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">Frequency</label>
              <select
                value={form.frequency}
                onChange={(e) => setForm({ ...form, frequency: e.target.value })}
                className="w-full px-3 py-2 border rounded-lg"
              >
                <option value="daily">Daily</option>
                <option value="weekly">Weekly</option>
                <option value="monthly">Monthly</option>
              </select>
            </div>
            
            {form.frequency === 'weekly' && (
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">Day of Week</label>
                <select
                  value={form.dayOfWeek}
                  onChange={(e) => setForm({ ...form, dayOfWeek: e.target.value })}
                  className="w-full px-3 py-2 border rounded-lg"
                >
                  {['sunday', 'monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday'].map(d => (
                    <option key={d} value={d}>{d.charAt(0).toUpperCase() + d.slice(1)}</option>
                  ))}
                </select>
              </div>
            )}
            
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">Time</label>
              <input
                type="time"
                value={form.time}
                onChange={(e) => setForm({ ...form, time: e.target.value })}
                className="w-full px-3 py-2 border rounded-lg"
              />
            </div>
          </div>
          
          <div className="flex space-x-3 mt-4">
            <button
              onClick={createSchedule}
              className="px-4 py-2 bg-green-600 text-white rounded-lg hover:bg-green-700"
            >
              Create Schedule
            </button>
            <button
              onClick={() => setShowCreate(false)}
              className="px-4 py-2 bg-gray-300 rounded-lg hover:bg-gray-400"
            >
              Cancel
            </button>
          </div>
        </div>
      )}

      {/* Schedules List */}
      <div className="bg-white rounded-lg shadow-sm border border-gray-200">
        <div className="p-4 border-b border-gray-200">
          <h2 className="text-lg font-semibold">Active Schedules</h2>
        </div>
        
        {schedules.length === 0 ? (
          <div className="p-8 text-center text-gray-500">
            <Calendar className="h-12 w-12 mx-auto mb-3 text-gray-300" />
            <p>No scheduled scans yet</p>
            <p className="text-sm">Create a schedule to automate your scans</p>
          </div>
        ) : (
          <div className="divide-y divide-gray-200">
            {schedules.map(schedule => (
              <div key={schedule.id} className="p-4 flex items-center justify-between">
                <div className="flex items-center space-x-4">
                  <div className={`p-2 rounded-lg ${schedule.enabled ? 'bg-green-100' : 'bg-gray-100'}`}>
                    <Calendar className={`h-5 w-5 ${schedule.enabled ? 'text-green-600' : 'text-gray-400'}`} />
                  </div>
                  <div>
                    <p className="font-medium">{schedule.name}</p>
                    <p className="text-sm text-gray-500">{schedule.target}</p>
                    <div className="flex items-center space-x-3 mt-1 text-xs text-gray-400">
                      <span className="flex items-center">
                        <RefreshCw className="h-3 w-3 mr-1" />
                        {schedule.frequency}
                      </span>
                      <span className="flex items-center">
                        <Clock className="h-3 w-3 mr-1" />
                        {schedule.time}
                      </span>
                      {schedule.lastRunAt && (
                        <span>Last run: {new Date(schedule.lastRunAt).toLocaleDateString()}</span>
                      )}
                    </div>
                  </div>
                </div>
                <div className="flex items-center space-x-2">
                  <span className={`px-2 py-1 rounded text-xs ${schedule.enabled ? 'bg-green-100 text-green-800' : 'bg-gray-100 text-gray-600'}`}>
                    {schedule.enabled ? 'Active' : 'Paused'}
                  </span>
                  <button
                    onClick={() => deleteSchedule(schedule.id)}
                    className="p-2 text-red-500 hover:bg-red-50 rounded"
                  >
                    <Trash2 className="h-4 w-4" />
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Info Box */}
      <div className="bg-blue-50 border border-blue-200 rounded-lg p-4">
        <h3 className="font-medium text-blue-800 mb-2">How Scheduled Scans Work</h3>
        <ul className="text-sm text-blue-700 space-y-1">
          <li>• Scans run automatically at the specified time</li>
          <li>• You'll receive notifications when scans complete</li>
          <li>• Reports can be downloaded after each scan</li>
          <li>• Daily scans run every day at the specified time</li>
          <li>• Weekly scans run on the selected day</li>
          <li>• Monthly scans run on the 1st of each month</li>
        </ul>
      </div>
    </div>
  );
};

export default ScheduledScans;
