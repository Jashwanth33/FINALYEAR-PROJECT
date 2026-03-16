import React, { useState } from 'react';
import { useAuth } from '../context/AuthContext';
import { useQuery } from 'react-query';
import { usersAPI } from '../services/api';
import { 
  User, 
  Mail, 
  Calendar, 
  Shield, 
  Settings, 
  Lock, 
  Activity, 
  Eye,
  EyeOff,
  Save,
  X,
  Edit,
  Clock,
  MapPin,
  Smartphone,
  Monitor,
  AlertTriangle,
  CheckCircle,
  XCircle
} from 'lucide-react';

const Profile = () => {
  const { user, updateProfile, changePassword } = useAuth();
  const [activeTab, setActiveTab] = useState('profile');
  const [isEditingProfile, setIsEditingProfile] = useState(false);
  const [isChangingPassword, setIsChangingPassword] = useState(false);
  const [showCurrentPassword, setShowCurrentPassword] = useState(false);
  const [showNewPassword, setShowNewPassword] = useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);
  
  // Profile form state
  const [profileForm, setProfileForm] = useState({
    firstName: user?.firstName || '',
    lastName: user?.lastName || '',
    email: user?.email || '',
    phone: user?.phone || '',
    location: user?.location || '',
    bio: user?.bio || ''
  });

  // Password form state
  const [passwordForm, setPasswordForm] = useState({
    currentPassword: '',
    newPassword: '',
    confirmPassword: ''
  });

  // Fetch user activity logs
  const { data: activityData, isLoading: activityLoading } = useQuery(
    ['userActivity', user?.id],
    () => usersAPI.getUserActivity(user?.id),
    { enabled: !!user?.id }
  );

  // Fetch user sessions
  const { data: sessionsData, isLoading: sessionsLoading } = useQuery(
    ['userSessions', user?.id],
    () => usersAPI.getUserSessions(user?.id),
    { enabled: !!user?.id }
  );

  const activities = activityData?.data?.activities || [];
  const sessions = sessionsData?.data?.sessions || [];

  if (!user) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600"></div>
      </div>
    );
  }

  const handleProfileSubmit = async (e) => {
    e.preventDefault();
    const result = await updateProfile(profileForm);
    if (result.success) {
      setIsEditingProfile(false);
    }
  };

  const handlePasswordSubmit = async (e) => {
    e.preventDefault();
    if (passwordForm.newPassword !== passwordForm.confirmPassword) {
      alert('New passwords do not match');
      return;
    }
    const result = await changePassword(passwordForm.currentPassword, passwordForm.newPassword);
    if (result.success) {
      setIsChangingPassword(false);
      setPasswordForm({ currentPassword: '', newPassword: '', confirmPassword: '' });
    }
  };

  const getActivityIcon = (type) => {
    switch (type) {
      case 'login': return <Shield className="h-4 w-4 text-green-500" />;
      case 'logout': return <XCircle className="h-4 w-4 text-gray-500" />;
      case 'profile_update': return <Edit className="h-4 w-4 text-blue-500" />;
      case 'password_change': return <Lock className="h-4 w-4 text-orange-500" />;
      case 'scan_created': return <Activity className="h-4 w-4 text-purple-500" />;
      case 'report_generated': return <CheckCircle className="h-4 w-4 text-indigo-500" />;
      default: return <Activity className="h-4 w-4 text-gray-500" />;
    }
  };

  const getDeviceIcon = (deviceType) => {
    switch (deviceType) {
      case 'mobile': return <Smartphone className="h-4 w-4" />;
      case 'desktop': return <Monitor className="h-4 w-4" />;
      default: return <Monitor className="h-4 w-4" />;
    }
  };

  const tabs = [
    { id: 'profile', name: 'Profile', icon: User },
    { id: 'security', name: 'Security', icon: Shield },
    { id: 'activity', name: 'Activity', icon: Activity },
    { id: 'sessions', name: 'Sessions', icon: Monitor }
  ];

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-3xl font-bold text-gray-900">Profile Management</h1>
        <div className="flex items-center space-x-2">
          <span className={`badge ${
            user.role === 'admin' ? 'badge-critical' :
            user.role === 'analyst' ? 'badge-high' : 'badge-info'
          }`}>
            {user.role}
          </span>
          <span className={`badge ${user.isActive ? 'badge-success' : 'badge-danger'}`}>
            {user.isActive ? 'Active' : 'Inactive'}
          </span>
        </div>
      </div>

      {/* Tab Navigation */}
      <div className="border-b border-gray-200">
        <nav className="-mb-px flex space-x-8">
          {tabs.map((tab) => {
            const Icon = tab.icon;
            return (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`py-2 px-1 border-b-2 font-medium text-sm flex items-center space-x-2 ${
                  activeTab === tab.id
                    ? 'border-blue-500 text-blue-600'
                    : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
                }`}
              >
                <Icon className="h-4 w-4" />
                <span>{tab.name}</span>
              </button>
            );
          })}
        </nav>
      </div>

      {/* Profile Tab */}
      {activeTab === 'profile' && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          <div className="lg:col-span-1">
            <div className="card text-center">
              <div className="h-24 w-24 bg-gray-200 rounded-full flex items-center justify-center mx-auto mb-4">
                <User className="h-12 w-12 text-gray-600" />
              </div>
              <h2 className="text-xl font-semibold text-gray-900">
                {user.firstName} {user.lastName}
              </h2>
              <p className="text-sm text-gray-500">@{user.username}</p>
              <div className="mt-4 space-y-2">
                <span className={`badge ${
                  user.role === 'admin' ? 'badge-critical' :
                  user.role === 'analyst' ? 'badge-high' : 'badge-info'
                }`}>
                  {user.role}
                </span>
                <div className="text-xs text-gray-500">
                  Member since {new Date(user.createdAt).toLocaleDateString()}
                </div>
              </div>
            </div>
          </div>

          <div className="lg:col-span-2">
            <div className="card">
              <div className="flex items-center justify-between mb-4">
                <h3 className="text-lg font-semibold text-gray-900">Profile Information</h3>
                <button
                  onClick={() => setIsEditingProfile(!isEditingProfile)}
                  className="btn btn-secondary flex items-center"
                >
                  {isEditingProfile ? (
                    <>
                      <X className="h-4 w-4 mr-2" />
                      Cancel
                    </>
                  ) : (
                    <>
                      <Edit className="h-4 w-4 mr-2" />
                      Edit Profile
                    </>
                  )}
                </button>
              </div>

              {isEditingProfile ? (
                <form onSubmit={handleProfileSubmit} className="space-y-4">
                  <div className="grid grid-cols-2 gap-4">
                    <div>
                      <label className="label">First Name</label>
                      <input
                        type="text"
                        value={profileForm.firstName}
                        onChange={(e) => setProfileForm({...profileForm, firstName: e.target.value})}
                        className="input"
                        required
                      />
                    </div>
                    <div>
                      <label className="label">Last Name</label>
                      <input
                        type="text"
                        value={profileForm.lastName}
                        onChange={(e) => setProfileForm({...profileForm, lastName: e.target.value})}
                        className="input"
                        required
                      />
                    </div>
                  </div>
                  <div>
                    <label className="label">Email</label>
                    <input
                      type="email"
                      value={profileForm.email}
                      onChange={(e) => setProfileForm({...profileForm, email: e.target.value})}
                      className="input"
                      required
                    />
                  </div>
                  <div>
                    <label className="label">Phone</label>
                    <input
                      type="tel"
                      value={profileForm.phone}
                      onChange={(e) => setProfileForm({...profileForm, phone: e.target.value})}
                      className="input"
                    />
                  </div>
                  <div>
                    <label className="label">Location</label>
                    <input
                      type="text"
                      value={profileForm.location}
                      onChange={(e) => setProfileForm({...profileForm, location: e.target.value})}
                      className="input"
                    />
                  </div>
                  <div>
                    <label className="label">Bio</label>
                    <textarea
                      value={profileForm.bio}
                      onChange={(e) => setProfileForm({...profileForm, bio: e.target.value})}
                      className="input"
                      rows="3"
                    />
                  </div>
                  <div className="flex justify-end">
                    <button type="submit" className="btn btn-primary flex items-center">
                      <Save className="h-4 w-4 mr-2" />
                      Save Changes
                    </button>
                  </div>
                </form>
              ) : (
                <div className="space-y-4">
                  <div className="flex items-center">
                    <Mail className="h-5 w-5 text-gray-400 mr-3" />
                    <div>
                      <p className="text-sm font-medium text-gray-500">Email</p>
                      <p className="text-gray-900">{user.email}</p>
                    </div>
                  </div>
                  <div className="flex items-center">
                    <Smartphone className="h-5 w-5 text-gray-400 mr-3" />
                    <div>
                      <p className="text-sm font-medium text-gray-500">Phone</p>
                      <p className="text-gray-900">{user.phone || 'Not provided'}</p>
                    </div>
                  </div>
                  <div className="flex items-center">
                    <MapPin className="h-5 w-5 text-gray-400 mr-3" />
                    <div>
                      <p className="text-sm font-medium text-gray-500">Location</p>
                      <p className="text-gray-900">{user.location || 'Not provided'}</p>
                    </div>
                  </div>
                  <div className="flex items-center">
                    <Calendar className="h-5 w-5 text-gray-400 mr-3" />
                    <div>
                      <p className="text-sm font-medium text-gray-500">Member Since</p>
                      <p className="text-gray-900">{new Date(user.createdAt).toLocaleDateString()}</p>
                    </div>
                  </div>
                  {user.lastLogin && (
                    <div className="flex items-center">
                      <Shield className="h-5 w-5 text-gray-400 mr-3" />
                      <div>
                        <p className="text-sm font-medium text-gray-500">Last Login</p>
                        <p className="text-gray-900">{new Date(user.lastLogin).toLocaleString()}</p>
                      </div>
                    </div>
                  )}
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Security Tab */}
      {activeTab === 'security' && (
        <div className="space-y-6">
          <div className="card">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-lg font-semibold text-gray-900">Password & Security</h3>
              <button
                onClick={() => setIsChangingPassword(!isChangingPassword)}
                className="btn btn-secondary flex items-center"
              >
                <Lock className="h-4 w-4 mr-2" />
                Change Password
              </button>
            </div>

            {isChangingPassword && (
              <form onSubmit={handlePasswordSubmit} className="space-y-4 border-t pt-4">
                <div>
                  <label className="label">Current Password</label>
                  <div className="relative">
                    <input
                      type={showCurrentPassword ? 'text' : 'password'}
                      value={passwordForm.currentPassword}
                      onChange={(e) => setPasswordForm({...passwordForm, currentPassword: e.target.value})}
                      className="input pr-10"
                      required
                    />
                    <button
                      type="button"
                      onClick={() => setShowCurrentPassword(!showCurrentPassword)}
                      className="absolute inset-y-0 right-0 pr-3 flex items-center"
                    >
                      {showCurrentPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                    </button>
                  </div>
                </div>
                <div>
                  <label className="label">New Password</label>
                  <div className="relative">
                    <input
                      type={showNewPassword ? 'text' : 'password'}
                      value={passwordForm.newPassword}
                      onChange={(e) => setPasswordForm({...passwordForm, newPassword: e.target.value})}
                      className="input pr-10"
                      required
                    />
                    <button
                      type="button"
                      onClick={() => setShowNewPassword(!showNewPassword)}
                      className="absolute inset-y-0 right-0 pr-3 flex items-center"
                    >
                      {showNewPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                    </button>
                  </div>
                </div>
                <div>
                  <label className="label">Confirm New Password</label>
                  <div className="relative">
                    <input
                      type={showConfirmPassword ? 'text' : 'password'}
                      value={passwordForm.confirmPassword}
                      onChange={(e) => setPasswordForm({...passwordForm, confirmPassword: e.target.value})}
                      className="input pr-10"
                      required
                    />
                    <button
                      type="button"
                      onClick={() => setShowConfirmPassword(!showConfirmPassword)}
                      className="absolute inset-y-0 right-0 pr-3 flex items-center"
                    >
                      {showConfirmPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                    </button>
                  </div>
                </div>
                <div className="flex justify-end space-x-2">
                  <button
                    type="button"
                    onClick={() => setIsChangingPassword(false)}
                    className="btn btn-secondary"
                  >
                    Cancel
                  </button>
                  <button type="submit" className="btn btn-primary">
                    Update Password
                  </button>
                </div>
              </form>
            )}

            <div className="space-y-4 mt-6">
              <div className="flex items-center justify-between p-4 bg-gray-50 rounded-lg">
                <div className="flex items-center">
                  <Shield className="h-5 w-5 text-green-500 mr-3" />
                  <div>
                    <p className="font-medium text-gray-900">Two-Factor Authentication</p>
                    <p className="text-sm text-gray-500">Add an extra layer of security to your account</p>
                  </div>
                </div>
                <button className="btn btn-secondary">
                  {user.twoFactorEnabled ? 'Disable' : 'Enable'}
                </button>
              </div>
              
              <div className="flex items-center justify-between p-4 bg-gray-50 rounded-lg">
                <div className="flex items-center">
                  <AlertTriangle className="h-5 w-5 text-orange-500 mr-3" />
                  <div>
                    <p className="font-medium text-gray-900">Login Notifications</p>
                    <p className="text-sm text-gray-500">Get notified when someone logs into your account</p>
                  </div>
                </div>
                <button className="btn btn-secondary">
                  {user.loginNotifications ? 'Disable' : 'Enable'}
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Activity Tab */}
      {activeTab === 'activity' && (
        <div className="card">
          <h3 className="text-lg font-semibold text-gray-900 mb-4">Recent Activity</h3>
          {activityLoading ? (
            <div className="flex items-center justify-center h-32">
              <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div>
            </div>
          ) : (
            <div className="space-y-4">
              {activities.map((activity) => (
                <div key={activity.id} className="flex items-center space-x-3 p-3 bg-gray-50 rounded-lg">
                  {getActivityIcon(activity.type)}
                  <div className="flex-1">
                    <p className="text-sm font-medium text-gray-900">{activity.description}</p>
                    <div className="flex items-center space-x-4 text-xs text-gray-500">
                      <span className="flex items-center">
                        <Clock className="h-3 w-3 mr-1" />
                        {new Date(activity.timestamp).toLocaleString()}
                      </span>
                      <span className="flex items-center">
                        <MapPin className="h-3 w-3 mr-1" />
                        {activity.ipAddress}
                      </span>
                      <span className="flex items-center">
                        {getDeviceIcon(activity.deviceType)}
                        <span className="ml-1">{activity.userAgent}</span>
                      </span>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Sessions Tab */}
      {activeTab === 'sessions' && (
        <div className="card">
          <h3 className="text-lg font-semibold text-gray-900 mb-4">Active Sessions</h3>
          {sessionsLoading ? (
            <div className="flex items-center justify-center h-32">
              <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div>
            </div>
          ) : (
            <div className="space-y-4">
              {sessions.map((session) => (
                <div key={session.id} className="flex items-center justify-between p-4 bg-gray-50 rounded-lg">
                  <div className="flex items-center space-x-3">
                    {getDeviceIcon(session.deviceType)}
                    <div>
                      <p className="text-sm font-medium text-gray-900">
                        {session.deviceType === 'mobile' ? 'Mobile Device' : 'Desktop'}
                        {session.isCurrent && <span className="ml-2 text-xs text-green-600">(Current)</span>}
                      </p>
                      <div className="text-xs text-gray-500 space-y-1">
                        <div>IP: {session.ipAddress}</div>
                        <div>Location: {session.location}</div>
                        <div>Last active: {new Date(session.lastActivity).toLocaleString()}</div>
                      </div>
                    </div>
                  </div>
                  {!session.isCurrent && (
                    <button className="btn btn-danger btn-sm">
                      Revoke
                    </button>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
};

export default Profile;
