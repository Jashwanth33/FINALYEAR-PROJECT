import React from 'react';
import { Link, useLocation } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { useSidebar } from '../context/SidebarContext';
import {
  LayoutDashboard,
  Search,
  Shield,
  FileText,
  Users,
  User,
  Settings,
  LogOut,
  Menu,
  X,
  File,
  Globe,
  Server,
  Wifi,
  Lock,
  Code,
  Zap,
  Target,
  Layers,
  GitBranch,
  MessageSquare,
  Calendar,
  Bug,
  Activity,
  Database,
  Cloud,
  Key,
  RefreshCw
} from 'lucide-react';

const Sidebar = () => {
  const { user, logout } = useAuth();
  const { isOpen, toggleSidebar } = useSidebar();
  const location = useLocation();

  const navigation = [
    { name: 'Dashboard', href: '/dashboard', icon: LayoutDashboard },
    { name: 'All Features', href: '/features', icon: Layers },
    { name: 'Network Scanner', href: '/network', icon: Globe },
    { name: 'Binary Analysis', href: '/binary', icon: File },
    { name: 'Scans', href: '/scans', icon: Search },
    { name: 'Scheduled Scans', href: '/scheduled', icon: Calendar },
    { name: 'Vulnerabilities', href: '/vulnerabilities', icon: Shield },
    { name: 'Reports', href: '/reports', icon: FileText },
    { name: 'Data Leaks', href: '/leaks', icon: Database },
    { name: 'Settings', href: '/settings', icon: Settings },
    ...(user?.role === 'admin' ? [{ name: 'Users', href: '/users', icon: Users }] : []),
    { name: 'Profile', href: '/profile', icon: User },
  ];

  const isActive = (href) => {
    return location.pathname === href || location.pathname.startsWith(href + '/');
  };

  return (
    <>
      {/* Mobile sidebar overlay */}
      {isOpen && (
        <div 
          className="fixed inset-0 z-40 bg-gray-600 bg-opacity-75 lg:hidden"
          onClick={toggleSidebar}
        />
      )}

      {/* Sidebar */}
      <div className={`sidebar ${isOpen ? 'sidebar-open' : 'sidebar-closed'} z-50`}>
        <div className="flex items-center justify-between h-16 px-6 border-b border-gray-700">
          <h1 className="text-xl font-bold text-white">vulNSecure</h1>
          <button
            onClick={toggleSidebar}
            className="text-gray-400 hover:text-white lg:hidden"
          >
            <X className="h-6 w-6" />
          </button>
        </div>

        <nav className="mt-6 px-3">
          <div className="space-y-1">
            {navigation.map((item) => {
              const Icon = item.icon;
              return (
                <Link
                  key={item.name}
                  to={item.href}
                  className={`group flex items-center px-3 py-2 text-sm font-medium rounded-md transition-colors ${
                    isActive(item.href)
                      ? 'bg-gray-800 text-white'
                      : 'text-gray-300 hover:bg-gray-700 hover:text-white'
                  }`}
                >
                  <Icon className="mr-3 h-5 w-5" />
                  {item.name}
                </Link>
              );
            })}
          </div>
        </nav>

        {/* Logout */}
        <div className="absolute bottom-0 w-full p-4 border-t border-gray-700">
          <button
            onClick={logout}
            className="flex items-center w-full px-3 py-2 text-sm font-medium text-gray-300 hover:bg-gray-700 hover:text-white rounded-md transition-colors"
          >
            <LogOut className="mr-3 h-5 w-5" />
            Logout
          </button>
        </div>
      </div>
    </>
  );
};

export default Sidebar;
