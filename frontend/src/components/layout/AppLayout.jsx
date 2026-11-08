/**
 * TrustLens AppLayout Component
 * Primary application shell featuring persistent sidebar navigation,
 * role-aware sections, breadcrumbs, real-time health indicator, and user profile controls.
 */

import React, { useState, useEffect } from 'react';
import { NavLink, Outlet, useNavigate, useLocation } from 'react-router-dom';
import {
  Shield,
  LayoutDashboard,
  Search,
  History,
  ShieldCheck,
  Globe,
  Users,
  ShieldAlert,
  LogOut,
  Menu,
  X,
  Activity,
  User as UserIcon,
} from 'lucide-react';
import { useAuth } from '../../context/AuthContext';
import { healthService } from '../../services/health.service';
import { Button, Tooltip, Tag } from 'antd';

export function AppLayout() {
  const { user, logout, isModerator } = useAuth();
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const [systemHealth, setSystemHealth] = useState({ status: 'checking', text: 'Connecting...' });
  const navigate = useNavigate();
  const location = useLocation();

  const handleLogout = async () => {
    await logout();
    navigate('/login');
  };

  useEffect(() => {
    let isMounted = true;
    const checkStatus = async () => {
      try {
        const res = await healthService.getHealth();
        if (isMounted) {
          if (res.status === 'alive') {
            setSystemHealth({ status: 'online', text: `API v${res.version || '1.0'}` });
          } else {
            setSystemHealth({ status: 'degraded', text: 'Degraded' });
          }
        }
      } catch {
        if (isMounted) {
          setSystemHealth({ status: 'offline', text: 'API Offline' });
        }
      }
    };

    checkStatus();
    const timer = setInterval(checkStatus, 30000);
    return () => {
      isMounted = false;
      clearInterval(timer);
    };
  }, []);

  const getBreadcrumbLabel = () => {
    const p = location.pathname;
    if (p === '/dashboard') return 'Overview';
    if (p.startsWith('/scans/') && p.includes('/certificate')) return 'Scan Certificate Details';
    if (p.startsWith('/scans/')) return 'Scan Assessment Report';
    if (p === '/scan') return 'Asynchronous Web Scan';
    if (p === '/web-security') return 'Web Security Posture';
    if (p.startsWith('/web-security/')) return 'Posture Assessment Report';
    if (p === '/certificates') return 'Certificate Intelligence';
    if (p.startsWith('/certificates/')) return 'Certificate Report';
    if (p === '/community') return 'Collaborative Threat Intelligence';
    if (p.startsWith('/community/')) return 'Community Report';
    if (p === '/history') return 'Historical Investigations';
    if (p.startsWith('/admin')) return 'Moderation & Operations';
    return 'Security Console';
  };

  const navItems = [
    { to: '/dashboard', label: 'Overview', icon: LayoutDashboard },
    { to: '/scan', label: 'Full Scan', icon: Search },
    { to: '/web-security', label: 'Web Posture', icon: Globe },
    { to: '/certificates', label: 'Certificates', icon: ShieldCheck },
    { to: '/community', label: 'Community Intel', icon: Users },
    { to: '/history', label: 'Scan History', icon: History },
  ];

  if (isModerator) {
    navItems.push({ to: '/admin/moderation', label: 'Moderation Queue', icon: ShieldAlert });
  }

  return (
    <div className="app-container">
      {/* Mobile Drawer Overlay */}
      {mobileMenuOpen && (
        <div
          onClick={() => setMobileMenuOpen(false)}
          style={{
            position: 'fixed',
            inset: 0,
            backgroundColor: 'rgba(0, 0, 0, 0.75)',
            zIndex: 99,
          }}
        />
      )}

      {/* Main Persistent Sidebar */}
      <aside className={`app-sidebar ${mobileMenuOpen ? 'open' : ''}`}>
        <div className="sidebar-header">
          <div className="sidebar-logo">
            <div className="sidebar-logo-icon">
              <Shield size={16} />
            </div>
            <span>TrustLens</span>
          </div>
        </div>

        <nav className="sidebar-nav">
          <div className="nav-section-title">Security Modules</div>
          {navItems.map((item) => {
            const Icon = item.icon;
            return (
              <NavLink
                key={item.to}
                to={item.to}
                onClick={() => setMobileMenuOpen(false)}
                className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}
              >
                <Icon size={16} />
                <span>{item.label}</span>
              </NavLink>
            );
          })}

          <div className="nav-section-title" style={{ marginTop: '0.75rem' }}>
            System Integrity
          </div>
          <div
            style={{
              padding: '0.6rem 0.75rem',
              display: 'flex',
              flexDirection: 'column',
              gap: '0.5rem',
              backgroundColor: 'var(--bg-surface)',
              borderRadius: 'var(--radius-md)',
              border: '1px solid var(--border-color-subtle)',
              margin: '0 0.5rem',
            }}
          >
            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                fontSize: '0.75rem',
              }}
            >
              <span style={{ color: 'var(--text-secondary)' }}>Status:</span>
              <span
                style={{
                  fontFamily: 'var(--font-mono)',
                  fontSize: '0.7rem',
                  fontWeight: 600,
                  color:
                    systemHealth.status === 'online'
                      ? 'var(--color-safe-text)'
                      : systemHealth.status === 'degraded'
                        ? 'var(--color-suspicious-text)'
                        : 'var(--color-malicious-text)',
                }}
              >
                {systemHealth.text}
              </span>
            </div>
            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                fontSize: '0.75rem',
              }}
            >
              <span style={{ color: 'var(--text-secondary)' }}>Threat Feeds:</span>
              <span style={{ color: 'var(--color-safe-text)', fontFamily: 'var(--font-mono)', fontSize: '0.7rem' }}>
                ONLINE
              </span>
            </div>
          </div>
        </nav>

        <div className="sidebar-footer">
          <div className="user-profile-pill">
            <div className="user-info">
              <div className="user-avatar">
                {user?.display_name ? (
                  user.display_name.charAt(0).toUpperCase()
                ) : (
                  <UserIcon size={14} />
                )}
              </div>
              <div className="user-details">
                <div className="user-name" style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                  <span>{user?.display_name || 'User'}</span>
                  {user?.role && user.role !== 'user' && (
                    <Tag
                      color={user.role === 'admin' ? 'red' : 'gold'}
                      style={{
                        margin: 0,
                        fontSize: '0.625rem',
                        lineHeight: '14px',
                        padding: '0 4px',
                        textTransform: 'uppercase',
                      }}
                    >
                      {user.role}
                    </Tag>
                  )}
                </div>
                <div className="user-email">{user?.email || 'authenticated'}</div>
              </div>
            </div>
            <Tooltip title="Log out session">
              <Button
                type="text"
                size="small"
                icon={<LogOut size={14} />}
                onClick={handleLogout}
                style={{ color: 'var(--text-muted)' }}
              />
            </Tooltip>
          </div>
        </div>
      </aside>

      {/* Main Content Area */}
      <div className="app-main">
        <header className="app-header">
          <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
            <Button
              type="text"
              className="mobile-toggle"
              icon={mobileMenuOpen ? <X size={18} /> : <Menu size={18} />}
              onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
              style={{ display: 'none', color: 'var(--text-primary)' }}
            />
            <div className="header-breadcrumbs">
              <span>TrustLens</span>
              <span>/</span>
              <span className="current">{getBreadcrumbLabel()}</span>
            </div>
          </div>

          <div className="header-actions">
            <span
              className={`mode-badge ${systemHealth.status === 'online' ? 'connected' : ''}`}
              title="Connection status to the backend"
            >
              <Activity size={12} />
              <span>{systemHealth.text}</span>
            </span>

            <Button
              type="primary"
              size="small"
              icon={<Search size={13} />}
              onClick={() => navigate('/scan')}
              style={{
                backgroundColor: 'var(--color-accent)',
                borderColor: 'var(--color-accent)',
                fontWeight: 500,
                fontSize: '0.8rem',
              }}
            >
              New Scan
            </Button>
          </div>
        </header>

        <main className="page-content">
          <Outlet />
        </main>
      </div>

      <style>{`
        @media (max-width: 900px) {
          .mobile-toggle {
            display: inline-flex !important;
          }
        }
      `}</style>
    </div>
  );
}

