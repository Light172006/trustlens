/**
 * AppLayout Component
 * Primary layout container with persistent sidebar, responsive navigation,
 * system status header, and consistent cybersecurity brand identity.
 */

import React, { useState } from 'react';
import { NavLink, Outlet, useNavigate, useLocation } from 'react-router-dom';
import {
  Shield,
  LayoutDashboard,
  Search,
  History,
  Lock,
  LogOut,
  Menu,
  X,
  ExternalLink,
  Radio,
  User,
  Activity,
  ShieldCheck,
} from 'lucide-react';
import { useAuth } from '../../context/AuthContext';
import { Button, Tooltip } from 'antd';

export function AppLayout() {
  const { user, logout, isMockMode } = useAuth();
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const navigate = useNavigate();
  const location = useLocation();

  const handleLogout = async () => {
    await logout();
    navigate('/login');
  };

  // Determine breadcrumb current label
  const getBreadcrumbLabel = () => {
    const p = location.pathname;
    if (p === '/dashboard') return 'Overview';
    if (p.startsWith('/scans/') && p.includes('/certificate')) return 'Certificate Intelligence';
    if (p.startsWith('/scans/')) return 'Scan Report';
    if (p === '/scan') return 'New Investigation';
    if (p === '/certificates') return 'Certificate Analyzer';
    if (p === '/history') return 'Scan History';
    return 'Console';
  };

  const navItems = [
    { to: '/dashboard', label: 'Overview', icon: LayoutDashboard },
    { to: '/scan', label: 'New Scan', icon: Search },
    { to: '/certificates', label: 'Certificate Analyzer', icon: ShieldCheck },
    { to: '/history', label: 'Scan History', icon: History },
  ];

  return (
    <div className="app-container">
      {/* Sidebar Overlay on Mobile */}
      {mobileMenuOpen && (
        <div
          onClick={() => setMobileMenuOpen(false)}
          style={{
            position: 'fixed',
            inset: 0,
            backgroundColor: 'rgba(0, 0, 0, 0.7)',
            zIndex: 99,
          }}
        />
      )}

      {/* Main Sidebar */}
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
          <div className="nav-section-title">Investigation</div>
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

          <div className="nav-section-title">Intelligence Feeds</div>
          <div
            style={{
              padding: '0.5rem 0.75rem',
              display: 'flex',
              flexDirection: 'column',
              gap: '0.4rem',
            }}
          >
            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                fontSize: '0.75rem',
                color: 'var(--text-secondary)',
              }}
            >
              <span style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                <Radio size={12} color="var(--color-safe-text)" /> OpenPhish Feed
              </span>
              <span style={{ fontSize: '0.675rem', color: 'var(--color-safe-text)', fontFamily: 'var(--font-mono)' }}>ACTIVE</span>
            </div>
            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                fontSize: '0.75rem',
                color: 'var(--text-secondary)',
              }}
            >
              <span style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                <Radio size={12} color="var(--color-safe-text)" /> URLhaus Intel
              </span>
              <span style={{ fontSize: '0.675rem', color: 'var(--color-safe-text)', fontFamily: 'var(--font-mono)' }}>ACTIVE</span>
            </div>
          </div>
        </nav>

        <div className="sidebar-footer">
          <div className="user-profile-pill">
            <div className="user-info">
              <div className="user-avatar">
                {user?.display_name ? user.display_name.charAt(0).toUpperCase() : <User size={14} />}
              </div>
              <div className="user-details">
                <div className="user-name">{user?.display_name || 'Analyst'}</div>
                <div className="user-email">{user?.email || 'analyst@trustlens.dev'}</div>
              </div>
            </div>
            <Tooltip title="Log out">
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

      {/* Main View Area */}
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
            {isMockMode ? (
              <span className="mode-badge" title="Running in simulated offline/mock API mode for demonstration">
                <Activity size={12} />
                <span>DEMO / MOCK MODE</span>
              </span>
            ) : (
              <span className="mode-badge connected" title="Connected to live FastAPI backend at http://localhost:8000/api/v1">
                <Activity size={12} />
                <span>API CONNECTED</span>
              </span>
            )}

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
              Quick Scan
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
