/**
 * TrustLens Application Entry & Router Configuration
 * Maps all routes across authentication, scanning, intelligence analysis,
 * community feeds, and administrative moderation.
 */

import React from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { ConfigProvider, theme } from 'antd';
import { AuthProvider } from './context/AuthContext';
import { ProtectedRoute } from './components/common/ProtectedRoute';
import { AppLayout } from './components/layout/AppLayout';

// Pages
import { LandingPage } from './pages/LandingPage';
import { LoginPage } from './pages/LoginPage';
import { RegisterPage } from './pages/RegisterPage';
import { DashboardPage } from './pages/DashboardPage';
import { ScanPage } from './pages/ScanPage';
import { ScanReportPage } from './pages/ScanReportPage';
import { WebSecurityPage } from './pages/WebSecurityPage';
import { CertificatePage } from './pages/CertificatePage';
import { CommunityReportsPage } from './pages/CommunityReportsPage';
import { ScanHistoryPage } from './pages/ScanHistoryPage';
import { ModerationPage } from './pages/ModerationPage';
import { NotFoundPage } from './pages/NotFoundPage';

export default function App() {
  return (
    <ConfigProvider
      theme={{
        algorithm: theme.darkAlgorithm,
        token: {
          colorPrimary: '#D6A45B',
          colorBgBase: '#101112',
          colorBgContainer: '#191B1D',
          colorBorder: '#2B2E32',
          fontFamily: "'Geist', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif",
          borderRadius: 6,
        },
      }}
    >
      <AuthProvider>
        <BrowserRouter>
          <Routes>
            {/* Public Entry & Marketing */}
            <Route path="/" element={<LandingPage />} />
            <Route path="/login" element={<LoginPage />} />
            <Route path="/register" element={<RegisterPage />} />

            {/* Authenticated Application Shell */}
            <Route
              element={
                <ProtectedRoute>
                  <AppLayout />
                </ProtectedRoute>
              }
            >
              <Route path="/dashboard" element={<DashboardPage />} />
              <Route path="/scan" element={<ScanPage />} />
              <Route path="/scans/:scanId" element={<ScanReportPage />} />
              <Route path="/scans/:scanId/certificate" element={<CertificatePage />} />

              {/* Dedicated Web Security Posture Analysis */}
              <Route path="/web-security" element={<WebSecurityPage />} />
              <Route path="/web-security/:id" element={<WebSecurityPage />} />

              {/* Dedicated Certificate Intelligence */}
              <Route path="/certificates" element={<CertificatePage />} />
              <Route path="/certificates/:scanId" element={<CertificatePage />} />

              {/* Collaborative Threat Intelligence */}
              <Route path="/community" element={<CommunityReportsPage />} />
              <Route path="/community/:reportId" element={<CommunityReportsPage />} />

              {/* Comprehensive Historical Directory */}
              <Route path="/history" element={<ScanHistoryPage />} />

              {/* Restricted Moderation & Admin */}
              <Route
                path="/admin/moderation"
                element={
                  <ProtectedRoute requiredRole="moderator">
                    <ModerationPage />
                  </ProtectedRoute>
                }
              />
            </Route>

            {/* Fallback 404 */}
            <Route path="*" element={<NotFoundPage />} />
          </Routes>
        </BrowserRouter>
      </AuthProvider>
    </ConfigProvider>
  );
}

