/**
 * TrustLens Application Root & Routing Configuration
 * Configures Ant Design dark theme tokens, global AuthProvider, and route structure.
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
import { CertificatePage } from './pages/CertificatePage';
import { ScanHistoryPage } from './pages/ScanHistoryPage';
import { NotFoundPage } from './pages/NotFoundPage';

export function App() {
  return (
    <ConfigProvider
      theme={{
        algorithm: theme.darkAlgorithm,
        token: {
          colorPrimary: '#D6A45B',
          colorBgBase: '#101112',
          colorBgContainer: '#191B1D',
          colorBgElevated: '#202225',
          colorBorder: '#2B2E32',
          colorBorderSecondary: '#222529',
          colorText: '#F2F2F0',
          colorTextSecondary: '#92969D',
          borderRadius: 6,
          fontFamily: "'Geist', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif",
        },
        components: {
          Button: {
            colorPrimary: '#D6A45B',
          },
          Table: {
            colorBgContainer: '#191B1D',
            headerBg: '#141516',
            borderColor: '#2B2E32',
            colorText: '#F2F2F0',
            colorTextHeading: '#92969D',
          },
          Card: {
            colorBgContainer: '#191B1D',
            colorBorderSecondary: '#2B2E32',
          },
          Input: {
            colorBgContainer: '#141516',
            colorBorder: '#2B2E32',
            colorText: '#F2F2F0',
          },
          Select: {
            colorBgContainer: '#141516',
            colorBorder: '#2B2E32',
            colorText: '#F2F2F0',
          },
          Tabs: {
            itemColor: '#92969D',
            itemSelectedColor: '#D6A45B',
            inkBarColor: '#D6A45B',
          },
        },
      }}
    >
      <AuthProvider>
        <BrowserRouter>
          <Routes>
            {/* Public Routes */}
            <Route path="/" element={<LandingPage />} />
            <Route path="/login" element={<LoginPage />} />
            <Route path="/register" element={<RegisterPage />} />

            {/* Protected Console Routes */}
            <Route
              element={
                <ProtectedRoute>
                  <AppLayout />
                </ProtectedRoute>
              }
            >
              <Route path="/dashboard" element={<DashboardPage />} />
              <Route path="/scan" element={<ScanPage />} />
              <Route path="/certificates" element={<CertificatePage />} />
              <Route path="/scans" element={<Navigate to="/history" replace />} />
              <Route path="/scans/:scanId" element={<ScanReportPage />} />
              <Route path="/scans/:scanId/certificate" element={<CertificatePage />} />
              <Route path="/history" element={<ScanHistoryPage />} />
            </Route>

            {/* 404 Route */}
            <Route path="*" element={<NotFoundPage />} />
          </Routes>
        </BrowserRouter>
      </AuthProvider>
    </ConfigProvider>
  );
}

export default App;
