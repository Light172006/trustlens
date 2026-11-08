/**
 * LandingPage Component
 * Professional product presentation for TrustLens.
 * Clean, technical, minimal cybersecurity interface inspired by Linear and Raycast.
 */

import React from 'react';
import { Link, useNavigate } from 'react-router-dom';
import {
  Shield,
  Search,
  ArrowRight,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  HelpCircle,
  GitFork,
  Key,
  Radio,
  ExternalLink,
  ChevronRight,
  Lock,
} from 'lucide-react';
import { Button } from 'antd';
import { UrlScannerForm } from '../components/scanner/UrlScannerForm';
import { VERDICT_DESCRIPTIONS } from '../lib/utils';
import { useAuth } from '../context/AuthContext';

export function LandingPage() {
  const { isAuthenticated } = useAuth();
  const navigate = useNavigate();

  return (
    <div style={{ minHeight: '100vh', backgroundColor: 'var(--bg-app)', color: 'var(--text-primary)' }}>
      {/* Navigation Header */}
      <header
        style={{
          borderBottom: '1px solid var(--border-color)',
          backgroundColor: 'rgba(16, 17, 18, 0.85)',
          backdropFilter: 'blur(8px)',
          position: 'sticky',
          top: 0,
          zIndex: 50,
          padding: '0.85rem 2rem',
        }}
      >
        <div style={{ maxWidth: '1200px', margin: '0 auto', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem', fontWeight: 700, fontSize: '1.1rem' }}>
            <div
              style={{
                width: '30px',
                height: '30px',
                borderRadius: '6px',
                backgroundColor: 'var(--bg-surface-secondary)',
                border: '1px solid var(--border-color-strong)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                color: 'var(--color-accent)',
              }}
            >
              <Shield size={18} />
            </div>
            <span>TrustLens</span>
          </div>

          <nav style={{ display: 'flex', alignItems: 'center', gap: '1.5rem' }}>
            <a href="#capabilities" style={{ fontSize: '0.85rem', color: 'var(--text-secondary)' }}>Capabilities</a>
            <a href="#verdicts" style={{ fontSize: '0.85rem', color: 'var(--text-secondary)' }}>Verdict System</a>
            <a href="#how-it-works" style={{ fontSize: '0.85rem', color: 'var(--text-secondary)' }}>Architecture</a>
          </nav>

          <div>
            {isAuthenticated ? (
              <Button
                type="primary"
                onClick={() => navigate('/dashboard')}
                style={{ backgroundColor: 'var(--color-accent)', borderColor: 'var(--color-accent)', color: '#101112', fontWeight: 600 }}
              >
                Go to Console
              </Button>
            ) : (
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
                <Link to="/login" style={{ fontSize: '0.85rem', color: 'var(--text-secondary)' }}>Log in</Link>
                <Button
                  type="primary"
                  onClick={() => navigate('/register')}
                  style={{ backgroundColor: 'var(--color-accent)', borderColor: 'var(--color-accent)', color: '#101112', fontWeight: 600 }}
                >
                  Get Started
                </Button>
              </div>
            )}
          </div>
        </div>
      </header>

      {/* Hero Section */}
      <section style={{ padding: '5rem 1.5rem 3rem', textAlign: 'center', maxWidth: '960px', margin: '0 auto' }}>
        <div
          style={{
            display: 'inline-flex',
            alignItems: 'center',
            gap: '0.5rem',
            padding: '0.3rem 0.75rem',
            borderRadius: '999px',
            backgroundColor: 'var(--color-accent-subtle)',
            border: '1px solid rgba(214, 164, 91, 0.3)',
            color: 'var(--color-accent)',
            fontSize: '0.75rem',
            fontFamily: 'var(--font-mono)',
            marginBottom: '1.75rem',
          }}
        >
          <span>CYBERSECURITY INTELLIGENCE PLATFORM</span>
        </div>

        <h1
          style={{
            fontSize: 'clamp(2.2rem, 5vw, 3.5rem)',
            fontWeight: 800,
            letterSpacing: '-0.03em',
            lineHeight: 1.15,
            color: 'var(--text-primary)',
            marginBottom: '1.25rem',
          }}
        >
          AI-Powered Web Threat Detection & Digital Trust Intelligence
        </h1>

        <p
          style={{
            fontSize: '1.1rem',
            color: 'var(--text-secondary)',
            maxWidth: '680px',
            margin: '0 auto 2.5rem',
            lineHeight: 1.6,
          }}
        >
          Rigorous perimeter evaluation identifying phishing indicators, credential harvesting,
          untrusted TLS authorities, and malicious redirection pipelines with explainable verdicts.
        </p>

        {/* Live Scan Trigger Box */}
        <div style={{ maxWidth: '720px', margin: '0 auto', textAlign: 'left' }}>
          <UrlScannerForm />
        </div>
      </section>

      {/* 4 Security Verdicts Showcase */}
      <section id="verdicts" style={{ padding: '4rem 1.5rem', maxWidth: '1200px', margin: '0 auto' }}>
        <div style={{ textAlign: 'center', marginBottom: '3rem' }}>
          <h2 style={{ fontSize: '1.75rem', fontWeight: 700, letterSpacing: '-0.02em', marginBottom: '0.5rem' }}>
            Explainable Security Verdicts
          </h2>
          <p style={{ fontSize: '0.9rem', color: 'var(--text-secondary)', maxWidth: '540px', margin: '0 auto' }}>
            TrustLens enforces 4 distinct, unambiguous assessments backed by transparent heuristic evidence.
          </p>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))', gap: '1.25rem' }}>
          {/* SAFE */}
          <div className="tl-card" style={{ borderTop: '3px solid var(--color-safe)' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.75rem', color: 'var(--color-safe-text)' }}>
              <ShieldCheck size={20} />
              <span style={{ fontWeight: 700, fontSize: '1rem', fontFamily: 'var(--font-mono)' }}>SAFE</span>
            </div>
            <p style={{ fontSize: '0.825rem', color: 'var(--text-secondary)', lineHeight: 1.5 }}>
              {VERDICT_DESCRIPTIONS.SAFE}
            </p>
            <div style={{ marginTop: '1rem', fontSize: '0.725rem', color: 'var(--text-muted)' }}>
              *Never implies 100% guarantee or absence of zero-day threats.
            </div>
          </div>

          {/* SUSPICIOUS */}
          <div className="tl-card" style={{ borderTop: '3px solid var(--color-suspicious)' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.75rem', color: 'var(--color-suspicious-text)' }}>
              <AlertTriangle size={20} />
              <span style={{ fontWeight: 700, fontSize: '1rem', fontFamily: 'var(--font-mono)' }}>SUSPICIOUS</span>
            </div>
            <p style={{ fontSize: '0.825rem', color: 'var(--text-secondary)', lineHeight: 1.5 }}>
              {VERDICT_DESCRIPTIONS.SUSPICIOUS}
            </p>
            <div style={{ marginTop: '1rem', fontSize: '0.725rem', color: 'var(--text-muted)' }}>
              Identifies self-signed certificates, missing HSTS, or suspicious TLDs.
            </div>
          </div>

          {/* MALICIOUS */}
          <div className="tl-card" style={{ borderTop: '3px solid var(--color-malicious)' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.75rem', color: 'var(--color-malicious-text)' }}>
              <ShieldAlert size={20} />
              <span style={{ fontWeight: 700, fontSize: '1rem', fontFamily: 'var(--font-mono)' }}>MALICIOUS</span>
            </div>
            <p style={{ fontSize: '0.825rem', color: 'var(--text-secondary)', lineHeight: 1.5 }}>
              {VERDICT_DESCRIPTIONS.MALICIOUS}
            </p>
            <div style={{ marginTop: '1rem', fontSize: '0.725rem', color: 'var(--text-muted)' }}>
              Confirmed OpenPhish or URLhaus indicator match. Immediate hazard.
            </div>
          </div>

          {/* INCONCLUSIVE */}
          <div className="tl-card" style={{ borderTop: '3px solid var(--color-inconclusive)' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.75rem', color: 'var(--color-inconclusive-text)' }}>
              <HelpCircle size={20} />
              <span style={{ fontWeight: 700, fontSize: '1rem', fontFamily: 'var(--font-mono)' }}>INCONCLUSIVE</span>
            </div>
            <p style={{ fontSize: '0.825rem', color: 'var(--text-secondary)', lineHeight: 1.5 }}>
              {VERDICT_DESCRIPTIONS.INCONCLUSIVE}
            </p>
            <div style={{ marginTop: '1rem', fontSize: '0.725rem', color: 'var(--text-muted)' }}>
              Triggered on DNS lookup failure, gateway timeout, or privacy mode.
            </div>
          </div>
        </div>
      </section>

      {/* Core Capabilities Grid */}
      <section id="capabilities" style={{ padding: '4rem 1.5rem', backgroundColor: 'var(--bg-sidebar)', borderTop: '1px solid var(--border-color)', borderBottom: '1px solid var(--border-color)' }}>
        <div style={{ maxWidth: '1200px', margin: '0 auto' }}>
          <div style={{ textAlign: 'center', marginBottom: '3rem' }}>
            <h2 style={{ fontSize: '1.75rem', fontWeight: 700, letterSpacing: '-0.02em', marginBottom: '0.5rem' }}>
              Multi-Layered Threat Intelligence
            </h2>
            <p style={{ fontSize: '0.9rem', color: 'var(--text-secondary)', maxWidth: '540px', margin: '0 auto' }}>
              Built specifically for security analysts, incident responders, and privacy-conscious organizations.
            </p>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: '1.5rem' }}>
            <div className="tl-card">
              <div style={{ width: 36, height: 36, borderRadius: 6, backgroundColor: 'var(--bg-surface-secondary)', display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--color-accent)', marginBottom: '1rem' }}>
                <GitFork size={18} />
              </div>
              <h3 style={{ fontSize: '1rem', fontWeight: 600, color: 'var(--text-primary)', marginBottom: '0.5rem' }}>
                Redirect Chain Explorer
              </h3>
              <p style={{ fontSize: '0.825rem', color: 'var(--text-secondary)', lineHeight: 1.5 }}>
                Inspect multi-hop HTTP redirections, protocol downgrades from HTTPS to HTTP, intermediate proxy IPs, and SSL stripping vectors.
              </p>
            </div>

            <div className="tl-card">
              <div style={{ width: 36, height: 36, borderRadius: 6, backgroundColor: 'var(--bg-surface-secondary)', display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--color-accent)', marginBottom: '1rem' }}>
                <Key size={18} />
              </div>
              <h3 style={{ fontSize: '1rem', fontWeight: 600, color: 'var(--text-primary)', marginBottom: '0.5rem' }}>
                X.509 Certificate Intelligence
              </h3>
              <p style={{ fontSize: '0.825rem', color: 'var(--text-secondary)', lineHeight: 1.5 }}>
                Cryptographic examination of subject, issuer, SANs, days until expiration, SHA-256 fingerprint, and chain validity diagnostics.
              </p>
            </div>

            <div className="tl-card">
              <div style={{ width: 36, height: 36, borderRadius: 6, backgroundColor: 'var(--bg-surface-secondary)', display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--color-accent)', marginBottom: '1rem' }}>
                <Radio size={18} />
              </div>
              <h3 style={{ fontSize: '1rem', fontWeight: 600, color: 'var(--text-primary)', marginBottom: '0.5rem' }}>
                Live Threat Feeds
              </h3>
              <p style={{ fontSize: '0.825rem', color: 'var(--text-secondary)', lineHeight: 1.5 }}>
                Synchronized telemetry against OpenPhish and URLhaus databases to catch verified active zero-day campaigns.
              </p>
            </div>
          </div>
        </div>
      </section>

      {/* Footer */}
      <footer style={{ padding: '3rem 1.5rem', textAlign: 'center', fontSize: '0.8rem', color: 'var(--text-muted)' }}>
        <div style={{ maxWidth: '1200px', margin: '0 auto', display: 'flex', flexDirection: 'column', gap: '0.75rem', alignItems: 'center' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontWeight: 600, color: 'var(--text-primary)' }}>
            <Shield size={14} color="var(--color-accent)" /> TrustLens Intelligence Platform
          </div>
          <p style={{ maxWidth: '600px', lineHeight: 1.4 }}>
            Engineered for high-assurance cybersecurity assessment. Adheres to strict SSRF boundary validation and transparent heuristics.
          </p>
          <div style={{ marginTop: '0.5rem', fontSize: '0.75rem' }}>
            © {new Date().getFullYear()} TrustLens. All rights reserved.
          </div>
        </div>
      </footer>
    </div>
  );
}
