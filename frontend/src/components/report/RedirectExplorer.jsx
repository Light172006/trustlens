/**
 * RedirectExplorer Component (SIGNATURE FEATURE)
 * Interactive redirect chain node-and-connection visualization.
 * Displays hops, HTTP status codes, resolved IPs, and TLS verification state.
 */

import React, { useState } from 'react';
import {
  ArrowRight,
  ShieldCheck,
  ShieldAlert,
  Server,
  Globe,
  Copy,
  Check,
  Info,
  ExternalLink,
} from 'lucide-react';
import { Tooltip, Button, message } from 'antd';

export function RedirectExplorer({ redirects = [], originalUrl, canonicalUrl }) {
  const [selectedNodeIndex, setSelectedNodeIndex] = useState(0);
  const [copiedUrl, setCopiedUrl] = useState(null);

  // If no redirects occurred, display direct connection empty state
  if (!redirects || redirects.length === 0) {
    return (
      <div
        style={{
          padding: '2.5rem 1.5rem',
          textAlign: 'center',
          backgroundColor: 'var(--bg-surface-secondary)',
          borderRadius: 'var(--radius-lg)',
          border: '1px solid var(--border-color)',
        }}
      >
        <div
          style={{
            width: '42px',
            height: '42px',
            borderRadius: '50%',
            backgroundColor: 'var(--bg-surface)',
            border: '1px solid var(--border-color-strong)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            margin: '0 auto 1rem',
            color: 'var(--color-accent)',
          }}
        >
          <Globe size={20} />
        </div>
        <h4 style={{ fontSize: '0.95rem', fontWeight: 600, color: 'var(--text-primary)', marginBottom: '0.35rem' }}>
          Direct Single-Hop Connection
        </h4>
        <p style={{ fontSize: '0.825rem', color: 'var(--text-secondary)', maxWidth: '460px', margin: '0 auto 1.25rem' }}>
          No HTTP redirects were encountered during analysis. The server responded directly at the target URL without intermediate hops.
        </p>
        <div
          style={{
            display: 'inline-flex',
            alignItems: 'center',
            gap: '0.5rem',
            backgroundColor: 'var(--bg-app)',
            padding: '0.4rem 0.8rem',
            borderRadius: 'var(--radius-sm)',
            border: '1px solid var(--border-color)',
            fontFamily: 'var(--font-mono)',
            fontSize: '0.75rem',
            color: 'var(--color-safe-text)',
          }}
        >
          <span>Target Host: {originalUrl || canonicalUrl}</span>
        </div>
      </div>
    );
  }

  // Construct structured nodes list:
  // Node 0: Initial Origin
  // Node 1..N: Redirect Hop targets
  // Node Final: Resolved Destination
  const nodes = [];

  // Initial Target Node
  nodes.push({
    type: 'origin',
    title: 'Initial Target',
    url: redirects[0]?.source_url || originalUrl,
    host: redirects[0]?.host || 'origin.target',
    ip: redirects[0]?.ip || '—',
    statusCode: redirects[0]?.status_code,
    tlsVerified: redirects[0]?.tls_verified,
    hopNumber: 0,
  });

  // Intermediate Hops
  redirects.forEach((r, idx) => {
    const isLast = idx === redirects.length - 1;
    nodes.push({
      type: isLast ? 'final' : 'hop',
      title: isLast ? 'Final Destination' : `Hop ${r.hop}`,
      url: r.destination_url,
      host: r.destination_url ? new URL(r.destination_url).hostname : r.host,
      ip: r.ip,
      statusCode: r.status_code,
      tlsVerified: r.tls_verified,
      hopNumber: r.hop,
      details: r,
    });
  });

  const selectedNode = nodes[selectedNodeIndex] || nodes[0];

  const handleCopy = (text) => {
    if (!text) return;
    navigator.clipboard.writeText(text);
    setCopiedUrl(text);
    message.success('URL copied to clipboard');
    setTimeout(() => setCopiedUrl(null), 2000);
  };

  return (
    <div className="redirect-explorer">
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '1rem' }}>
        <div>
          <h4 style={{ fontSize: '0.95rem', fontWeight: 600, color: 'var(--text-primary)' }}>
            HTTP Redirection Journey
          </h4>
          <span style={{ fontSize: '0.775rem', color: 'var(--text-secondary)' }}>
            Inspected {redirects.length} intermediate redirection {redirects.length === 1 ? 'hop' : 'hops'}
          </span>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.75rem', color: 'var(--text-muted)' }}>
          <span style={{ display: 'inline-flex', alignItems: 'center', gap: '0.25rem' }}>
            <span style={{ width: 8, height: 8, borderRadius: '50%', backgroundColor: 'var(--color-safe)' }} />
            TLS Verified
          </span>
          <span style={{ display: 'inline-flex', alignItems: 'center', gap: '0.25rem' }}>
            <span style={{ width: 8, height: 8, borderRadius: '50%', backgroundColor: 'var(--color-malicious)' }} />
            Insecure / HTTP
          </span>
        </div>
      </div>

      {/* Horizontal Flow Container */}
      <div className="redirect-chain-flow">
        {nodes.map((node, index) => {
          const isSelected = index === selectedNodeIndex;
          const isInitial = index === 0;
          const isFinal = index === nodes.length - 1;

          return (
            <React.Fragment key={index}>
              {index > 0 && (
                <div className="redirect-connector">
                  <div className="redirect-connector-line" />
                </div>
              )}

              <div
                className={`redirect-node ${isSelected ? 'selected' : ''}`}
                onClick={() => setSelectedNodeIndex(index)}
              >
                <div className="redirect-node-header">
                  <span className="redirect-hop-badge">
                    {isInitial ? 'START' : isFinal ? 'DEST' : `HOP ${node.hopNumber}`}
                  </span>
                  {node.statusCode && (
                    <span className={`redirect-status-badge status-${node.statusCode}`}>
                      HTTP {node.statusCode}
                    </span>
                  )}
                </div>

                <div className="redirect-node-host" title={node.host}>
                  {node.host}
                </div>

                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginTop: '0.5rem' }}>
                  <span className="redirect-node-ip" title="Resolved IP Address">
                    {node.ip}
                  </span>
                  {node.tlsVerified !== undefined && (
                    <Tooltip title={node.tlsVerified ? 'TLS Handshake Verified' : 'Insecure / Plain HTTP or Invalid Certificate'}>
                      {node.tlsVerified ? (
                        <ShieldCheck size={14} color="var(--color-safe-text)" />
                      ) : (
                        <ShieldAlert size={14} color="var(--color-malicious-text)" />
                      )}
                    </Tooltip>
                  )}
                </div>
              </div>
            </React.Fragment>
          );
        })}
      </div>

      {/* Detailed Node Inspector Panel */}
      <div
        style={{
          marginTop: '1.5rem',
          padding: '1.25rem',
          backgroundColor: 'var(--bg-surface-secondary)',
          border: '1px solid var(--border-color)',
          borderRadius: 'var(--radius-md)',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '1rem', borderBottom: '1px solid var(--border-color)', paddingBottom: '0.75rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <Server size={16} color="var(--color-accent)" />
            <span style={{ fontSize: '0.85rem', fontWeight: 600, color: 'var(--text-primary)' }}>
              Telemetry Inspection: {selectedNode.title}
            </span>
          </div>
          <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.75rem', color: 'var(--text-muted)' }}>
            Node {selectedNodeIndex + 1} of {nodes.length}
          </span>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '1rem', marginBottom: '1rem' }}>
          <div>
            <div style={{ fontSize: '0.725rem', color: 'var(--text-muted)', marginBottom: '0.25rem' }}>TARGET HOST</div>
            <div style={{ fontSize: '0.85rem', fontWeight: 600, color: 'var(--text-primary)' }}>
              {selectedNode.host}
            </div>
          </div>

          <div>
            <div style={{ fontSize: '0.725rem', color: 'var(--text-muted)', marginBottom: '0.25rem' }}>RESOLVED IP ADDRESS</div>
            <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.85rem', color: 'var(--text-primary)' }}>
              {selectedNode.ip || '—'}
            </div>
          </div>

          <div>
            <div style={{ fontSize: '0.725rem', color: 'var(--text-muted)', marginBottom: '0.25rem' }}>HTTP RESPONSE CODE</div>
            <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.85rem', color: 'var(--text-primary)' }}>
              {selectedNode.statusCode ? `HTTP ${selectedNode.statusCode}` : '200 OK'}
            </div>
          </div>

          <div>
            <div style={{ fontSize: '0.725rem', color: 'var(--text-muted)', marginBottom: '0.25rem' }}>TRANSPORT ENCRYPTION</div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.35rem', fontSize: '0.85rem', color: selectedNode.tlsVerified ? 'var(--color-safe-text)' : 'var(--color-malicious-text)' }}>
              {selectedNode.tlsVerified ? <ShieldCheck size={14} /> : <ShieldAlert size={14} />}
              <span>{selectedNode.tlsVerified ? 'TLS Handshake Verified' : 'Unencrypted / Insecure'}</span>
            </div>
          </div>
        </div>

        <div>
          <div style={{ fontSize: '0.725rem', color: 'var(--text-muted)', marginBottom: '0.25rem' }}>FULL RESOURCE URL</div>
          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              backgroundColor: 'var(--bg-app)',
              padding: '0.5rem 0.75rem',
              borderRadius: 'var(--radius-sm)',
              border: '1px solid var(--border-color)',
              fontFamily: 'var(--font-mono)',
              fontSize: '0.775rem',
              color: 'var(--text-primary)',
              wordBreak: 'break-all',
              gap: '0.5rem',
            }}
          >
            <span>{selectedNode.url}</span>
            <Button
              type="text"
              size="small"
              icon={copiedUrl === selectedNode.url ? <Check size={14} color="var(--color-safe-text)" /> : <Copy size={14} />}
              onClick={() => handleCopy(selectedNode.url)}
              style={{ flexShrink: 0, color: 'var(--text-secondary)' }}
            />
          </div>
        </div>
      </div>
    </div>
  );
}
