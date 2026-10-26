import React, { useState } from 'react';
import { X, Copy, Check, AlertTriangle, AlertCircle, ShieldAlert, FileText, Code, CheckCircle2 } from 'lucide-react';

export default function LogInspectorModal({ log, onClose, onCopy }) {
  const [copied, setCopied] = useState(false);
  const [activeTab, setActiveTab] = useState('canonical'); // 'canonical', 'raw', 'intel'

  if (!log) return null;

  const handleCopy = (text) => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
    if (onCopy) onCopy(text);
  };

  const sev = (log.severity || 'low').toLowerCase();
  const status = (log.normalization_status || 'success').toLowerCase();
  const validationErrors = log.validation_errors || [];
  const conflictingFields = log.conflicting_fields || [];
  const unmappedFields = log.unmapped_fields || [];

  return (
    <div className="modal-overlay" onClick={onClose} role="dialog" aria-modal="true">
      <div className="modal-dialog" onClick={(e) => e.stopPropagation()} style={{ maxWidth: '780px', width: '95vw', maxHeight: '92vh', display: 'flex', flexDirection: 'column' }}>
        
        {/* Header */}
        <div className="modal-header">
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
            <span className={`badge-sev ${sev}`}>{log.severity}</span>
            <span className="badge-tech">{log.siem_source}</span>
            <span className={`badge-norm-${status}`}>
              {status.toUpperCase()}
            </span>
            <span className="code-val" style={{ fontSize: '10px' }}>
              Schema {log.mapping_version || '2.0.0'}
            </span>
            <span style={{ fontSize: '13px', fontWeight: '700', color: 'var(--text-primary)', marginLeft: '4px' }}>
              {log.alert_name}
            </span>
          </div>
          <button className="btn btn-secondary btn-xs" onClick={onClose}>
            <X size={14} />
          </button>
        </div>

        {/* Modal Body */}
        <div className="modal-body" style={{ overflowY: 'auto', flex: 1, display: 'flex', flexDirection: 'column', gap: '14px', padding: '16px' }}>
          
          {/* Diagnostics Section (if warnings/errors exist) */}
          {(validationErrors.length > 0 || conflictingFields.length > 0 || unmappedFields.length > 0) && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
              {validationErrors.length > 0 && (
                <div style={{ background: 'rgba(244, 63, 94, 0.1)', border: '1px solid rgba(244, 63, 94, 0.3)', borderRadius: '6px', padding: '10px 12px' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '6px', color: '#fb7185', fontSize: '12px', fontWeight: '700', marginBottom: '4px' }}>
                    <AlertCircle size={14} />
                    <span>Normalization & Validation Diagnostics</span>
                  </div>
                  <ul style={{ margin: 0, paddingLeft: '18px', fontSize: '11px', color: '#fda4af' }}>
                    {validationErrors.map((err, i) => (
                      <li key={i}>{err}</li>
                    ))}
                  </ul>
                </div>
              )}

              {conflictingFields.length > 0 && (
                <div style={{ background: 'rgba(245, 158, 11, 0.1)', border: '1px solid rgba(245, 158, 11, 0.3)', borderRadius: '6px', padding: '10px 12px' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '6px', color: '#fbbf24', fontSize: '12px', fontWeight: '700', marginBottom: '6px' }}>
                    <AlertTriangle size={14} />
                    <span>Conflicting Aliases Detected</span>
                  </div>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                    {conflictingFields.map((c, i) => (
                      <div key={i} style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>
                        <strong style={{ color: '#ffffff' }}>{c.field}:</strong> candidates {JSON.stringify(c.candidates)} &rarr; resolved to <code style={{ color: '#38bdf8' }}>{c.selected}</code>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {unmappedFields.length > 0 && (
                <div style={{ background: 'rgba(56, 189, 248, 0.06)', border: '1px solid rgba(56, 189, 248, 0.2)', borderRadius: '6px', padding: '8px 12px' }}>
                  <div style={{ fontSize: '11px', color: 'var(--text-muted)', marginBottom: '4px', fontWeight: '600' }}>
                    Unmapped Vendor Fields ({unmappedFields.length})
                  </div>
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: '4px' }}>
                    {unmappedFields.map((f, i) => (
                      <span key={i} className="code-val" style={{ fontSize: '10px', color: '#94a3b8' }}>
                        {f}
                      </span>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* Canonical Endpoint & Provenance Grid */}
          <div className="detail-grid">
            <div className="detail-item">
              <span className="detail-key">Observed Timestamp</span>
              <span className="detail-val text-mono">{log.timestamp}</span>
            </div>
            <div className="detail-item">
              <span className="detail-key">User Entity / Identity</span>
              <span className="detail-val text-mono" style={{ color: '#38bdf8' }}>
                {log.user || log.src_user || '—'}
              </span>
            </div>
            <div className="detail-item">
              <span className="detail-key">Source Endpoint</span>
              <span className="detail-val text-mono">
                {log.src_ip || '—'}{log.src_port ? `:${log.src_port}` : ''} {log.src_host ? `(${log.src_host})` : ''}
              </span>
            </div>
            <div className="detail-item">
              <span className="detail-key">Destination Endpoint</span>
              <span className="detail-val text-mono">
                {log.dest_ip || '—'}{log.dest_port ? `:${log.dest_port}` : ''} {log.dest_host ? `(${log.dest_host})` : ''}
              </span>
            </div>
            <div className="detail-item">
              <span className="detail-key">Action & Protocol</span>
              <span className="detail-val text-mono">
                {log.action ? log.action.toUpperCase() : '—'} / {log.protocol || 'TCP'}
              </span>
            </div>
            <div className="detail-item">
              <span className="detail-key">Target Domain / FQDN</span>
              <span className="detail-val text-mono">{log.domain || '—'}</span>
            </div>
            <div className="detail-item" style={{ gridColumn: 'span 2' }}>
              <span className="detail-key">Payload File Hash</span>
              <span className="detail-val text-mono" style={{ fontSize: '11px' }}>{log.file_hash || '—'}</span>
            </div>
          </div>

          {/* Tab Navigation for Event Content */}
          <div style={{ display: 'flex', borderBottom: '1px solid rgba(255,255,255,0.08)', gap: '12px' }}>
            <button 
              className={`btn btn-xs ${activeTab === 'canonical' ? 'btn-primary' : 'btn-secondary'}`}
              onClick={() => setActiveTab('canonical')}
            >
              <Code size={12} />
              <span>Canonical Event (JSON)</span>
            </button>
            <button 
              className={`btn btn-xs ${activeTab === 'raw' ? 'btn-primary' : 'btn-secondary'}`}
              onClick={() => setActiveTab('raw')}
            >
              <FileText size={12} />
              <span>Original Raw Event</span>
            </button>
            {log.threat_intel && Object.keys(log.threat_intel).length > 0 && (
              <button 
                className={`btn btn-xs ${activeTab === 'intel' ? 'btn-primary' : 'btn-secondary'}`}
                onClick={() => setActiveTab('intel')}
              >
                <ShieldAlert size={12} />
                <span>Threat Intelligence ({Object.keys(log.threat_intel).length})</span>
              </button>
            )}
          </div>

          {/* Tab Content */}
          {activeTab === 'canonical' && (
            <div>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
                <span style={{ fontSize: '11px', fontWeight: '600', color: 'var(--text-secondary)' }}>
                  Normalized Canonical Schema (ECS / CIM)
                </span>
                <button 
                  className="btn btn-secondary btn-xs" 
                  onClick={() => handleCopy(JSON.stringify(log, null, 2))}
                >
                  {copied ? <Check size={11} color="var(--sev-low)" /> : <Copy size={11} />}
                  <span>{copied ? 'Copied' : 'Copy JSON'}</span>
                </button>
              </div>
              <pre className="code-block" style={{ maxHeight: '240px', overflowY: 'auto' }}>
                <code>{JSON.stringify(log, null, 2)}</code>
              </pre>
            </div>
          )}

          {activeTab === 'raw' && (
            <div>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
                <span style={{ fontSize: '11px', fontWeight: '600', color: 'var(--text-secondary)' }}>
                  Unaltered Raw Ingested Record
                </span>
                <button 
                  className="btn btn-secondary btn-xs" 
                  onClick={() => handleCopy(log.raw_log || (typeof log.raw_event === 'string' ? log.raw_event : JSON.stringify(log.raw_event, null, 2)))}
                >
                  {copied ? <Check size={11} color="var(--sev-low)" /> : <Copy size={11} />}
                  <span>{copied ? 'Copied' : 'Copy Raw Record'}</span>
                </button>
              </div>
              <pre className="code-block" style={{ maxHeight: '240px', overflowY: 'auto', whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}>
                <code>{log.raw_log || (typeof log.raw_event === 'string' ? log.raw_event : JSON.stringify(log.raw_event, null, 2))}</code>
              </pre>
            </div>
          )}

          {activeTab === 'intel' && log.threat_intel && (
            <div>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
                <span style={{ fontSize: '11px', fontWeight: '600', color: 'var(--text-secondary)' }}>
                  Decoupled Threat Intelligence Findings
                </span>
              </div>
              <pre className="code-block" style={{ maxHeight: '240px', overflowY: 'auto' }}>
                <code>{JSON.stringify(log.threat_intel, null, 2)}</code>
              </pre>
            </div>
          )}

        </div>

        {/* Footer */}
        <div className="modal-footer">
          <button className="btn btn-secondary btn-sm" onClick={onClose}>
            Close
          </button>
        </div>

      </div>
    </div>
  );
}
