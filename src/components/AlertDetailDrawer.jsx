import React, { useState, useEffect } from 'react';
import { 
  X, 
  Copy, 
  Check, 
  Terminal, 
  Clock, 
  User, 
  FileCode, 
  Layers, 
  ShieldAlert,
  Hash,
  Globe,
  Server
} from 'lucide-react';

export default function AlertDetailDrawer({ alert, onClose, onInvestigate, onCopy }) {
  const [copiedKey, setCopiedKey] = useState(null);
  const [status, setStatus] = useState(alert?.status || 'NEW');
  const [analystNotes, setAnalystNotes] = useState('');
  const [viewRaw, setViewRaw] = useState(false);

  // Close on Escape key press
  useEffect(() => {
    const handleKeyDown = (e) => {
      if (e.key === 'Escape' && onClose) {
        onClose();
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [onClose]);

  if (!alert) return null;

  const handleCopy = (text, key) => {
    if (!text) return;
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
    if (onCopy) onCopy(text);
  };

  const sev = (alert.severity || 'low').toLowerCase();

  // Extract nested rule or details if available
  const ruleDetails = alert.details?.rule || {};
  const fullLog = alert.details?.full_log || alert.details?.command || alert.details?.cmd;

  return (
    <div 
      className="drawer-overlay" 
      onClick={onClose} 
      role="dialog" 
      aria-modal="true" 
      aria-labelledby="drawer-title"
      style={{
        position: 'fixed',
        top: 0,
        left: 0,
        right: 0,
        bottom: 0,
        backgroundColor: 'rgba(0, 0, 0, 0.75)',
        backdropFilter: 'blur(4px)',
        display: 'flex',
        justifyContent: 'flex-end',
        zIndex: 1000
      }}
    >
      <div 
        className="drawer-content" 
        onClick={(e) => e.stopPropagation()}
        style={{
          width: '640px',
          maxWidth: '95vw',
          height: '100vh',
          maxHeight: '100vh',
          backgroundColor: '#08090c',
          borderLeft: '1px solid var(--border-color)',
          display: 'flex',
          flexDirection: 'column',
          boxShadow: '-15px 0 35px rgba(0, 0, 0, 0.85)',
          overflow: 'hidden'
        }}
      >
        
        {/* Drawer Header (Fixed at top) */}
        <div 
          className="drawer-header"
          style={{
            flexShrink: 0,
            padding: '16px 20px',
            backgroundColor: '#0d0f14',
            borderBottom: '1px solid var(--border-color)',
            display: 'flex',
            alignItems: 'flex-start',
            justifyContent: 'space-between'
          }}
        >
          <div style={{ display: 'flex', flexDirection: 'column', gap: '6px', maxWidth: '85%' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
              <span className={`badge-sev ${sev}`}>{alert.severity}</span>
              <span className="badge-tech">{alert.siem_source}</span>
              <span className={`badge-norm-${(alert.normalization_status || 'success').toLowerCase()}`}>
                {(alert.normalization_status || 'success').toUpperCase()}
              </span>
              <span className="code-val">{alert.id ? alert.id : 'ALERT'}</span>
            </div>
            <h2 id="drawer-title" style={{ fontSize: '15px', fontWeight: '700', color: '#ffffff', lineHeight: 1.3, margin: 0 }}>
              {alert.alert_name || 'Security Event Detection'}
            </h2>
          </div>
          <button 
            className="btn btn-secondary btn-xs" 
            onClick={onClose} 
            aria-label="Close drawer"
            style={{ padding: '6px', borderRadius: '4px' }}
          >
            <X size={16} />
          </button>
        </div>

        {/* Drawer Scrollable Body */}
        <div 
          className="drawer-body"
          style={{
            flex: '1 1 auto',
            minHeight: 0,
            overflowY: 'auto',
            overflowX: 'hidden',
            padding: '20px',
            display: 'flex',
            flexDirection: 'column',
            gap: '16px'
          }}
        >
          
          {/* Status & Ownership Toolbar */}
          <div style={{ flexShrink: 0, display: 'flex', justifyContent: 'space-between', alignItems: 'center', background: '#0e1217', padding: '10px 14px', borderRadius: '6px', border: '1px solid var(--border-color)' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px', fontSize: '12px' }}>
              <span style={{ color: 'var(--text-muted)', fontWeight: '600' }}>Triage Status:</span>
              <select 
                className="select-ctrl" 
                value={status} 
                onChange={(e) => setStatus(e.target.value)}
                style={{ fontSize: '11.5px', padding: '4px 8px' }}
              >
                <option value="NEW">NEW / UNTRIAGED</option>
                <option value="IN_TRIAGE">IN TRIAGE</option>
                <option value="ESCALATED">ESCALATED TO SOC T2</option>
                <option value="CONTAINED">CONTAINED</option>
                <option value="CLOSED">CLOSED / RESOLVED</option>
              </select>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '11.5px', color: 'var(--text-secondary)' }}>
              <span>Assignee:</span>
              <span className="code-val" style={{ color: '#38bdf8' }}>secops_analyst_1</span>
            </div>
          </div>

          {/* Section 1: Timestamps & Detection Provenance */}
          <div className="panel" style={{ flexShrink: 0, overflow: 'visible', border: '1px solid var(--border-subtle)' }}>
            <div className="panel-header" style={{ padding: '8px 12px' }}>
              <span className="panel-title">
                <Clock size={13} />
                <span>Detection Provenance</span>
              </span>
            </div>
            <div className="panel-body" style={{ padding: '14px', overflow: 'visible' }}>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '14px 18px' }}>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                  <span className="detail-key">Observed Timestamp</span>
                  <span style={{ fontSize: '12px', color: '#ffffff', fontFamily: 'var(--font-mono)' }}>
                    {alert.timestamp || alert.created_at || '—'}
                  </span>
                </div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                  <span className="detail-key">SIEM Ingestion Source</span>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                    <span className="badge-tech" style={{ margin: 0 }}>{alert.siem_source}</span>
                    <span style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>Pipeline</span>
                  </div>
                </div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                  <span className="detail-key">Event Type / Classification</span>
                  <span style={{ fontSize: '12px', color: '#ffffff', fontFamily: 'var(--font-mono)' }}>
                    {alert.event_type || 'Threat Detection Signature'}
                  </span>
                </div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                  <span className="detail-key">Event UUID</span>
                  <div style={{ fontSize: '12px', color: '#ffffff', fontFamily: 'var(--font-mono)', display: 'flex', alignItems: 'center', gap: '6px' }}>
                    <span>{alert.id || 'N/A'}</span>
                    {alert.id && (
                      <button className="copy-btn" onClick={() => handleCopy(alert.id, 'id')} title="Copy ID">
                        {copiedKey === 'id' ? <Check size={11} color="var(--sev-low)" /> : <Copy size={11} />}
                      </button>
                    )}
                  </div>
                </div>
              </div>
            </div>
          </div>

          {/* Section 2: Targeted Assets & Identities */}
          <div className="panel" style={{ flexShrink: 0, overflow: 'visible', border: '1px solid var(--border-subtle)' }}>
            <div className="panel-header" style={{ padding: '8px 12px' }}>
              <span className="panel-title">
                <User size={13} />
                <span>Targeted Assets &amp; User Identities</span>
              </span>
            </div>
            <div className="panel-body" style={{ padding: '14px', overflow: 'visible' }}>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '14px 18px' }}>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                  <span className="detail-key">User / Account Entity</span>
                  <div style={{ fontSize: '12px', color: '#38bdf8', fontFamily: 'var(--font-mono)', display: 'flex', alignItems: 'center', gap: '6px' }}>
                    <span>{alert.user || '—'}</span>
                    {alert.user && (
                      <button className="copy-btn" onClick={() => handleCopy(alert.user, 'user')} title="Copy User">
                        {copiedKey === 'user' ? <Check size={11} color="var(--sev-low)" /> : <Copy size={11} />}
                      </button>
                    )}
                  </div>
                </div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                  <span className="detail-key">Source Endpoint (src)</span>
                  <div style={{ fontSize: '12px', color: '#ffffff', fontFamily: 'var(--font-mono)', display: 'flex', alignItems: 'center', gap: '6px' }}>
                    <span>{alert.src_ip ? `${alert.src_ip}${alert.src_port ? `:${alert.src_port}` : ''}` : '—'}</span>
                    {alert.src_ip && (
                      <button className="copy-btn" onClick={() => handleCopy(alert.src_ip, 'src')} title="Copy Source IP">
                        {copiedKey === 'src' ? <Check size={11} color="var(--sev-low)" /> : <Copy size={11} />}
                      </button>
                    )}
                  </div>
                </div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                  <span className="detail-key">Destination Asset (dest)</span>
                  <div style={{ fontSize: '12px', color: '#ffffff', fontFamily: 'var(--font-mono)', display: 'flex', alignItems: 'center', gap: '6px' }}>
                    <span>{alert.dest_ip ? `${alert.dest_ip}${alert.dest_port ? `:${alert.dest_port}` : ''}` : '—'}</span>
                    {alert.dest_ip && (
                      <button className="copy-btn" onClick={() => handleCopy(alert.dest_ip, 'dest')} title="Copy Destination IP">
                        {copiedKey === 'dest' ? <Check size={11} color="var(--sev-low)" /> : <Copy size={11} />}
                      </button>
                    )}
                  </div>
                </div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                  <span className="detail-key">FQDN / Target Domain</span>
                  <div style={{ fontSize: '12px', color: '#ffffff', fontFamily: 'var(--font-mono)', display: 'flex', alignItems: 'center', gap: '6px' }}>
                    <span>{alert.domain || '—'}</span>
                    {alert.domain && (
                      <button className="copy-btn" onClick={() => handleCopy(alert.domain, 'domain')} title="Copy Domain">
                        {copiedKey === 'domain' ? <Check size={11} color="var(--sev-low)" /> : <Copy size={11} />}
                      </button>
                    )}
                  </div>
                </div>
                
                {/* File Hash spanning full width */}
                <div style={{ gridColumn: 'span 2', display: 'flex', flexDirection: 'column', gap: '4px' }}>
                  <span className="detail-key">Payload File Hash (SHA-256 / MD5)</span>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginTop: '2px' }}>
                    <div style={{ 
                      fontSize: '11px', 
                      wordBreak: 'break-all', 
                      background: '#040508', 
                      padding: '8px 10px', 
                      borderRadius: '4px', 
                      border: '1px solid var(--border-subtle)', 
                      flex: 1,
                      fontFamily: 'var(--font-mono)',
                      color: alert.file_hash ? '#ffffff' : 'var(--text-muted)'
                    }}>
                      {alert.file_hash || '—'}
                    </div>
                    {alert.file_hash && (
                      <button className="btn btn-secondary btn-xs" onClick={() => handleCopy(alert.file_hash, 'hash')} title="Copy Hash">
                        {copiedKey === 'hash' ? <Check size={12} color="var(--sev-low)" /> : <Copy size={12} />}
                      </button>
                    )}
                  </div>
                </div>
              </div>
            </div>
          </div>

          {/* Section 3: Correlated SIEM Telemetry & Attributes (if present) */}
          {(ruleDetails.id || fullLog) && (
            <div className="panel" style={{ flexShrink: 0, overflow: 'visible', border: '1px solid var(--border-subtle)' }}>
              <div className="panel-header" style={{ padding: '8px 12px' }}>
                <span className="panel-title">
                  <Layers size={13} />
                  <span>SIEM Telemetry &amp; Rule Context</span>
                </span>
              </div>
              <div className="panel-body" style={{ padding: '14px', overflow: 'visible' }}>
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '14px 18px' }}>
                  {ruleDetails.id && (
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                      <span className="detail-key">SIEM Rule ID</span>
                      <span style={{ fontSize: '12px', color: '#ffffff', fontFamily: 'var(--font-mono)' }}>{ruleDetails.id}</span>
                    </div>
                  )}
                  {ruleDetails.level !== undefined && (
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                      <span className="detail-key">Rule Severity Level</span>
                      <span style={{ fontSize: '12px', color: '#ffffff', fontFamily: 'var(--font-mono)' }}>{ruleDetails.level}</span>
                    </div>
                  )}
                  {ruleDetails.description && (
                    <div style={{ gridColumn: 'span 2', display: 'flex', flexDirection: 'column', gap: '4px' }}>
                      <span className="detail-key">Rule Description</span>
                      <span style={{ fontSize: '12px', color: '#ffffff' }}>{ruleDetails.description}</span>
                    </div>
                  )}
                  {fullLog && (
                    <div style={{ gridColumn: 'span 2', display: 'flex', flexDirection: 'column', gap: '4px' }}>
                      <span className="detail-key">Process / Command Line Execution</span>
                      <pre className="code-block" style={{ margin: 0, padding: '8px 10px', fontSize: '11px', whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}>
                        <code>{fullLog}</code>
                      </pre>
                    </div>
                  )}
                </div>
              </div>
            </div>
          )}

          {/* Section 4: Analyst Investigation Notes */}
          <div className="panel" style={{ flexShrink: 0, overflow: 'visible', border: '1px solid var(--border-subtle)' }}>
            <div className="panel-header" style={{ padding: '8px 12px' }}>
              <span className="panel-title">
                <FileCode size={13} />
                <span>Analyst Investigation Notes</span>
              </span>
            </div>
            <div className="panel-body" style={{ padding: '14px', overflow: 'visible' }}>
              <textarea
                className="input-ctrl"
                rows={3}
                placeholder="Document containment decisions, quarantine tickets, or triage findings..."
                value={analystNotes}
                onChange={(e) => setAnalystNotes(e.target.value)}
                style={{ width: '100%', resize: 'vertical', fontSize: '12px' }}
              />
            </div>
          </div>

          {/* Section 5: Toggle Raw JSON / Normalized Record */}
          <div className="panel" style={{ flexShrink: 0, overflow: 'visible', border: '1px solid var(--border-subtle)' }}>
            <div className="panel-header" style={{ padding: '8px 12px' }}>
              <span className="panel-title">
                <Terminal size={13} />
                <span>{viewRaw ? 'Raw Ingested SIEM Record' : 'Normalized Event JSON (CIM / ECS)'}</span>
              </span>
              <div style={{ display: 'flex', gap: '8px' }}>
                <button 
                  className="btn btn-secondary btn-xs" 
                  onClick={() => setViewRaw(!viewRaw)}
                >
                  {viewRaw ? 'Show Normalized' : 'Show Raw Record'}
                </button>
                <button 
                  className="btn btn-secondary btn-xs" 
                  onClick={() => handleCopy(
                    viewRaw ? (alert.raw_log || '') : JSON.stringify(alert.details || alert, null, 2),
                    'json'
                  )}
                  title="Copy JSON"
                >
                  {copiedKey === 'json' ? <Check size={11} color="var(--sev-low)" /> : <Copy size={11} />}
                </button>
              </div>
            </div>
            <div className="panel-body" style={{ padding: '12px', overflow: 'visible' }}>
              <pre className="code-block" style={{ maxHeight: '220px', overflowY: 'auto', margin: 0, whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}>
                <code>
                  {viewRaw 
                    ? (alert.raw_log || 'Raw event text not preserved.')
                    : JSON.stringify(alert.details || alert, null, 2)}
                </code>
              </pre>
            </div>
          </div>

        </div>

        {/* Drawer Footer Actions (Fixed at bottom) */}
        <div 
          className="drawer-footer"
          style={{
            flexShrink: 0,
            padding: '14px 20px',
            borderTop: '1px solid var(--border-color)',
            backgroundColor: '#0d0f14',
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center'
          }}
        >
          <button className="btn btn-secondary btn-sm" onClick={onClose}>
            Close
          </button>
          <div style={{ display: 'flex', gap: '8px' }}>
            <button 
              className="btn btn-primary btn-sm"
              onClick={() => {
                if (onInvestigate) onInvestigate(alert);
                onClose();
              }}
              style={{ display: 'inline-flex', alignItems: 'center', gap: '6px' }}
            >
              <Terminal size={13} />
              <span>Investigate in Copilot</span>
            </button>
          </div>
        </div>

      </div>
    </div>
  );
}
