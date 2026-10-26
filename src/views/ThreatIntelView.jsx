import React, { useState, useEffect } from 'react';
import { Shield, Search, ExternalLink, Check, Copy, AlertTriangle, Trash2 } from 'lucide-react';

export default function ThreatIntelView({ onToast, resetKey }) {
  const [indicatorInput, setIndicatorInput] = useState('185.220.101.5');
  const [activeResult, setActiveResult] = useState(null);
  const [cachedIntel, setCachedIntel] = useState([]);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    loadCachedIntel();
  }, [resetKey]);

  const loadCachedIntel = async () => {
    try {
      const res = await fetch('/api/threat-intel/cached');
      const data = await res.json();
      setCachedIntel(data || []);
      if (data && data.length > 0) {
        if (!activeResult) setActiveResult(data[0]);
      } else {
        setActiveResult(null);
      }
    } catch (err) {
      console.error('Failed to load cached intel:', err);
    }
  };

  const handleClearCache = async () => {
    try {
      const res = await fetch('/api/threat-intel/clear', { method: 'POST' });
      const data = await res.json();
      setCachedIntel([]);
      setActiveResult(null);
      if (onToast) onToast(data.message || 'Reset all VirusTotal v3 cached threat intelligence indicators');
    } catch (err) {
      if (onToast) onToast(`Failed to reset intel cache: ${err.message}`, 'error');
    }
  };

  const handleScan = async (queryVal) => {
    const val = (queryVal || indicatorInput).trim();
    if (!val || loading) return;

    setLoading(true);
    try {
      const res = await fetch('/api/threat-intel/lookup', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ indicator: val })
      });
      const data = await res.json();
      setActiveResult(data);
      loadCachedIntel();
      if (onToast) onToast(`VirusTotal inspection complete for ${val}`);
    } catch (err) {
      if (onToast) onToast(`Lookup failed: ${err.message}`, 'error');
    } finally {
      setLoading(false);
    }
  };

  const totalEngines = activeResult ? 
    (activeResult.malicious_count || 0) + (activeResult.suspicious_count || 0) + (activeResult.harmless_count || 0) + (activeResult.undetected_count || 0) || 72
    : 72;
  const isMalicious = activeResult && (activeResult.malicious_count || 0) > 0;

  return (
    <div style={{ display: 'grid', gridTemplateColumns: '360px 1fr', gap: '16px' }}>
      
      {/* Left: IOC Scanner & Active Inspection */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
        
        <div className="panel">
          <div className="panel-header">
            <span className="panel-title">
              <Shield size={14} />
              <span>VirusTotal IOC Inspection</span>
            </span>
          </div>
          <div className="panel-body" style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
            <p style={{ fontSize: '11px', color: 'var(--text-secondary)', lineHeight: '1.4' }}>
              Query any IPv4, FQDN domain, or SHA256/MD5 payload hash against VirusTotal v3. Automatic local cache fallback when offline.
            </p>

            <div style={{ display: 'flex', gap: '6px' }}>
              <input 
                type="text"
                className="input-ctrl" 
                placeholder="e.g. 185.220.101.5 or update-microsoft-cloud.top"
                value={indicatorInput}
                onChange={(e) => setIndicatorInput(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === 'Enter') handleScan();
                }}
                style={{ flex: 1, fontFamily: 'var(--font-mono)' }}
              />
              <button className="btn btn-primary btn-sm" onClick={() => handleScan()} disabled={loading}>
                <Search size={13} />
                <span>{loading ? 'Scanning...' : 'Analyze'}</span>
              </button>
            </div>
          </div>
        </div>

        {/* Detailed Inspection Readout */}
        {activeResult && (
          <div className="panel">
            <div className="panel-header">
              <span className="panel-title" style={{ fontSize: '11px' }}>
                <span>Reputation Consensus</span>
              </span>
              <span className="badge-tech">{(activeResult.ioc_type || 'IOC').toUpperCase()}</span>
            </div>
            <div className="panel-body" style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
              
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '1px solid var(--border-subtle)', paddingBottom: '8px' }}>
                <span className="code-val" style={{ fontSize: '12px', fontWeight: '700' }}>{activeResult.indicator}</span>
                <span className={`badge-sev ${isMalicious ? 'critical' : 'low'}`}>
                  {isMalicious ? `${activeResult.malicious_count}/${totalEngines} FLAGGED` : 'CLEAN'}
                </span>
              </div>

              <div className="detail-grid" style={{ fontSize: '11px' }}>
                <div className="detail-item">
                  <span className="detail-key">Malicious Score</span>
                  <span className={`detail-val text-mono ${isMalicious ? 'text-danger' : 'text-success'}`} style={{ fontWeight: '700' }}>
                    {activeResult.malicious_count || 0} / {totalEngines}
                  </span>
                </div>
                <div className="detail-item">
                  <span className="detail-key">Reputation Value</span>
                  <span className="detail-val text-mono" style={{ fontWeight: '600' }}>
                    {activeResult.reputation || 0}
                  </span>
                </div>
                <div className="detail-item" style={{ gridColumn: 'span 2' }}>
                  <span className="detail-key">Threat Source</span>
                  <span className="detail-val text-mono" style={{ fontSize: '10px' }}>
                    {activeResult.source || 'VirusTotal v3 Intelligence Model'}
                  </span>
                </div>
              </div>

              {/* Threat Tags */}
              <div>
                <span className="detail-key" style={{ display: 'block', marginBottom: '4px' }}>Threat Classification Tags</span>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: '4px' }}>
                  {(activeResult.tags || []).length === 0 ? (
                    <span style={{ fontSize: '11px', color: 'var(--text-muted)' }}>None assigned</span>
                  ) : (
                    (activeResult.tags || []).map((t, idx) => (
                      <span key={idx} className="badge-sev high" style={{ fontSize: '9px' }}>{t}</span>
                    ))
                  )}
                </div>
              </div>

              {/* Vendor Engine Detections */}
              <div>
                <span className="detail-key" style={{ display: 'block', marginBottom: '4px' }}>Engine Detections</span>
                <div style={{ maxHeight: '140px', overflowY: 'auto', background: '#0b0f15', border: '1px solid var(--border-subtle)', borderRadius: '4px', padding: '6px' }}>
                  {Object.entries(activeResult.engine_details || {}).length === 0 ? (
                    <span style={{ fontSize: '10px', color: 'var(--text-muted)' }}>Zero security vendor detections flagged.</span>
                  ) : (
                    Object.entries(activeResult.engine_details || {}).map(([eng, det], i) => (
                      <div key={i} style={{ display: 'flex', justifyContent: 'space-between', fontSize: '10px', padding: '2px 0', borderBottom: '1px solid #141923' }}>
                        <span style={{ color: 'var(--text-primary)', fontWeight: '600', fontFamily: 'var(--font-mono)' }}>{eng}</span>
                        <span style={{ color: 'var(--sev-critical)' }}>{det}</span>
                      </div>
                    ))
                  )}
                </div>
              </div>

            </div>
          </div>
        )}

      </div>

      {/* Right: Local Threat Intel Registry (SQLite Cache) */}
      <div className="panel" style={{ height: 'calc(100vh - 84px)', display: 'flex', flexDirection: 'column' }}>
        <div className="panel-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <span className="panel-title">
            <Shield size={14} />
            <span>Threat Intelligence Registry (Cached Indicators: {cachedIntel.length})</span>
          </span>
          <button 
            className="btn btn-danger btn-xs" 
            onClick={handleClearCache}
            title="Reset all cached VirusTotal threat intelligence indicators"
          >
            <Trash2 size={11} />
            <span>Reset Intel Cache</span>
          </button>
        </div>
        <div className="table-container" style={{ border: 'none', borderRadius: '0', flex: 1, overflowY: 'auto' }}>
          <table className="data-table">
            <thead>
              <tr>
                <th style={{ width: '70px' }}>Type</th>
                <th>Indicator (IP / Domain / Hash)</th>
                <th style={{ width: '130px' }}>VT Verdict</th>
                <th style={{ width: '80px' }}>Reputation</th>
                <th>Threat Tags</th>
                <th style={{ width: '75px', textAlign: 'center' }}>Action</th>
              </tr>
            </thead>
            <tbody>
              {cachedIntel.length === 0 ? (
                <tr><td colSpan={6} className="empty-state">No threat indicators cached yet. Scan an indicator on the left.</td></tr>
              ) : (
                cachedIntel.map((item, idx) => {
                  const mal = item.malicious_count > 0;
                  return (
                    <tr key={idx} className="clickable" onClick={() => setActiveResult(item)}>
                      <td>
                        <span className="badge-tech">{item.ioc_type}</span>
                      </td>
                      <td>
                        <strong className="text-mono" style={{ color: 'var(--text-primary)', fontSize: '11px' }}>
                          {item.indicator}
                        </strong>
                      </td>
                      <td>
                        <span className={`badge-sev ${mal ? 'critical' : 'low'}`}>
                          {mal ? `VT: ${item.malicious_count} Engines` : 'CLEAN'}
                        </span>
                      </td>
                      <td className="text-mono" style={{ fontSize: '11px' }}>
                        {item.reputation}
                      </td>
                      <td>
                        <div style={{ display: 'flex', gap: '3px', flexWrap: 'wrap' }}>
                          {(item.tags || []).slice(0, 3).map((t, ti) => (
                            <span key={ti} className="badge-sev medium" style={{ fontSize: '8px', padding: '1px 3px' }}>
                              {t}
                            </span>
                          ))}
                        </div>
                      </td>
                      <td style={{ textAlign: 'center' }}>
                        <button 
                          className="btn btn-secondary btn-xs"
                          onClick={(e) => {
                            e.stopPropagation();
                            setActiveResult(item);
                          }}
                        >
                          Inspect
                        </button>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>

    </div>
  );
}
