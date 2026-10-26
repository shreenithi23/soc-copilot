import React, { useState, useEffect } from 'react';
import { X, CheckCircle2, AlertTriangle, AlertOctagon, RefreshCw, BarChart2, ShieldCheck, Layers } from 'lucide-react';

export default function MappingCoverageModal({ isOpen, onClose, onRefreshData, onNotify }) {
  const [coverage, setCoverage] = useState(null);
  const [loading, setLoading] = useState(false);
  const [reprocessing, setReprocessing] = useState(false);

  useEffect(() => {
    if (isOpen) {
      fetchCoverage();
    }
  }, [isOpen]);

  const fetchCoverage = async () => {
    setLoading(true);
    try {
      const res = await fetch('/api/logs/coverage');
      const data = await res.json();
      setCoverage(data);
    } catch (err) {
      if (onNotify) onNotify(`Failed to fetch coverage: ${err.message}`, 'error');
    } finally {
      setLoading(false);
    }
  };

  const handleReprocess = async () => {
    setReprocessing(true);
    try {
      const res = await fetch('/api/logs/reprocess', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ source: 'all' })
      });
      const data = await res.json();
      if (onNotify) onNotify(`Reprocessed ${data.reprocessed_count} logs using schema v2.0.0`, 'success');
      await fetchCoverage();
      if (onRefreshData) onRefreshData();
    } catch (err) {
      if (onNotify) onNotify(`Reprocessing failed: ${err.message}`, 'error');
    } finally {
      setReprocessing(false);
    }
  };

  if (!isOpen) return null;

  const total = coverage?.total_events || 0;
  const statusCounts = coverage?.overall_status || { success: 0, partial: 0, failed: 0 };
  const sources = coverage?.sources || {};
  const canonicalFields = coverage?.canonical_field_coverage || {};
  const topUnmapped = coverage?.top_unmapped_fields || [];
  const conflictsCount = coverage?.conflicts_count || 0;

  return (
    <div className="modal-overlay" onClick={onClose} role="dialog" aria-modal="true">
      <div className="modal-dialog" onClick={(e) => e.stopPropagation()} style={{ maxWidth: '820px', width: '95vw', maxHeight: '90vh', display: 'flex', flexDirection: 'column' }}>
        
        {/* Header */}
        <div className="modal-header">
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <BarChart2 size={16} color="#38bdf8" />
            <span style={{ fontSize: '14px', fontWeight: '700' }}>SIEM Field-Mapping Coverage & Normalization Diagnostics</span>
            <span className="badge-tech" style={{ fontSize: '10px' }}>v2.0.0 Canonical ECS</span>
          </div>
          <button className="btn btn-secondary btn-xs" onClick={onClose}>
            <X size={14} />
          </button>
        </div>

        {/* Body */}
        <div className="modal-body" style={{ overflowY: 'auto', flex: 1, padding: '16px', display: 'flex', flexDirection: 'column', gap: '16px' }}>
          
          {loading && !coverage ? (
            <div style={{ textAlign: 'center', padding: '30px', color: 'var(--text-muted)' }}>
              <RefreshCw size={24} className="spin" style={{ margin: '0 auto 10px auto' }} />
              <p>Analyzing canonical mapping telemetry...</p>
            </div>
          ) : (
            <>
              {/* Summary Metric Cards */}
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(130px, 1fr))', gap: '10px' }}>
                <div className="panel" style={{ padding: '12px', borderLeft: '3px solid #38bdf8' }}>
                  <div style={{ fontSize: '11px', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: '600' }}>Total Events</div>
                  <div style={{ fontSize: '20px', fontWeight: '800', color: 'var(--text-primary)', marginTop: '4px' }}>{total}</div>
                </div>

                <div className="panel" style={{ padding: '12px', borderLeft: '3px solid #34d399' }}>
                  <div style={{ fontSize: '11px', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: '600' }}>Successful</div>
                  <div style={{ fontSize: '20px', fontWeight: '800', color: '#34d399', marginTop: '4px' }}>{statusCounts.success}</div>
                </div>

                <div className="panel" style={{ padding: '12px', borderLeft: '3px solid #fbbf24' }}>
                  <div style={{ fontSize: '11px', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: '600' }}>Partial</div>
                  <div style={{ fontSize: '20px', fontWeight: '800', color: '#fbbf24', marginTop: '4px' }}>{statusCounts.partial}</div>
                </div>

                <div className="panel" style={{ padding: '12px', borderLeft: '3px solid #fb7185' }}>
                  <div style={{ fontSize: '11px', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: '600' }}>Failed</div>
                  <div style={{ fontSize: '20px', fontWeight: '800', color: '#fb7185', marginTop: '4px' }}>{statusCounts.failed}</div>
                </div>

                <div className="panel" style={{ padding: '12px', borderLeft: '3px solid #c084fc' }}>
                  <div style={{ fontSize: '11px', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: '600' }}>Conflicting Aliases</div>
                  <div style={{ fontSize: '20px', fontWeight: '800', color: '#c084fc', marginTop: '4px' }}>{conflictsCount}</div>
                </div>
              </div>

              {/* Data Source Breakdown */}
              <div className="panel" style={{ padding: '14px' }}>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '10px' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                    <Layers size={14} color="#38bdf8" />
                    <span style={{ fontSize: '12px', fontWeight: '700', color: 'var(--text-primary)' }}>Normalization Status by SIEM Vendor</span>
                  </div>
                </div>

                <table className="data-table">
                  <thead>
                    <tr>
                      <th>SIEM Connector</th>
                      <th>Total Ingested</th>
                      <th>Success</th>
                      <th>Partial</th>
                      <th>Failed</th>
                      <th>Health</th>
                    </tr>
                  </thead>
                  <tbody>
                    {Object.keys(sources).length === 0 ? (
                      <tr><td colSpan={6} style={{ textAlign: 'center', color: 'var(--text-muted)' }}>No logs ingested yet</td></tr>
                    ) : (
                      Object.entries(sources).map(([src, d]) => {
                        const rate = d.total > 0 ? Math.round(((d.success + d.partial) / d.total) * 100) : 0;
                        return (
                          <tr key={src}>
                            <td><strong style={{ color: '#ffffff' }}>{src}</strong></td>
                            <td className="text-mono">{d.total}</td>
                            <td><span style={{ color: '#34d399', fontWeight: '700' }}>{d.success}</span></td>
                            <td><span style={{ color: '#fbbf24', fontWeight: '700' }}>{d.partial}</span></td>
                            <td><span style={{ color: d.failed > 0 ? '#fb7185' : 'var(--text-muted)', fontWeight: '700' }}>{d.failed}</span></td>
                            <td>
                              <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                                <div style={{ width: '60px', height: '6px', background: 'rgba(255,255,255,0.1)', borderRadius: '3px', overflow: 'hidden' }}>
                                  <div style={{ width: `${rate}%`, height: '100%', background: rate >= 90 ? '#34d399' : rate >= 70 ? '#fbbf24' : '#fb7185' }} />
                                </div>
                                <span style={{ fontSize: '11px', fontWeight: '600', color: 'var(--text-secondary)' }}>{rate}%</span>
                              </div>
                            </td>
                          </tr>
                        );
                      })
                    )}
                  </tbody>
                </table>
              </div>

              {/* Canonical Field Coverage & Unmapped Grid */}
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '14px' }}>
                
                {/* Canonical Fields */}
                <div className="panel" style={{ padding: '14px' }}>
                  <div style={{ fontSize: '12px', fontWeight: '700', marginBottom: '10px', color: 'var(--text-primary)' }}>
                    Canonical Field Mapping Coverage
                  </div>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', maxHeight: '220px', overflowY: 'auto' }}>
                    {Object.entries(canonicalFields).map(([fName, val]) => (
                      <div key={fName} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: '11px' }}>
                        <span className="code-val" style={{ width: '100px' }}>{fName}</span>
                        <div style={{ flex: 1, margin: '0 10px', height: '6px', background: 'rgba(255,255,255,0.08)', borderRadius: '3px', overflow: 'hidden' }}>
                          <div style={{ width: `${val.percentage}%`, height: '100%', background: '#38bdf8' }} />
                        </div>
                        <span style={{ width: '65px', textAlign: 'right', color: 'var(--text-secondary)', fontWeight: '600' }}>
                          {val.percentage}% ({val.count})
                        </span>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Top Unmapped Fields */}
                <div className="panel" style={{ padding: '14px' }}>
                  <div style={{ fontSize: '12px', fontWeight: '700', marginBottom: '10px', color: 'var(--text-primary)' }}>
                    Top Unmapped Vendor Fields
                  </div>
                  {topUnmapped.length === 0 ? (
                    <div style={{ color: 'var(--text-muted)', fontSize: '12px', textAlign: 'center', padding: '20px' }}>
                      All ingested vendor attributes cleanly mapped to canonical schema.
                    </div>
                  ) : (
                    <table className="data-table" style={{ fontSize: '11px' }}>
                      <thead>
                        <tr>
                          <th>Raw Key Name</th>
                          <th style={{ textAlign: 'right' }}>Occurrences</th>
                        </tr>
                      </thead>
                      <tbody>
                        {topUnmapped.map((u) => (
                          <tr key={u.field}>
                            <td><span className="code-val" style={{ color: '#f59e0b' }}>{u.field}</span></td>
                            <td style={{ textAlign: 'right', fontWeight: '700' }}>{u.count}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  )}
                </div>

              </div>
            </>
          )}

        </div>

        {/* Footer */}
        <div className="modal-footer" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <button 
            className="btn btn-secondary btn-sm" 
            onClick={handleReprocess} 
            disabled={reprocessing}
            title="Re-run canonical mapping rules over existing stored events"
          >
            <RefreshCw size={12} className={reprocessing ? "spin" : ""} />
            <span>{reprocessing ? "Reprocessing Events..." : "Reprocess All Stored Events"}</span>
          </button>
          
          <button className="btn btn-primary btn-sm" onClick={onClose}>
            Close
          </button>
        </div>

      </div>
    </div>
  );
}
