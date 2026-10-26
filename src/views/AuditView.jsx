import React, { useState, useEffect, useMemo } from 'react';
import { Activity, Search, Download, RefreshCw, Copy, Check } from 'lucide-react';

export default function AuditView({ onToast }) {
  const [auditRecords, setAuditRecords] = useState([]);
  const [searchTerm, setSearchTerm] = useState('');
  const [actionFilter, setActionFilter] = useState('all');
  const [copiedId, setCopiedId] = useState(null);

  useEffect(() => {
    loadAudit();
  }, []);

  const loadAudit = async () => {
    try {
      const res = await fetch('/api/audit?limit=100');
      const data = await res.json();
      setAuditRecords(data || []);
    } catch (err) {
      console.error('Failed to load audit records:', err);
    }
  };

  const filteredRecords = useMemo(() => {
    return auditRecords.filter(r => {
      if (actionFilter !== 'all' && !r.action.includes(actionFilter)) return false;
      if (searchTerm) {
        const q = searchTerm.toLowerCase();
        return (
          r.actor.toLowerCase().includes(q) ||
          r.action.toLowerCase().includes(q) ||
          r.target.toLowerCase().includes(q) ||
          (r.evidence || '').toLowerCase().includes(q) ||
          (r.correlation_id || '').toLowerCase().includes(q)
        );
      }
      return true;
    });
  }, [auditRecords, searchTerm, actionFilter]);

  const handleCopy = (text, id) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  const exportAuditJson = () => {
    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(filteredRecords, null, 2));
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute("href", dataStr);
    downloadAnchor.setAttribute("download", `soc_copilot_audit_${new Date().toISOString().slice(0, 10)}.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
    if (onToast) onToast('Exported audit trail JSON');
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
      
      {/* Filtering Toolbar */}
      <div className="panel" style={{ padding: '10px 14px' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '10px' }}>
          
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flexWrap: 'wrap' }}>
            <div style={{ position: 'relative', width: '280px' }}>
              <Search size={14} style={{ position: 'absolute', left: '8px', top: '8px', color: 'var(--text-muted)' }} />
              <input 
                type="text" 
                className="input-ctrl" 
                placeholder="Search actor, action, correlation ID..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                style={{ width: '100%', paddingLeft: '28px' }}
              />
            </div>

            <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
              <span style={{ fontSize: '11px', color: 'var(--text-muted)', fontWeight: '600' }}>Action Category:</span>
              <select className="select-ctrl" value={actionFilter} onChange={(e) => setActionFilter(e.target.value)}>
                <option value="all">All Audit Actions</option>
                <option value="QUERY">Query &amp; Investigation</option>
                <option value="INGESTION">Log Ingestion</option>
                <option value="BENCHMARK">Pipeline Benchmark</option>
                <option value="COPILOT">Copilot Response</option>
              </select>
            </div>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <span className="code-val">{filteredRecords.length} Records</span>
            <button className="btn btn-secondary btn-sm" onClick={exportAuditJson} title="Export audit trail as JSON">
              <Download size={13} />
              <span>Export Audit Trail</span>
            </button>
            <button className="btn btn-secondary btn-xs" onClick={loadAudit} title="Refresh audit log">
              <RefreshCw size={12} />
            </button>
          </div>

        </div>
      </div>

      {/* Audit Log Table */}
      <div className="table-container">
        <table className="data-table">
          <thead>
            <tr>
              <th style={{ width: '135px' }}>Timestamp (UTC)</th>
              <th style={{ width: '140px' }}>Actor / Origin</th>
              <th style={{ width: '180px' }}>Action</th>
              <th>Target Resource</th>
              <th style={{ width: '110px' }}>Outcome</th>
              <th style={{ width: '120px' }}>Correlation ID</th>
            </tr>
          </thead>
          <tbody>
            {filteredRecords.length === 0 ? (
              <tr><td colSpan={6} className="empty-state">No audit records match the current filter.</td></tr>
            ) : (
              filteredRecords.map((r, idx) => (
                <tr key={idx}>
                  <td className="text-mono" style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
                    {r.timestamp ? r.timestamp.slice(0, 19).replace('T', ' ') : '—'}
                  </td>
                  <td>
                    <span className="badge-tech">{r.actor}</span>
                  </td>
                  <td>
                    <strong className="text-mono" style={{ fontSize: '11px', color: 'var(--text-primary)' }}>{r.action}</strong>
                    {r.evidence && (
                      <div style={{ fontSize: '10px', color: 'var(--text-muted)', marginTop: '2px', maxWidth: '300px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                        {r.evidence}
                      </div>
                    )}
                  </td>
                  <td>
                    <span className="code-val">{r.target}</span>
                  </td>
                  <td>
                    <span className={`badge-sev ${r.outcome === 'SUCCESS' || r.outcome === 'NORMALIZED' ? 'low' : 'info'}`}>
                      {r.outcome}
                    </span>
                  </td>
                  <td>
                    <span className="code-val" style={{ fontSize: '10px' }}>
                      {r.correlation_id ? r.correlation_id.slice(0, 12) : '—'}
                      <button 
                        className="copy-btn" 
                        onClick={() => handleCopy(r.correlation_id, r.id)}
                        title="Copy correlation ID"
                      >
                        {copiedId === r.id ? <Check size={10} color="var(--sev-low)" /> : <Copy size={10} />}
                      </button>
                    </span>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

    </div>
  );
}
