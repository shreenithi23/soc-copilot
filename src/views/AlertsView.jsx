import React, { useState, useMemo } from 'react';
import { 
  Search, 
  Upload, 
  RefreshCw, 
  BarChart2, 
  Trash2, 
  Database, 
  ShieldAlert, 
  ArrowUpDown, 
  Code2, 
  Eye, 
  CheckCircle2, 
  AlertTriangle, 
  AlertOctagon 
} from 'lucide-react';

export default function AlertsView({ 
  alerts, 
  onSelectAlert, 
  onInspectLog, 
  onOpenIngest, 
  onOpenCoverage, 
  onClearAllLogs, 
  onPurgeRawLogs, 
  onRefresh 
}) {
  const [searchTerm, setSearchTerm] = useState('');
  const [severityFilter, setSeverityFilter] = useState('all');
  const [sourceFilter, setSourceFilter] = useState('all');
  const [statusFilter, setStatusFilter] = useState('all');
  const [sortField, setSortField] = useState('timestamp');
  const [sortAsc, setSortAsc] = useState(false);

  // Severity ranking for sorting
  const severityRank = {
    'CRITICAL': 5,
    'HIGH': 4,
    'MEDIUM': 3,
    'LOW': 2,
    'INFORMATIONAL': 1
  };

  // Filter and sort alerts
  const filteredAlerts = useMemo(() => {
    return (alerts || []).filter(a => {
      if (severityFilter !== 'all' && (a.severity || '').toUpperCase() !== severityFilter) {
        return false;
      }
      if (sourceFilter !== 'all' && a.siem_source !== sourceFilter) {
        return false;
      }
      if (statusFilter !== 'all' && (a.normalization_status || 'success').toLowerCase() !== statusFilter.toLowerCase()) {
        return false;
      }
      if (searchTerm) {
        const q = searchTerm.toLowerCase();
        return (
          (a.alert_name || '').toLowerCase().includes(q) ||
          (a.user || '').toLowerCase().includes(q) ||
          (a.src_ip || '').toLowerCase().includes(q) ||
          (a.dest_ip || '').toLowerCase().includes(q) ||
          (a.src_host || '').toLowerCase().includes(q) ||
          (a.dest_host || '').toLowerCase().includes(q) ||
          (a.domain || '').toLowerCase().includes(q) ||
          (a.file_hash || '').toLowerCase().includes(q) ||
          (a.raw_log || '').toLowerCase().includes(q)
        );
      }
      return true;
    }).sort((a, b) => {
      if (sortField === 'severity') {
        const ra = severityRank[(a.severity || '').toUpperCase()] || 0;
        const rb = severityRank[(b.severity || '').toUpperCase()] || 0;
        return sortAsc ? ra - rb : rb - ra;
      }
      let va = a[sortField] || '';
      let vb = b[sortField] || '';
      if (va < vb) return sortAsc ? -1 : 1;
      if (va > vb) return sortAsc ? 1 : -1;
      return 0;
    });
  }, [alerts, searchTerm, severityFilter, sourceFilter, statusFilter, sortField, sortAsc]);

  const handleSort = (field) => {
    if (sortField === field) {
      setSortAsc(!sortAsc);
    } else {
      setSortField(field);
      setSortAsc(false);
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
      
      {/* Comprehensive Filtering & Ingestion Toolbar */}
      <div className="panel" style={{ padding: '10px 14px' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '10px' }}>
          
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flexWrap: 'wrap' }}>
            <div style={{ position: 'relative', width: '250px' }}>
              <Search size={14} style={{ position: 'absolute', left: '8px', top: '8px', color: 'var(--text-muted)' }} />
              <input 
                type="text" 
                className="input-ctrl" 
                placeholder="Search alerts, IPs, hosts, hashes, raw logs..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                style={{ width: '100%', paddingLeft: '28px' }}
              />
            </div>

            <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
              <span style={{ fontSize: '11px', color: 'var(--text-muted)', fontWeight: '600' }}>SIEM:</span>
              <select 
                className="select-ctrl" 
                value={sourceFilter} 
                onChange={(e) => setSourceFilter(e.target.value)}
              >
                <option value="all">All SIEM Tools</option>
                <option value="Splunk">Splunk (CIM/KV)</option>
                <option value="Elastic">Elastic (ECS)</option>
                <option value="Sentinel">Microsoft Sentinel</option>
                <option value="QRadar">IBM QRadar (LEEF)</option>
                <option value="Wazuh">Wazuh (OSSEC)</option>
                <option value="CSV Ingestion">CSV Ingestion</option>
              </select>
            </div>

            <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
              <span style={{ fontSize: '11px', color: 'var(--text-muted)', fontWeight: '600' }}>Severity:</span>
              <select 
                className="select-ctrl" 
                value={severityFilter} 
                onChange={(e) => setSeverityFilter(e.target.value)}
              >
                <option value="all">All Severities</option>
                <option value="CRITICAL">Critical</option>
                <option value="HIGH">High</option>
                <option value="MEDIUM">Medium</option>
                <option value="LOW">Low</option>
                <option value="INFORMATIONAL">Informational</option>
              </select>
            </div>

            <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
              <span style={{ fontSize: '11px', color: 'var(--text-muted)', fontWeight: '600' }}>Status:</span>
              <select 
                className="select-ctrl" 
                value={statusFilter} 
                onChange={(e) => setStatusFilter(e.target.value)}
              >
                <option value="all">All Statuses</option>
                <option value="success">Success</option>
                <option value="partial">Partial</option>
                <option value="failed">Failed</option>
              </select>
            </div>
          </div>

          {/* Action Toolset: Ingestion, Coverage, and Reset */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
            {onPurgeRawLogs && (
              <button 
                className="btn btn-secondary btn-sm" 
                onClick={onPurgeRawLogs}
                title="Purge raw log strings from existing database records (preserves all analysis details)"
              >
                <ShieldAlert size={13} />
                <span>Purge Raw Logs</span>
              </button>
            )}

            {onClearAllLogs && (
              <button 
                className="btn btn-danger btn-sm" 
                onClick={onClearAllLogs}
                title="Reset all log files across all functionalities"
              >
                <Trash2 size={13} />
                <span>Reset All Logs</span>
              </button>
            )}

            {onOpenCoverage && (
              <button 
                className="btn btn-secondary btn-sm" 
                onClick={onOpenCoverage}
                title="Inspect canonical field-mapping coverage & health"
              >
                <BarChart2 size={13} color="#38bdf8" />
                <span>Coverage</span>
              </button>
            )}

            {onOpenIngest && (
              <button className="btn btn-primary btn-sm" onClick={onOpenIngest}>
                <Upload size={13} />
                <span>Ingest Telemetry</span>
              </button>
            )}

            <button className="btn btn-secondary btn-xs" onClick={onRefresh} title="Refresh alert table">
              <RefreshCw size={12} />
            </button>
          </div>

        </div>
      </div>

      {/* Unified Alert & Telemetry Table */}
      <div className="table-container">
        <table className="data-table">
          <thead>
            <tr>
              <th style={{ width: '85px' }}>SIEM</th>
              <th style={{ width: '90px' }} onClick={() => handleSort('severity')} className="clickable">
                <span style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
                  Severity <ArrowUpDown size={11} />
                </span>
              </th>
              <th style={{ width: '85px' }} onClick={() => handleSort('normalization_status')} className="clickable">
                <span style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
                  Status <ArrowUpDown size={11} />
                </span>
              </th>
              <th style={{ width: '135px' }} onClick={() => handleSort('timestamp')} className="clickable">
                <span style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
                  Timestamp <ArrowUpDown size={11} />
                </span>
              </th>
              <th onClick={() => handleSort('alert_name')} className="clickable">
                <span style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
                  Detection Signature / Alert Name <ArrowUpDown size={11} />
                </span>
              </th>
              <th>Source &rarr; Destination</th>
              <th style={{ width: '130px' }}>Target Identity</th>
              <th style={{ width: '120px', textAlign: 'center' }}>Actions</th>
            </tr>
          </thead>
          <tbody>
            {filteredAlerts.length === 0 ? (
              <tr>
                <td colSpan={8} className="empty-state">
                  No detection alerts match the current filter criteria.
                </td>
              </tr>
            ) : (
              filteredAlerts.map((a) => {
                const normStatus = (a.normalization_status || 'success').toLowerCase();
                return (
                  <tr key={a.id} className="clickable" onClick={() => onSelectAlert && onSelectAlert(a)}>
                    <td>
                      <span className="badge-tech">{a.siem_source}</span>
                    </td>
                    <td>
                      <span className={`badge-sev ${(a.severity || 'low').toLowerCase()}`}>
                        {a.severity}
                      </span>
                    </td>
                    <td>
                      <span className={`badge-norm-${normStatus}`}>
                        {normStatus.toUpperCase()}
                      </span>
                    </td>
                    <td className="text-mono" style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
                      {a.timestamp ? a.timestamp.slice(0, 19).replace('T', ' ') : '—'}
                    </td>
                    <td>
                      <strong style={{ color: 'var(--text-primary)', fontSize: '12px' }}>{a.alert_name}</strong>
                    </td>
                    <td>
                      <span className="code-val">{a.src_host || a.src_ip || '—'}</span>
                      <span style={{ color: 'var(--text-muted)', margin: '0 4px' }}>&rarr;</span>
                      <span className="code-val">{a.dest_host || a.dest_ip || '—'}</span>
                    </td>
                    <td>
                      <span className="code-val" style={{ color: '#38bdf8' }}>{a.user || '—'}</span>
                    </td>
                    <td style={{ textAlign: 'center' }} onClick={(e) => e.stopPropagation()}>
                      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '6px' }}>
                        <button 
                          className="btn btn-secondary btn-xs"
                          onClick={() => onSelectAlert && onSelectAlert(a)}
                          title="Triage alert, view MITRE tactics & escalate to AI Threat Hunting"
                        >
                          <Eye size={11} />
                          <span>Triage</span>
                        </button>
                        {onInspectLog && (
                          <button 
                            className="btn btn-secondary btn-xs"
                            onClick={() => onInspectLog(a)}
                            title="Inspect canonical schema mapping, unmapped fields & diagnostics"
                          >
                            <Code2 size={11} />
                            <span>Schema</span>
                          </button>
                        )}
                      </div>
                    </td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>

    </div>
  );
}
