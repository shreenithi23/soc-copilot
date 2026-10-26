import React, { useState, useEffect } from 'react';
import { 
  Play, 
  ShieldCheck, 
  CheckCircle2, 
  AlertCircle, 
  ExternalLink, 
  RefreshCw, 
  Database, 
  Cpu, 
  Activity, 
  Clock, 
  Check, 
  X,
  History,
  ChevronDown,
  ChevronRight,
  Sparkles
} from 'lucide-react';

export default function SettingsView({ onToast }) {
  const [evalResult, setEvalResult] = useState(null);
  const [historyRuns, setHistoryRuns] = useState([]);
  const [evalRunning, setEvalRunning] = useState(false);
  const [syncCloud, setSyncCloud] = useState(true);
  const [expandedCase, setExpandedCase] = useState(null);

  useEffect(() => {
    loadEvalData();
  }, []);

  const loadEvalData = async () => {
    try {
      const res = await fetch('/api/eval/history?limit=10');
      const data = await res.json();
      if (Array.isArray(data) && data.length > 0) {
        setHistoryRuns(data);
        setEvalResult(data[0]);
      }
    } catch (err) {
      console.error('Failed to load eval history:', err);
    }
  };

  const handleRunEvaluation = async () => {
    setEvalRunning(true);
    try {
      const res = await fetch(`/api/eval/run?sync_remote=${syncCloud}`, { method: 'POST' });
      const data = await res.json();
      setEvalResult(data);
      if (onToast) {
        const msg = data.sync_status === 'SYNCED'
          ? `LangSmith Benchmark completed: ${data.accuracy_score}% Accuracy (Cloud Synced)`
          : `Benchmark completed: ${data.accuracy_score}% Accuracy (${data.sync_status})`;
        onToast(msg);
      }
      // Refresh history list
      loadEvalData();
    } catch (err) {
      if (onToast) onToast(`Benchmark execution failed: ${err.message}`, 'error');
    } finally {
      setEvalRunning(false);
    }
  };

  const categories = [
    { key: 'threat_intel', label: 'Threat Intelligence', icon: Activity, desc: 'IOC Extraction & VirusTotal Engine Consensus' },
    { key: 'siem_parsing', label: 'SIEM Parsing Fidelity', icon: Database, desc: 'Splunk, Elastic, Sentinel, Wazuh & QRadar LEEF' },
    { key: 'memory', label: 'Conversational Memory', icon: Cpu, desc: 'Multi-turn Recall & Session Isolation' },
  ];

  const getSyncBadge = (status, experimentUrl) => {
    switch (status) {
      case 'SYNCED':
        return (
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <span className="badge-sev low" style={{ display: 'inline-flex', alignItems: 'center', gap: '4px' }}>
              <Check size={11} /> Cloud Synced
            </span>
            {experimentUrl && (
              <a 
                href={experimentUrl} 
                target="_blank" 
                rel="noreferrer" 
                className="btn btn-secondary btn-sm"
                style={{ fontSize: '11px', padding: '2px 8px', height: '22px', display: 'inline-flex', alignItems: 'center', gap: '4px', textDecoration: 'none' }}
              >
                <span>View Experiment</span>
                <ExternalLink size={10} />
              </a>
            )}
          </div>
        );
      case 'FAILED':
        return (
          <span className="badge-sev critical" style={{ display: 'inline-flex', alignItems: 'center', gap: '4px' }}>
            <X size={11} /> Sync Failed (Local Preserved)
          </span>
        );
      default:
        return (
          <span className="badge-sev medium" style={{ display: 'inline-flex', alignItems: 'center', gap: '4px' }}>
            <AlertCircle size={11} /> Local Benchmark Mode
          </span>
        );
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '20px', width: '100%', maxWidth: '1400px', margin: '0 auto' }}>
      
      {/* LangSmith Pipeline Evaluation & Benchmarking Panel */}
      <div className="panel" style={{ display: 'flex', flexDirection: 'column' }}>

        <div className="panel-body" style={{ padding: '20px', display: 'flex', flexDirection: 'column', gap: '20px' }}>
          
          {/* Cloud Synchronization Status Banner */}
          {evalResult && (
            <div style={{
              padding: '12px 16px',
              borderRadius: '8px',
              background: evalResult.sync_status === 'SYNCED' 
                ? 'rgba(16, 185, 129, 0.08)' 
                : evalResult.sync_status === 'FAILED'
                ? 'rgba(239, 68, 68, 0.08)'
                : 'rgba(245, 158, 11, 0.08)',
              border: `1px solid ${
                evalResult.sync_status === 'SYNCED' 
                  ? 'rgba(16, 185, 129, 0.25)' 
                  : evalResult.sync_status === 'FAILED'
                  ? 'rgba(239, 68, 68, 0.25)'
                  : 'rgba(245, 158, 11, 0.25)'
              }`,
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between'
            }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                {evalResult.sync_status === 'SYNCED' ? (
                  <CheckCircle2 size={16} style={{ color: '#10b981' }} />
                ) : evalResult.sync_status === 'FAILED' ? (
                  <AlertCircle size={16} style={{ color: '#ef4444' }} />
                ) : (
                  <ShieldCheck size={16} style={{ color: '#f59e0b' }} />
                )}
                <div>
                  <div style={{ fontSize: '13px', fontWeight: '600', color: '#ffffff' }}>
                    {evalResult.sync_status === 'SYNCED' && 'Authentic LangSmith Experiment Executed & Recorded'}
                    {evalResult.sync_status === 'NOT_CONFIGURED' && 'Local Evaluation Benchmark Mode Active'}
                    {evalResult.sync_status === 'FAILED' && 'LangSmith Cloud Synchronization Failed — Local SQLite Preserved'}
                  </div>
                  <div style={{ fontSize: '11.5px', color: 'var(--text-secondary)', marginTop: '2px' }}>
                    {evalResult.sync_status === 'SYNCED' && (
                      <span>Experiment: <code style={{ color: '#38bdf8' }}>{evalResult.experiment_name}</code> recorded on LangSmith SaaS cloud.</span>
                    )}
                    {evalResult.sync_status === 'NOT_CONFIGURED' && (
                      <span>Provide LANGCHAIN_API_KEY in .env to publish experiment metrics to remote LangSmith dashboard.</span>
                    )}
                    {evalResult.sync_status === 'FAILED' && (
                      <span>{evalResult.error_details || 'Remote API error occurred. Local verification results remain intact.'}</span>
                    )}
                  </div>
                </div>
              </div>

              {evalResult.experiment_url && (
                <a 
                  href={evalResult.experiment_url} 
                  target="_blank" 
                  rel="noreferrer" 
                  className="btn btn-primary btn-sm"
                  style={{ display: 'inline-flex', alignItems: 'center', gap: '6px', textDecoration: 'none' }}
                >
                  <span>Open in LangSmith</span>
                  <ExternalLink size={12} />
                </a>
              )}
            </div>
          )}

          {/* 4 Primary Metric Summary Cards */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '14px' }}>
            <div className="panel" style={{ padding: '14px 16px', background: '#0a0d12', border: '1px solid var(--border-subtle)' }}>
              <div style={{ fontSize: '11px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                Pipeline Accuracy
              </div>
              <div style={{ fontSize: '28px', fontWeight: '800', color: '#38bdf8', fontFamily: 'var(--font-mono)', marginTop: '6px' }}>
                {evalResult?.accuracy_score !== undefined ? `${evalResult.accuracy_score}%` : '—'}
              </div>
              <div style={{ fontSize: '11px', color: 'var(--text-secondary)', marginTop: '4px' }}>
                Target evaluation score
              </div>
            </div>

            <div className="panel" style={{ padding: '14px 16px', background: '#0a0d12', border: '1px solid var(--border-subtle)' }}>
              <div style={{ fontSize: '11px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                Verified Test Cases
              </div>
              <div style={{ fontSize: '28px', fontWeight: '800', color: '#10b981', fontFamily: 'var(--font-mono)', marginTop: '6px' }}>
                {evalResult?.passed_count !== undefined ? `${evalResult.passed_count}/${evalResult.test_cases_count}` : '—'}
              </div>
              <div style={{ fontSize: '11px', color: 'var(--text-secondary)', marginTop: '4px' }}>
                {evalResult?.failed_count ? `${evalResult.failed_count} failing cases` : 'All test cases passing'}
              </div>
            </div>

            <div className="panel" style={{ padding: '14px 16px', background: '#0a0d12', border: '1px solid var(--border-subtle)' }}>
              <div style={{ fontSize: '11px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                Avg Latency
              </div>
              <div style={{ fontSize: '28px', fontWeight: '800', color: 'var(--text-primary)', fontFamily: 'var(--font-mono)', marginTop: '6px' }}>
                {evalResult?.avg_latency_ms !== undefined ? `${evalResult.avg_latency_ms}ms` : '—'}
              </div>
              <div style={{ fontSize: '11px', color: 'var(--text-secondary)', marginTop: '4px' }}>
                Deterministic + LLM execution
              </div>
            </div>

            <div className="panel" style={{ padding: '14px 16px', background: '#0a0d12', border: '1px solid var(--border-subtle)' }}>
              <div style={{ fontSize: '11px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                Synchronization Status
              </div>
              <div style={{ marginTop: '10px' }}>
                {getSyncBadge(evalResult?.sync_status, evalResult?.experiment_url)}
              </div>
              <div style={{ fontSize: '11px', color: 'var(--text-secondary)', marginTop: '8px' }}>
                Run ID: <code style={{ fontSize: '10px', color: 'var(--text-primary)' }}>{evalResult?.id ? evalResult.id.slice(0, 16) : '—'}</code>
              </div>
            </div>
          </div>

          {/* Category-Level Performance Breakdown */}
          <div>
            <div style={{ fontSize: '12.5px', fontWeight: '700', color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: '10px' }}>
              Category Verification Performance
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '14px' }}>
              {categories.map((cat) => {
                const CatIcon = cat.icon;
                const agg = evalResult?.aggregate_metrics?.categories?.[cat.key];
                const accuracy = agg ? agg.accuracy : (evalResult ? 100 : 0);
                const passed = agg ? agg.passed : 0;
                const total = agg ? agg.total : 0;

                return (
                  <div key={cat.key} className="panel" style={{ padding: '14px 16px', background: '#080a0f', border: '1px solid var(--border-subtle)' }}>
                    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                        <CatIcon size={15} style={{ color: '#38bdf8' }} />
                        <span style={{ fontSize: '13px', fontWeight: '700', color: '#ffffff' }}>{cat.label}</span>
                      </div>
                      <span className={`badge-sev ${accuracy === 100 ? 'low' : 'critical'}`} style={{ fontSize: '10.5px' }}>
                        {accuracy}%
                      </span>
                    </div>
                    <div style={{ fontSize: '11px', color: 'var(--text-secondary)', marginTop: '6px' }}>
                      {cat.desc}
                    </div>
                    <div style={{ marginTop: '10px', height: '4px', background: 'rgba(255,255,255,0.08)', borderRadius: '2px', overflow: 'hidden' }}>
                      <div style={{ width: `${accuracy}%`, height: '100%', background: accuracy === 100 ? '#10b981' : '#ef4444' }} />
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Benchmark Results Table */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <div style={{ fontSize: '12.5px', fontWeight: '700', color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                Benchmark Test Specifications ({evalResult?.results ? evalResult.results.length : 0} Cases)
              </div>
              <span style={{ fontSize: '11.5px', color: 'var(--text-muted)' }}>
                Click row to inspect input/output provenance &amp; evaluation metrics
              </span>
            </div>

            <div className="table-container" style={{ border: '1px solid var(--border-subtle)', borderRadius: '8px' }}>
              <table className="data-table">
                <thead>
                  <tr>
                    <th style={{ width: '40px' }}></th>
                    <th style={{ width: '85px' }}>ID</th>
                    <th>Specification &amp; Evaluator</th>
                    <th style={{ width: '130px' }}>Category</th>
                    <th style={{ width: '90px' }}>Status</th>
                    <th style={{ width: '95px' }}>Latency</th>
                    <th>Verification Findings &amp; Provenance</th>
                  </tr>
                </thead>
                <tbody>
                  {!evalResult || (evalResult.results || []).length === 0 ? (
                    <tr><td colSpan={7} className="empty-state">No benchmark runs recorded. Click 'Run Pipeline Evaluation' above to execute.</td></tr>
                  ) : (
                    evalResult.results.map((r, i) => {
                      const isExpanded = expandedCase === r.id;
                      return (
                        <React.Fragment key={r.id || i}>
                          <tr 
                            onClick={() => setExpandedCase(isExpanded ? null : r.id)}
                            style={{ cursor: 'pointer', background: isExpanded ? 'rgba(56, 189, 248, 0.04)' : undefined }}
                          >
                            <td style={{ textAlign: 'center', color: 'var(--text-muted)' }}>
                              {isExpanded ? <ChevronDown size={13} /> : <ChevronRight size={13} />}
                            </td>
                            <td><span className="code-val">{r.id}</span></td>
                            <td><strong style={{ color: '#ffffff' }}>{r.name}</strong></td>
                            <td>
                              <span style={{ fontSize: '11px', fontFamily: 'var(--font-mono)', color: 'var(--text-secondary)' }}>
                                {r.category}
                              </span>
                            </td>
                            <td>
                              <span className={`badge-sev ${r.status === 'PASSED' ? 'low' : 'critical'}`}>
                                {r.status}
                              </span>
                            </td>
                            <td className="text-mono" style={{ fontSize: '11px' }}>{r.latency_ms}ms</td>
                            <td style={{ color: 'var(--text-secondary)', fontSize: '11.5px' }}>{r.details}</td>
                          </tr>

                          {/* Expanded Provenance Drawer */}
                          {isExpanded && (
                            <tr style={{ background: '#07090e' }}>
                              <td colSpan={7} style={{ padding: '16px 20px', borderBottom: '1px solid var(--border-subtle)' }}>
                                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: '16px' }}>
                                  
                                  {/* Metrics & Evaluator Details */}
                                  <div style={{ background: '#0d1117', padding: '12px', borderRadius: '6px', border: '1px solid var(--border-subtle)' }}>
                                    <div style={{ fontSize: '11px', fontWeight: '700', color: '#38bdf8', marginBottom: '8px', textTransform: 'uppercase' }}>
                                      Evaluator Metrics
                                    </div>
                                    <pre style={{ margin: 0, fontSize: '11px', color: 'var(--text-primary)', fontFamily: 'var(--font-mono)', whiteSpace: 'pre-wrap' }}>
                                      {JSON.stringify(r.metrics || {}, null, 2)}
                                    </pre>
                                  </div>

                                  {/* Actual Output */}
                                  <div style={{ background: '#0d1117', padding: '12px', borderRadius: '6px', border: '1px solid var(--border-subtle)' }}>
                                    <div style={{ fontSize: '11px', fontWeight: '700', color: '#10b981', marginBottom: '8px', textTransform: 'uppercase' }}>
                                      Actual Target Output
                                    </div>
                                    <pre style={{ margin: 0, fontSize: '11px', color: 'var(--text-primary)', fontFamily: 'var(--font-mono)', whiteSpace: 'pre-wrap' }}>
                                      {JSON.stringify(r.actual_output || {}, null, 2)}
                                    </pre>
                                  </div>

                                  {/* Expected Reference Output */}
                                  <div style={{ background: '#0d1117', padding: '12px', borderRadius: '6px', border: '1px solid var(--border-subtle)' }}>
                                    <div style={{ fontSize: '11px', fontWeight: '700', color: 'var(--text-secondary)', marginBottom: '8px', textTransform: 'uppercase' }}>
                                      Expected Reference Output
                                    </div>
                                    <pre style={{ margin: 0, fontSize: '11px', color: 'var(--text-primary)', fontFamily: 'var(--font-mono)', whiteSpace: 'pre-wrap' }}>
                                      {JSON.stringify(r.expected_output || {}, null, 2)}
                                    </pre>
                                  </div>

                                </div>
                              </td>
                            </tr>
                          )}
                        </React.Fragment>
                      );
                    })
                  )}
                </tbody>
              </table>
            </div>
          </div>

          {/* Historical Run Audit Log from SQLite */}
          {historyRuns.length > 1 && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '10px', marginTop: '10px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <History size={14} style={{ color: 'var(--text-muted)' }} />
                <span style={{ fontSize: '12.5px', fontWeight: '700', color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                  Local Evaluation Audit Trail (SQLite Persistent Storage)
                </span>
              </div>

              <div className="table-container" style={{ border: '1px solid var(--border-subtle)', borderRadius: '8px' }}>
                <table className="data-table">
                  <thead>
                    <tr>
                      <th style={{ width: '150px' }}>Run ID</th>
                      <th>Benchmark Run</th>
                      <th style={{ width: '100px' }}>Accuracy</th>
                      <th style={{ width: '100px' }}>Cases</th>
                      <th style={{ width: '140px' }}>Cloud Status</th>
                      <th style={{ width: '150px' }}>Experiment</th>
                      <th style={{ width: '150px' }}>Timestamp</th>
                    </tr>
                  </thead>
                  <tbody>
                    {historyRuns.slice(0, 5).map((run, idx) => (
                      <tr 
                        key={run.id || idx}
                        onClick={() => setEvalResult(run)}
                        style={{ cursor: 'pointer', background: evalResult?.id === run.id ? 'rgba(56, 189, 248, 0.05)' : undefined }}
                      >
                        <td><span className="code-val">{run.id?.slice(0, 14)}</span></td>
                        <td><strong style={{ color: '#ffffff' }}>{run.run_name || 'Aegis SOC Benchmark'}</strong></td>
                        <td>
                          <span style={{ color: run.accuracy_score === 100 ? '#10b981' : '#38bdf8', fontWeight: '700', fontFamily: 'var(--font-mono)' }}>
                            {run.accuracy_score}%
                          </span>
                        </td>
                        <td className="text-mono" style={{ fontSize: '11px' }}>{run.passed_count}/{run.test_cases_count}</td>
                        <td>{getSyncBadge(run.sync_status, run.experiment_url)}</td>
                        <td>
                          {run.experiment_name ? (
                            <code style={{ fontSize: '10.5px', color: '#38bdf8' }}>{run.experiment_name}</code>
                          ) : (
                            <span style={{ color: 'var(--text-muted)', fontSize: '11px' }}>Local only</span>
                          )}
                        </td>
                        <td className="text-mono" style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>
                          {run.created_at ? new Date(run.created_at).toLocaleString() : '—'}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

        </div>
      </div>

    </div>
  );
}
