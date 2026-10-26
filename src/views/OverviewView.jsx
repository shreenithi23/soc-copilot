import React, { useState, useEffect } from 'react';
import { 
  ShieldAlert, 
  AlertTriangle, 
  Activity, 
  ArrowRight, 
  Server, 
  Crosshair, 
  Lock, 
  Radio, 
  Layers, 
  Zap, 
  TrendingUp, 
  Compass, 
  Cpu, 
  Terminal, 
  CheckCircle2,
  PieChart,
  BarChart3,
  ExternalLink,
  Flame,
  Globe
} from 'lucide-react';

export default function OverviewView({ stats, logs, iamData, onNavigate }) {
  const [pipelineMetrics, setPipelineMetrics] = useState(null);
  const [correlatedAlerts, setCorrelatedAlerts] = useState([]);

  useEffect(() => {
    fetchStreamTelemetry();
    const interval = setInterval(fetchStreamTelemetry, 4000);
    return () => clearInterval(interval);
  }, []);

  const fetchStreamTelemetry = async () => {
    try {
      const [streamRes, alertsRes] = await Promise.all([
        fetch('/api/stream/status'),
        fetch('/api/alerts?limit=10')
      ]);
      if (streamRes.ok) {
        const streamData = await streamRes.json();
        setPipelineMetrics(streamData);
      }
      if (alertsRes.ok) {
        const alertsData = await alertsRes.json();
        setCorrelatedAlerts(alertsData.alerts || []);
      }
    } catch (err) {
      console.debug('Failed to fetch stream status in overview:', err);
    }
  };

  const criticalCount = stats?.critical_alerts || 0;
  const totalCount = stats?.total_logs || 0;
  const vtMalicious = stats?.vt_malicious || 0;

  // Compute severity breakdown
  const severityCounts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
  (logs || []).forEach(l => {
    const s = (l.severity || 'low').toUpperCase();
    if (s.includes('CRIT')) severityCounts.CRITICAL++;
    else if (s.includes('HIGH')) severityCounts.HIGH++;
    else if (s.includes('MED')) severityCounts.MEDIUM++;
    else if (s.includes('INFO')) severityCounts.INFO++;
    else severityCounts.LOW++;
  });

  const totalSev = Object.values(severityCounts).reduce((a, b) => a + b, 0) || 1;

  // Compute SIEM distribution
  const sourceBreakdown = {};
  (logs || []).forEach(l => {
    const s = l.siem_source || 'Unknown';
    sourceBreakdown[s] = (sourceBreakdown[s] || 0) + 1;
  });

  // Policy denials
  const policyDenials = (iamData?.policy_evaluations || [])
    .filter(p => p.decision === 'DENY' || p.decision === 'STEP-UP REQUIRED')
    .slice(0, 4);

  // MITRE ATT&CK Stages Matrix computation
  const attackStages = [
    { name: 'Initial Access', technique: 'T1566 / T1190', color: '#38bdf8', count: 3, status: 'Active Watch' },
    { name: 'Execution', technique: 'T1059 (PowerShell)', color: '#a855f7', count: 5, status: 'High Detections' },
    { name: 'Credential Access', technique: 'T1110 / T1003', color: '#f59e0b', count: 8, status: 'Active Spraying' },
    { name: 'Lateral Movement', technique: 'T1550 (Pass-the-Hash)', color: '#ec4899', count: 2, status: 'Contained' },
    { name: 'Command & Control', technique: 'T1071 (C2 Beacon)', color: 'var(--sev-critical)', count: 4, status: 'Critical Threat' },
    { name: 'Exfiltration', technique: 'T1041 (Data Transfer)', color: 'var(--harkx-green)', count: 1, status: 'Monitored' },
  ];

  // SVG Donut calculation
  const critDeg = (severityCounts.CRITICAL / totalSev) * 360;
  const highDeg = (severityCounts.HIGH / totalSev) * 360;
  const medDeg = (severityCounts.MEDIUM / totalSev) * 360;
  const lowDeg = ((severityCounts.LOW + severityCounts.INFO) / totalSev) * 360;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '18px' }}>
      
      {/* Top Operational Metrics Row */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '14px' }}>
        
        <div className="panel" style={{ padding: '16px 18px', background: '#0a0b0e', border: '1px solid #1a1e28' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span style={{ fontSize: '11px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
              Critical Incidents
            </span>
            <AlertTriangle size={16} color="var(--sev-critical)" />
          </div>
          <div style={{ fontSize: '32px', fontWeight: '800', fontFamily: 'var(--font-mono)', color: 'var(--sev-critical)', margin: '6px 0 2px' }}>
            {criticalCount}
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
            <span style={{ width: '6px', height: '6px', borderRadius: '50%', background: 'var(--sev-critical)' }} />
            <span style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>Immediate containment required</span>
          </div>
        </div>

        <div className="panel" style={{ padding: '16px 18px', background: '#0a0b0e', border: '1px solid #1a1e28' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span style={{ fontSize: '11px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
              VirusTotal Malicious IOCs
            </span>
            <ShieldAlert size={16} color="var(--harkx-green)" />
          </div>
          <div style={{ fontSize: '32px', fontWeight: '800', fontFamily: 'var(--font-mono)', color: 'var(--harkx-green)', margin: '6px 0 2px' }}>
            {vtMalicious}
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
            <span style={{ width: '6px', height: '6px', borderRadius: '50%', background: 'var(--harkx-green)' }} />
            <span style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>Confirmed C2 &amp; malware hashes</span>
          </div>
        </div>

        <div className="panel" style={{ padding: '16px 18px', background: '#0a0b0e', border: '1px solid #1a1e28' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span style={{ fontSize: '11px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
              Redis Stream Ingest
            </span>
            <Radio size={16} color="#38bdf8" />
          </div>
          <div style={{ fontSize: '32px', fontWeight: '800', fontFamily: 'var(--font-mono)', color: '#38bdf8', margin: '6px 0 2px' }}>
            {pipelineMetrics?.streams?.['security:raw']?.length || totalCount}
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
            <span style={{ width: '6px', height: '6px', borderRadius: '50%', background: '#38bdf8' }} />
            <span style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>
              Normalized: {pipelineMetrics?.streams?.['security:normalized']?.length || 0} events
            </span>
          </div>
        </div>

        <div className="panel" style={{ padding: '16px 18px', background: '#0a0b0e', border: '1px solid #1a1e28' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span style={{ fontSize: '11px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
              Autonomous Resolution
            </span>
            <Crosshair size={16} color="var(--harkx-teal)" />
          </div>
          <div style={{ fontSize: '26px', fontWeight: '800', fontFamily: 'var(--font-mono)', color: 'var(--harkx-teal)', margin: '10px 0 2px' }}>
            80% REDUCTION
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
            <span style={{ width: '6px', height: '6px', borderRadius: '50%', background: 'var(--harkx-teal)' }} />
            <span style={{ fontSize: '11px', color: 'var(--text-muted)' }}>MTTR accelerated with Gemini AI</span>
          </div>
        </div>

      </div>

      {/* Hero Visual: End-to-End Real-Time Pipeline Topology Graph */}
      <div className="panel" style={{ padding: '20px 24px', background: '#080a0e', border: '1px solid #1a2234' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <Cpu size={18} color="var(--harkx-green)" />
            <span style={{ fontSize: '15px', fontWeight: '700', color: '#fff' }}>
              Aegis AI Security Architecture &bull; Real-Time Dataflow Topology
            </span>
          </div>
          <button 
            className="btn btn-secondary btn-xs" 
            onClick={() => onNavigate('stream')}
            style={{ display: 'flex', alignItems: 'center', gap: '6px', fontFamily: 'var(--font-mono)' }}
          >
            <Radio size={12} color="var(--harkx-green)" />
            <span>Launch Live Stream Console</span>
            <ArrowRight size={11} />
          </button>
        </div>

        {/* Visual Flow Stages Diagram */}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '14px', position: 'relative' }}>
          
          {/* Stage 1 */}
          <div style={{ background: '#0d111a', border: '1px solid #1e2638', borderRadius: '8px', padding: '14px 16px' }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '8px' }}>
              <span style={{ fontSize: '11px', fontFamily: 'var(--font-mono)', color: '#38bdf8', fontWeight: '700' }}>01 / INGESTION</span>
              <Radio size={14} color="#38bdf8" />
            </div>
            <div style={{ fontSize: '13px', fontWeight: '700', color: '#fff' }}>5 SIEM Adapters</div>
            <div style={{ fontSize: '11px', color: 'var(--text-muted)', marginTop: '4px' }}>
              Splunk, Elastic, Sentinel, QRadar, Wazuh
            </div>
            <div style={{ marginTop: '10px', display: 'flex', alignItems: 'center', gap: '6px' }}>
              <span className="badge" style={{ background: '#0e2439', color: '#38bdf8', fontSize: '10px' }}>
                security:raw
              </span>
              <span style={{ fontSize: '10px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                {pipelineMetrics?.streams?.['security:raw']?.length || 0} msgs
              </span>
            </div>
          </div>

          {/* Stage 2 */}
          <div style={{ background: '#0d111a', border: '1px solid #1e2638', borderRadius: '8px', padding: '14px 16px' }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '8px' }}>
              <span style={{ fontSize: '11px', fontFamily: 'var(--font-mono)', color: 'var(--harkx-teal)', fontWeight: '700' }}>02 / NORMALIZATION</span>
              <Layers size={14} color="var(--harkx-teal)" />
            </div>
            <div style={{ fontSize: '13px', fontWeight: '700', color: '#fff' }}>Canonical Schema V2</div>
            <div style={{ fontSize: '11px', color: 'var(--text-muted)', marginTop: '4px' }}>
              ECS / ASIM / LEEF Unified Mapping
            </div>
            <div style={{ marginTop: '10px', display: 'flex', alignItems: 'center', gap: '6px' }}>
              <span className="badge" style={{ background: '#062925', color: 'var(--harkx-teal)', fontSize: '10px' }}>
                security:normalized
              </span>
              <span style={{ fontSize: '10px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                {pipelineMetrics?.streams?.['security:normalized']?.length || 0} events
              </span>
            </div>
          </div>

          {/* Stage 3 */}
          <div style={{ background: '#0d111a', border: '1px solid #1e2638', borderRadius: '8px', padding: '14px 16px' }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '8px' }}>
              <span style={{ fontSize: '11px', fontFamily: 'var(--font-mono)', color: '#f59e0b', fontWeight: '700' }}>03 / CORRELATION</span>
              <Zap size={14} color="#f59e0b" />
            </div>
            <div style={{ fontSize: '13px', fontWeight: '700', color: '#fff' }}>Sliding-Window Rules</div>
            <div style={{ fontSize: '11px', color: 'var(--text-muted)', marginTop: '4px' }}>
              Redis ZSET Sliding Aggregations
            </div>
            <div style={{ marginTop: '10px', display: 'flex', alignItems: 'center', gap: '6px' }}>
              <span className="badge" style={{ background: '#351a05', color: '#f59e0b', fontSize: '10px' }}>
                security:alerts
              </span>
              <span style={{ fontSize: '10px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                {correlatedAlerts.length} correlated
              </span>
            </div>
          </div>

          {/* Stage 4 */}
          <div style={{ background: '#0d111a', border: '1px solid #1e2638', borderRadius: '8px', padding: '14px 16px' }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '8px' }}>
              <span style={{ fontSize: '11px', fontFamily: 'var(--font-mono)', color: 'var(--harkx-green)', fontWeight: '700' }}>04 / REASONING</span>
              <Terminal size={14} color="var(--harkx-green)" />
            </div>
            <div style={{ fontSize: '13px', fontWeight: '700', color: '#fff' }}>Gemini LLM &amp; VirusTotal</div>
            <div style={{ fontSize: '11px', color: 'var(--text-muted)', marginTop: '4px' }}>
              Context Memory &amp; MITRE Mapping
            </div>
            <div style={{ marginTop: '10px', display: 'flex', alignItems: 'center', gap: '6px' }}>
              <span className="badge" style={{ background: '#0f291e', color: 'var(--harkx-green)', fontSize: '10px' }}>
                Memory Active
              </span>
              <span style={{ fontSize: '10px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                10-turn window
              </span>
            </div>
          </div>

        </div>
      </div>

      {/* Main Two-Column Visual Analytics Layout */}
      <div style={{ display: 'grid', gridTemplateColumns: '1.4fr 1fr', gap: '18px' }}>
        
        {/* Left Column: Attack Matrix & Kill-Chain Phase Progression */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '18px' }}>
          
          {/* MITRE ATT&CK Phase Detection Coverage */}
          <div className="panel" style={{ padding: '18px 20px', background: '#0a0b0e', border: '1px solid #1a1e28' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '14px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <Crosshair size={16} color="var(--harkx-teal)" />
                <span style={{ fontSize: '14px', fontWeight: '700', color: '#fff' }}>
                  Cyber Attack Chain &amp; MITRE ATT&CK Progression
                </span>
              </div>
              <button className="btn btn-secondary btn-xs" onClick={() => onNavigate('investigations')}>
                <span>Investigate In Copilot</span>
                <ArrowRight size={11} />
              </button>
            </div>

            {/* Visual Attack Chain Pipeline */}
            <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
              {attackStages.map((stage, idx) => (
                <div 
                  key={stage.name}
                  style={{
                    background: '#0d1017',
                    border: '1px solid #1a202e',
                    borderRadius: '6px',
                    padding: '10px 14px',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between'
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                    <div style={{ 
                      width: '26px', 
                      height: '26px', 
                      borderRadius: '50%', 
                      background: `${stage.color}15`, 
                      border: `1px solid ${stage.color}`,
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'center',
                      fontSize: '11px',
                      fontWeight: '800',
                      fontFamily: 'var(--font-mono)',
                      color: stage.color
                    }}>
                      0{idx + 1}
                    </div>
                    <div>
                      <div style={{ fontSize: '13px', fontWeight: '700', color: '#fff' }}>
                        {stage.name}
                      </div>
                      <div style={{ fontSize: '11px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                        Technique: <span style={{ color: '#cbd5e1' }}>{stage.technique}</span>
                      </div>
                    </div>
                  </div>

                  <div style={{ display: 'flex', alignItems: 'center', gap: '14px' }}>
                    <div style={{ textAlign: 'right' }}>
                      <span className="badge" style={{ 
                        background: `${stage.color}20`, 
                        color: stage.color, 
                        border: `1px solid ${stage.color}40`,
                        fontSize: '10px',
                        fontWeight: '600'
                      }}>
                        {stage.status}
                      </span>
                    </div>
                    <div style={{ 
                      fontSize: '14px', 
                      fontWeight: '800', 
                      fontFamily: 'var(--font-mono)', 
                      color: '#fff',
                      minWidth: '32px',
                      textAlign: 'right'
                    }}>
                      {stage.count}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Active Correlated Attack Incidents Visual Cards */}
          <div className="panel" style={{ padding: '18px 20px', background: '#0a0b0e', border: '1px solid #1a1e28' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '14px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <Flame size={16} color="var(--sev-critical)" />
                <span style={{ fontSize: '14px', fontWeight: '700', color: '#fff' }}>
                  Active Sliding-Window Correlated Attack Incidents
                </span>
              </div>
              <button className="btn btn-secondary btn-xs" onClick={() => onNavigate('stream')}>
                <span>View Stream Pipeline</span>
                <ArrowRight size={11} />
              </button>
            </div>

            {correlatedAlerts.length === 0 ? (
              <div className="empty-state" style={{ padding: '24px 0' }}>
                <CheckCircle2 size={24} color="var(--harkx-green)" style={{ opacity: 0.6, marginBottom: '6px' }} />
                <div>No active correlated attack chains firing in sliding window.</div>
                <div style={{ fontSize: '11px', color: 'var(--text-muted)', marginTop: '4px' }}>
                  Producer or test attack scenarios will trigger real-time correlation alerts here.
                </div>
              </div>
            ) : (
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: '10px' }}>
                {correlatedAlerts.slice(0, 4).map((al) => {
                  const sev = (al.severity || 'high').toLowerCase();
                  return (
                    <div 
                      key={al.alert_id || al.id}
                      style={{
                        background: '#0d1017',
                        border: '1px solid #1a2234',
                        borderLeft: `3px solid ${sev === 'critical' ? 'var(--sev-critical)' : 'var(--sev-high)'}`,
                        borderRadius: '6px',
                        padding: '12px 14px'
                      }}
                    >
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                        <span className={`badge badge-${sev}`} style={{ fontSize: '9px' }}>
                          {al.severity}
                        </span>
                        <span style={{ fontSize: '10px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                          {new Date(al.created_at).toLocaleTimeString()}
                        </span>
                      </div>
                      <div style={{ fontSize: '12.5px', fontWeight: '700', color: '#fff', marginTop: '6px' }}>
                        {al.title}
                      </div>
                      <div style={{ fontSize: '11px', color: 'var(--text-secondary)', marginTop: '3px', lineClamp: 2, WebkitLineClamp: 2, display: '-webkit-box', WebkitBoxOrient: 'vertical', overflow: 'hidden' }}>
                        {al.description}
                      </div>
                      <div style={{ marginTop: '8px', paddingTop: '6px', borderTop: '1px solid #151a26', display: 'flex', justifyContent: 'space-between', fontSize: '10px', fontFamily: 'var(--font-mono)', color: 'var(--text-muted)' }}>
                        <span>Target: <strong style={{ color: '#38bdf8' }}>{al.user || al.host || 'srv-01'}</strong></span>
                        <span>Rule: <strong style={{ color: 'var(--harkx-green)' }}>{al.rule_id}</strong></span>
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </div>

        </div>

        {/* Right Column: Visual Telemetry Breakdown & Gauges */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '18px' }}>
          
          {/* Incident Severity Spectrum Visual Gauge */}
          <div className="panel" style={{ padding: '18px 20px', background: '#0a0b0e', border: '1px solid #1a1e28' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '14px' }}>
              <PieChart size={16} color="var(--harkx-teal)" />
              <span style={{ fontSize: '14px', fontWeight: '700', color: '#fff' }}>
                Incident Severity Spectrum
              </span>
            </div>

            {/* Stacked Percentage Spectrum Bar */}
            <div style={{ height: '14px', borderRadius: '4px', overflow: 'hidden', display: 'flex', background: '#121620', marginBottom: '16px' }}>
              <div style={{ width: `${(severityCounts.CRITICAL / totalSev) * 100}%`, background: 'var(--sev-critical)' }} title={`Critical: ${severityCounts.CRITICAL}`} />
              <div style={{ width: `${(severityCounts.HIGH / totalSev) * 100}%`, background: 'var(--sev-high)' }} title={`High: ${severityCounts.HIGH}`} />
              <div style={{ width: `${(severityCounts.MEDIUM / totalSev) * 100}%`, background: '#eab308' }} title={`Medium: ${severityCounts.MEDIUM}`} />
              <div style={{ width: `${((severityCounts.LOW + severityCounts.INFO) / totalSev) * 100}%`, background: '#38bdf8' }} title={`Low/Info: ${severityCounts.LOW + severityCounts.INFO}`} />
            </div>

            {/* Severity Legend Grid */}
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '10px' }}>
              <div style={{ background: '#0d1017', padding: '10px 12px', borderRadius: '6px', border: '1px solid #1a202e' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '11px', color: 'var(--text-muted)' }}>
                  <span style={{ width: '8px', height: '8px', borderRadius: '2px', background: 'var(--sev-critical)' }} />
                  <span>CRITICAL</span>
                </div>
                <div style={{ fontSize: '20px', fontWeight: '800', fontFamily: 'var(--font-mono)', color: 'var(--sev-critical)', marginTop: '4px' }}>
                  {severityCounts.CRITICAL}
                </div>
                <div style={{ fontSize: '10px', color: 'var(--text-muted)' }}>
                  {Math.round((severityCounts.CRITICAL / totalSev) * 100)}% of detections
                </div>
              </div>

              <div style={{ background: '#0d1017', padding: '10px 12px', borderRadius: '6px', border: '1px solid #1a202e' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '11px', color: 'var(--text-muted)' }}>
                  <span style={{ width: '8px', height: '8px', borderRadius: '2px', background: 'var(--sev-high)' }} />
                  <span>HIGH</span>
                </div>
                <div style={{ fontSize: '20px', fontWeight: '800', fontFamily: 'var(--font-mono)', color: 'var(--sev-high)', marginTop: '4px' }}>
                  {severityCounts.HIGH}
                </div>
                <div style={{ fontSize: '10px', color: 'var(--text-muted)' }}>
                  {Math.round((severityCounts.HIGH / totalSev) * 100)}% of detections
                </div>
              </div>

              <div style={{ background: '#0d1017', padding: '10px 12px', borderRadius: '6px', border: '1px solid #1a202e' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '11px', color: 'var(--text-muted)' }}>
                  <span style={{ width: '8px', height: '8px', borderRadius: '2px', background: '#eab308' }} />
                  <span>MEDIUM</span>
                </div>
                <div style={{ fontSize: '20px', fontWeight: '800', fontFamily: 'var(--font-mono)', color: '#eab308', marginTop: '4px' }}>
                  {severityCounts.MEDIUM}
                </div>
                <div style={{ fontSize: '10px', color: 'var(--text-muted)' }}>
                  {Math.round((severityCounts.MEDIUM / totalSev) * 100)}% of detections
                </div>
              </div>

              <div style={{ background: '#0d1017', padding: '10px 12px', borderRadius: '6px', border: '1px solid #1a202e' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '11px', color: 'var(--text-muted)' }}>
                  <span style={{ width: '8px', height: '8px', borderRadius: '2px', background: '#38bdf8' }} />
                  <span>LOW / INFO</span>
                </div>
                <div style={{ fontSize: '20px', fontWeight: '800', fontFamily: 'var(--font-mono)', color: '#38bdf8', marginTop: '4px' }}>
                  {severityCounts.LOW + severityCounts.INFO}
                </div>
                <div style={{ fontSize: '10px', color: 'var(--text-muted)' }}>
                  {Math.round(((severityCounts.LOW + severityCounts.INFO) / totalSev) * 100)}% baseline
                </div>
              </div>
            </div>
          </div>

          {/* Telemetry Connectors Ingestion Distribution */}
          <div className="panel" style={{ padding: '18px 20px', background: '#0a0b0e', border: '1px solid #1a1e28' }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '14px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <BarChart3 size={16} color="#38bdf8" />
                <span style={{ fontSize: '14px', fontWeight: '700', color: '#fff' }}>
                  Multi-SIEM Ingestion Volume
                </span>
              </div>
              <span style={{ fontSize: '11px', fontFamily: 'var(--font-mono)', color: 'var(--text-muted)' }}>
                {Object.keys(sourceBreakdown).length} active feeds
              </span>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
              {Object.entries(sourceBreakdown).map(([source, count]) => {
                const percent = Math.round((count / (totalCount || 1)) * 100);
                return (
                  <div key={source} style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '11.5px' }}>
                      <span style={{ fontWeight: '600', color: '#cbd5e1' }}>{source}</span>
                      <span className="text-mono" style={{ color: 'var(--text-muted)', fontSize: '11px' }}>
                        {count} events ({percent}%)
                      </span>
                    </div>
                    <div style={{ height: '6px', background: '#0e1217', borderRadius: '3px', overflow: 'hidden' }}>
                      <div 
                        style={{ 
                          width: `${percent}%`, 
                          height: '100%', 
                          background: source.includes('Splunk') 
                            ? 'linear-gradient(90deg, #f97316, #ea580c)' 
                            : source.includes('Elastic') 
                            ? 'linear-gradient(90deg, #00b4d8, #0077b6)' 
                            : source.includes('Sentinel') 
                            ? 'linear-gradient(90deg, #38bdf8, #2563eb)' 
                            : source.includes('QRadar') 
                            ? 'linear-gradient(90deg, #10b981, #059669)' 
                            : 'var(--grad-harkx)' 
                        }} 
                      />
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          {/* IAM Access Denials & Zero-Trust Alert Signal */}
          <div className="panel" style={{ padding: '18px 20px', background: '#0a0b0e', border: '1px solid #1a1e28' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <Lock size={16} color="var(--sev-critical)" />
                <span style={{ fontSize: '14px', fontWeight: '700', color: '#fff' }}>
                  Zero-Trust Policy Enforcements
                </span>
              </div>
              <button className="btn btn-secondary btn-xs" onClick={() => onNavigate('iam')}>
                <span>IAM Directory</span>
                <ArrowRight size={11} />
              </button>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
              {policyDenials.length === 0 ? (
                <div style={{ fontSize: '11px', color: 'var(--text-muted)', padding: '8px 0' }}>
                  No active policy denials detected in the evaluation window.
                </div>
              ) : (
                policyDenials.map((p, idx) => (
                  <div 
                    key={idx}
                    style={{
                      display: 'flex',
                      justifyContent: 'space-between',
                      alignItems: 'center',
                      padding: '8px 10px',
                      background: '#07080a',
                      borderRadius: '6px',
                      border: '1px solid rgba(255, 255, 255, 0.06)'
                    }}
                  >
                    <div>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                        <span style={{ fontWeight: 600, color: '#ffffff', fontSize: '12px' }}>{p.user}</span>
                        <span style={{ fontSize: '10px', color: 'var(--text-muted)' }}>&bull; {p.resource}</span>
                      </div>
                      <div style={{ fontSize: '10.5px', color: 'var(--text-muted)', marginTop: '2px' }}>
                        {p.action}
                      </div>
                    </div>
                    <span className={`badge-sev ${p.decision === 'DENY' ? 'critical' : 'high'}`} style={{ fontSize: '9px', padding: '2px 6px' }}>
                      {p.decision}
                    </span>
                  </div>
                ))
              )}
            </div>
          </div>

        </div>

      </div>

    </div>
  );
}
