import React, { useState, useEffect, useRef } from 'react';
import { 
  Radio, 
  Play, 
  Square, 
  Zap, 
  RotateCw, 
  AlertOctagon, 
  AlertTriangle, 
  CheckCircle2, 
  Pause, 
  Flame, 
  ShieldAlert, 
  Server, 
  Eye, 
  RefreshCw, 
  Layers, 
  Terminal, 
  Activity,
  Bug,
  Filter,
  Check,
  ChevronRight,
  X
} from 'lucide-react';

export default function LiveStreamView({ onToast, onSelectAlert }) {
  // Operational state
  const [pipelineStatus, setPipelineStatus] = useState(null);
  const [streamConfig, setStreamConfig] = useState({ eps: 5 });
  const [activeTab, setActiveTab] = useState('feed'); // 'feed' | 'alerts' | 'dlq'
  
  // Live SSE events
  const [events, setEvents] = useState([]);
  const [isFeedPaused, setIsFeedPaused] = useState(false);
  const isFeedPausedRef = useRef(false);
  
  // Correlated alerts
  const [alerts, setAlerts] = useState([]);
  const [selectedCorrelatedAlert, setSelectedCorrelatedAlert] = useState(null);
  
  // DLQ items
  const [dlqItems, setDlqItems] = useState([]);
  const [reprocessingId, setReprocessingId] = useState(null);
  
  // EventSource ref
  const eventSourceRef = useRef(null);
  const [connectionStatus, setConnectionStatus] = useState('disconnected'); // 'connecting' | 'connected' | 'disconnected'
  
  // Filter for live feed
  const [sourceFilter, setSourceFilter] = useState('ALL');
  const [searchQuery, setSearchQuery] = useState('');

  // Synchronize pause ref
  useEffect(() => {
    isFeedPausedRef.current = isFeedPaused;
  }, [isFeedPaused]);

  // Fetch initial data
  useEffect(() => {
    fetchPipelineStatus();
    fetchCorrelatedAlerts();
    fetchDlqItems();
    fetchInitialEvents();
    
    // Poll status & alerts every 3 seconds
    const interval = setInterval(() => {
      fetchPipelineStatus();
      if (activeTab === 'alerts') fetchCorrelatedAlerts();
      if (activeTab === 'dlq') fetchDlqItems();
    }, 3000);

    return () => clearInterval(interval);
  }, [activeTab]);

  const fetchInitialEvents = async () => {
    try {
      const res = await fetch('/api/events?limit=30');
      if (res.ok) {
        const data = await res.json();
        if (data.logs && data.logs.length > 0) {
          setEvents(data.logs);
        }
      }
    } catch (err) {
      console.error('Failed to fetch initial events:', err);
    }
  };

  // Manage SSE Connection
  useEffect(() => {
    connectEventSource();

    return () => {
      if (eventSourceRef.current) {
        eventSourceRef.current.close();
      }
    };
  }, []);

  const connectEventSource = () => {
    if (eventSourceRef.current) {
      eventSourceRef.current.close();
    }

    setConnectionStatus('connecting');
    const es = new EventSource('/api/events/live');
    eventSourceRef.current = es;

    es.onopen = () => {
      setConnectionStatus('connected');
    };

    es.onmessage = (e) => {
      try {
        const data = JSON.parse(e.data);
        if (data.type === 'heartbeat' || data.type === 'connected') return;
        
        if (data.type === 'correlated_alert') {
          // Immediately update correlated alerts
          fetchCorrelatedAlerts();
          return;
        }

        if (!isFeedPausedRef.current) {
          setEvents((prev) => {
            if (data.event_id && prev.some(x => x.event_id === data.event_id)) return prev;
            return [data, ...prev].slice(0, 200);
          });
        }
      } catch (err) {
        console.error('SSE JSON parse error:', err);
      }
    };

    es.onerror = () => {
      setConnectionStatus('disconnected');
    };
  };

  const fetchPipelineStatus = async () => {
    try {
      const res = await fetch('/api/stream/status');
      if (res.ok) {
        const data = await res.json();
        setPipelineStatus(data);
        if (data.producer?.rate_limit_eps) {
          setStreamConfig((prev) => ({ ...prev, eps: data.producer.rate_limit_eps }));
        }
      }
    } catch (err) {
      console.error('Failed to fetch stream status:', err);
    }
  };

  const fetchCorrelatedAlerts = async () => {
    try {
      const res = await fetch('/api/alerts?limit=50');
      if (res.ok) {
        const data = await res.json();
        setAlerts(data.alerts || []);
      }
    } catch (err) {
      console.error('Failed to fetch alerts:', err);
    }
  };

  const fetchDlqItems = async () => {
    try {
      const res = await fetch('/api/stream/dlq?limit=50');
      if (res.ok) {
        const data = await res.json();
        setDlqItems(data.dlq_events || []);
      }
    } catch (err) {
      console.error('Failed to fetch DLQ items:', err);
    }
  };

  const handleStartStream = async () => {
    try {
      const res = await fetch('/api/stream/start', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ eps: streamConfig.eps, scenario: 'mixed' })
      });
      const data = await res.json();
      if (res.ok) {
        onToast?.('Redis Stream Producer started', 'success');
        fetchPipelineStatus();
      } else {
        onToast?.(`Failed: ${data.detail || 'Error'}`, 'error');
      }
    } catch (err) {
      onToast?.(`Start error: ${err.message}`, 'error');
    }
  };

  const handleStopStream = async () => {
    try {
      const res = await fetch('/api/stream/stop', { method: 'POST' });
      if (res.ok) {
        onToast?.('Redis Stream Producer stopped', 'success');
        fetchPipelineStatus();
      }
    } catch (err) {
      onToast?.(`Stop error: ${err.message}`, 'error');
    }
  };

  const handleEpsChange = async (newEps) => {
    setStreamConfig((prev) => ({ ...prev, eps: newEps }));
    try {
      await fetch('/api/stream/config', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ eps: newEps })
      });
      fetchPipelineStatus();
    } catch (err) {
      console.error('Failed to update EPS:', err);
    }
  };

  const handleTriggerScenario = async (scenarioName, count = 5) => {
    try {
      const res = await fetch('/api/stream/trigger-scenario', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ scenario: scenarioName, count })
      });
      const data = await res.json();
      if (res.ok) {
        onToast?.(`Triggered burst scenario: ${scenarioName} (${count} events)`, 'success');
        fetchPipelineStatus();
        setTimeout(fetchCorrelatedAlerts, 1200);
      } else {
        onToast?.(`Scenario failed: ${data.detail || 'Error'}`, 'error');
      }
    } catch (err) {
      onToast?.(`Scenario error: ${err.message}`, 'error');
    }
  };

  const handleReprocessDlq = async (eventId) => {
    setReprocessingId(eventId);
    try {
      const res = await fetch(`/api/stream/dlq/${encodeURIComponent(eventId)}/reprocess`, {
        method: 'POST'
      });
      const data = await res.json();
      if (res.ok) {
        onToast?.(`Event re-injected to raw stream for reprocessing`, 'success');
        fetchDlqItems();
        fetchPipelineStatus();
      } else {
        onToast?.(`Reprocess error: ${data.detail}`, 'error');
      }
    } catch (err) {
      onToast?.(`Reprocess error: ${err.message}`, 'error');
    } finally {
      setReprocessingId(null);
    }
  };

  const isRunning = pipelineStatus?.producer?.is_running;
  const metrics = pipelineStatus?.producer?.metrics || {};
  const streams = pipelineStatus?.streams || {};

  // Filter live events
  const filteredEvents = events.filter((e) => {
    if (sourceFilter !== 'ALL' && e.siem_source !== sourceFilter) return false;
    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      const match = 
        (e.event_name && e.event_name.toLowerCase().includes(q)) ||
        (e.user && e.user.toLowerCase().includes(q)) ||
        (e.src_ip && e.src_ip.includes(q)) ||
        (e.dest_ip && e.dest_ip.includes(q)) ||
        (e.host && e.host.toLowerCase().includes(q));
      if (!match) return false;
    }
    return true;
  });

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
      
      {/* Top Banner / Stream Control Hub */}
      <div className="panel" style={{ padding: '18px 22px', background: '#0a0a0a', border: '1px solid #1a1e28' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '16px' }}>
          
          {/* Header & Status */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '14px' }}>
            <div style={{
              width: '42px', 
              height: '42px', 
              borderRadius: '8px', 
              background: isRunning ? 'rgba(47, 163, 97, 0.15)' : 'rgba(239, 68, 68, 0.12)',
              border: `1px solid ${isRunning ? 'var(--harkx-green)' : 'var(--sev-critical)'}`,
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center'
            }}>
              <Radio size={22} color={isRunning ? 'var(--harkx-green)' : '#ef4444'} />
            </div>
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <h2 style={{ fontSize: '18px', fontWeight: '700', color: '#fff', margin: 0 }}>
                  Redis Streams Real-Time Pipeline
                </h2>
                <span className={`badge ${isRunning ? 'badge-low' : 'badge-high'}`} style={{ fontSize: '10px', textTransform: 'uppercase' }}>
                  {isRunning ? 'PRODUCER ACTIVE' : 'PRODUCER IDLE'}
                </span>
                <span style={{ 
                  display: 'inline-flex', 
                  alignItems: 'center', 
                  gap: '5px', 
                  fontSize: '11px', 
                  fontFamily: 'var(--font-mono)', 
                  color: connectionStatus === 'connected' ? 'var(--harkx-green)' : 'var(--text-muted)' 
                }}>
                  <span style={{
                    width: '7px', 
                    height: '7px', 
                    borderRadius: '50%', 
                    backgroundColor: connectionStatus === 'connected' ? 'var(--harkx-green)' : '#ef4444' 
                  }} />
                  SSE {connectionStatus}
                </span>
              </div>
              <p style={{ margin: '4px 0 0', fontSize: '12px', color: 'var(--text-secondary)' }}>
                Continuous asynchronous ingestion, multi-SIEM normalization, sliding-window stateful correlation, and Redis DLQ.
              </p>
            </div>
          </div>

          {/* Controls: Start, Stop, EPS Rate */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
            
            {/* EPS Selector */}
            <div style={{ display: 'flex', alignItems: 'center', gap: '6px', background: '#12151c', padding: '4px 10px', borderRadius: '6px', border: '1px solid #202634' }}>
              <Zap size={14} color="var(--harkx-teal)" />
              <span style={{ fontSize: '11px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>Rate:</span>
              {[1, 5, 10, 25, 50].map((rate) => (
                <button
                  key={rate}
                  onClick={() => handleEpsChange(rate)}
                  style={{
                    background: streamConfig.eps === rate ? 'var(--harkx-green)' : 'transparent',
                    color: streamConfig.eps === rate ? '#000' : '#8892b0',
                    fontWeight: streamConfig.eps === rate ? '700' : '500',
                    border: 'none',
                    borderRadius: '4px',
                    padding: '3px 8px',
                    fontSize: '11px',
                    fontFamily: 'var(--font-mono)',
                    cursor: 'pointer'
                  }}
                >
                  {rate} EPS
                </button>
              ))}
            </div>

            {/* Run / Stop Button */}
            {isRunning ? (
              <button 
                onClick={handleStopStream}
                className="btn btn-secondary"
                style={{ 
                  background: '#2b1014', 
                  borderColor: '#ef4444', 
                  color: '#ef4444',
                  display: 'flex', 
                  alignItems: 'center', 
                  gap: '6px', 
                  fontSize: '12px', 
                  fontWeight: '600' 
                }}
              >
                <Square size={14} fill="#ef4444" /> Stop Streaming
              </button>
            ) : (
              <button 
                onClick={handleStartStream}
                className="btn btn-primary"
                style={{ 
                  background: 'var(--harkx-green)', 
                  borderColor: 'var(--harkx-green)', 
                  color: '#000',
                  display: 'flex', 
                  alignItems: 'center', 
                  gap: '6px', 
                  fontSize: '12px', 
                  fontWeight: '700' 
                }}
              >
                <Play size={14} fill="#000" /> Start Streaming
              </button>
            )}

            {/* SSE Reconnect */}
            <button
              onClick={connectEventSource}
              title="Reconnect Live SSE Stream"
              className="btn btn-secondary"
              style={{ padding: '8px' }}
            >
              <RotateCw size={14} />
            </button>
          </div>

        </div>

        {/* Attack Scenario Burst Triggers */}
        <div style={{ marginTop: '16px', paddingTop: '14px', borderTop: '1px solid #161a22', display: 'flex', alignItems: 'center', gap: '10px', flexWrap: 'wrap' }}>
          <span style={{ fontSize: '11px', fontFamily: 'var(--font-mono)', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.04em', display: 'flex', alignItems: 'center', gap: '5px' }}>
            <Flame size={13} color="#f59e0b" /> Trigger Scenario Burst:
          </span>

          <button 
            onClick={() => handleTriggerScenario('brute_force', 5)}
            className="btn btn-secondary" 
            style={{ fontSize: '11px', padding: '5px 10px', fontFamily: 'var(--font-mono)' }}
          >
            Brute Force Attack (T1110)
          </button>

          <button 
            onClick={() => handleTriggerScenario('auth_compromise', 4)}
            className="btn btn-secondary" 
            style={{ fontSize: '11px', padding: '5px 10px', fontFamily: 'var(--font-mono)' }}
          >
            Compromise After Failures (T1078)
          </button>

          <button 
            onClick={() => handleTriggerScenario('endpoint_chain', 3)}
            className="btn btn-secondary" 
            style={{ fontSize: '11px', padding: '5px 10px', fontFamily: 'var(--font-mono)' }}
          >
            Endpoint Attack Chain (T1059)
          </button>

          <button 
            onClick={() => handleTriggerScenario('c2_outbound', 4)}
            className="btn btn-secondary" 
            style={{ fontSize: '11px', padding: '5px 10px', fontFamily: 'var(--font-mono)' }}
          >
            C2 / Exfiltration Beacon (T1071)
          </button>

          <button 
            onClick={() => handleTriggerScenario('dlq_test', 2)}
            className="btn btn-secondary" 
            style={{ fontSize: '11px', padding: '5px 10px', fontFamily: 'var(--font-mono)', borderColor: '#eab308', color: '#eab308' }}
          >
            <Bug size={12} /> Inject Malformed Log (DLQ Test)
          </button>
        </div>
      </div>

      {/* Metrics Row */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: '14px' }}>
        
        {/* Produced */}
        <div className="panel" style={{ padding: '14px 16px', background: '#0a0a0a' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span style={{ fontSize: '11px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', textTransform: 'uppercase' }}>
              Produced (Raw)
            </span>
            <Activity size={15} color="#38bdf8" />
          </div>
          <div style={{ fontSize: '26px', fontWeight: '800', fontFamily: 'var(--font-mono)', color: '#ffffff', margin: '4px 0 2px' }}>
            {metrics.total_produced || 0}
          </div>
          <span style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
            Stream: <code style={{ color: '#38bdf8' }}>security:raw</code> ({streams['security:raw']?.length || 0})
          </span>
        </div>

        {/* Normalized */}
        <div className="panel" style={{ padding: '14px 16px', background: '#0a0a0a' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span style={{ fontSize: '11px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', textTransform: 'uppercase' }}>
              Normalized Events
            </span>
            <CheckCircle2 size={15} color="var(--harkx-green)" />
          </div>
          <div style={{ fontSize: '26px', fontWeight: '800', fontFamily: 'var(--font-mono)', color: 'var(--harkx-green)', margin: '4px 0 2px' }}>
            {streams['security:normalized']?.length || 0}
          </div>
          <span style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
            Group lag: {streams['security:normalized']?.groups?.['group:correlators']?.lag ?? 0}
          </span>
        </div>

        {/* Correlated Alerts */}
        <div className="panel" style={{ padding: '14px 16px', background: '#0a0a0a' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span style={{ fontSize: '11px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', textTransform: 'uppercase' }}>
              Correlated Alerts
            </span>
            <AlertTriangle size={15} color="var(--sev-critical)" />
          </div>
          <div style={{ fontSize: '26px', fontWeight: '800', fontFamily: 'var(--font-mono)', color: 'var(--sev-critical)', margin: '4px 0 2px' }}>
            {alerts.length}
          </div>
          <span style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
            Stream: <code style={{ color: '#f87171' }}>security:alerts</code>
          </span>
        </div>

        {/* DLQ */}
        <div className="panel" style={{ padding: '14px 16px', background: '#0a0a0a' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span style={{ fontSize: '11px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', textTransform: 'uppercase' }}>
              Dead Letter Queue
            </span>
            <AlertOctagon size={15} color="#eab308" />
          </div>
          <div style={{ fontSize: '26px', fontWeight: '800', fontFamily: 'var(--font-mono)', color: dlqItems.length > 0 ? '#eab308' : '#8892b0', margin: '4px 0 2px' }}>
            {streams['security:dlq']?.length || dlqItems.length || 0}
          </div>
          <span style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
            Unprocessable/Malformed logs
          </span>
        </div>

        {/* Redis Node */}
        <div className="panel" style={{ padding: '14px 16px', background: '#0a0a0a' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span style={{ fontSize: '11px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', textTransform: 'uppercase' }}>
              Redis Stream Node
            </span>
            <Server size={15} color="var(--harkx-teal)" />
          </div>
          <div style={{ fontSize: '18px', fontWeight: '700', fontFamily: 'var(--font-mono)', color: 'var(--harkx-teal)', margin: '8px 0 2px' }}>
            127.0.0.1:6379
          </div>
          <span style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
            Status: Healthy (Connected)
          </span>
        </div>

      </div>

      {/* Main Multi-Tab Section */}
      <div className="panel" style={{ background: '#0a0a0a', border: '1px solid #1a1e28', display: 'flex', flexDirection: 'column' }}>
        
        {/* Tab Navigation Header */}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '12px 18px', borderBottom: '1px solid #1a1e28' }}>
          
          <div style={{ display: 'flex', gap: '8px' }}>
            <button
              onClick={() => setActiveTab('feed')}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '8px',
                padding: '8px 14px',
                background: activeTab === 'feed' ? '#161b26' : 'transparent',
                color: activeTab === 'feed' ? '#fff' : 'var(--text-muted)',
                border: activeTab === 'feed' ? '1px solid #283347' : '1px solid transparent',
                borderRadius: '6px',
                fontSize: '12px',
                fontFamily: 'var(--font-mono)',
                fontWeight: activeTab === 'feed' ? '600' : '400',
                cursor: 'pointer'
              }}
            >
              <Radio size={14} color={activeTab === 'feed' ? 'var(--harkx-green)' : 'currentColor'} />
              Live Ingestion Feed ({events.length})
            </button>

            <button
              onClick={() => setActiveTab('alerts')}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '8px',
                padding: '8px 14px',
                background: activeTab === 'alerts' ? '#161b26' : 'transparent',
                color: activeTab === 'alerts' ? '#fff' : 'var(--text-muted)',
                border: activeTab === 'alerts' ? '1px solid #283347' : '1px solid transparent',
                borderRadius: '6px',
                fontSize: '12px',
                fontFamily: 'var(--font-mono)',
                fontWeight: activeTab === 'alerts' ? '600' : '400',
                cursor: 'pointer'
              }}
            >
              <ShieldAlert size={14} color={activeTab === 'alerts' ? 'var(--sev-critical)' : 'currentColor'} />
              Correlated Alerts ({alerts.length})
            </button>

            <button
              onClick={() => setActiveTab('dlq')}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '8px',
                padding: '8px 14px',
                background: activeTab === 'dlq' ? '#161b26' : 'transparent',
                color: activeTab === 'dlq' ? '#fff' : 'var(--text-muted)',
                border: activeTab === 'dlq' ? '1px solid #283347' : '1px solid transparent',
                borderRadius: '6px',
                fontSize: '12px',
                fontFamily: 'var(--font-mono)',
                fontWeight: activeTab === 'dlq' ? '600' : '400',
                cursor: 'pointer'
              }}
            >
              <AlertOctagon size={14} color={activeTab === 'dlq' ? '#eab308' : 'currentColor'} />
              Dead Letter Queue ({dlqItems.length})
            </button>
          </div>

          {/* Right Header Toolbar */}
          {activeTab === 'feed' && (
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
              
              {/* SIEM Source Filter */}
              <select
                value={sourceFilter}
                onChange={(e) => setSourceFilter(e.target.value)}
                style={{
                  background: '#12151c',
                  border: '1px solid #202634',
                  color: '#cbd5e1',
                  borderRadius: '5px',
                  padding: '5px 8px',
                  fontSize: '11px',
                  fontFamily: 'var(--font-mono)'
                }}
              >
                <option value="ALL">All SIEM Formats</option>
                <option value="Splunk">Splunk Enterprise</option>
                <option value="Elastic ECS">Elastic ECS</option>
                <option value="Microsoft Sentinel ASIM">Sentinel ASIM</option>
                <option value="IBM QRadar LEEF">IBM QRadar LEEF</option>
                <option value="Wazuh HIDS">Wazuh HIDS</option>
              </select>

              {/* Pause/Resume Visual Rendering */}
              <button
                onClick={() => setIsFeedPaused(!isFeedPaused)}
                className="btn btn-secondary"
                style={{ 
                  display: 'flex', 
                  alignItems: 'center', 
                  gap: '6px', 
                  fontSize: '11px',
                  fontFamily: 'var(--font-mono)',
                  borderColor: isFeedPaused ? '#eab308' : '#283347',
                  color: isFeedPaused ? '#eab308' : '#cbd5e1'
                }}
                title={isFeedPaused ? "Resume visual updates" : "Pause visual updates (stream continues in background)"}
              >
                {isFeedPaused ? <Play size={12} fill="#eab308" /> : <Pause size={12} />}
                {isFeedPaused ? 'Paused' : 'Pause Feed'}
              </button>

              {/* Clear Feed Buffer */}
              <button
                onClick={() => setEvents([])}
                className="btn btn-secondary"
                style={{ fontSize: '11px', padding: '5px 9px', fontFamily: 'var(--font-mono)' }}
                title="Clear local view buffer"
              >
                Clear
              </button>
            </div>
          )}

          {activeTab === 'alerts' && (
            <button
              onClick={fetchCorrelatedAlerts}
              className="btn btn-secondary"
              style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '11px' }}
            >
              <RefreshCw size={12} /> Refresh Alerts
            </button>
          )}

          {activeTab === 'dlq' && (
            <button
              onClick={fetchDlqItems}
              className="btn btn-secondary"
              style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '11px' }}
            >
              <RefreshCw size={12} /> Refresh DLQ
            </button>
          )}

        </div>

        {/* Tab 1: Live Ingestion Feed Table */}
        {activeTab === 'feed' && (
          <div style={{ overflowX: 'auto', maxHeight: '550px', overflowY: 'auto' }}>
            <table className="data-table" style={{ width: '100%', borderCollapse: 'collapse', fontSize: '12px' }}>
              <thead>
                <tr style={{ background: '#0e1118', textAlign: 'left', borderBottom: '1px solid #1a1e28' }}>
                  <th style={{ padding: '10px 14px', width: '130px', fontFamily: 'var(--font-mono)', fontSize: '11px' }}>Timestamp</th>
                  <th style={{ padding: '10px 14px', width: '150px', fontFamily: 'var(--font-mono)', fontSize: '11px' }}>Source Format</th>
                  <th style={{ padding: '10px 14px', width: '100px', fontFamily: 'var(--font-mono)', fontSize: '11px' }}>Severity</th>
                  <th style={{ padding: '10px 14px', fontFamily: 'var(--font-mono)', fontSize: '11px' }}>Event Name / Action</th>
                  <th style={{ padding: '10px 14px', width: '140px', fontFamily: 'var(--font-mono)', fontSize: '11px' }}>User</th>
                  <th style={{ padding: '10px 14px', width: '140px', fontFamily: 'var(--font-mono)', fontSize: '11px' }}>Host</th>
                  <th style={{ padding: '10px 14px', width: '160px', fontFamily: 'var(--font-mono)', fontSize: '11px' }}>Source / Dest IP</th>
                </tr>
              </thead>
              <tbody>
                {filteredEvents.length === 0 ? (
                  <tr>
                    <td colSpan="7" className="empty-state" style={{ padding: '40px 16px' }}>
                      <Radio size={24} style={{ opacity: 0.3, marginBottom: '8px' }} />
                      <div>No live events captured in buffer yet.</div>
                      <div style={{ color: 'var(--text-muted)', fontSize: '11px', marginTop: '4px' }}>
                        Click <strong>Start Streaming</strong> or <strong>Trigger Scenario Burst</strong> above to stream events via Redis.
                      </div>
                    </td>
                  </tr>
                ) : (
                  filteredEvents.map((evt, idx) => {
                    const sev = (evt.severity || 'low').toLowerCase();
                    return (
                      <tr 
                        key={evt.event_id || idx}
                        style={{ 
                          borderBottom: '1px solid #141720',
                          animation: idx === 0 ? 'fadeIn 0.3s ease' : 'none'
                        }}
                      >
                        <td style={{ padding: '8px 14px', fontFamily: 'var(--font-mono)', color: 'var(--text-muted)', fontSize: '11px' }}>
                          {evt.timestamp ? new Date(evt.timestamp).toLocaleTimeString() : 'Just now'}
                        </td>
                        <td style={{ padding: '8px 14px' }}>
                          <span style={{ 
                            fontSize: '11px', 
                            fontFamily: 'var(--font-mono)', 
                            background: '#141824', 
                            padding: '2px 7px', 
                            borderRadius: '4px',
                            color: '#93c5fd',
                            border: '1px solid #232d42'
                          }}>
                            {evt.siem_source || 'Unknown'}
                          </span>
                        </td>
                        <td style={{ padding: '8px 14px' }}>
                          <span className={`badge badge-${sev}`}>
                            {evt.severity || 'INFO'}
                          </span>
                        </td>
                        <td style={{ padding: '8px 14px', fontWeight: '500', color: '#f1f5f9' }}>
                          {evt.event_name || evt.event_type || 'Security Event'}
                        </td>
                        <td style={{ padding: '8px 14px', fontFamily: 'var(--font-mono)', color: evt.user ? 'var(--text-primary)' : 'var(--text-muted)' }}>
                          {evt.user || '—'}
                        </td>
                        <td style={{ padding: '8px 14px', fontFamily: 'var(--font-mono)', color: evt.host ? 'var(--text-primary)' : 'var(--text-muted)' }}>
                          {evt.host || '—'}
                        </td>
                        <td style={{ padding: '8px 14px', fontFamily: 'var(--font-mono)', fontSize: '11px', color: 'var(--text-muted)' }}>
                          {evt.src_ip ? `${evt.src_ip} → ${evt.dest_ip || '*'}` : '—'}
                        </td>
                      </tr>
                    );
                  })
                )}
              </tbody>
            </table>
          </div>
        )}

        {/* Tab 2: Correlated Alerts */}
        {activeTab === 'alerts' && (
          <div style={{ padding: '16px' }}>
            {alerts.length === 0 ? (
              <div className="empty-state" style={{ padding: '40px 16px' }}>
                <CheckCircle2 size={28} color="var(--harkx-green)" style={{ opacity: 0.6, marginBottom: '8px' }} />
                <div>No correlated threat detections active.</div>
                <div style={{ color: 'var(--text-muted)', fontSize: '11px', marginTop: '4px' }}>
                  Trigger an attack scenario above to fire the Redis stateful correlation sliding window rules.
                </div>
              </div>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
                {alerts.map((al) => {
                  const sev = (al.severity || 'high').toLowerCase();
                  const contributing = Array.isArray(al.contributing_event_ids) ? al.contributing_event_ids : [];
                  return (
                    <div 
                      key={al.alert_id} 
                      className="panel"
                      style={{ 
                        padding: '14px 18px', 
                        background: '#0d0f14', 
                        border: '1px solid #1c2230',
                        display: 'flex',
                        justifyContent: 'space-between',
                        alignItems: 'center',
                        cursor: 'pointer'
                      }}
                      onClick={() => setSelectedCorrelatedAlert(al)}
                    >
                      <div style={{ display: 'flex', alignItems: 'center', gap: '14px' }}>
                        <span className={`badge badge-${sev}`} style={{ minWidth: '70px', textAlign: 'center' }}>
                          {al.severity}
                        </span>
                        <div>
                          <div style={{ fontSize: '14px', fontWeight: '700', color: '#fff' }}>
                            {al.title}
                          </div>
                          <div style={{ fontSize: '12px', color: 'var(--text-secondary)', marginTop: '3px' }}>
                            {al.description}
                          </div>
                          <div style={{ display: 'flex', gap: '12px', marginTop: '6px', fontSize: '11px', fontFamily: 'var(--font-mono)', color: 'var(--text-muted)' }}>
                            <span>Rule: <strong style={{ color: '#38bdf8' }}>{al.rule_id}</strong></span>
                            {al.user && <span>User: <strong style={{ color: '#f1f5f9' }}>{al.user}</strong></span>}
                            {al.host && <span>Host: <strong style={{ color: '#f1f5f9' }}>{al.host}</strong></span>}
                            <span>Events Correlated: <strong style={{ color: 'var(--harkx-green)' }}>{contributing.length}</strong></span>
                            <span>Detected: {new Date(al.created_at).toLocaleTimeString()}</span>
                          </div>
                        </div>
                      </div>

                      <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            setSelectedCorrelatedAlert(al);
                          }}
                          className="btn btn-secondary"
                          style={{ fontSize: '11px', padding: '6px 12px', fontFamily: 'var(--font-mono)' }}
                        >
                          <Eye size={12} /> Inspect Evidence
                        </button>
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        )}

        {/* Tab 3: Dead Letter Queue (DLQ) */}
        {activeTab === 'dlq' && (
          <div style={{ padding: '16px' }}>
            {dlqItems.length === 0 ? (
              <div className="empty-state" style={{ padding: '40px 16px' }}>
                <CheckCircle2 size={28} color="var(--harkx-green)" style={{ opacity: 0.6, marginBottom: '8px' }} />
                <div>Dead Letter Queue is empty.</div>
                <div style={{ color: 'var(--text-muted)', fontSize: '11px', marginTop: '4px' }}>
                  All incoming security log records have passed schema validation and normalization without errors.
                </div>
              </div>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                {dlqItems.map((item) => (
                  <div 
                    key={item.id} 
                    className="panel"
                    style={{ 
                      padding: '14px 18px', 
                      background: '#120f09', 
                      border: '1px solid #3b280a' 
                    }}
                  >
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                      <div>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                          <span className="badge" style={{ background: '#78350f', color: '#fef3c7', border: '1px solid #b45309' }}>
                            MALFORMED LOG
                          </span>
                          <span style={{ fontSize: '12px', fontFamily: 'var(--font-mono)', color: '#fde68a' }}>
                            {item.reason || 'Schema validation failure'}
                          </span>
                        </div>
                        <div style={{ fontSize: '11px', color: 'var(--text-muted)', marginTop: '4px', fontFamily: 'var(--font-mono)' }}>
                          Stream Entry ID: {item.id} &bull; Received: {new Date(item.timestamp).toLocaleString()}
                        </div>
                      </div>

                      <button
                        onClick={() => handleReprocessDlq(item.id)}
                        disabled={reprocessingId === item.id}
                        className="btn btn-primary"
                        style={{ 
                          fontSize: '11px', 
                          padding: '6px 12px', 
                          background: 'var(--harkx-green)', 
                          color: '#000', 
                          fontWeight: '700',
                          fontFamily: 'var(--font-mono)',
                          display: 'flex',
                          alignItems: 'center',
                          gap: '6px'
                        }}
                      >
                        <RefreshCw size={12} className={reprocessingId === item.id ? 'spin' : ''} />
                        {reprocessingId === item.id ? 'Re-injecting...' : 'Reprocess Log'}
                      </button>
                    </div>

                    {/* Raw payload snippet */}
                    <div style={{ marginTop: '10px' }}>
                      <pre className="code-block" style={{ maxHeight: '120px', fontSize: '11px', color: '#fef08a' }}>
                        {item.raw_payload}
                      </pre>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

      </div>

      {/* Correlated Alert Evidence Modal / Drawer */}
      {selectedCorrelatedAlert && (
        <div className="modal-overlay" onClick={() => setSelectedCorrelatedAlert(null)}>
          <div className="modal-dialog" onClick={(e) => e.stopPropagation()} style={{ maxWidth: '680px' }}>
            <div className="modal-header">
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                <ShieldAlert size={18} color="var(--sev-critical)" />
                <span style={{ fontWeight: '700', fontSize: '14px', color: '#fff' }}>
                  Correlated Alert Evidence &bull; {selectedCorrelatedAlert.rule_id}
                </span>
              </div>
              <button onClick={() => setSelectedCorrelatedAlert(null)} className="btn-icon">
                <X size={16} />
              </button>
            </div>

            <div className="modal-body">
              <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                <span style={{ fontSize: '16px', fontWeight: '800', color: '#fff' }}>
                  {selectedCorrelatedAlert.title}
                </span>
                <span style={{ fontSize: '13px', color: 'var(--text-secondary)' }}>
                  {selectedCorrelatedAlert.description}
                </span>
              </div>

              <div className="detail-grid" style={{ marginTop: '10px' }}>
                <div className="detail-item">
                  <span className="detail-key">Rule Identifier</span>
                  <span className="detail-val" style={{ color: '#38bdf8' }}>{selectedCorrelatedAlert.rule_id}</span>
                </div>
                <div className="detail-item">
                  <span className="detail-key">Severity Level</span>
                  <span className="detail-val">
                    <span className={`badge badge-${selectedCorrelatedAlert.severity.toLowerCase()}`}>
                      {selectedCorrelatedAlert.severity}
                    </span>
                  </span>
                </div>
                <div className="detail-item">
                  <span className="detail-key">Target User</span>
                  <span className="detail-val">{selectedCorrelatedAlert.user || 'None / Not Applicable'}</span>
                </div>
                <div className="detail-item">
                  <span className="detail-key">Target Host</span>
                  <span className="detail-val">{selectedCorrelatedAlert.host || 'None / Not Applicable'}</span>
                </div>
                <div className="detail-item">
                  <span className="detail-key">MITRE Technique</span>
                  <span className="detail-val">
                    {selectedCorrelatedAlert.rule_id.includes('BRUTEFORCE') && 'T1110 (Brute Force)'}
                    {selectedCorrelatedAlert.rule_id.includes('COMPROMISE') && 'T1078 (Valid Accounts)'}
                    {selectedCorrelatedAlert.rule_id.includes('ENDPOINT') && 'T1059 / T1055 (Execution & Injection)'}
                    {selectedCorrelatedAlert.rule_id.includes('C2') && 'T1071 / T1041 (Command & Control)'}
                  </span>
                </div>
                <div className="detail-item">
                  <span className="detail-key">Detection Time</span>
                  <span className="detail-val">{new Date(selectedCorrelatedAlert.created_at).toLocaleString()}</span>
                </div>
              </div>

              {/* Contributing Event IDs */}
              <div style={{ marginTop: '12px' }}>
                <span className="detail-key" style={{ display: 'block', marginBottom: '6px' }}>
                  Contributing Event IDs ({Array.isArray(selectedCorrelatedAlert.contributing_event_ids) ? selectedCorrelatedAlert.contributing_event_ids.length : 0})
                </span>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px' }}>
                  {(Array.isArray(selectedCorrelatedAlert.contributing_event_ids) ? selectedCorrelatedAlert.contributing_event_ids : []).map((id) => (
                    <span 
                      key={id}
                      style={{ 
                        fontFamily: 'var(--font-mono)', 
                        fontSize: '11px', 
                        background: '#161d2d', 
                        border: '1px solid #283754', 
                        color: '#93c5fd', 
                        padding: '3px 8px', 
                        borderRadius: '4px' 
                      }}
                    >
                      {id}
                    </span>
                  ))}
                </div>
              </div>

              {/* Evidence JSON */}
              <div style={{ marginTop: '12px' }}>
                <span className="detail-key" style={{ display: 'block', marginBottom: '6px' }}>
                  Rule Evidence & Context
                </span>
                <pre className="code-block" style={{ maxHeight: '180px' }}>
                  {JSON.stringify(selectedCorrelatedAlert.evidence, null, 2)}
                </pre>
              </div>
            </div>

            <div className="modal-footer">
              <button 
                onClick={() => setSelectedCorrelatedAlert(null)} 
                className="btn btn-secondary"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}

    </div>
  );
}
