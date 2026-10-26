import React, { useState, useEffect } from 'react';
import Sidebar from './components/Sidebar';
import Header from './components/Header';
import AlertDetailDrawer from './components/AlertDetailDrawer';
import LogInspectorModal from './components/LogInspectorModal';
import IngestModal from './components/IngestModal';
import MappingCoverageModal from './components/MappingCoverageModal';

import OverviewView from './views/OverviewView';
import LiveStreamView from './views/LiveStreamView';
import AlertsView from './views/AlertsView';
import InvestigationsView from './views/InvestigationsView';
import IamView from './views/IamView';
import ThreatIntelView from './views/ThreatIntelView';
import AuditView from './views/AuditView';
import SettingsView from './views/SettingsView';

export default function App() {
  const [activeTab, setActiveTab] = useState('overview');
  const [stats, setStats] = useState(null);
  const [logs, setLogs] = useState([]);
  const [iamData, setIamData] = useState(null);

  // Modals & Drawers
  const [selectedAlert, setSelectedAlert] = useState(null);
  const [logToInspect, setLogToInspect] = useState(null);
  const [isIngestOpen, setIsIngestOpen] = useState(false);
  const [isCoverageOpen, setIsCoverageOpen] = useState(false);
  const [investigationAlertTarget, setInvestigationAlertTarget] = useState(null);

  // Confirmation dialogs
  const [showResetConfirm, setShowResetConfirm] = useState(false);
  const [showClearAllLogsConfirm, setShowClearAllLogsConfirm] = useState(false);
  const [resetTrigger, setResetTrigger] = useState(0);

  // Toasts
  const [toasts, setToasts] = useState([]);

  useEffect(() => {
    refreshAllData();
  }, []);

  const addToast = (message, type = 'success') => {
    const id = Date.now() + Math.random();
    setToasts(prev => [...prev, { id, message, type }]);
    setTimeout(() => {
      setToasts(prev => prev.filter(t => t.id !== id));
    }, 4000);
  };

  const refreshAllData = async () => {
    try {
      const [statsRes, logsRes, iamRes] = await Promise.all([
        fetch('/api/stats'),
        fetch('/api/logs?limit=100'),
        fetch('/api/iam')
      ]);

      const statsData = await statsRes.json();
      const logsData = await logsRes.json();
      const iamDataRes = await iamRes.json();

      setStats(statsData);
      setLogs(logsData.logs || []);
      setIamData(iamDataRes);
    } catch (err) {
      console.error('Failed to refresh data:', err);
      addToast(`Telemetry sync error: ${err.message}`, 'error');
    }
  };

  const handleResetDataset = async () => {
    setShowResetConfirm(false);
    try {
      const res = await fetch('/api/logs/seed', { method: 'POST' });
      const data = await res.json();
      addToast(`Dataset reset: Ingested ${data.seeded_count} realistic events (AI conversations & threat intel reset)`);
      setResetTrigger(prev => prev + 1);
      refreshAllData();
    } catch (err) {
      addToast(`Reset failed: ${err.message}`, 'error');
    }
  };

  const handleClearAllLogs = async () => {
    setShowClearAllLogsConfirm(false);
    try {
      const res = await fetch('/api/logs/clear', { method: 'POST' });
      const data = await res.json();
      addToast(data.message || 'Reset complete: All logs, AI threat hunting conversations, and VirusTotal threat intel cleared');
      setResetTrigger(prev => prev + 1);
      refreshAllData();
    } catch (err) {
      addToast(`Reset all logs failed: ${err.message}`, 'error');
    }
  };

  const handlePurgeRawLogs = async () => {
    try {
      const res = await fetch('/api/logs/purge-raw', { method: 'POST' });
      const data = await res.json();
      addToast(data.message || `Purged raw log payloads from ${data.affected_count} records (analysis details kept)`);
      refreshAllData();
    } catch (err) {
      addToast(`Purge raw logs failed: ${err.message}`, 'error');
    }
  };

  const handleInvestigateAlert = (alert) => {
    setInvestigationAlertTarget(alert);
    setActiveTab('investigations');
  };

  return (
    <div className="app-shell">
      
      {/* Persistent Left Navigation Sidebar */}
      <Sidebar 
        activeTab={activeTab} 
        setActiveTab={setActiveTab} 
        stats={stats} 
      />

      {/* Main Workstation */}
      <div className="app-main-wrapper">
        
        {/* Top Operational Status Bar */}
        <Header 
          activeTab={activeTab}
          stats={stats}
          onResetDataset={() => setShowResetConfirm(true)}
          onClearAllLogs={() => setShowClearAllLogsConfirm(true)}
          onOpenIngestModal={() => setIsIngestOpen(true)}
          onOpenSettings={() => setActiveTab('settings')}
        />

        {/* Dynamic Content Views */}
        <main className="app-content">
          {activeTab === 'overview' && (
            <OverviewView 
              stats={stats}
              logs={logs}
              iamData={iamData}
              onSelectAlert={(a) => setSelectedAlert(a)}
              onNavigate={(tab) => setActiveTab(tab)}
            />
          )}

          {activeTab === 'stream' && (
            <LiveStreamView 
              onToast={(msg, type) => addToast(msg, type)}
              onSelectAlert={(a) => setSelectedAlert(a)}
            />
          )}

          {activeTab === 'alerts' && (
            <AlertsView 
              alerts={logs}
              onSelectAlert={(a) => setSelectedAlert(a)}
              onInspectLog={(l) => setLogToInspect(l)}
              onOpenIngest={() => setIsIngestOpen(true)}
              onOpenCoverage={() => setIsCoverageOpen(true)}
              onClearAllLogs={() => setShowClearAllLogsConfirm(true)}
              onPurgeRawLogs={handlePurgeRawLogs}
              onRefresh={refreshAllData}
            />
          )}

          {activeTab === 'investigations' && (
            <InvestigationsView 
              initialAlert={investigationAlertTarget}
              onToast={(msg, type) => addToast(msg, type)}
              resetKey={resetTrigger}
            />
          )}

          {activeTab === 'iam' && (
            <IamView 
              iamData={iamData}
            />
          )}

          {activeTab === 'intel' && (
            <ThreatIntelView 
              onToast={(msg, type) => addToast(msg, type)}
              resetKey={resetTrigger}
            />
          )}

          {activeTab === 'audit' && (
            <AuditView 
              onToast={(msg, type) => addToast(msg, type)}
            />
          )}

          {activeTab === 'settings' && (
            <SettingsView 
              onToast={(msg, type) => addToast(msg, type)}
            />
          )}
        </main>

      </div>

      {/* Contextual Slide-Over Alert Detail Drawer */}
      <AlertDetailDrawer 
        alert={selectedAlert}
        onClose={() => setSelectedAlert(null)}
        onInvestigate={handleInvestigateAlert}
        onCopy={(text) => addToast(`Copied to clipboard: ${text}`)}
      />

      {/* Log Inspector Modal */}
      <LogInspectorModal 
        log={logToInspect}
        onClose={() => setLogToInspect(null)}
        onCopy={(text) => addToast('Copied log attributes to clipboard')}
      />

      {/* Mapping Coverage Modal */}
      <MappingCoverageModal 
        isOpen={isCoverageOpen}
        onClose={() => setIsCoverageOpen(false)}
        onRefreshData={refreshAllData}
        onNotify={(msg, type) => addToast(msg, type)}
      />

      {/* Ingest Telemetry Modal */}
      <IngestModal 
        isOpen={isIngestOpen}
        onClose={() => setIsIngestOpen(false)}
        onIngestSuccess={(msg) => {
          addToast(msg);
          refreshAllData();
        }}
        onError={(msg) => addToast(msg, 'error')}
      />

      {/* Confirm Dataset Reset Modal */}
      {showResetConfirm && (
        <div className="modal-overlay" onClick={() => setShowResetConfirm(false)} role="dialog" aria-modal="true">
          <div className="modal-dialog" onClick={(e) => e.stopPropagation()} style={{ maxWidth: '440px' }}>
            <div className="modal-header">
              <span style={{ fontWeight: '600' }}>Confirm Multi-SIEM Scenario Reset</span>
            </div>
            <div className="modal-body" style={{ fontSize: '12px', color: 'var(--text-secondary)', lineHeight: '1.6' }}>
              Are you sure you want to reset the attack scenario? This will regenerate baseline security logs across Splunk, Elastic, Sentinel, QRadar, and Wazuh, while also resetting all <strong>AI threat hunting conversations</strong> and <strong>VirusTotal threat intelligence</strong>.
            </div>
            <div className="modal-footer">
              <button className="btn btn-secondary btn-sm" onClick={() => setShowResetConfirm(false)}>
                Cancel
              </button>
              <button className="btn btn-primary btn-sm" onClick={handleResetDataset}>
                Reset Scenario
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Confirm Clear All Logs Modal */}
      {showClearAllLogsConfirm && (
        <div className="modal-overlay" onClick={() => setShowClearAllLogsConfirm(false)} role="dialog" aria-modal="true">
          <div className="modal-dialog" onClick={(e) => e.stopPropagation()} style={{ maxWidth: '460px' }}>
            <div className="modal-header">
              <span style={{ fontWeight: '600', color: 'var(--sev-critical)' }}>Reset All Platform Telemetry &amp; Intelligence</span>
            </div>
            <div className="modal-body" style={{ fontSize: '12px', color: 'var(--text-secondary)', lineHeight: '1.6' }}>
              Are you sure you want to perform a complete reset? This will wipe:
              <ul style={{ paddingLeft: '18px', marginTop: '6px', marginBottom: '6px' }}>
                <li><strong>All log files and telemetry</strong> across all functionalities</li>
                <li><strong>AI threat hunting tab</strong> (all conversations and memory turns)</li>
                <li><strong>Context-Rich Threat Intelligence</strong> (all VirusTotal v3 cached indicators)</li>
              </ul>
            </div>
            <div className="modal-footer">
              <button className="btn btn-secondary btn-sm" onClick={() => setShowClearAllLogsConfirm(false)}>
                Cancel
              </button>
              <button className="btn btn-danger btn-sm" onClick={handleClearAllLogs}>
                Reset Everything
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Toast Feedback Notifications */}
      <div className="toast-container" role="status" aria-live="polite">
        {toasts.map((t) => (
          <div key={t.id} className={`toast ${t.type}`}>
            <span style={{ fontWeight: '700', color: t.type === 'error' ? 'var(--sev-critical)' : 'var(--sev-low)' }}>
              [{t.type === 'error' ? 'ERR' : 'OK'}]
            </span>
            <span>{t.message}</span>
          </div>
        ))}
      </div>

    </div>
  );
}
