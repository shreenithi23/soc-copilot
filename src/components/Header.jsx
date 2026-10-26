import React from 'react';
import { RefreshCw, Upload, Sparkles, Terminal, Trash2 } from 'lucide-react';

export default function Header({ 
  activeTab, 
  stats, 
  onResetDataset, 
  onClearAllLogs,
  onOpenIngestModal, 
  onOpenSettings 
}) {
  const titles = {
    overview: 'Agentic Defense & Security Overview',
    alerts: 'Unified Alert Center',
    investigations: 'Aegis Autonomous Threat Hunting & Playbooks',
    iam: 'Identity & Access Control Visibility',
    intel: 'Context-Rich Threat Intelligence (VirusTotal v3)',
    audit: 'Operational Audit & Compliance Governance',
    settings: 'Aegis Platform Pipeline & Evaluation'
  };

  return (
    <header className="app-topbar" role="banner">
      <div className="topbar-left">
        <span className="breadcrumb-root">Aegis Platform</span>
        <span className="breadcrumb-sep">/</span>
        <span className="breadcrumb-current">{titles[activeTab] || 'Console'}</span>
      </div>

      <div className="topbar-right">

        <button 
          className="btn btn-secondary btn-sm" 
          onClick={onOpenIngestModal}
          title="Ingest raw security logs or SIEM dataset"
        >
          <Upload size={13} />
          <span>Ingest Telemetry</span>
        </button>

        <button 
          className="btn btn-danger btn-sm" 
          onClick={onClearAllLogs}
          title="Reset all log files across all functionalities"
        >
          <Trash2 size={13} />
          <span>Reset All Logs</span>
        </button>

        <button 
          className="btn btn-primary btn-sm" 
          onClick={onResetDataset}
          title="Reset multi-SIEM attack simulation scenario"
        >
          <RefreshCw size={13} />
          <span>Reset Scenario</span>
        </button>
      </div>
    </header>
  );
}

