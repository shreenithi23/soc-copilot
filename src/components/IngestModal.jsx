import React, { useState } from 'react';
import { X, Upload, FileText, CheckCircle2 } from 'lucide-react';

export default function IngestModal({ isOpen, onClose, onIngestSuccess, onError }) {
  const [formatType, setFormatType] = useState('auto');
  const [file, setFile] = useState(null);
  const [rawText, setRawText] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);

  if (!isOpen) return null;

  const handleSubmit = async () => {
    if (!file && !rawText.trim()) {
      if (onError) onError('Select a file or paste raw event data to ingest.');
      return;
    }

    setIsSubmitting(true);
    try {
      if (file) {
        const formData = new FormData();
        formData.append('file', file);
        formData.append('format_type', formatType);

        const res = await fetch('/api/logs/upload', {
          method: 'POST',
          body: formData
        });
        const data = await res.json();
        if (data.status === 'success') {
          const detail = `Ingested ${data.ingested_count} events from ${data.filename}`;
          if (onIngestSuccess) onIngestSuccess(detail);
          onClose();
        } else {
          throw new Error(data.detail || 'Ingestion failed');
        }
      } else {
        const res = await fetch('/api/logs/ingest-text', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ 
            content: rawText, 
            format_type: formatType
          })
        });
        const data = await res.json();
        if (data.status === 'success') {
          const detail = `Ingested ${data.ingested_count} events from text`;
          if (onIngestSuccess) onIngestSuccess(detail);
          onClose();
        } else {
          throw new Error(data.detail || 'Ingestion failed');
        }
      }
    } catch (err) {
      if (onError) onError(`Ingestion failed: ${err.message}`);
    } finally {
      setIsSubmitting(false);
    }
  };


  return (
    <div className="modal-overlay" onClick={onClose} role="dialog" aria-modal="true">
      <div className="modal-dialog" onClick={(e) => e.stopPropagation()}>
        <div className="modal-header">
          <span style={{ fontSize: '13px', fontWeight: '600' }}>Ingest Security Telemetry</span>
          <button className="btn btn-secondary btn-xs" onClick={onClose}>
            <X size={14} />
          </button>
        </div>

        <div className="modal-body">
          <div className="detail-item">
            <label className="detail-key" htmlFor="formatSelect">SIEM Tool / Parser Format</label>
            <select 
              id="formatSelect"
              className="select-ctrl" 
              value={formatType} 
              onChange={(e) => setFormatType(e.target.value)}
              style={{ width: '100%', marginTop: '4px' }}
            >
              <option value="auto">Auto-Detect Format (Splunk, Elastic, Sentinel, QRadar, Wazuh)</option>
              <option value="splunk">Splunk CIM / Key-Value Syslog</option>
              <option value="elastic">Elastic Common Schema (ECS JSON)</option>
              <option value="sentinel">Microsoft Sentinel SecurityAlert JSON</option>
              <option value="qradar">IBM QRadar LEEF 2.0</option>
              <option value="wazuh">Wazuh JSON Alerts</option>
              <option value="csv">Standard Security CSV</option>
            </select>
          </div>

          <div className="detail-item">
            <label className="detail-key">Option A: Upload Log File (.json, .csv, .log, .txt)</label>
            <input 
              type="file" 
              className="input-ctrl" 
              onChange={(e) => setFile(e.target.files[0] || null)}
              style={{ width: '100%', marginTop: '4px' }}
            />
          </div>

          <div className="detail-item">
            <label className="detail-key">Option B: Paste Raw Events or Syslog Strings</label>
            <textarea 
              className="input-ctrl" 
              rows={5} 
              placeholder="Paste raw syslog, LEEF 2.0 strings, or JSON array..."
              value={rawText}
              onChange={(e) => setRawText(e.target.value)}
              style={{ width: '100%', fontFamily: 'var(--font-mono)', fontSize: '11px', marginTop: '4px' }}
            />
          </div>
        </div>

        <div className="modal-footer">
          <button className="btn btn-secondary btn-sm" onClick={onClose} disabled={isSubmitting}>
            Cancel
          </button>
          <button className="btn btn-primary btn-sm" onClick={handleSubmit} disabled={isSubmitting}>
            <Upload size={13} />
            <span>{isSubmitting ? 'Ingesting...' : 'Ingest & Normalize'}</span>
          </button>
        </div>
      </div>
    </div>
  );
}
