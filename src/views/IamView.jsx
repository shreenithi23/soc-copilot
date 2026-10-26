import React, { useState } from 'react';
import { Users, Key, ShieldCheck, ShieldX, UserCheck, AlertOctagon, Search } from 'lucide-react';

export default function IamView({ iamData }) {
  const [searchTerm, setSearchTerm] = useState('');
  const [decisionFilter, setDecisionFilter] = useState('all');

  const identities = (iamData?.identities || []).filter(i => {
    if (searchTerm) {
      const q = searchTerm.toLowerCase();
      return i.username.toLowerCase().includes(q) || i.role.toLowerCase().includes(q);
    }
    return true;
  });

  const policyEvaluations = (iamData?.policy_evaluations || []).filter(p => {
    if (decisionFilter !== 'all' && p.decision !== decisionFilter) return false;
    if (searchTerm) {
      const q = searchTerm.toLowerCase();
      return p.identity.toLowerCase().includes(q) || p.resource.toLowerCase().includes(q) || p.reason.toLowerCase().includes(q);
    }
    return true;
  });

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
      
      {/* Top IAM Stat Bar */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '12px' }}>
        <div className="panel" style={{ padding: '12px 14px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span style={{ fontSize: '11px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', textTransform: 'uppercase' }}>
              Identities Tracked
            </span>
            <Users size={15} color="#38bdf8" />
          </div>
          <div style={{ fontSize: '22px', fontWeight: '700', fontFamily: 'var(--font-mono)', color: 'var(--text-primary)', margin: '4px 0 2px' }}>
            {iamData?.identities?.length || 0}
          </div>
          <span style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>
            Users &amp; Service Accounts in Telemetry
          </span>
        </div>

        <div className="panel" style={{ padding: '12px 14px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span style={{ fontSize: '11px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', textTransform: 'uppercase' }}>
              Authorization Denials
            </span>
            <ShieldX size={15} color="var(--sev-critical)" />
          </div>
          <div style={{ fontSize: '22px', fontWeight: '700', fontFamily: 'var(--font-mono)', color: 'var(--sev-critical)', margin: '4px 0 2px' }}>
            {(iamData?.policy_evaluations || []).filter(p => p.decision === 'DENY').length}
          </div>
          <span style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>
            Blocked Access or Brute-Force Events
          </span>
        </div>

        <div className="panel" style={{ padding: '12px 14px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span style={{ fontSize: '11px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', textTransform: 'uppercase' }}>
              Step-Up MFA Required
            </span>
            <Key size={15} color="var(--sev-high)" />
          </div>
          <div style={{ fontSize: '22px', fontWeight: '700', fontFamily: 'var(--font-mono)', color: 'var(--sev-high)', margin: '4px 0 2px' }}>
            {(iamData?.policy_evaluations || []).filter(p => p.decision === 'STEP-UP REQUIRED').length}
          </div>
          <span style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>
            Kerberos / Privileged Ticket Requests
          </span>
        </div>
      </div>

      {/* Two-Column IAM View */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1.3fr', gap: '16px' }}>
        
        {/* Left: Identity Directory Table */}
        <div className="panel">
          <div className="panel-header">
            <span className="panel-title">
              <Users size={14} />
              <span>Identity Directory &amp; Risk Posture</span>
            </span>
          </div>
          <div className="table-container" style={{ border: 'none', borderRadius: '0' }}>
            <table className="data-table">
              <thead>
                <tr>
                  <th>Identity / Account</th>
                  <th>Role Classification</th>
                  <th style={{ width: '85px' }}>Risk</th>
                  <th style={{ width: '70px', textAlign: 'center' }}>Alerts</th>
                </tr>
              </thead>
              <tbody>
                {identities.length === 0 ? (
                  <tr><td colSpan={4} className="empty-state">No identities located in ingested logs.</td></tr>
                ) : (
                  identities.map((id, idx) => (
                    <tr key={idx}>
                      <td>
                        <strong className="text-mono" style={{ color: '#38bdf8', fontSize: '12px' }}>{id.username}</strong>
                        <div style={{ fontSize: '10px', color: 'var(--text-muted)' }}>
                          IPs: {id.source_ips.join(', ') || 'Internal'}
                        </div>
                      </td>
                      <td>
                        <span className="badge-tech">{id.role}</span>
                      </td>
                      <td>
                        <span className={`badge-sev ${(id.risk_level || 'low').toLowerCase()}`}>
                          {id.risk_level}
                        </span>
                      </td>
                      <td style={{ textAlign: 'center', fontFamily: 'var(--font-mono)', fontWeight: '600' }}>
                        {id.alert_count}
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>

        {/* Right: Policy Evaluation Decisions */}
        <div className="panel">
          <div className="panel-header">
            <span className="panel-title">
              <ShieldCheck size={14} />
              <span>Policy Evaluation &amp; Authorization Decisions</span>
            </span>
            <div style={{ display: 'flex', gap: '6px' }}>
              <select className="select-ctrl" value={decisionFilter} onChange={(e) => setDecisionFilter(e.target.value)} style={{ fontSize: '10px', padding: '2px 6px' }}>
                <option value="all">All Outcomes</option>
                <option value="DENY">DENY</option>
                <option value="STEP-UP REQUIRED">STEP-UP REQUIRED</option>
                <option value="ALLOW">ALLOW</option>
              </select>
            </div>
          </div>
          <div className="table-container" style={{ border: 'none', borderRadius: '0' }}>
            <table className="data-table">
              <thead>
                <tr>
                  <th style={{ width: '110px' }}>Outcome</th>
                  <th>Identity &rarr; Resource</th>
                  <th>Evaluation Reason &amp; Source</th>
                </tr>
              </thead>
              <tbody>
                {policyEvaluations.length === 0 ? (
                  <tr><td colSpan={3} className="empty-state">No policy evaluation records available.</td></tr>
                ) : (
                  policyEvaluations.map((p) => {
                    const authClass = p.decision === 'ALLOW' ? 'allow' : p.decision === 'DENY' ? 'deny' : 'stepup';
                    return (
                      <tr key={p.id}>
                        <td>
                          <span className={`badge-auth ${authClass}`}>
                            {p.decision}
                          </span>
                        </td>
                        <td>
                          <div className="text-mono" style={{ fontWeight: '600', color: 'var(--text-primary)', fontSize: '11px' }}>
                            {p.identity}
                          </div>
                          <div style={{ fontSize: '10px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                            &rarr; {p.resource}
                          </div>
                        </td>
                        <td>
                          <div style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>
                            {p.reason}
                          </div>
                          <div style={{ fontSize: '9px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', marginTop: '2px' }}>
                            SIEM: {p.siem_source} &bull; {p.timestamp ? p.timestamp.slice(11, 19) : ''}
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

      </div>

    </div>
  );
}
