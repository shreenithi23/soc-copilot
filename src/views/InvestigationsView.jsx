import React, { useState, useEffect, useRef } from 'react';
import { Send, Sparkles, Plus, Shield, RefreshCw, ChevronDown, ChevronRight, Check, Copy, ExternalLink, Bot, User, Terminal, Trash2 } from 'lucide-react';

// Lightweight, crisp Markdown Formatter for SOC & IR responses
function FormattedContent({ content }) {
  if (!content) return null;

  // Split into lines to parse headings, bullet lists, code blocks, and paragraphs
  const lines = content.split('\n');
  const elements = [];
  let inCodeBlock = false;
  let codeBuffer = [];
  let codeLang = '';

  const renderInline = (text) => {
    // Bold **text** and inline `code`
    const parts = [];
    const regex = /(\*\*[^*]+\*\*|`[^`]+`)/g;
    let lastIndex = 0;
    let match;

    while ((match = regex.exec(text)) !== null) {
      if (match.index > lastIndex) {
        parts.push(text.substring(lastIndex, match.index));
      }
      const token = match[0];
      if (token.startsWith('**') && token.endsWith('**')) {
        parts.push(
          <strong key={match.index} style={{ color: '#ffffff', fontWeight: 600 }}>
            {token.slice(2, -2)}
          </strong>
        );
      } else if (token.startsWith('`') && token.endsWith('`')) {
        parts.push(
          <code 
            key={match.index} 
            style={{ 
              background: 'rgba(12, 147, 126, 0.15)', 
              color: 'var(--harkx-green)', 
              padding: '2px 6px', 
              borderRadius: '4px', 
              fontSize: '11.5px', 
              fontFamily: 'var(--font-mono)',
              border: '1px solid rgba(12, 147, 126, 0.3)'
            }}
          >
            {token.slice(1, -1)}
          </code>
        );
      }
      lastIndex = regex.lastIndex;
    }
    if (lastIndex < text.length) {
      parts.push(text.substring(lastIndex));
    }
    return parts.length > 0 ? parts : text;
  };

  lines.forEach((line, idx) => {
    if (line.startsWith('```')) {
      if (inCodeBlock) {
        // End code block
        const fullCode = codeBuffer.join('\n');
        elements.push(
          <CodeBlockSnippet key={`code-${idx}`} code={fullCode} lang={codeLang} />
        );
        codeBuffer = [];
        codeLang = '';
        inCodeBlock = false;
      } else {
        // Start code block
        inCodeBlock = true;
        codeLang = line.replace('```', '').trim();
      }
      return;
    }

    if (inCodeBlock) {
      codeBuffer.push(line);
      return;
    }

    const trimmed = line.trim();

    if (!trimmed) {
      elements.push(<div key={`spacer-${idx}`} style={{ height: '8px' }} />);
      return;
    }

    // Headings
    if (trimmed.startsWith('### ')) {
      elements.push(
        <h3 key={`h3-${idx}`} style={{ fontSize: '14px', fontWeight: 700, color: '#ffffff', margin: '14px 0 6px 0', borderBottom: '1px solid rgba(255,255,255,0.06)', paddingBottom: '4px' }}>
          {renderInline(trimmed.replace('### ', ''))}
        </h3>
      );
    } else if (trimmed.startsWith('## ')) {
      elements.push(
        <h2 key={`h2-${idx}`} style={{ fontSize: '15px', fontWeight: 700, color: 'var(--harkx-green)', margin: '16px 0 8px 0' }}>
          {renderInline(trimmed.replace('## ', ''))}
        </h2>
      );
    } else if (trimmed.startsWith('---')) {
      elements.push(<hr key={`hr-${idx}`} style={{ border: 'none', borderTop: '1px solid rgba(255,255,255,0.08)', margin: '12px 0' }} />);
    } else if (trimmed.startsWith('* ') || trimmed.startsWith('- ')) {
      elements.push(
        <div key={`li-${idx}`} style={{ display: 'flex', gap: '8px', margin: '4px 0', paddingLeft: '4px' }}>
          <span style={{ color: 'var(--harkx-teal)', fontSize: '13px' }}>&bull;</span>
          <div style={{ flex: 1, fontSize: '12.5px', color: 'var(--text-primary)', lineHeight: '1.6' }}>
            {renderInline(trimmed.slice(2))}
          </div>
        </div>
      );
    } else if (/^\d+\.\s/.test(trimmed)) {
      const numMatch = trimmed.match(/^(\d+\.)\s(.*)/);
      elements.push(
        <div key={`num-${idx}`} style={{ display: 'flex', gap: '8px', margin: '4px 0', paddingLeft: '4px' }}>
          <span style={{ color: 'var(--harkx-green)', fontSize: '12px', fontFamily: 'var(--font-mono)', fontWeight: 600 }}>{numMatch[1]}</span>
          <div style={{ flex: 1, fontSize: '12.5px', color: 'var(--text-primary)', lineHeight: '1.6' }}>
            {renderInline(numMatch[2])}
          </div>
        </div>
      );
    } else {
      elements.push(
        <p key={`p-${idx}`} style={{ margin: '4px 0', fontSize: '12.5px', color: 'var(--text-primary)', lineHeight: '1.6' }}>
          {renderInline(trimmed)}
        </p>
      );
    }
  });

  // Flush dangling code block if not closed
  if (inCodeBlock && codeBuffer.length > 0) {
    elements.push(
      <CodeBlockSnippet key="code-end" code={codeBuffer.join('\n')} lang={codeLang} />
    );
  }

  return <div>{elements}</div>;
}

function CodeBlockSnippet({ code, lang }) {
  const [copied, setCopied] = useState(false);

  const handleCopy = () => {
    navigator.clipboard.writeText(code);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div style={{ margin: '10px 0', borderRadius: '8px', background: '#050608', border: '1px solid rgba(255, 255, 255, 0.1)', overflow: 'hidden' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '6px 12px', background: '#0a0d12', borderBottom: '1px solid rgba(255,255,255,0.06)' }}>
        <span style={{ fontSize: '11px', fontFamily: 'var(--font-mono)', color: 'var(--text-muted)', textTransform: 'uppercase' }}>
          {lang || 'command / script'}
        </span>
        <button 
          onClick={handleCopy}
          style={{ background: 'transparent', border: 'none', color: copied ? 'var(--harkx-green)' : 'var(--text-muted)', cursor: 'pointer', display: 'flex', alignItems: 'center', gap: '4px', fontSize: '11px' }}
        >
          {copied ? <Check size={12} /> : <Copy size={12} />}
          <span>{copied ? 'Copied' : 'Copy'}</span>
        </button>
      </div>
      <pre style={{ margin: 0, padding: '12px', overflowX: 'auto', fontSize: '12px', fontFamily: 'var(--font-mono)', color: '#e2e8f0', lineHeight: '1.5' }}>
        <code>{code}</code>
      </pre>
    </div>
  );
}

export default function InvestigationsView({ initialAlert, onToast, resetKey }) {
  const [messages, setMessages] = useState([]);
  const [inputQuery, setInputQuery] = useState('');
  const [loading, setLoading] = useState(false);
  const [currentSessionId, setCurrentSessionId] = useState(null);
  const [expandedSources, setExpandedSources] = useState({});
  const messagesEndRef = useRef(null);
  const textareaRef = useRef(null);

  useEffect(() => {
    loadLatestSession();
  }, [resetKey]);

  useEffect(() => {
    if (initialAlert) {
      setInputQuery(`Analyze alert '${initialAlert.alert_name}' on target host ${initialAlert.dest_ip || initialAlert.src_ip || 'unknown'} and entity '${initialAlert.user || 'N/A'}'. Reconstruct the attack chain and generate containment steps.`);
      textareaRef.current?.focus();
    }
  }, [initialAlert]);

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages, loading]);

  const loadLatestSession = async () => {
    try {
      const res = await fetch('/api/chat/sessions');
      const sessions = await res.json();
      if (sessions && sessions.length > 0) {
        const latestId = sessions[0].id;
        setCurrentSessionId(latestId);
        const histRes = await fetch(`/api/chat/history/${latestId}`);
        const history = await histRes.json();
        if (history && history.length > 0) {
          setMessages(history);
          return;
        }
      }
      // If no history, leave empty to show the sleek welcome screen
      setMessages([]);
      setCurrentSessionId(null);
    } catch (err) {
      console.error('Failed to load session history:', err);
    }
  };

  const startNewChat = () => {
    setCurrentSessionId(null);
    setMessages([]);
    setInputQuery('');
    setExpandedSources({});
    if (onToast) onToast('Started fresh Aegis AI investigation session');
  };

  const handleClearAllChats = async () => {
    try {
      const res = await fetch('/api/chat/clear', { method: 'POST' });
      const data = await res.json();
      setCurrentSessionId(null);
      setMessages([]);
      setInputQuery('');
      setExpandedSources({});
      if (onToast) onToast(data.message || 'Reset all AI threat hunting conversations');
    } catch (err) {
      if (onToast) onToast(`Failed to reset conversations: ${err.message}`, 'error');
    }
  };

  const handleSubmit = async (presetPrompt) => {
    const text = (presetPrompt || inputQuery).trim();
    if (!text || loading) return;

    setInputQuery('');
    const userMsg = { role: 'user', content: text, created_at: new Date().toISOString() };
    setMessages(prev => [...prev, userMsg]);
    setLoading(true);

    try {
      const res = await fetch('/api/chat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          session_id: currentSessionId,
          message: text
        })
      });
      const data = await res.json();
      setCurrentSessionId(data.session_id);

      const assistantMsg = {
        role: 'assistant',
        content: data.content,
        created_at: new Date().toISOString(),
        model: data.model || 'Gemini 3.6 Flash',
        latency_ms: data.latency_ms,
        context_logs: data.context_logs,
        threat_intel: data.threat_intel
      };

      setMessages(prev => [...prev, assistantMsg]);
    } catch (err) {
      setMessages(prev => [
        ...prev,
        {
          role: 'assistant',
          content: `### Query Execution Error\nFailed to connect to the SOC intelligence engine: ${err.message}`,
          created_at: new Date().toISOString(),
          model: 'Error'
        }
      ]);
    } finally {
      setLoading(false);
    }
  };

  const toggleSourceExpand = (idx) => {
    setExpandedSources(prev => ({
      ...prev,
      [idx]: !prev[idx]
    }));
  };

  const promptSuggestions = [
    {
      title: 'Triage Critical Incidents',
      desc: 'Correlate high & critical alerts across Splunk, Elastic, Sentinel, QRadar, and Wazuh.',
      prompt: 'Triage all critical and high severity alerts across all SIEM sources. Reconstruct the attack timeline and highlight compromised assets.'
    },
    {
      title: 'Investigate Cobalt Strike C2',
      desc: 'Deep-dive into external IP 185.220.101.5 and associated network beaconing.',
      prompt: 'Check external IP 185.220.101.5 against VirusTotal threat intelligence and explain the Cobalt Strike C2 activity observed in Splunk.'
    },
    {
      title: 'Compromised Hosts & Users',
      desc: 'Identify affected endpoints and hijacked user credentials.',
      prompt: 'Which internal hosts and user accounts have been compromised? List each affected entity with corresponding SIEM evidence.'
    },
    {
      title: 'IR Containment Playbook',
      desc: 'Generate immediate step-by-step isolation commands and firewall rules.',
      prompt: 'Draft a prioritized Incident Response Containment Playbook with actionable commands for compromised host 10.0.4.15 and user victim_jdoe.'
    }
  ];

  return (
    <div style={{ 
      display: 'flex', 
      flexDirection: 'column', 
      height: 'calc(100vh - 82px)', 
      maxWidth: '920px', 
      margin: '0 auto', 
      width: '100%',
      padding: '0 16px'
    }}>
      
      {/* Sleek Top Chat Header */}
      <div style={{
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center',
        padding: '12px 18px',
        background: '#07080a',
        border: '1px solid var(--border-color)',
        borderRadius: '12px',
        marginTop: '8px',
        marginBottom: '12px',
        flexShrink: 0
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          <div style={{
            width: '34px',
            height: '34px',
            borderRadius: '10px',
            background: 'linear-gradient(135deg, rgba(12, 147, 126, 0.25) 0%, rgba(106, 191, 47, 0.15) 100%)',
            border: '1px solid var(--harkx-teal)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            boxShadow: '0 0 12px rgba(12, 147, 126, 0.25)'
          }}>
            <Sparkles size={16} color="var(--harkx-green)" />
          </div>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <span style={{ fontSize: '13px', fontWeight: 700, color: '#ffffff' }}>Aegis AI Threat Hunting</span>
              <span style={{ 
                fontSize: '9.5px', 
                fontFamily: 'var(--font-mono)', 
                color: 'var(--harkx-green)', 
                background: 'rgba(106, 191, 47, 0.1)', 
                padding: '2px 6px', 
                borderRadius: '4px',
                border: '1px solid rgba(106, 191, 47, 0.25)' 
              }}>
                ONLINE &bull; GEMINI 2.5 FLASH
              </span>
            </div>
            <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
              Grounded on Multi-SIEM telemetry &amp; live VirusTotal threat intelligence
            </div>
          </div>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <button 
            className="btn btn-secondary btn-sm"
            onClick={startNewChat}
            style={{ display: 'flex', alignItems: 'center', gap: '6px', borderRadius: '8px', padding: '6px 12px' }}
            title="Start fresh conversation"
          >
            <Plus size={13} />
            <span>New Chat</span>
          </button>

          <button 
            className="btn btn-danger btn-sm"
            onClick={handleClearAllChats}
            style={{ display: 'flex', alignItems: 'center', gap: '6px', borderRadius: '8px', padding: '6px 12px' }}
            title="Reset all AI threat hunting conversations"
          >
            <Trash2 size={13} />
            <span>Reset Conversations</span>
          </button>
        </div>
      </div>

      {/* Main Chat Stream Container */}
      <div style={{ 
        flex: 1, 
        overflowY: 'auto', 
        display: 'flex', 
        flexDirection: 'column', 
        gap: '18px', 
        paddingRight: '6px',
        paddingBottom: '16px'
      }}>

        {/* Empty State: Clean Welcome & Quick Starters */}
        {messages.length === 0 && (
          <div style={{ 
            margin: 'auto 0', 
            display: 'flex', 
            flexDirection: 'column', 
            alignItems: 'center', 
            textAlign: 'center', 
            padding: '30px 20px' 
          }}>
            <div style={{
              width: '54px',
              height: '54px',
              borderRadius: '16px',
              background: 'linear-gradient(135deg, rgba(12, 147, 126, 0.3) 0%, rgba(106, 191, 47, 0.2) 100%)',
              border: '1px solid var(--harkx-teal)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              marginBottom: '16px',
              boxShadow: '0 0 24px rgba(12, 147, 126, 0.2)'
            }}>
              <Shield size={26} color="var(--harkx-green)" />
            </div>

            <h2 style={{ fontSize: '18px', fontWeight: 700, color: '#ffffff', marginBottom: '8px' }}>
              How can Aegis AI assist your threat investigation?
            </h2>
            <p style={{ fontSize: '13px', color: 'var(--text-secondary)', maxWidth: '560px', lineHeight: '1.6', marginBottom: '28px' }}>
              Ask questions directly about your ingested SIEM logs (Splunk, Elastic, Sentinel, QRadar, Wazuh) or query cached VirusTotal threat intelligence.
            </p>

            {/* 2x2 Clean Starter Cards */}
            <div style={{ 
              display: 'grid', 
              gridTemplateColumns: 'repeat(2, 1fr)', 
              gap: '12px', 
              width: '100%', 
              maxWidth: '680px',
              textAlign: 'left'
            }}>
              {promptSuggestions.map((item, idx) => (
                <div 
                  key={idx}
                  onClick={() => handleSubmit(item.prompt)}
                  style={{
                    padding: '14px 16px',
                    borderRadius: '10px',
                    background: '#090a0d',
                    border: '1px solid rgba(255, 255, 255, 0.08)',
                    cursor: 'pointer',
                    transition: 'all 0.2s ease',
                    boxShadow: '0 2px 8px rgba(0,0,0,0.3)'
                  }}
                  onMouseEnter={(e) => {
                    e.currentTarget.style.borderColor = 'var(--harkx-teal)';
                    e.currentTarget.style.transform = 'translateY(-2px)';
                    e.currentTarget.style.background = '#0e1117';
                  }}
                  onMouseLeave={(e) => {
                    e.currentTarget.style.borderColor = 'rgba(255, 255, 255, 0.08)';
                    e.currentTarget.style.transform = 'translateY(0)';
                    e.currentTarget.style.background = '#090a0d';
                  }}
                >
                  <div style={{ fontSize: '13px', fontWeight: 600, color: '#ffffff', marginBottom: '4px' }}>
                    {item.title}
                  </div>
                  <div style={{ fontSize: '11.5px', color: 'var(--text-muted)', lineHeight: '1.4' }}>
                    {item.desc}
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Message History */}
        {messages.map((m, idx) => {
          const isUser = m.role === 'user';
          const hasCitations = !isUser && ((m.context_logs && m.context_logs.length > 0) || (m.threat_intel && Object.keys(m.threat_intel.ips || {}).length > 0));
          const isExpanded = !!expandedSources[idx];

          return (
            <div 
              key={idx}
              style={{
                display: 'flex',
                gap: '12px',
                alignSelf: isUser ? 'flex-end' : 'flex-start',
                maxWidth: isUser ? '80%' : '100%',
                width: isUser ? 'auto' : '100%',
                flexDirection: isUser ? 'row-reverse' : 'row'
              }}
            >
              {/* Avatar Icon */}
              <div style={{
                width: '32px',
                height: '32px',
                borderRadius: '8px',
                background: isUser ? '#1a2230' : 'linear-gradient(135deg, rgba(12, 147, 126, 0.25) 0%, rgba(106, 191, 47, 0.15) 100%)',
                border: `1px solid ${isUser ? '#334155' : 'var(--harkx-teal)'}`,
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                color: isUser ? '#94a3b8' : 'var(--harkx-green)',
                flexShrink: 0
              }}>
                {isUser ? <User size={15} /> : <Bot size={15} />}
              </div>

              {/* Message Content Bubble */}
              <div style={{ flex: 1, minWidth: 0, display: 'flex', flexDirection: 'column', gap: '6px' }}>
                
                {/* Meta line */}
                <div style={{ 
                  display: 'flex', 
                  alignItems: 'center', 
                  gap: '8px', 
                  justifyContent: isUser ? 'flex-end' : 'flex-start',
                  fontSize: '11px',
                  color: 'var(--text-muted)',
                  fontFamily: 'var(--font-mono)'
                }}>
                  <span style={{ fontWeight: 600, color: isUser ? 'var(--text-secondary)' : 'var(--harkx-green)' }}>
                    {isUser ? 'You (Analyst)' : 'Aegis AI'}
                  </span>
                  {m.latency_ms && (
                    <span>&bull; {m.latency_ms} ms</span>
                  )}
                  {m.created_at && (
                    <span>&bull; {new Date(m.created_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</span>
                  )}
                </div>

                {/* Message Body */}
                <div style={{
                  padding: isUser ? '10px 16px' : '16px 20px',
                  borderRadius: '12px',
                  background: isUser ? '#121721' : '#08090c',
                  border: `1px solid ${isUser ? 'rgba(255, 255, 255, 0.12)' : 'rgba(12, 147, 126, 0.25)'}`,
                  fontSize: '13px',
                  lineHeight: '1.6',
                  color: 'var(--text-primary)',
                  boxShadow: isUser ? 'none' : '0 4px 16px rgba(0, 0, 0, 0.4)'
                }}>
                  {isUser ? (
                    <div style={{ whiteSpace: 'pre-wrap' }}>{m.content}</div>
                  ) : (
                    <FormattedContent content={m.content} />
                  )}
                </div>

                {/* Collapsible Telemetry Reference Badge (Inline & Uncluttered) */}
                {hasCitations && (
                  <div style={{ marginTop: '2px' }}>
                    <button
                      onClick={() => toggleSourceExpand(idx)}
                      style={{
                        background: 'transparent',
                        border: '1px solid rgba(255, 255, 255, 0.08)',
                        borderRadius: '6px',
                        padding: '4px 10px',
                        fontSize: '11px',
                        color: 'var(--text-muted)',
                        cursor: 'pointer',
                        display: 'inline-flex',
                        alignItems: 'center',
                        gap: '6px',
                        transition: 'all 0.15s ease'
                      }}
                      onMouseEnter={(e) => e.currentTarget.style.color = 'var(--harkx-green)'}
                      onMouseLeave={(e) => e.currentTarget.style.color = 'var(--text-muted)'}
                    >
                      {isExpanded ? <ChevronDown size={12} /> : <ChevronRight size={12} />}
                      <span style={{ fontFamily: 'var(--font-mono)' }}>
                        {m.context_logs?.length || 0} SIEM logs &bull; {Object.keys(m.threat_intel?.ips || {}).length} VT indicators cited
                      </span>
                    </button>

                    {/* Expanded details */}
                    {isExpanded && (
                      <div style={{
                        marginTop: '8px',
                        padding: '12px',
                        borderRadius: '8px',
                        background: '#040507',
                        border: '1px solid rgba(255, 255, 255, 0.06)',
                        fontSize: '11.5px',
                        display: 'flex',
                        flexDirection: 'column',
                        gap: '8px'
                      }}>
                        {/* Threat Intel citations */}
                        {m.threat_intel?.ips && Object.keys(m.threat_intel.ips).length > 0 && (
                          <div>
                            <div style={{ fontSize: '10px', color: 'var(--text-muted)', textTransform: 'uppercase', fontFamily: 'var(--font-mono)', marginBottom: '4px' }}>
                              VirusTotal Threat Indicators:
                            </div>
                            <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px' }}>
                              {Object.entries(m.threat_intel.ips).map(([ip, info]) => (
                                <span key={ip} className="code-val" style={{ display: 'inline-flex', alignItems: 'center', gap: '6px' }}>
                                  <span>{ip}</span>
                                  <span className={`badge-sev ${info.malicious_count > 0 ? 'critical' : 'low'}`} style={{ fontSize: '9px', padding: '1px 4px' }}>
                                    VT {info.malicious_count}/90
                                  </span>
                                </span>
                              ))}
                            </div>
                          </div>
                        )}

                        {/* SIEM logs citations */}
                        {m.context_logs && m.context_logs.length > 0 && (
                          <div>
                            <div style={{ fontSize: '10px', color: 'var(--text-muted)', textTransform: 'uppercase', fontFamily: 'var(--font-mono)', marginBottom: '4px' }}>
                              Correlated Log Sources:
                            </div>
                            <div style={{ display: 'flex', flexWrap: 'wrap', gap: '4px' }}>
                              {m.context_logs.map((log, lIdx) => (
                                <span key={lIdx} className="badge-tech" style={{ fontSize: '10px' }}>
                                  {log.siem_source}: {log.alert_name}
                                </span>
                              ))}
                            </div>
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                )}

              </div>
            </div>
          );
        })}

        {/* Loading Indicator */}
        {loading && (
          <div style={{ display: 'flex', gap: '12px', alignItems: 'center', alignSelf: 'flex-start' }}>
            <div style={{
              width: '32px',
              height: '32px',
              borderRadius: '8px',
              background: 'linear-gradient(135deg, rgba(12, 147, 126, 0.25) 0%, rgba(106, 191, 47, 0.15) 100%)',
              border: '1px solid var(--harkx-teal)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              color: 'var(--harkx-green)'
            }}>
              <Sparkles size={15} />
            </div>
            <div style={{
              padding: '10px 16px',
              borderRadius: '10px',
              background: '#08090c',
              border: '1px solid rgba(12, 147, 126, 0.3)',
              fontSize: '12px',
              fontFamily: 'var(--font-mono)',
              color: 'var(--harkx-teal)',
              display: 'flex',
              alignItems: 'center',
              gap: '8px'
            }}>
              <RefreshCw size={12} className="animate-spin" />
              <span>Aegis AI is analyzing multi-SIEM events and correlating threat intelligence...</span>
            </div>
          </div>
        )}

        <div ref={messagesEndRef} />
      </div>

      {/* Floating Bottom Input Bar */}
      <div style={{ 
        paddingTop: '10px', 
        paddingBottom: '8px', 
        borderTop: '1px solid rgba(255, 255, 255, 0.08)', 
        background: '#000000',
        flexShrink: 0
      }}>
        <div style={{ 
          display: 'flex', 
          gap: '8px', 
          alignItems: 'center',
          background: '#090b0e',
          border: '1px solid rgba(255, 255, 255, 0.12)',
          borderRadius: '12px',
          padding: '6px 8px 6px 14px',
          boxShadow: '0 4px 20px rgba(0,0,0,0.5)',
          transition: 'border-color 0.2s ease'
        }}>
          <input
            ref={textareaRef}
            type="text"
            className="input-ctrl"
            placeholder="Ask Aegis AI about alerts, IOCs, compromised hosts, or containment steps..."
            value={inputQuery}
            onChange={(e) => setInputQuery(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === 'Enter') {
                e.preventDefault();
                handleSubmit();
              }
            }}
            disabled={loading}
            style={{ 
              flex: 1, 
              background: 'transparent', 
              border: 'none', 
              outline: 'none',
              boxShadow: 'none',
              padding: '8px 0',
              fontSize: '13px',
              color: '#ffffff'
            }}
          />
          <button 
            className="btn btn-primary"
            onClick={() => handleSubmit()}
            disabled={loading || !inputQuery.trim()}
            style={{
              padding: '8px 16px',
              borderRadius: '8px',
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
              fontWeight: 600
            }}
          >
            <span>Send</span>
            <Send size={13} />
          </button>
        </div>

        <div style={{ 
          textAlign: 'center', 
          fontSize: '10.5px', 
          color: 'var(--text-muted)', 
          marginTop: '6px', 
          fontFamily: 'var(--font-mono)' 
        }}>
          Aegis AI references live Multi-SIEM logs (Splunk, Elastic, Sentinel, QRadar, Wazuh) and cached VirusTotal v3 threat feeds.
        </div>
      </div>

    </div>
  );
}
