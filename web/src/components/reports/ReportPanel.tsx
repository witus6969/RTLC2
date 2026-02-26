// ═══════════════════════════════════════════════════════════════
//  RTLC2 Report Generation Panel
//  Select templates, date range, format, and generate/download reports.
// ═══════════════════════════════════════════════════════════════

import { useState, useEffect } from 'react';
import { useReportStore } from '../../store/reportStore';

const FORMAT_OPTIONS = [
  { value: 'json', label: 'JSON' },
  { value: 'csv', label: 'CSV' },
  { value: 'markdown', label: 'Markdown' },
];

export default function ReportPanel() {
  const { templates, generating, lastReport, fetchTemplates, generate, clear } = useReportStore();

  const [selectedTemplate, setSelectedTemplate] = useState('');
  const [format, setFormat] = useState('markdown');
  const [dateFrom, setDateFrom] = useState('');
  const [dateTo, setDateTo] = useState('');
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetchTemplates();
    // Default date range: last 30 days
    const now = new Date();
    const monthAgo = new Date(now);
    monthAgo.setDate(monthAgo.getDate() - 30);
    setDateTo(now.toISOString().split('T')[0]);
    setDateFrom(monthAgo.toISOString().split('T')[0]);
  }, [fetchTemplates]);

  useEffect(() => {
    if (templates.length > 0 && !selectedTemplate) {
      setSelectedTemplate(templates[0].id);
    }
  }, [templates, selectedTemplate]);

  const handleGenerate = async () => {
    if (!selectedTemplate) {
      setError('Select a report template');
      return;
    }
    setError(null);
    try {
      await generate(selectedTemplate, format, dateFrom, dateTo);
    } catch (err: any) {
      setError(err.message || 'Failed to generate report');
    }
  };

  const handleDownload = () => {
    if (!lastReport) return;
    const ext = lastReport.format === 'json' ? 'json' : lastReport.format === 'csv' ? 'csv' : 'md';
    const mime = lastReport.format === 'json' ? 'application/json' : lastReport.format === 'csv' ? 'text/csv' : 'text/markdown';
    const blob = new Blob([lastReport.data], { type: mime });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `rtlc2-${lastReport.template}-${new Date().toISOString().slice(0, 10)}.${ext}`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const selectedTmpl = templates.find((t) => t.id === selectedTemplate);

  // ── Styles ──────────────────────────────────────────────────

  const containerStyle: React.CSSProperties = {
    display: 'flex',
    flexDirection: 'column',
    height: '100%',
    background: '#0a0a0a',
    color: '#e0e0e0',
  };

  const toolbarStyle: React.CSSProperties = {
    display: 'flex',
    alignItems: 'center',
    gap: '8px',
    padding: '8px 12px',
    borderBottom: '1px solid #222',
    background: '#111',
    flexShrink: 0,
  };

  const btnStyle: React.CSSProperties = {
    padding: '4px 12px',
    background: '#1a1a1a',
    border: '1px solid #333',
    borderRadius: '3px',
    color: '#e0e0e0',
    cursor: 'pointer',
    fontSize: '12px',
    fontFamily: 'inherit',
  };

  const btnAccentStyle: React.CSSProperties = {
    ...btnStyle,
    background: '#cc0000',
    borderColor: '#cc0000',
    color: '#fff',
  };

  const inputStyle: React.CSSProperties = {
    padding: '6px 10px',
    background: '#0a0a0a',
    border: '1px solid #333',
    borderRadius: '3px',
    color: '#e0e0e0',
    fontSize: '12px',
    fontFamily: 'inherit',
    outline: 'none',
    boxSizing: 'border-box',
  };

  const selectStyle: React.CSSProperties = {
    ...inputStyle,
    cursor: 'pointer',
    appearance: 'none',
    backgroundImage:
      'url("data:image/svg+xml;charset=utf-8,%3Csvg xmlns=%27http://www.w3.org/2000/svg%27 width=%2712%27 height=%278%27%3E%3Cpath fill=%27%23888%27 d=%27M6 8L0 0h12z%27/%3E%3C/svg%3E")',
    backgroundRepeat: 'no-repeat',
    backgroundPosition: 'right 10px center',
    paddingRight: '30px',
  };

  const labelStyle: React.CSSProperties = {
    display: 'block',
    fontSize: '10px',
    color: '#666',
    marginBottom: '4px',
    textTransform: 'uppercase',
    letterSpacing: '0.5px',
    fontFamily: 'monospace',
  };

  const formContainerStyle: React.CSSProperties = {
    padding: '14px 16px',
    background: '#0d0d0d',
    borderBottom: '1px solid #222',
    flexShrink: 0,
  };

  const fieldStyle: React.CSSProperties = {
    marginBottom: '10px',
  };

  const emptyStyle: React.CSSProperties = {
    display: 'flex',
    flexDirection: 'column',
    alignItems: 'center',
    justifyContent: 'center',
    height: '100%',
    color: '#444',
    fontSize: '14px',
    gap: '8px',
  };

  // ── Render ──────────────────────────────────────────────────

  return (
    <div style={containerStyle}>
      {/* Toolbar */}
      <div style={toolbarStyle}>
        <span style={{ fontSize: '13px', fontWeight: 600, color: '#cc0000' }}>
          Reports
        </span>
        <span style={{ fontSize: '11px', color: '#555' }}>
          ({templates.length} templates)
        </span>
        <div style={{ flex: 1 }} />
        {lastReport && (
          <>
            <button style={btnStyle} onClick={handleDownload}>
              Download
            </button>
            <button style={btnStyle} onClick={clear}>
              Clear
            </button>
          </>
        )}
      </div>

      {/* Error */}
      {error && (
        <div
          style={{
            padding: '6px 12px',
            background: '#1a0000',
            borderBottom: '1px solid #330000',
            color: '#cc0000',
            fontSize: '11px',
            flexShrink: 0,
          }}
        >
          {error}
        </div>
      )}

      {/* Configuration Form */}
      <div style={formContainerStyle}>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr 1fr', gap: '10px' }}>
          <div style={fieldStyle}>
            <label style={labelStyle}>Template</label>
            <select
              style={{ ...selectStyle, width: '100%' }}
              value={selectedTemplate}
              onChange={(e) => setSelectedTemplate(e.target.value)}
            >
              <option value="">-- Select --</option>
              {templates.map((t) => (
                <option key={t.id} value={t.id}>{t.name}</option>
              ))}
            </select>
          </div>
          <div style={fieldStyle}>
            <label style={labelStyle}>Format</label>
            <select
              style={{ ...selectStyle, width: '100%' }}
              value={format}
              onChange={(e) => setFormat(e.target.value)}
            >
              {FORMAT_OPTIONS.map((f) => (
                <option key={f.value} value={f.value}>{f.label}</option>
              ))}
            </select>
          </div>
          <div style={fieldStyle}>
            <label style={labelStyle}>Date From</label>
            <input
              type="date"
              style={{ ...inputStyle, width: '100%', colorScheme: 'dark' }}
              value={dateFrom}
              onChange={(e) => setDateFrom(e.target.value)}
            />
          </div>
          <div style={fieldStyle}>
            <label style={labelStyle}>Date To</label>
            <input
              type="date"
              style={{ ...inputStyle, width: '100%', colorScheme: 'dark' }}
              value={dateTo}
              onChange={(e) => setDateTo(e.target.value)}
            />
          </div>
        </div>
        {selectedTmpl && (
          <div style={{ fontSize: '11px', color: '#555', marginBottom: '8px' }}>
            {selectedTmpl.description}
          </div>
        )}
        <div style={{ display: 'flex', gap: '8px', justifyContent: 'flex-end' }}>
          <button
            style={btnAccentStyle}
            onClick={handleGenerate}
            disabled={generating}
          >
            {generating ? 'Generating...' : 'Generate Report'}
          </button>
        </div>
      </div>

      {/* Report Preview */}
      {lastReport ? (
        <div style={{ flex: 1, overflow: 'auto', padding: '12px' }}>
          <div style={{
            fontSize: '10px',
            color: '#555',
            marginBottom: '8px',
            fontFamily: 'monospace',
          }}>
            Generated: {lastReport.generated} | Template: {lastReport.template} | Format: {lastReport.format}
          </div>
          <pre style={{
            background: '#0d0d0d',
            border: '1px solid #222',
            borderRadius: '4px',
            padding: '12px',
            fontSize: '11px',
            fontFamily: 'var(--font-mono, monospace)',
            color: '#ccc',
            whiteSpace: 'pre-wrap',
            wordBreak: 'break-word',
            margin: 0,
            overflow: 'auto',
          }}>
            {lastReport.data}
          </pre>
        </div>
      ) : (
        <div style={emptyStyle}>
          <span style={{ fontSize: '32px', opacity: 0.3 }}>[R]</span>
          <span>No report generated</span>
          <span style={{ fontSize: '11px', color: '#333' }}>
            Select a template and click Generate to create a report
          </span>
        </div>
      )}
    </div>
  );
}
