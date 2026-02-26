// ═══════════════════════════════════════════════════════════════
//  RTLC2 Download Cradle Generator Dialog
//  Modal for generating download cradles in various formats.
// ═══════════════════════════════════════════════════════════════

import { useState } from 'react';
import { api } from '../../api/client';

interface DownloadCradleDialogProps {
  onClose: () => void;
}

const CRADLE_FORMATS = [
  { value: 'powershell', label: 'PowerShell (IEX)' },
  { value: 'powershell_iwr', label: 'PowerShell (Invoke-WebRequest)' },
  { value: 'certutil', label: 'CertUtil' },
  { value: 'curl', label: 'cURL' },
  { value: 'wget', label: 'wget' },
  { value: 'bitsadmin', label: 'BITSAdmin' },
  { value: 'python', label: 'Python' },
  { value: 'mshta', label: 'MSHTA' },
  { value: 'regsvr32', label: 'RegSvr32' },
  { value: 'rundll32', label: 'RunDLL32' },
  { value: 'bash', label: 'Bash' },
  { value: 'perl', label: 'Perl' },
] as const;

export default function DownloadCradleDialog({ onClose }: DownloadCradleDialogProps) {
  const [format, setFormat] = useState<string>(CRADLE_FORMATS[0].value);
  const [url, setUrl] = useState('');
  const [proxy, setProxy] = useState('');
  const [generatedCradle, setGeneratedCradle] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  const handleGenerate = async () => {
    if (!url.trim()) {
      setError('URL is required');
      return;
    }

    setIsLoading(true);
    setError(null);
    setGeneratedCradle(null);

    try {
      const res = await api.generateCradle({
        url: url.trim(),
        format,
        proxy: proxy.trim() || undefined,
      });
      setGeneratedCradle(res.cradle);
    } catch (err: any) {
      setError(err.message || 'Failed to generate cradle');
    } finally {
      setIsLoading(false);
    }
  };

  const handleCopy = () => {
    if (!generatedCradle) return;
    navigator.clipboard.writeText(generatedCradle).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    });
  };

  // ── Styles ──────────────────────────────────────────────────

  const backdropStyle: React.CSSProperties = {
    position: 'fixed',
    top: 0,
    left: 0,
    right: 0,
    bottom: 0,
    background: 'rgba(0,0,0,0.8)',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    zIndex: 9999,
  };

  const dialogStyle: React.CSSProperties = {
    background: '#111',
    border: '1px solid #333',
    borderRadius: '6px',
    width: '540px',
    maxWidth: '90vw',
    maxHeight: '85vh',
    display: 'flex',
    flexDirection: 'column',
    overflow: 'hidden',
    boxShadow: '0 8px 32px rgba(0,0,0,0.6)',
  };

  const headerStyle: React.CSSProperties = {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
    padding: '12px 16px',
    borderBottom: '1px solid #222',
    background: '#0d0d0d',
  };

  const bodyStyle: React.CSSProperties = {
    padding: '16px',
    overflow: 'auto',
    flex: 1,
  };

  const labelStyle: React.CSSProperties = {
    display: 'block',
    fontSize: '11px',
    color: '#888',
    marginBottom: '4px',
    fontFamily: 'monospace',
    textTransform: 'uppercase',
    letterSpacing: '0.5px',
  };

  const inputStyle: React.CSSProperties = {
    width: '100%',
    padding: '8px 10px',
    background: '#0a0a0a',
    border: '1px solid #333',
    borderRadius: '3px',
    color: '#e0e0e0',
    fontSize: '13px',
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

  const fieldGroupStyle: React.CSSProperties = {
    marginBottom: '14px',
  };

  const btnStyle: React.CSSProperties = {
    padding: '6px 16px',
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

  const codeBlockStyle: React.CSSProperties = {
    background: '#0a0a0a',
    border: '1px solid #222',
    borderRadius: '4px',
    padding: '12px',
    fontFamily: '"Cascadia Code", "Fira Code", "Consolas", monospace',
    fontSize: '12px',
    color: '#cc0000',
    whiteSpace: 'pre-wrap',
    wordBreak: 'break-all',
    lineHeight: 1.5,
    maxHeight: '200px',
    overflow: 'auto',
    position: 'relative',
  };

  const closeBtnStyle: React.CSSProperties = {
    background: 'none',
    border: 'none',
    color: '#666',
    cursor: 'pointer',
    fontSize: '18px',
    fontFamily: 'monospace',
    padding: '0 4px',
    lineHeight: 1,
  };

  // ── Render ──────────────────────────────────────────────────

  return (
    <div style={backdropStyle} onClick={onClose}>
      <div style={dialogStyle} onClick={(e) => e.stopPropagation()}>
        {/* Header */}
        <div style={headerStyle}>
          <span style={{ fontSize: '14px', fontWeight: 600, color: '#cc0000' }}>
            Download Cradle Generator
          </span>
          <button
            style={closeBtnStyle}
            onClick={onClose}
            onMouseEnter={(e) => { (e.currentTarget as HTMLButtonElement).style.color = '#cc0000'; }}
            onMouseLeave={(e) => { (e.currentTarget as HTMLButtonElement).style.color = '#666'; }}
          >
            X
          </button>
        </div>

        {/* Body */}
        <div style={bodyStyle}>
          {/* Format Select */}
          <div style={fieldGroupStyle}>
            <label style={labelStyle}>Format</label>
            <select
              style={selectStyle}
              value={format}
              onChange={(e) => {
                setFormat(e.target.value);
                setGeneratedCradle(null);
              }}
            >
              {CRADLE_FORMATS.map((f) => (
                <option key={f.value} value={f.value}>
                  {f.label}
                </option>
              ))}
            </select>
          </div>

          {/* URL Input */}
          <div style={fieldGroupStyle}>
            <label style={labelStyle}>URL (required)</label>
            <input
              type="text"
              placeholder="https://your-server/payload.exe"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              style={inputStyle}
              onFocus={(e) => { e.currentTarget.style.borderColor = '#cc0000'; }}
              onBlur={(e) => { e.currentTarget.style.borderColor = '#333'; }}
            />
          </div>

          {/* Proxy Input */}
          <div style={fieldGroupStyle}>
            <label style={labelStyle}>Proxy (optional)</label>
            <input
              type="text"
              placeholder="http://proxy:8080"
              value={proxy}
              onChange={(e) => setProxy(e.target.value)}
              style={inputStyle}
              onFocus={(e) => { e.currentTarget.style.borderColor = '#cc0000'; }}
              onBlur={(e) => { e.currentTarget.style.borderColor = '#333'; }}
            />
          </div>

          {/* Generate Button */}
          <div style={{ display: 'flex', gap: '8px', marginBottom: '14px' }}>
            <button
              style={btnAccentStyle}
              onClick={handleGenerate}
              disabled={isLoading || !url.trim()}
            >
              {isLoading ? 'Generating...' : 'Generate'}
            </button>
          </div>

          {/* Error */}
          {error && (
            <div
              style={{
                padding: '8px 10px',
                background: '#1a0000',
                border: '1px solid #330000',
                borderRadius: '3px',
                color: '#cc0000',
                fontSize: '12px',
                marginBottom: '14px',
              }}
            >
              {error}
            </div>
          )}

          {/* Generated Cradle Output */}
          {generatedCradle && (
            <div style={fieldGroupStyle}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
                <label style={{ ...labelStyle, marginBottom: 0 }}>Generated Cradle</label>
                <button
                  style={{
                    ...btnStyle,
                    fontSize: '11px',
                    padding: '2px 10px',
                  }}
                  onClick={handleCopy}
                >
                  {copied ? 'Copied!' : 'Copy'}
                </button>
              </div>
              <div style={codeBlockStyle}>{generatedCradle}</div>
            </div>
          )}
        </div>

        {/* Footer */}
        <div
          style={{
            display: 'flex',
            justifyContent: 'flex-end',
            padding: '10px 16px',
            borderTop: '1px solid #222',
            background: '#0d0d0d',
          }}
        >
          <button style={btnStyle} onClick={onClose}>
            Close
          </button>
        </div>
      </div>
    </div>
  );
}
