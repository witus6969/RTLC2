import { useState, useEffect, useRef } from 'react';
import { api } from '../../api/client';
import type { HostedFile } from '../../types';

function formatSize(bytes: number): string {
  if (bytes < 1024) return bytes + ' B';
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
  return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
}

export default function HostedFilesPanel() {
  const [files, setFiles] = useState<HostedFile[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [maxDownloads, setMaxDownloads] = useState(0);
  const [expiryMinutes, setExpiryMinutes] = useState(0);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const fetchFiles = async () => {
    try {
      const res = await api.getHostedFiles();
      setFiles(res.files || []);
    } catch {
      // silent
    }
  };

  useEffect(() => {
    fetchFiles();
    const interval = setInterval(fetchFiles, 30000);
    return () => clearInterval(interval);
  }, []);

  const handleUpload = async () => {
    const input = fileInputRef.current;
    if (!input?.files?.[0]) return;
    const file = input.files[0];
    setLoading(true);
    setError('');
    try {
      const reader = new FileReader();
      reader.onload = async () => {
        const base64 = (reader.result as string).split(',')[1] || '';
        await api.uploadHostedFile(base64, file.name, maxDownloads || undefined, expiryMinutes || undefined);
        await fetchFiles();
        setLoading(false);
        if (input) input.value = '';
      };
      reader.readAsDataURL(file);
    } catch (err: any) {
      setError(err.message);
      setLoading(false);
    }
  };

  const handleDelete = async (id: string) => {
    if (!confirm('Delete this hosted file?')) return;
    try {
      await api.deleteHostedFile(id);
      setFiles(files.filter(f => f.id !== id));
    } catch (err: any) {
      setError(err.message);
    }
  };

  const copyUrl = (url: string) => {
    navigator.clipboard.writeText(url);
  };

  const cardStyle: React.CSSProperties = {
    background: '#0d0d0d', border: '1px solid #1a1a1a', borderRadius: 8, padding: 16,
  };

  return (
    <div style={{ height: '100%', overflow: 'auto', padding: 16 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
        <span style={{ color: '#cc0000', fontSize: 14, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.5px' }}>
          Hosted Files ({files.length})
        </span>
        <button className="btn btn--small" onClick={fetchFiles}>Refresh</button>
      </div>

      {/* Upload Form */}
      <div style={{ ...cardStyle, marginBottom: 16 }}>
        <div style={{ color: '#888', fontSize: 11, fontWeight: 700, textTransform: 'uppercase', marginBottom: 8 }}>Upload File</div>
        <div style={{ display: 'flex', gap: 12, alignItems: 'flex-end', flexWrap: 'wrap' }}>
          <div>
            <div style={{ color: '#555', fontSize: 10, marginBottom: 4 }}>File</div>
            <input ref={fileInputRef} type="file" style={{ color: '#999', fontSize: 11 }} />
          </div>
          <div>
            <div style={{ color: '#555', fontSize: 10, marginBottom: 4 }}>Max Downloads (0=unlimited)</div>
            <input className="input" type="number" value={maxDownloads} onChange={e => setMaxDownloads(Number(e.target.value))}
              style={{ width: 100 }} />
          </div>
          <div>
            <div style={{ color: '#555', fontSize: 10, marginBottom: 4 }}>Expiry (minutes, 0=never)</div>
            <input className="input" type="number" value={expiryMinutes} onChange={e => setExpiryMinutes(Number(e.target.value))}
              style={{ width: 100 }} />
          </div>
          <button className="btn btn--primary btn--small" onClick={handleUpload} disabled={loading}>
            {loading ? 'Uploading...' : 'Upload'}
          </button>
        </div>
        {error && <div style={{ color: '#ff3333', fontSize: 11, marginTop: 8 }}>{error}</div>}
      </div>

      {/* Files Table */}
      <div style={cardStyle}>
        <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 11 }}>
          <thead>
            <tr style={{ color: '#555', borderBottom: '1px solid #1a1a1a' }}>
              <th style={{ textAlign: 'left', padding: '6px 8px' }}>Filename</th>
              <th style={{ textAlign: 'left', padding: '6px 8px' }}>Content-Type</th>
              <th style={{ textAlign: 'right', padding: '6px 8px' }}>Size</th>
              <th style={{ textAlign: 'right', padding: '6px 8px' }}>Downloads</th>
              <th style={{ textAlign: 'left', padding: '6px 8px' }}>Expires</th>
              <th style={{ textAlign: 'left', padding: '6px 8px' }}>URL</th>
              <th style={{ textAlign: 'center', padding: '6px 8px' }}>Actions</th>
            </tr>
          </thead>
          <tbody>
            {files.length === 0 ? (
              <tr><td colSpan={7} style={{ textAlign: 'center', color: '#444', padding: 20 }}>No hosted files</td></tr>
            ) : files.map(f => (
              <tr key={f.id} style={{ borderBottom: '1px solid #111' }}>
                <td style={{ padding: '6px 8px', color: '#e0e0e0', fontFamily: 'var(--font-mono)' }}>{f.filename}</td>
                <td style={{ padding: '6px 8px', color: '#888' }}>{f.content_type}</td>
                <td style={{ padding: '6px 8px', color: '#888', textAlign: 'right' }}>{formatSize(f.size)}</td>
                <td style={{ padding: '6px 8px', color: '#888', textAlign: 'right' }}>
                  {f.download_count}{f.max_downloads > 0 ? `/${f.max_downloads}` : ''}
                </td>
                <td style={{ padding: '6px 8px', color: '#888' }}>{f.expires_at || 'Never'}</td>
                <td style={{ padding: '6px 8px', color: '#cc0000', fontFamily: 'var(--font-mono)', fontSize: 10, maxWidth: 200, overflow: 'hidden', textOverflow: 'ellipsis' }}>
                  {f.url}
                </td>
                <td style={{ padding: '6px 8px', textAlign: 'center' }}>
                  <div style={{ display: 'flex', gap: 4, justifyContent: 'center' }}>
                    <button className="btn btn--small" onClick={() => copyUrl(f.url)} title="Copy URL">Copy</button>
                    <button className="btn btn--small" onClick={() => handleDelete(f.id)}
                      style={{ color: '#cc0000', borderColor: '#440000' }}>Del</button>
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
