import { useState, useEffect, useRef, useCallback } from 'react';
import { api } from '../../api/client';
import type { MalleableProfile } from '../../types';
import type { ProfileCategory } from '../../types';

type CategoryTab = 'all' | ProfileCategory;

const CATEGORY_LABELS: Record<CategoryTab, string> = {
  all: 'All',
  normal: 'Normal',
  apt: 'APT',
  crimeware: 'Crimeware',
  custom: 'Custom',
  builtin: 'Built-in',
};

// Extended profile with optional category/builtin fields
interface ProfileExt extends MalleableProfile {
  category?: ProfileCategory;
  builtin?: boolean;
}

export default function MalleableProfilePanel() {
  const [profiles, setProfiles] = useState<ProfileExt[]>([]);
  const [selectedProfile, setSelectedProfile] = useState<ProfileExt | null>(null);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [categoryTab, setCategoryTab] = useState<CategoryTab>('all');
  const [editMode, setEditMode] = useState(false);
  const [editJson, setEditJson] = useState('');
  const [jsonError, setJsonError] = useState('');
  const fileInputRef = useRef<HTMLInputElement>(null);

  const fetchProfiles = useCallback(async () => {
    try {
      const res = await api.getProfiles();
      setProfiles((res.profiles || []) as ProfileExt[]);
    } catch {
      // silent
    }
  }, []);

  useEffect(() => {
    fetchProfiles();
  }, [fetchProfiles]);

  const handleUpload = async () => {
    const input = fileInputRef.current;
    if (!input?.files?.[0]) return;
    const file = input.files[0];
    setLoading(true);
    setError('');
    const reader = new FileReader();
    reader.onload = async () => {
      try {
        const base64 = (reader.result as string).split(',')[1] || '';
        await api.uploadProfile(base64, file.name);
        await fetchProfiles();
        if (input) input.value = '';
      } catch (err: unknown) {
        const message = err instanceof Error ? err.message : String(err);
        setError(message);
      } finally {
        setLoading(false);
      }
    };
    reader.onerror = () => {
      setError('Failed to read file');
      setLoading(false);
    };
    reader.readAsDataURL(file);
  };

  const handleImportJson = () => {
    const input = document.createElement('input');
    input.type = 'file';
    input.accept = '.json';
    input.onchange = () => {
      const file = input.files?.[0];
      if (!file) return;
      const reader = new FileReader();
      reader.onload = async () => {
        try {
          const text = reader.result as string;
          const profile = JSON.parse(text);
          const base64 = btoa(text);
          await api.uploadProfile(base64, file.name);
          await fetchProfiles();
          setSelectedProfile(profile);
        } catch (err: unknown) {
          const message = err instanceof Error ? err.message : String(err);
          setError(`Import failed: ${message}`);
        }
      };
      reader.readAsText(file);
    };
    input.click();
  };

  const handleExport = () => {
    if (!selectedProfile) return;
    const json = JSON.stringify(selectedProfile, null, 2);
    const blob = new Blob([json], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${selectedProfile.name || 'profile'}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleDelete = async () => {
    if (!selectedProfile || selectedProfile.builtin) return;
    try {
      await api.deleteProfile(selectedProfile.name);
      setSelectedProfile(null);
      await fetchProfiles();
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : String(err);
      setError(`Delete failed: ${message}`);
    }
  };

  const handleSaveEdit = async () => {
    setJsonError('');
    try {
      const parsed = JSON.parse(editJson);
      const base64 = btoa(editJson);
      await api.uploadProfile(base64, `${parsed.name || 'custom'}.json`);
      await fetchProfiles();
      setEditMode(false);
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : String(err);
      setJsonError(message);
    }
  };

  const filteredProfiles = profiles.filter((p) => {
    if (categoryTab === 'all') return true;
    if (categoryTab === 'builtin') return p.builtin === true;
    if (categoryTab === 'custom') return !p.builtin && (p.category === 'custom' || !p.category);
    return p.category === categoryTab;
  });

  const cardStyle: React.CSSProperties = {
    background: '#0d0d0d', border: '1px solid #1a1a1a', borderRadius: 8, padding: 16,
  };

  const sectionLabel: React.CSSProperties = {
    color: '#888', fontSize: 11, fontWeight: 700, textTransform: 'uppercase' as const, letterSpacing: '0.5px', marginBottom: 8,
  };

  // Generate traffic preview
  const getTrafficPreview = (p: ProfileExt): { request: string; response: string } => {
    const uris = p.uri_paths || p.uris || ['/updates'];
    const ua = p.user_agent || 'Mozilla/5.0';
    const reqHeaders = p.request_headers || p.headers || {};
    const respHeaders = p.response_headers || {};

    let request = `GET ${uris[0] || '/'} HTTP/1.1\r\nHost: c2.example.com\r\nUser-Agent: ${ua}`;
    for (const [k, v] of Object.entries(reqHeaders)) {
      request += `\r\n${k}: ${v}`;
    }

    let response = `HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream`;
    for (const [k, v] of Object.entries(respHeaders)) {
      response += `\r\n${k}: ${v}`;
    }
    if (p.body_transform) {
      response += `\r\n\r\n[Body transform: ${p.body_transform}]`;
    }

    return { request, response };
  };

  return (
    <div style={{ height: '100%', overflow: 'auto', padding: 16 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
        <span style={{ color: '#cc0000', fontSize: 14, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.5px' }}>
          Malleable Profiles ({profiles.length})
        </span>
        <div style={{ display: 'flex', gap: 8 }}>
          <button className="btn btn--small" onClick={handleImportJson}>Import JSON</button>
          <button className="btn btn--small" onClick={fetchProfiles}>Refresh</button>
        </div>
      </div>

      {/* Category tabs */}
      <div style={{ display: 'flex', gap: 0, borderBottom: '1px solid #1a1a1a', marginBottom: 12 }}>
        {(Object.keys(CATEGORY_LABELS) as CategoryTab[]).map((cat) => (
          <button
            key={cat}
            onClick={() => setCategoryTab(cat)}
            style={{
              padding: '6px 14px',
              background: 'transparent',
              border: 'none',
              borderBottom: categoryTab === cat ? '2px solid #cc0000' : '2px solid transparent',
              color: categoryTab === cat ? '#cc0000' : '#666',
              fontSize: 11,
              fontWeight: 600,
              cursor: 'pointer',
              textTransform: 'uppercase',
              letterSpacing: '0.3px',
            }}
          >
            {CATEGORY_LABELS[cat]}
          </button>
        ))}
      </div>

      {/* Upload */}
      <div style={{ ...cardStyle, marginBottom: 16 }}>
        <div style={sectionLabel}>Upload Profile (YAML/JSON)</div>
        <div style={{ display: 'flex', gap: 12, alignItems: 'center' }}>
          <input ref={fileInputRef} type="file" accept=".yaml,.yml,.json" style={{ color: '#999', fontSize: 11 }} />
          <button className="btn btn--primary btn--small" onClick={handleUpload} disabled={loading}>
            {loading ? 'Uploading...' : 'Upload'}
          </button>
        </div>
        {error && <div style={{ color: '#ff3333', fontSize: 11, marginTop: 8 }}>{error}</div>}
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: selectedProfile || editMode ? '1fr 1fr' : '1fr', gap: 16 }}>
        {/* Profile cards */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
          {filteredProfiles.length === 0 ? (
            <div style={{ ...cardStyle, textAlign: 'center', color: '#444', padding: 30 }}>No profiles match this category</div>
          ) : filteredProfiles.map((p, i) => {
            const uris = p.uri_paths || p.uris || [];
            return (
              <div
                key={p.id || p.name || i}
                onClick={() => { setSelectedProfile(p); setEditMode(false); }}
                style={{
                  ...cardStyle,
                  cursor: 'pointer',
                  borderColor: selectedProfile?.name === p.name ? '#cc0000' : '#1a1a1a',
                  transition: 'border-color 0.15s',
                }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6 }}>
                  <span style={{ color: '#cc0000', fontWeight: 700, fontSize: 13 }}>{p.name}</span>
                  <div style={{ display: 'flex', gap: 4 }}>
                    {p.builtin && (
                      <span style={{ padding: '1px 6px', background: '#111', border: '1px solid #333', borderRadius: 3, color: '#888', fontSize: 9, textTransform: 'uppercase' }}>
                        Built-in
                      </span>
                    )}
                    {p.category && (
                      <span style={{ padding: '1px 6px', background: '#1a0000', border: '1px solid #330000', borderRadius: 3, color: '#cc0000', fontSize: 9, textTransform: 'uppercase' }}>
                        {p.category}
                      </span>
                    )}
                  </div>
                </div>
                <div style={{ color: '#666', fontSize: 10, fontFamily: 'var(--font-mono)', marginBottom: 4, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                  {p.user_agent || '(no user-agent)'}
                </div>
                <div style={{ display: 'flex', gap: 12, fontSize: 10, color: '#555' }}>
                  <span>URIs: {uris.length}</span>
                  <span>Transform: {p.body_transform || 'none'}</span>
                </div>
              </div>
            );
          })}
        </div>

        {/* Detail / Editor pane */}
        {(selectedProfile || editMode) && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
            {/* Profile editor mode */}
            {editMode ? (
              <div style={cardStyle}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 10 }}>
                  <span style={sectionLabel}>Profile Editor (JSON)</span>
                  <div style={{ display: 'flex', gap: 6 }}>
                    <button className="btn btn--primary btn--small" onClick={handleSaveEdit}>Save</button>
                    <button className="btn btn--small" onClick={() => setEditMode(false)}>Cancel</button>
                  </div>
                </div>
                {jsonError && <div style={{ color: '#ff3333', fontSize: 11, marginBottom: 8 }}>{jsonError}</div>}
                <textarea
                  value={editJson}
                  onChange={(e) => setEditJson(e.target.value)}
                  style={{
                    width: '100%',
                    height: 300,
                    background: '#080808',
                    border: '1px solid #333',
                    borderRadius: 4,
                    color: '#e0e0e0',
                    fontFamily: 'var(--font-mono)',
                    fontSize: 11,
                    padding: 10,
                    resize: 'vertical',
                  }}
                  spellCheck={false}
                />
              </div>
            ) : selectedProfile && (
              <>
                {/* Detail view */}
                <div style={cardStyle}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
                    <span style={{ color: '#cc0000', fontSize: 13, fontWeight: 700 }}>{selectedProfile.name}</span>
                    <div style={{ display: 'flex', gap: 6 }}>
                      <button className="btn btn--small" onClick={() => {
                        setEditMode(true);
                        setEditJson(JSON.stringify(selectedProfile, null, 2));
                      }}>Edit</button>
                      <button className="btn btn--small" onClick={handleExport}>Export</button>
                      {!selectedProfile.builtin && (
                        <button className="btn btn--small" onClick={handleDelete} style={{ color: '#ff3333' }}>Delete</button>
                      )}
                      <button className="btn btn--small" onClick={() => setSelectedProfile(null)}>Close</button>
                    </div>
                  </div>

                  {selectedProfile.description && (
                    <div style={{ color: '#888', fontSize: 11, marginBottom: 10 }}>{selectedProfile.description}</div>
                  )}

                  {/* User-Agent */}
                  <div style={{ marginBottom: 12 }}>
                    <div style={sectionLabel}>User-Agent</div>
                    <div style={{ color: '#e0e0e0', fontFamily: 'var(--font-mono)', fontSize: 10, wordBreak: 'break-all', background: '#080808', padding: 8, borderRadius: 4 }}>
                      {selectedProfile.user_agent || '-'}
                    </div>
                  </div>

                  {/* Request Headers */}
                  <div style={{ marginBottom: 12 }}>
                    <div style={sectionLabel}>Request Headers</div>
                    <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 10 }}>
                      <thead>
                        <tr style={{ color: '#555', borderBottom: '1px solid #1a1a1a' }}>
                          <th style={{ textAlign: 'left', padding: '4px 6px' }}>Header</th>
                          <th style={{ textAlign: 'left', padding: '4px 6px' }}>Value</th>
                        </tr>
                      </thead>
                      <tbody>
                        {Object.entries(selectedProfile.request_headers || selectedProfile.headers || {}).map(([k, v]) => (
                          <tr key={k} style={{ borderBottom: '1px solid #111' }}>
                            <td style={{ padding: '4px 6px', color: '#cc0000', fontFamily: 'var(--font-mono)' }}>{k}</td>
                            <td style={{ padding: '4px 6px', color: '#e0e0e0', fontFamily: 'var(--font-mono)' }}>{v}</td>
                          </tr>
                        ))}
                        {Object.keys(selectedProfile.request_headers || selectedProfile.headers || {}).length === 0 && (
                          <tr><td colSpan={2} style={{ color: '#444', padding: '4px 6px' }}>No custom headers</td></tr>
                        )}
                      </tbody>
                    </table>
                  </div>

                  {/* Response Headers */}
                  <div style={{ marginBottom: 12 }}>
                    <div style={sectionLabel}>Response Headers</div>
                    <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 10 }}>
                      <thead>
                        <tr style={{ color: '#555', borderBottom: '1px solid #1a1a1a' }}>
                          <th style={{ textAlign: 'left', padding: '4px 6px' }}>Header</th>
                          <th style={{ textAlign: 'left', padding: '4px 6px' }}>Value</th>
                        </tr>
                      </thead>
                      <tbody>
                        {Object.entries(selectedProfile.response_headers || {}).map(([k, v]) => (
                          <tr key={k} style={{ borderBottom: '1px solid #111' }}>
                            <td style={{ padding: '4px 6px', color: '#cc0000', fontFamily: 'var(--font-mono)' }}>{k}</td>
                            <td style={{ padding: '4px 6px', color: '#e0e0e0', fontFamily: 'var(--font-mono)' }}>{v}</td>
                          </tr>
                        ))}
                        {Object.keys(selectedProfile.response_headers || {}).length === 0 && (
                          <tr><td colSpan={2} style={{ color: '#444', padding: '4px 6px' }}>No custom headers</td></tr>
                        )}
                      </tbody>
                    </table>
                  </div>

                  {/* URIs */}
                  <div style={{ marginBottom: 12 }}>
                    <div style={sectionLabel}>URI Paths</div>
                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
                      {(selectedProfile.uri_paths || selectedProfile.uris || []).map((uri, i) => (
                        <span key={i} style={{
                          padding: '2px 8px',
                          background: '#111',
                          border: '1px solid #222',
                          borderRadius: 3,
                          color: '#e0e0e0',
                          fontFamily: 'var(--font-mono)',
                          fontSize: 10,
                        }}>
                          {uri}
                        </span>
                      ))}
                      {(selectedProfile.uri_paths || selectedProfile.uris || []).length === 0 && (
                        <span style={{ color: '#444', fontSize: 10 }}>No URIs defined</span>
                      )}
                    </div>
                  </div>

                  {/* Body Transform */}
                  <div style={{ marginBottom: 12 }}>
                    <div style={sectionLabel}>Body Transform</div>
                    <span style={{ color: '#e0e0e0', fontSize: 11 }}>{selectedProfile.body_transform || 'none'}</span>
                  </div>
                </div>

                {/* JSON display */}
                <div style={cardStyle}>
                  <div style={sectionLabel}>Raw JSON</div>
                  <pre style={{
                    background: '#080808',
                    borderRadius: 4,
                    padding: 10,
                    color: '#e0e0e0',
                    fontFamily: 'var(--font-mono)',
                    fontSize: 10,
                    overflow: 'auto',
                    maxHeight: 200,
                    whiteSpace: 'pre-wrap',
                    wordBreak: 'break-all',
                    margin: 0,
                  }}>
                    {JSON.stringify(selectedProfile, null, 2)}
                  </pre>
                </div>

                {/* Traffic Preview */}
                <div style={cardStyle}>
                  <div style={sectionLabel}>Traffic Preview</div>
                  {(() => {
                    const preview = getTrafficPreview(selectedProfile);
                    return (
                      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10 }}>
                        <div>
                          <div style={{ color: '#555', fontSize: 9, fontWeight: 700, textTransform: 'uppercase', marginBottom: 4 }}>Request</div>
                          <pre style={{
                            background: '#080808',
                            borderRadius: 4,
                            padding: 8,
                            color: '#22c55e',
                            fontFamily: 'var(--font-mono)',
                            fontSize: 9,
                            overflow: 'auto',
                            maxHeight: 120,
                            whiteSpace: 'pre-wrap',
                            margin: 0,
                          }}>
                            {preview.request}
                          </pre>
                        </div>
                        <div>
                          <div style={{ color: '#555', fontSize: 9, fontWeight: 700, textTransform: 'uppercase', marginBottom: 4 }}>Response</div>
                          <pre style={{
                            background: '#080808',
                            borderRadius: 4,
                            padding: 8,
                            color: '#eab308',
                            fontFamily: 'var(--font-mono)',
                            fontSize: 9,
                            overflow: 'auto',
                            maxHeight: 120,
                            whiteSpace: 'pre-wrap',
                            margin: 0,
                          }}>
                            {preview.response}
                          </pre>
                        </div>
                      </div>
                    );
                  })()}
                </div>
              </>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
