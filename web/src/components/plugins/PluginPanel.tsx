import { useState, useEffect } from 'react';
import { api } from '../../api/client';
import type { Plugin } from '../../types';
import ImgPayloadPanel from './ImgPayloadPanel';

export default function PluginPanel() {
  const [plugins, setPlugins] = useState<Plugin[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const [activePlugin, setActivePlugin] = useState<string | null>(null);

  const fetchPlugins = async () => {
    try {
      const res = await api.getPlugins();
      setPlugins(res.plugins || []);
    } catch { /* ignore */ }
  };

  useEffect(() => { fetchPlugins(); }, []);

  const handleUpload = () => {
    const input = document.createElement('input');
    input.type = 'file';
    input.accept = '.json,.so,.dll,.dylib';
    input.onchange = async () => {
      const file = input.files?.[0];
      if (!file) return;
      setIsLoading(true);
      const reader = new FileReader();
      reader.onload = async () => {
        const b64 = btoa(String.fromCharCode(...new Uint8Array(reader.result as ArrayBuffer)));
        try {
          await api.loadPlugin(b64, file.name);
          await fetchPlugins();
        } catch { /* ignore */ }
        setIsLoading(false);
      };
      reader.readAsArrayBuffer(file);
    };
    input.click();
  };

  const statusColor = (status: string) => {
    if (status === 'active' || status === 'loaded') return '#00cc00';
    if (status === 'error') return '#ff3333';
    return '#888';
  };

  const hasImgPayload = plugins.some((p) =>
    p.name?.toLowerCase() === 'imgpayload' && (p.status === 'active' || p.status === 'loaded' || !p.status)
  );

  return (
    <div style={{ height: '100%', display: 'flex', flexDirection: 'column' }}>
      {/* Plugin list header */}
      <div style={{
        display: 'flex', alignItems: 'center', justifyContent: 'space-between',
        padding: '10px 16px', borderBottom: '1px solid #1a1a1a', background: '#0d0d0d',
      }}>
        <span style={{ color: '#888', fontSize: '11px', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.5px' }}>
          Plugins ({plugins.length})
        </span>
        <div style={{ display: 'flex', gap: '8px' }}>
          <button className="btn btn--small" onClick={fetchPlugins}>Refresh</button>
          <button className="btn btn--primary btn--small" onClick={handleUpload} disabled={isLoading}>
            {isLoading ? 'Uploading...' : '+ Upload Plugin'}
          </button>
        </div>
      </div>

      {/* Plugin table */}
      <div style={{ overflow: 'auto', maxHeight: activePlugin ? '160px' : undefined, flexShrink: activePlugin ? 0 : 1, flex: activePlugin ? undefined : 1 }}>
        <table className="rtl-table">
          <thead>
            <tr>
              <th>Name</th>
              <th style={{ width: '80px' }}>Version</th>
              <th>Author</th>
              <th>Description</th>
              <th style={{ width: '80px' }}>Status</th>
              <th style={{ width: '80px' }}>Actions</th>
            </tr>
          </thead>
          <tbody>
            {plugins.length === 0 ? (
              <tr>
                <td colSpan={6} style={{ textAlign: 'center', color: '#444', padding: '24px' }}>
                  No plugins loaded. Click "Upload Plugin" to add one.
                </td>
              </tr>
            ) : (
              plugins.map((p) => {
                const pluginKey = p.name?.toLowerCase() || '';
                const isOpen = activePlugin === pluginKey;
                const canUse = pluginKey === 'imgpayload';
                return (
                  <tr key={p.name} style={{ background: isOpen ? '#1a0000' : undefined }}>
                    <td style={{ fontWeight: 600, color: '#e0e0e0' }}>{p.name}</td>
                    <td style={{ fontFamily: 'var(--font-mono)', fontSize: '11px' }}>{p.version}</td>
                    <td style={{ color: '#888' }}>{p.author}</td>
                    <td style={{ color: '#a0a0a0', fontSize: '11px' }}>{p.description}</td>
                    <td>
                      <span style={{ color: statusColor(p.status), fontWeight: 700, fontSize: '11px', textTransform: 'uppercase' }}>
                        {p.status || 'active'}
                      </span>
                    </td>
                    <td>
                      {canUse && (
                        <button
                          className={`btn btn--small ${isOpen ? 'btn--primary' : ''}`}
                          onClick={() => setActivePlugin(isOpen ? null : pluginKey)}
                        >
                          {isOpen ? 'Close' : 'Use'}
                        </button>
                      )}
                    </td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>

      {/* Active plugin panel */}
      {activePlugin === 'imgpayload' && hasImgPayload && (
        <div style={{ flex: 1, overflow: 'auto', borderTop: '2px solid #cc0000' }}>
          <ImgPayloadPanel />
        </div>
      )}
    </div>
  );
}
