import { useState, useEffect } from 'react';
import { useListenerStore } from '../../store/listenerStore';
import ListenerCreateDialog from './ListenerCreateDialog';
import type { Listener, ListenerConfig } from '../../types';

export default function ListenerPanel() {
  const { listeners, stop, remove, create } = useListenerStore();
  const [showCreate, setShowCreate] = useState(false);
  const [editListener, setEditListener] = useState<Listener | null>(null);
  const [contextMenu, setContextMenu] = useState<{ x: number; y: number; listener: Listener } | null>(null);

  useEffect(() => {
    const handler = () => setContextMenu(null);
    if (contextMenu) {
      window.addEventListener('click', handler);
      return () => window.removeEventListener('click', handler);
    }
  }, [contextMenu]);

  const protocolName = (p: number) => {
    const names: Record<number, string> = { 0: 'HTTP', 1: 'HTTPS', 2: 'TCP', 3: 'SMB', 4: 'DNS' };
    return names[p] || 'Unknown';
  };

  const handleRestart = async (listener: Listener) => {
    try {
      await stop(listener.id);
      // Re-create with same config
      if (listener.config) {
        await create(listener.config);
      }
    } catch {
      // ignore errors
    }
  };

  const handleEdit = (listener: Listener) => {
    setEditListener(listener);
  };

  return (
    <div style={{ height: '100%', display: 'flex', flexDirection: 'column' }}>
      {/* Header bar */}
      <div style={{
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        padding: '10px 16px',
        borderBottom: '1px solid #1a1a1a',
        background: '#0d0d0d',
      }}>
        <span style={{ color: '#888', fontSize: '11px', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.5px' }}>
          Listeners ({listeners.length})
        </span>
        <button className="btn btn--primary btn--small" onClick={() => setShowCreate(true)}>
          + Create Listener
        </button>
      </div>

      {/* Table */}
      <div style={{ flex: 1, overflow: 'auto' }}>
        <table className="rtl-table">
          <thead>
            <tr>
              <th style={{ width: '80px' }}>ID</th>
              <th>Name</th>
              <th style={{ width: '80px' }}>Protocol</th>
              <th>Bind Address</th>
              <th style={{ width: '80px' }}>Port</th>
              <th style={{ width: '80px' }}>Status</th>
              <th style={{ width: '140px' }}>Actions</th>
            </tr>
          </thead>
          <tbody>
            {listeners.length === 0 ? (
              <tr>
                <td colSpan={7} style={{ textAlign: 'center', color: '#444', padding: '24px' }}>
                  No active listeners. Click "Create Listener" to add one.
                </td>
              </tr>
            ) : (
              listeners.map((l) => (
                <tr
                  key={l.id}
                  onContextMenu={(e) => {
                    e.preventDefault();
                    setContextMenu({ x: e.clientX, y: e.clientY, listener: l });
                  }}
                  style={{ cursor: 'pointer' }}
                >
                  <td style={{ fontFamily: 'var(--font-mono)', fontSize: '11px' }}>{l.id.slice(0, 8)}</td>
                  <td>{l.config?.name || '-'}</td>
                  <td>{protocolName(l.config?.protocol ?? 0)}</td>
                  <td style={{ fontFamily: 'var(--font-mono)' }}>{l.config?.bind_host || '0.0.0.0'}</td>
                  <td style={{ fontFamily: 'var(--font-mono)' }}>{l.config?.bind_port}</td>
                  <td>
                    <span className={l.active ? 'status-alive' : 'status-dead'}>
                      {l.active ? 'ACTIVE' : 'STOPPED'}
                    </span>
                  </td>
                  <td>
                    <div style={{ display: 'flex', gap: 4 }}>
                      <button className="btn btn--small" onClick={() => handleEdit(l)}
                        style={{ fontSize: 10 }}>Edit</button>
                      <button className="btn btn--small" onClick={() => handleRestart(l)}
                        style={{ fontSize: 10 }}>Restart</button>
                    </div>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      {/* Context Menu */}
      {contextMenu && (
        <div
          className="context-menu"
          style={{ left: contextMenu.x, top: contextMenu.y }}
          onClick={(e) => e.stopPropagation()}
        >
          <div className="context-menu__item" onClick={() => {
            handleEdit(contextMenu.listener);
            setContextMenu(null);
          }}>Edit Listener</div>
          <div className="context-menu__item" onClick={() => {
            handleRestart(contextMenu.listener);
            setContextMenu(null);
          }}>Restart Listener</div>
          <div className="context-menu__item" onClick={() => {
            stop(contextMenu.listener.id);
            setContextMenu(null);
          }}>Stop Listener</div>
          <div className="context-menu__item context-menu__item--danger" onClick={() => {
            if (confirm('Delete this listener?')) remove(contextMenu.listener.id);
            setContextMenu(null);
          }}>Delete Listener</div>
          <div className="context-menu__separator" />
          <div className="context-menu__item" onClick={() => {
            navigator.clipboard.writeText(contextMenu.listener.id);
            setContextMenu(null);
          }}>Copy ID</div>
        </div>
      )}

      {/* Create Dialog */}
      {showCreate && <ListenerCreateDialog onClose={() => setShowCreate(false)} />}

      {/* Edit Dialog - reuse ListenerCreateDialog with edit props */}
      {editListener && (
        <ListenerEditDialog
          listener={editListener}
          onClose={() => setEditListener(null)}
        />
      )}
    </div>
  );
}

// Edit dialog that pre-populates fields from existing listener
function ListenerEditDialog({ listener, onClose }: { listener: Listener; onClose: () => void }) {
  const { update, isLoading } = useListenerStore();
  const config = listener.config || {} as ListenerConfig;
  const [name, setName] = useState(config.name || '');
  const [protocol, setProtocol] = useState(config.protocol ?? 0);
  const [bindHost, setBindHost] = useState(config.bind_host || '0.0.0.0');
  const [bindPort, setBindPort] = useState(config.bind_port || 80);
  const [certPath, setCertPath] = useState(config.cert_path || '');
  const [keyPath, setKeyPath] = useState(config.key_path || '');
  const [error, setError] = useState('');

  const isDNS = protocol === 4;
  const isHTTPS = protocol === 1;

  const handleSave = async () => {
    if (!name.trim()) { setError('Name is required'); return; }
    const newConfig: ListenerConfig = {
      name: name.trim(),
      protocol,
      bind_host: bindHost,
      bind_port: bindPort,
      secure: isHTTPS,
      cert_path: isHTTPS ? certPath : undefined,
      key_path: isHTTPS ? keyPath : undefined,
      options: config.options || {},
    };
    try {
      await update(listener.id, newConfig);
      onClose();
    } catch (err: any) {
      setError(err.message);
    }
  };

  return (
    <div className="dialog-overlay" onClick={onClose}>
      <div className="dialog" style={{ width: '500px' }} onClick={(e) => e.stopPropagation()}>
        <div className="dialog__header">
          <span className="dialog__title">Edit Listener</span>
          <button className="dialog__close" onClick={onClose}>&times;</button>
        </div>
        <div className="dialog__body">
          <div style={{ display: 'grid', gridTemplateColumns: 'auto 1fr', gap: '10px 14px', alignItems: 'center' }}>
            <label style={{ color: '#808080', fontSize: '12px' }}>Name:</label>
            <input className="input" value={name} onChange={(e) => setName(e.target.value)} autoFocus />

            <label style={{ color: '#808080', fontSize: '12px' }}>Protocol:</label>
            <select className="select" value={protocol} onChange={(e) => setProtocol(Number(e.target.value))}>
              <option value={0}>HTTP</option>
              <option value={1}>HTTPS</option>
              <option value={2}>TCP</option>
              <option value={3}>SMB</option>
              <option value={4}>DNS</option>
            </select>

            {!isDNS && (
              <>
                <label style={{ color: '#808080', fontSize: '12px' }}>Bind Host:</label>
                <input className="input" value={bindHost} onChange={(e) => setBindHost(e.target.value)} />

                <label style={{ color: '#808080', fontSize: '12px' }}>Bind Port:</label>
                <input className="input" type="number" value={bindPort} onChange={(e) => setBindPort(Number(e.target.value))} />
              </>
            )}

            {isHTTPS && (
              <>
                <label style={{ color: '#808080', fontSize: '12px' }}>Cert Path:</label>
                <input className="input" value={certPath} onChange={(e) => setCertPath(e.target.value)} />

                <label style={{ color: '#808080', fontSize: '12px' }}>Key Path:</label>
                <input className="input" value={keyPath} onChange={(e) => setKeyPath(e.target.value)} />
              </>
            )}
          </div>

          {error && (
            <div style={{ background: '#1a0000', border: '1px solid #cc0000', borderRadius: '4px', padding: '8px 12px', color: '#ff3333', fontSize: '12px', marginTop: '12px' }}>
              {error}
            </div>
          )}
        </div>
        <div className="dialog__footer">
          <button className="btn" onClick={onClose}>Cancel</button>
          <button className="btn btn--primary" onClick={handleSave} disabled={isLoading}>
            {isLoading ? 'Saving...' : 'Save'}
          </button>
        </div>
      </div>
    </div>
  );
}
