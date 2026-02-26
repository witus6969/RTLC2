import { useState } from 'react';
import { useListenerStore } from '../../store/listenerStore';
import type { ListenerConfig } from '../../types';

interface Props {
  onClose: () => void;
}

export default function ListenerCreateDialog({ onClose }: Props) {
  const { create, isLoading } = useListenerStore();
  const [name, setName] = useState('');
  const [protocol, setProtocol] = useState(0);
  const [bindHost, setBindHost] = useState('0.0.0.0');
  const [bindPort, setBindPort] = useState(80);
  const [certPath, setCertPath] = useState('');
  const [keyPath, setKeyPath] = useState('');
  // DNS fields
  const [domain, setDomain] = useState('');
  const [nsRecords, setNsRecords] = useState('');
  const [ttl, setTtl] = useState(60);
  // Redirector
  const [redirectorHost, setRedirectorHost] = useState('');
  const [redirectorPort, setRedirectorPort] = useState(0);
  const [error, setError] = useState('');

  const isDNS = protocol === 4;
  const isHTTPS = protocol === 1;

  const handleCreate = async () => {
    if (!name.trim()) { setError('Name is required'); return; }
    if (!isDNS && bindPort <= 0) { setError('Port must be positive'); return; }

    const config: ListenerConfig = {
      name: name.trim(),
      protocol,
      bind_host: isDNS ? '' : bindHost,
      bind_port: isDNS ? 53 : bindPort,
      secure: isHTTPS,
      cert_path: isHTTPS ? certPath : undefined,
      key_path: isHTTPS ? keyPath : undefined,
      options: {},
    };

    if (isDNS) {
      config.options = { domain, ns_records: nsRecords, ttl: String(ttl) };
    }
    if (redirectorHost) {
      config.options = { ...config.options, redirector_host: redirectorHost, redirector_port: String(redirectorPort) };
    }

    try {
      await create(config);
      onClose();
    } catch (err: any) {
      setError(err.message);
    }
  };

  return (
    <div className="dialog-overlay" onClick={onClose}>
      <div className="dialog" style={{ width: '500px' }} onClick={(e) => e.stopPropagation()}>
        <div className="dialog__header">
          <span className="dialog__title">Create Listener</span>
          <button className="dialog__close" onClick={onClose}>&times;</button>
        </div>
        <div className="dialog__body">
          <div style={{ display: 'grid', gridTemplateColumns: 'auto 1fr', gap: '10px 14px', alignItems: 'center' }}>
            <label style={{ color: '#808080', fontSize: '12px' }}>Name:</label>
            <input className="input" value={name} onChange={(e) => setName(e.target.value)} placeholder="My Listener" autoFocus />

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
                <input className="input" value={certPath} onChange={(e) => setCertPath(e.target.value)} placeholder="/path/to/cert.pem" />

                <label style={{ color: '#808080', fontSize: '12px' }}>Key Path:</label>
                <input className="input" value={keyPath} onChange={(e) => setKeyPath(e.target.value)} placeholder="/path/to/key.pem" />
              </>
            )}

            {isDNS && (
              <>
                <label style={{ color: '#808080', fontSize: '12px' }}>Domain:</label>
                <input className="input" value={domain} onChange={(e) => setDomain(e.target.value)} placeholder="c2.example.com" />

                <label style={{ color: '#808080', fontSize: '12px' }}>NS Records:</label>
                <input className="input" value={nsRecords} onChange={(e) => setNsRecords(e.target.value)} placeholder="ns1.example.com,ns2.example.com" />

                <label style={{ color: '#808080', fontSize: '12px' }}>TTL:</label>
                <input className="input" type="number" value={ttl} onChange={(e) => setTtl(Number(e.target.value))} />
              </>
            )}

            <label style={{ color: '#808080', fontSize: '12px' }}>Redirector Host:</label>
            <input className="input" value={redirectorHost} onChange={(e) => setRedirectorHost(e.target.value)} placeholder="(optional)" />

            <label style={{ color: '#808080', fontSize: '12px' }}>Redirector Port:</label>
            <input className="input" type="number" value={redirectorPort} onChange={(e) => setRedirectorPort(Number(e.target.value))} />
          </div>

          {error && (
            <div style={{ background: '#1a0000', border: '1px solid #cc0000', borderRadius: '4px', padding: '8px 12px', color: '#ff3333', fontSize: '12px', marginTop: '12px' }}>
              {error}
            </div>
          )}
        </div>
        <div className="dialog__footer">
          <button className="btn" onClick={onClose}>Cancel</button>
          <button className="btn btn--primary" onClick={handleCreate} disabled={isLoading}>
            {isLoading ? 'Creating...' : 'Create'}
          </button>
        </div>
      </div>
    </div>
  );
}
