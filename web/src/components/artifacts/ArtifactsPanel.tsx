import { useArtifactStore } from '../../store/artifactStore';

export default function ArtifactsPanel() {
  const { artifacts, downloadArtifact, removeArtifact, clearAll } = useArtifactStore();

  const formatSize = (bytes: number) => {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  };

  const osLabel = (os: string) => {
    if (os === 'windows') return 'Windows';
    if (os === 'linux') return 'Linux';
    if (os === 'macos') return 'macOS';
    return os;
  };

  return (
    <div style={{ height: '100%', display: 'flex', flexDirection: 'column' }}>
      <div style={{
        display: 'flex', alignItems: 'center', justifyContent: 'space-between',
        padding: '10px 16px', borderBottom: '1px solid #1a1a1a', background: '#0d0d0d',
      }}>
        <span style={{ color: '#888', fontSize: '11px', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.5px' }}>
          Generated Artifacts ({artifacts.length})
        </span>
        {artifacts.length > 0 && (
          <button className="btn btn--small btn--danger" onClick={() => {
            if (confirm('Clear all artifacts?')) clearAll();
          }}>
            Clear All
          </button>
        )}
      </div>

      <div style={{ flex: 1, overflow: 'auto' }}>
        <table className="rtl-table">
          <thead>
            <tr>
              <th>Name</th>
              <th>Listener</th>
              <th style={{ width: '80px' }}>OS</th>
              <th style={{ width: '60px' }}>Arch</th>
              <th style={{ width: '90px' }}>Format</th>
              <th style={{ width: '80px' }}>Size</th>
              <th style={{ width: '70px' }}>Type</th>
              <th style={{ width: '150px' }}>Date</th>
              <th style={{ width: '140px' }}>Actions</th>
            </tr>
          </thead>
          <tbody>
            {artifacts.length === 0 ? (
              <tr>
                <td colSpan={9} style={{ textAlign: 'center', color: '#444', padding: '24px' }}>
                  No artifacts generated yet. Use the Payload Generator to create payloads.
                </td>
              </tr>
            ) : (
              artifacts.map((a) => (
                <tr key={a.id}>
                  <td style={{ fontFamily: 'var(--font-mono)', fontSize: '11px', color: '#e0e0e0', fontWeight: 600 }}>
                    {a.name}
                  </td>
                  <td style={{ color: '#cc0000' }}>{a.listenerName}</td>
                  <td>{osLabel(a.os)}</td>
                  <td style={{ fontFamily: 'var(--font-mono)', fontSize: '11px' }}>{a.arch}</td>
                  <td style={{ fontFamily: 'var(--font-mono)', fontSize: '11px' }}>{a.format}</td>
                  <td style={{ fontFamily: 'var(--font-mono)', fontSize: '11px' }}>{formatSize(a.size)}</td>
                  <td>
                    <span style={{
                      color: a.shellcodeOnly ? '#ff6600' : '#00cc00',
                      fontSize: '10px', fontWeight: 700, textTransform: 'uppercase',
                    }}>
                      {a.shellcodeOnly ? 'SC' : 'Full'}
                    </span>
                  </td>
                  <td style={{ fontFamily: 'var(--font-mono)', fontSize: '11px', color: '#666' }}>
                    {a.createdAt}
                  </td>
                  <td>
                    <div style={{ display: 'flex', gap: '6px' }}>
                      <button className="btn btn--primary btn--small" onClick={() => downloadArtifact(a.id)}>
                        Download
                      </button>
                      <button className="btn btn--small btn--danger" onClick={() => removeArtifact(a.id)}>
                        Delete
                      </button>
                    </div>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
