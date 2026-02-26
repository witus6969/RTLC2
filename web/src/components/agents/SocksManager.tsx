// ═══════════════════════════════════════════════════════════════
//  RTLC2 SOCKS5 Proxy Manager
//  Lists active proxies, start/stop controls for the agent.
// ═══════════════════════════════════════════════════════════════

import { useState, useEffect, useCallback } from 'react';
import { useTaskStore } from '../../store/taskStore';
import { api } from '../../api/client';
import { TaskType, TaskStatus } from '../../types';
import type { TaskResult } from '../../types';

interface SocksManagerProps {
  agentId: string;
}

interface SocksProxy {
  jobId: string;
  port: number;
  status: 'running' | 'stopped' | 'error';
  startedAt: string;
  connections: number;
}

// Parse SOCKS proxy info from task outputs
// Expected format in task output:
//   SOCKS5 started on port 1080 (job: abc123)
//   or JSON: {"job_id": "abc123", "port": 1080, "status": "running", "connections": 5}
function parseSocksOutput(output: string): Partial<SocksProxy> | null {
  // Try JSON first
  try {
    const parsed = JSON.parse(output);
    if (parsed.job_id || parsed.port) {
      return {
        jobId: parsed.job_id || '',
        port: parsed.port || 0,
        status: parsed.status === 'running' ? 'running' : parsed.status === 'stopped' ? 'stopped' : 'error',
        connections: parsed.connections || 0,
      };
    }
  } catch {
    // Not JSON, try text parsing
  }

  const match = output.match(/SOCKS5?\s+started\s+on\s+port\s+(\d+)\s*\(?(?:job:\s*)?(\w+)?\)?/i);
  if (match) {
    return {
      port: parseInt(match[1], 10),
      jobId: match[2] || '',
      status: 'running',
      connections: 0,
    };
  }

  return null;
}

export default function SocksManager({ agentId }: SocksManagerProps) {
  const { sendCommand } = useTaskStore();
  const [proxies, setProxies] = useState<SocksProxy[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [newPort, setNewPort] = useState('1080');
  const [isStarting, setIsStarting] = useState(false);

  const fetchProxies = useCallback(async () => {
    setIsLoading(true);
    setError(null);

    try {
      const res = await api.getAgentTasks(agentId);
      const socksTasks = (res.tasks || []).filter(
        (t) => t.type === TaskType.SOCKS
      );

      const discovered: SocksProxy[] = [];

      for (const task of socksTasks) {
        try {
          const result: TaskResult = await api.getTaskResult(task.task_id);
          if (result.status !== TaskStatus.COMPLETE || !result.output) continue;

          const decoded = atob(result.output);
          const parsed = parseSocksOutput(decoded);
          if (parsed && parsed.port) {
            // Check if we already have this port
            const existing = discovered.find((p) => p.port === parsed.port);
            if (!existing) {
              discovered.push({
                jobId: parsed.jobId || task.task_id,
                port: parsed.port,
                status: parsed.status || 'running',
                startedAt: result.updated_at || result.created_at,
                connections: parsed.connections || 0,
              });
            }
          }
        } catch {
          // Skip failed tasks
        }
      }

      setProxies(discovered);
    } catch (err: any) {
      setError(err.message || 'Failed to fetch SOCKS proxies');
    } finally {
      setIsLoading(false);
    }
  }, [agentId]);

  useEffect(() => {
    fetchProxies();
  }, [fetchProxies]);

  const handleStart = async () => {
    const port = parseInt(newPort, 10);
    if (isNaN(port) || port < 1 || port > 65535) {
      setError('Invalid port number (1-65535)');
      return;
    }

    setIsStarting(true);
    setError(null);

    try {
      await sendCommand(agentId, `socks start ${port}`);
      // Refresh after a delay to allow the task to complete
      setTimeout(fetchProxies, 3000);
    } catch (err: any) {
      setError(err.message || 'Failed to start SOCKS proxy');
    } finally {
      setIsStarting(false);
    }
  };

  const handleStop = async (proxy: SocksProxy) => {
    try {
      await sendCommand(agentId, `socks stop ${proxy.jobId}`);
      // Optimistically update status
      setProxies((prev) =>
        prev.map((p) =>
          p.jobId === proxy.jobId ? { ...p, status: 'stopped' } : p
        )
      );
    } catch (err: any) {
      setError(err.message || 'Failed to stop SOCKS proxy');
    }
  };

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

  const btnDangerStyle: React.CSSProperties = {
    ...btnStyle,
    color: '#cc0000',
    borderColor: '#440000',
  };

  const inputStyle: React.CSSProperties = {
    padding: '4px 8px',
    background: '#0a0a0a',
    border: '1px solid #333',
    borderRadius: '3px',
    color: '#e0e0e0',
    fontSize: '12px',
    fontFamily: 'monospace',
    outline: 'none',
    width: '80px',
    textAlign: 'center',
  };

  const tableStyle: React.CSSProperties = {
    width: '100%',
    borderCollapse: 'collapse',
    fontSize: '12px',
  };

  const thStyle: React.CSSProperties = {
    textAlign: 'left',
    padding: '8px 10px',
    borderBottom: '1px solid #222',
    color: '#666',
    fontSize: '10px',
    textTransform: 'uppercase',
    letterSpacing: '0.5px',
    fontWeight: 600,
    background: '#0d0d0d',
  };

  const tdStyle: React.CSSProperties = {
    padding: '8px 10px',
    borderBottom: '1px solid #1a1a1a',
  };

  const statusBadge = (status: string): React.CSSProperties => ({
    display: 'inline-block',
    padding: '2px 8px',
    borderRadius: '10px',
    fontSize: '10px',
    fontWeight: 600,
    textTransform: 'uppercase',
    letterSpacing: '0.5px',
    ...(status === 'running'
      ? { background: '#00440022', border: '1px solid #004400', color: '#44cc44' }
      : status === 'stopped'
      ? { background: '#44440022', border: '1px solid #444400', color: '#aaaa44' }
      : { background: '#44000022', border: '1px solid #440000', color: '#cc4444' }),
  });

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
          SOCKS5 Proxies
        </span>
        <div style={{ flex: 1 }} />

        {/* Start new proxy */}
        <span style={{ fontSize: '11px', color: '#666' }}>Bind Port:</span>
        <input
          type="text"
          value={newPort}
          onChange={(e) => setNewPort(e.target.value.replace(/\D/g, ''))}
          onKeyDown={(e) => { if (e.key === 'Enter') handleStart(); }}
          style={inputStyle}
          placeholder="1080"
          onFocus={(e) => { e.currentTarget.style.borderColor = '#cc0000'; }}
          onBlur={(e) => { e.currentTarget.style.borderColor = '#333'; }}
        />
        <button
          style={btnAccentStyle}
          onClick={handleStart}
          disabled={isStarting}
        >
          {isStarting ? 'Starting...' : 'Start Proxy'}
        </button>
        <button style={btnStyle} onClick={fetchProxies} disabled={isLoading}>
          {isLoading ? 'Loading...' : 'Refresh'}
        </button>
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

      {/* Proxy Table */}
      {proxies.length === 0 && !isLoading ? (
        <div style={emptyStyle}>
          <span style={{ fontSize: '32px', opacity: 0.3 }}>[~]</span>
          <span>No SOCKS5 proxies active</span>
          <span style={{ fontSize: '11px', color: '#333' }}>
            Start a new proxy using the controls above
          </span>
        </div>
      ) : (
        <div style={{ flex: 1, overflow: 'auto' }}>
          <table style={tableStyle}>
            <thead>
              <tr>
                <th style={thStyle}>Job ID</th>
                <th style={thStyle}>Port</th>
                <th style={thStyle}>Status</th>
                <th style={thStyle}>Connection Info</th>
                <th style={thStyle}>Started</th>
                <th style={{ ...thStyle, textAlign: 'right' }}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {proxies.map((proxy) => (
                <tr
                  key={proxy.jobId}
                  onMouseEnter={(e) => { (e.currentTarget as HTMLTableRowElement).style.background = '#111'; }}
                  onMouseLeave={(e) => { (e.currentTarget as HTMLTableRowElement).style.background = 'transparent'; }}
                >
                  <td style={{ ...tdStyle, fontFamily: 'monospace', fontSize: '11px', color: '#888' }}>
                    {proxy.jobId.slice(0, 12)}
                  </td>
                  <td style={{ ...tdStyle, fontFamily: 'monospace', fontWeight: 600, color: '#cc0000' }}>
                    {proxy.port}
                  </td>
                  <td style={tdStyle}>
                    <span style={statusBadge(proxy.status)}>{proxy.status}</span>
                  </td>
                  <td style={{ ...tdStyle, fontFamily: 'monospace', fontSize: '11px', color: '#888' }}>
                    socks5://127.0.0.1:{proxy.port}
                    {proxy.connections > 0 && (
                      <span style={{ marginLeft: '8px', color: '#555' }}>
                        ({proxy.connections} conn)
                      </span>
                    )}
                  </td>
                  <td style={{ ...tdStyle, fontSize: '11px', color: '#555', fontFamily: 'monospace' }}>
                    {proxy.startedAt}
                  </td>
                  <td style={{ ...tdStyle, textAlign: 'right' }}>
                    {proxy.status === 'running' && (
                      <button
                        style={btnDangerStyle}
                        onClick={() => handleStop(proxy)}
                      >
                        Stop
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Status Bar */}
      <div
        style={{
          padding: '4px 12px',
          borderTop: '1px solid #222',
          background: '#111',
          fontSize: '10px',
          color: '#444',
          fontFamily: 'monospace',
          display: 'flex',
          justifyContent: 'space-between',
          flexShrink: 0,
        }}
      >
        <span>{proxies.filter((p) => p.status === 'running').length} active</span>
        <span>{proxies.length} total</span>
      </div>
    </div>
  );
}
