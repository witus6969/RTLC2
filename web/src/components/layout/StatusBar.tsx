import { useState, useEffect } from 'react';
import { useAuthStore } from '../../store/authStore';
import { useAgentStore } from '../../store/agentStore';
import { useListenerStore } from '../../store/listenerStore';
import { useUIStore } from '../../store/uiStore';
import { api } from '../../api/client';
import type { ServerInfo } from '../../types';

export default function StatusBar() {
  const username = useAuthStore((s) => s.username);
  const role = useAuthStore((s) => s.role);
  const agents = useAgentStore((s) => s.agents);
  const listeners = useListenerStore((s) => s.listeners);
  const wsConnected = useUIStore((s) => s.wsConnected);
  const [serverInfo, setServerInfo] = useState<ServerInfo | null>(null);

  useEffect(() => {
    api.getServerInfo().then(setServerInfo).catch(() => {});
  }, []);

  const aliveCount = agents.filter((a) => a.alive).length;

  return (
    <div style={{
      height: '28px',
      background: '#0d0d0d',
      borderTop: '1px solid #1a1a1a',
      display: 'flex',
      alignItems: 'center',
      padding: '0 12px',
      gap: '16px',
      fontSize: '11px',
      fontFamily: 'var(--font-mono)',
      color: '#666',
      flexShrink: 0,
    }}>
      {/* Connection status */}
      <span style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
        <span style={{
          width: '7px',
          height: '7px',
          borderRadius: '50%',
          background: wsConnected ? '#00cc00' : '#cc0000',
          display: 'inline-block',
          boxShadow: wsConnected ? '0 0 4px #00cc0066' : '0 0 4px #cc000066',
        }} />
        {wsConnected ? 'Connected' : 'Disconnected'}
      </span>

      <span style={{ color: '#444' }}>|</span>
      <span>Operator: <span style={{ color: '#c0c0c0' }}>{username}</span> ({role})</span>

      <span style={{ color: '#444' }}>|</span>
      <span>Agents: <span style={{ color: aliveCount > 0 ? '#00cc00' : '#666' }}>{aliveCount}</span>/{agents.length}</span>

      <span style={{ color: '#444' }}>|</span>
      <span>Listeners: <span style={{ color: '#c0c0c0' }}>{listeners.length}</span></span>

      <div style={{ flex: 1 }} />
      <span>RTLC2 {serverInfo?.version || 'v0.6.0'}</span>
    </div>
  );
}
