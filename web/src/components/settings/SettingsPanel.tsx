import { useState, useEffect } from 'react';
import { useUIStore } from '../../store/uiStore';
import { useAuthStore } from '../../store/authStore';
import { api } from '../../api/client';
import type { ServerInfo } from '../../types';

const ACCENT_KEY = 'rtlc2_accent_color';
const SOUND_KEY = 'rtlc2_notification_sound';

export default function SettingsPanel() {
  const wsConnected = useUIStore((s) => s.wsConnected);
  const username = useAuthStore((s) => s.username);
  const role = useAuthStore((s) => s.role);
  const token = useAuthStore((s) => s.token);

  const [serverInfo, setServerInfo] = useState<ServerInfo | null>(null);
  const [accentColor, setAccentColor] = useState(() => localStorage.getItem(ACCENT_KEY) || '#cc0000');
  const [notifSound, setNotifSound] = useState(() => localStorage.getItem(SOUND_KEY) !== 'false');
  const [oldPassword, setOldPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [pwMsg, setPwMsg] = useState('');
  const [showToken, setShowToken] = useState(false);

  useEffect(() => {
    api.getServerInfo().then(setServerInfo).catch(() => {});
  }, []);

  const handleAccentChange = (color: string) => {
    setAccentColor(color);
    localStorage.setItem(ACCENT_KEY, color);
  };

  const handleSoundToggle = () => {
    const next = !notifSound;
    setNotifSound(next);
    localStorage.setItem(SOUND_KEY, String(next));
  };

  const handlePasswordChange = async () => {
    if (!newPassword.trim()) { setPwMsg('New password is required'); return; }
    try {
      const authStore = useAuthStore.getState();
      const userId = authStore.operator?.id || '';
      await api.updateOperator(userId, { password: newPassword });
      setPwMsg('Password updated successfully');
      setOldPassword('');
      setNewPassword('');
    } catch (err: any) {
      setPwMsg('Error: ' + err.message);
    }
  };

  const cardStyle: React.CSSProperties = {
    background: '#0d0d0d', border: '1px solid #1a1a1a', borderRadius: 8, padding: 16, marginBottom: 16,
  };
  const headerStyle: React.CSSProperties = {
    color: '#cc0000', fontSize: 12, fontWeight: 700, textTransform: 'uppercase',
    letterSpacing: '0.5px', marginBottom: 12,
  };
  const labelStyle: React.CSSProperties = {
    color: '#555', fontSize: 11, fontWeight: 600,
  };

  return (
    <div style={{ height: '100%', overflow: 'auto', padding: 16, maxWidth: 700 }}>
      <div style={{ color: '#cc0000', fontSize: 14, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: 16 }}>
        Settings
      </div>

      {/* Connection */}
      <div style={cardStyle}>
        <div style={headerStyle}>Connection</div>
        <div style={{ display: 'grid', gridTemplateColumns: 'auto 1fr', gap: '8px 16px', fontSize: 12 }}>
          <span style={labelStyle}>WebSocket Status</span>
          <span style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
            <span style={{
              width: 7, height: 7, borderRadius: '50%',
              background: wsConnected ? '#00cc00' : '#cc0000',
              display: 'inline-block',
            }} />
            <span style={{ color: wsConnected ? '#00cc00' : '#cc0000' }}>
              {wsConnected ? 'Connected' : 'Disconnected'}
            </span>
          </span>
          <span style={labelStyle}>Server URL</span>
          <span style={{ color: '#e0e0e0', fontFamily: 'var(--font-mono)' }}>{window.location.origin}</span>
          <span style={labelStyle}>API Version</span>
          <span style={{ color: '#e0e0e0' }}>{serverInfo?.version || '-'}</span>
        </div>
      </div>

      {/* Preferences */}
      <div style={cardStyle}>
        <div style={headerStyle}>Preferences</div>
        <div style={{ display: 'flex', gap: 24, alignItems: 'center', marginBottom: 12 }}>
          <div>
            <span style={{ ...labelStyle, display: 'block', marginBottom: 4 }}>Accent Color</span>
            <input type="color" value={accentColor} onChange={e => handleAccentChange(e.target.value)}
              style={{ width: 40, height: 30, border: '1px solid #333', background: '#0a0a0a', cursor: 'pointer' }} />
          </div>
          <div>
            <span style={{ ...labelStyle, display: 'block', marginBottom: 4 }}>Notification Sound</span>
            <button className="btn btn--small" onClick={handleSoundToggle}
              style={{ background: notifSound ? '#cc000022' : '#1a1a1a', borderColor: notifSound ? '#cc0000' : '#333', color: notifSound ? '#cc0000' : '#888' }}>
              {notifSound ? 'ON' : 'OFF'}
            </button>
          </div>
        </div>
      </div>

      {/* Account */}
      <div style={cardStyle}>
        <div style={headerStyle}>Account</div>
        <div style={{ display: 'grid', gridTemplateColumns: 'auto 1fr', gap: '8px 16px', fontSize: 12, marginBottom: 16 }}>
          <span style={labelStyle}>Username</span>
          <span style={{ color: '#e0e0e0' }}>{username}</span>
          <span style={labelStyle}>Role</span>
          <span style={{ color: '#e0e0e0' }}>{role}</span>
          <span style={labelStyle}>API Token</span>
          <span style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
            <span style={{ color: '#888', fontFamily: 'var(--font-mono)', fontSize: 10 }}>
              {showToken ? (token || '-') : '****************************'}
            </span>
            <button className="btn btn--small" onClick={() => setShowToken(!showToken)} style={{ fontSize: 9 }}>
              {showToken ? 'Hide' : 'Show'}
            </button>
          </span>
        </div>

        <div style={{ borderTop: '1px solid #1a1a1a', paddingTop: 12 }}>
          <span style={{ ...labelStyle, display: 'block', marginBottom: 8 }}>Change Password</span>
          <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
            <input className="input" type="password" placeholder="Current password" value={oldPassword}
              onChange={e => setOldPassword(e.target.value)} style={{ width: 160 }} />
            <input className="input" type="password" placeholder="New password" value={newPassword}
              onChange={e => setNewPassword(e.target.value)} style={{ width: 160 }} />
            <button className="btn btn--primary btn--small" onClick={handlePasswordChange}>Update</button>
          </div>
          {pwMsg && <div style={{ color: pwMsg.startsWith('Error') ? '#ff3333' : '#00cc00', fontSize: 11, marginTop: 6 }}>{pwMsg}</div>}
        </div>
      </div>

      {/* About */}
      <div style={cardStyle}>
        <div style={headerStyle}>About</div>
        <div style={{ fontSize: 12, color: '#888' }}>
          <div style={{ marginBottom: 4 }}>
            <span style={{ color: '#cc0000', fontWeight: 700 }}>RTLC2</span> - Red Team Leaders C2 Framework
          </div>
          <div style={{ marginBottom: 4 }}>Version: <span style={{ color: '#e0e0e0' }}>{serverInfo?.version || 'v0.6.0'}</span></div>
          <div style={{ marginBottom: 4 }}>Author: Joas Antonio dos Santos</div>
          <div>Server OS: {serverInfo?.os || '-'} | Hostname: {serverInfo?.hostname || '-'}</div>
        </div>
      </div>
    </div>
  );
}
