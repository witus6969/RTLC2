import { useState, type FormEvent } from 'react';
import { useAuthStore } from '../store/authStore';

export default function LoginPage() {
  const { login, isLoading, error } = useAuthStore();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    try {
      await login(username, password);
    } catch {
      // Error is handled by store
    }
  };

  return (
    <div style={{
      height: '100vh',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      background: '#0a0a0a',
      fontFamily: 'var(--font-sans)',
    }}>
      <div style={{
        width: '420px',
        background: '#0d0d0d',
        border: '1px solid #1a1a1a',
        borderRadius: '12px',
        padding: '40px',
        boxShadow: '0 8px 32px rgba(0,0,0,0.5)',
      }}>
        {/* Banner */}
        <pre style={{
          color: '#cc0000',
          fontFamily: 'var(--font-mono)',
          fontSize: '11px',
          textAlign: 'center',
          marginBottom: '8px',
          lineHeight: 1.3,
        }}>{`  ____  _____ _     ____ ____
 |  _ \\|_   _| |   / ___|___ \\
 | |_) | | | | |  | |     __) |
 |  _ <  | | | |__| |___ / __/
 |_| \\_\\ |_| |____|\\____|_____|`}</pre>
        <div style={{
          textAlign: 'center',
          color: '#666',
          fontSize: '11px',
          marginBottom: '32px',
          fontFamily: 'var(--font-mono)',
        }}>
          Red Team Leaders — Command &amp; Control
        </div>

        <form onSubmit={handleSubmit}>
          <div style={{ marginBottom: '16px' }}>
            <label style={{ display: 'block', color: '#808080', fontSize: '11px', fontWeight: 600, marginBottom: '6px', textTransform: 'uppercase', letterSpacing: '0.5px' }}>
              Username
            </label>
            <input
              className="input"
              type="text"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              placeholder="operator username"
              autoFocus
              required
            />
          </div>

          <div style={{ marginBottom: '24px' }}>
            <label style={{ display: 'block', color: '#808080', fontSize: '11px', fontWeight: 600, marginBottom: '6px', textTransform: 'uppercase', letterSpacing: '0.5px' }}>
              Password
            </label>
            <input
              className="input"
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="••••••••"
              required
            />
          </div>

          {error && (
            <div style={{
              background: '#1a0000',
              border: '1px solid #cc0000',
              borderRadius: '4px',
              padding: '10px 14px',
              color: '#ff3333',
              fontSize: '12px',
              marginBottom: '16px',
            }}>
              {error}
            </div>
          )}

          <button
            type="submit"
            className="btn btn--primary btn--large"
            style={{ width: '100%' }}
            disabled={isLoading || !username || !password}
          >
            {isLoading ? (
              <span style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <span className="spinner" style={{ width: '16px', height: '16px', borderWidth: '2px' }} />
                CONNECTING...
              </span>
            ) : 'CONNECT'}
          </button>
        </form>

        <div style={{
          textAlign: 'center',
          color: '#444',
          fontSize: '10px',
          marginTop: '24px',
          fontFamily: 'var(--font-mono)',
        }}>
          RTLC2 Framework v0.1.0
        </div>
      </div>
    </div>
  );
}
