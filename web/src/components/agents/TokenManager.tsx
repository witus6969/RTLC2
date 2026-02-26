// ═══════════════════════════════════════════════════════════════
//  RTLC2 Token Manager
//  Lists stolen/created tokens, impersonate, revert, make token,
//  steal from PID.
// ═══════════════════════════════════════════════════════════════

import { useState, useEffect, useCallback } from 'react';
import { useTaskStore } from '../../store/taskStore';
import { api } from '../../api/client';
import { TaskType, TaskStatus } from '../../types';
import type { TaskResult } from '../../types';

interface TokenManagerProps {
  agentId: string;
}

interface TokenEntry {
  id: string;
  user: string;
  sid: string;
  integrity: string;
  tokenType: 'primary' | 'impersonation';
  active: boolean;
}

interface MakeTokenForm {
  domain: string;
  username: string;
  password: string;
}

// Parse token list from task output
// Expected: JSON array or text lines like:
//   [0] DOMAIN\User (S-1-5-...) Primary High [Active]
function parseTokenOutput(output: string): TokenEntry[] {
  // Try JSON
  try {
    const parsed = JSON.parse(output);
    if (Array.isArray(parsed)) {
      return parsed.map((t: any, i: number) => ({
        id: t.id || String(i),
        user: t.user || t.username || '',
        sid: t.sid || '',
        integrity: t.integrity || t.integrity_level || '',
        tokenType: t.type === 'impersonation' || t.token_type === 'impersonation' ? 'impersonation' : 'primary',
        active: Boolean(t.active),
      }));
    }
  } catch {
    // Not JSON
  }

  // Text parsing
  const entries: TokenEntry[] = [];
  const lines = output.split('\n');
  const lineRe = /^\[(\d+)\]\s+(\S+)\s+\((S-[\d-]+)\)\s+(Primary|Impersonation)\s+(\S+)\s*(\[Active\])?/i;

  for (const line of lines) {
    const match = line.match(lineRe);
    if (match) {
      entries.push({
        id: match[1],
        user: match[2],
        sid: match[3],
        tokenType: match[4].toLowerCase() === 'impersonation' ? 'impersonation' : 'primary',
        integrity: match[5],
        active: Boolean(match[6]),
      });
    }
  }

  return entries;
}

export default function TokenManager({ agentId }: TokenManagerProps) {
  const { sendCommand } = useTaskStore();
  const [tokens, setTokens] = useState<TokenEntry[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [showMakeToken, setShowMakeToken] = useState(false);
  const [makeTokenForm, setMakeTokenForm] = useState<MakeTokenForm>({
    domain: '',
    username: '',
    password: '',
  });
  const [stealPid, setStealPid] = useState('');
  const [showStealInput, setShowStealInput] = useState(false);

  const fetchTokens = useCallback(async () => {
    setIsLoading(true);
    setError(null);

    try {
      const res = await api.getAgentTasks(agentId);
      const tokenTasks = (res.tasks || []).filter(
        (t) => t.type === TaskType.TOKEN
      );

      // Find the most recent completed token list result
      let latestTokens: TokenEntry[] = [];
      for (const task of tokenTasks.reverse()) {
        try {
          const result: TaskResult = await api.getTaskResult(task.task_id);
          if (result.status !== TaskStatus.COMPLETE || !result.output) continue;

          const decoded = atob(result.output);
          const parsed = parseTokenOutput(decoded);
          if (parsed.length > 0) {
            latestTokens = parsed;
            break;
          }
        } catch {
          // Skip
        }
      }

      setTokens(latestTokens);
    } catch (err: any) {
      setError(err.message || 'Failed to fetch tokens');
    } finally {
      setIsLoading(false);
    }
  }, [agentId]);

  useEffect(() => {
    fetchTokens();
  }, [fetchTokens]);

  const handleListTokens = async () => {
    await sendCommand(agentId, 'token list');
    setTimeout(fetchTokens, 3000);
  };

  const handleImpersonate = async (token: TokenEntry) => {
    await sendCommand(agentId, `token impersonate ${token.id}`);
    setTimeout(fetchTokens, 3000);
  };

  const handleRevert = async () => {
    await sendCommand(agentId, 'token revert');
    setTimeout(fetchTokens, 3000);
  };

  const handleMakeToken = async () => {
    const { domain, username, password } = makeTokenForm;
    if (!username || !password) {
      setError('Username and password are required');
      return;
    }
    const domainPart = domain ? `${domain}\\` : '';
    await sendCommand(agentId, `token make ${domainPart}${username} ${password}`);
    setShowMakeToken(false);
    setMakeTokenForm({ domain: '', username: '', password: '' });
    setTimeout(fetchTokens, 3000);
  };

  const handleStealToken = async () => {
    const pid = parseInt(stealPid, 10);
    if (isNaN(pid) || pid <= 0) {
      setError('Invalid PID');
      return;
    }
    await sendCommand(agentId, `token steal ${pid}`);
    setShowStealInput(false);
    setStealPid('');
    setTimeout(fetchTokens, 3000);
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
    flexWrap: 'wrap',
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

  const inputStyle: React.CSSProperties = {
    padding: '4px 8px',
    background: '#0a0a0a',
    border: '1px solid #333',
    borderRadius: '3px',
    color: '#e0e0e0',
    fontSize: '12px',
    fontFamily: 'inherit',
    outline: 'none',
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

  const integrityBadge = (integrity: string): React.CSSProperties => {
    const lower = integrity.toLowerCase();
    const color =
      lower === 'system'
        ? '#ff4444'
        : lower === 'high'
        ? '#ffaa33'
        : lower === 'medium'
        ? '#44cc44'
        : '#888';
    return {
      display: 'inline-block',
      padding: '2px 6px',
      borderRadius: '3px',
      fontSize: '10px',
      fontWeight: 600,
      textTransform: 'uppercase',
      border: `1px solid ${color}44`,
      color,
    };
  };

  const typeBadge = (type: string): React.CSSProperties => ({
    display: 'inline-block',
    padding: '2px 6px',
    borderRadius: '3px',
    fontSize: '10px',
    fontWeight: 600,
    border: `1px solid ${type === 'impersonation' ? '#9933cc44' : '#0066cc44'}`,
    color: type === 'impersonation' ? '#cc77ff' : '#4499ff',
  });

  const dialogOverlayStyle: React.CSSProperties = {
    position: 'absolute',
    top: 0,
    left: 0,
    right: 0,
    bottom: 0,
    background: 'rgba(0,0,0,0.7)',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    zIndex: 10,
  };

  const dialogStyle: React.CSSProperties = {
    background: '#111',
    border: '1px solid #333',
    borderRadius: '6px',
    padding: '16px',
    width: '320px',
    maxWidth: '90%',
  };

  const fieldStyle: React.CSSProperties = {
    marginBottom: '10px',
  };

  const labelStyle: React.CSSProperties = {
    display: 'block',
    fontSize: '10px',
    color: '#666',
    marginBottom: '3px',
    textTransform: 'uppercase',
    letterSpacing: '0.5px',
    fontFamily: 'monospace',
  };

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
    <div style={{ ...containerStyle, position: 'relative' }}>
      {/* Toolbar */}
      <div style={toolbarStyle}>
        <span style={{ fontSize: '13px', fontWeight: 600, color: '#cc0000' }}>
          Token Manager
        </span>
        <div style={{ flex: 1 }} />
        <button style={btnStyle} onClick={handleListTokens} disabled={isLoading}>
          {isLoading ? 'Loading...' : 'List Tokens'}
        </button>
        <button style={btnAccentStyle} onClick={() => setShowMakeToken(true)}>
          Make Token
        </button>
        <button style={btnStyle} onClick={() => setShowStealInput(!showStealInput)}>
          Steal from PID
        </button>
        <button
          style={{ ...btnStyle, color: '#ffaa33', borderColor: '#443300' }}
          onClick={handleRevert}
        >
          Revert
        </button>
        <button style={btnStyle} onClick={fetchTokens} disabled={isLoading}>
          Refresh
        </button>
      </div>

      {/* Steal PID input bar */}
      {showStealInput && (
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: '8px',
            padding: '6px 12px',
            borderBottom: '1px solid #222',
            background: '#0d0d0d',
            flexShrink: 0,
          }}
        >
          <span style={{ fontSize: '11px', color: '#666' }}>PID:</span>
          <input
            type="text"
            value={stealPid}
            onChange={(e) => setStealPid(e.target.value.replace(/\D/g, ''))}
            onKeyDown={(e) => { if (e.key === 'Enter') handleStealToken(); }}
            style={{ ...inputStyle, width: '100px', fontFamily: 'monospace' }}
            placeholder="1234"
            autoFocus
            onFocus={(e) => { e.currentTarget.style.borderColor = '#cc0000'; }}
            onBlur={(e) => { e.currentTarget.style.borderColor = '#333'; }}
          />
          <button style={btnAccentStyle} onClick={handleStealToken}>
            Steal
          </button>
          <button style={btnStyle} onClick={() => { setShowStealInput(false); setStealPid(''); }}>
            Cancel
          </button>
        </div>
      )}

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

      {/* Token Table */}
      {tokens.length === 0 && !isLoading ? (
        <div style={emptyStyle}>
          <span style={{ fontSize: '32px', opacity: 0.3 }}>[T]</span>
          <span>No tokens discovered</span>
          <span style={{ fontSize: '11px', color: '#333' }}>
            Click "List Tokens" to enumerate available tokens
          </span>
        </div>
      ) : (
        <div style={{ flex: 1, overflow: 'auto' }}>
          <table style={tableStyle}>
            <thead>
              <tr>
                <th style={thStyle}>ID</th>
                <th style={thStyle}>User</th>
                <th style={thStyle}>SID</th>
                <th style={thStyle}>Integrity</th>
                <th style={thStyle}>Type</th>
                <th style={thStyle}>Status</th>
                <th style={{ ...thStyle, textAlign: 'right' }}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {tokens.map((token) => (
                <tr
                  key={token.id}
                  style={{ background: token.active ? '#cc000008' : 'transparent' }}
                  onMouseEnter={(e) => {
                    if (!token.active) (e.currentTarget as HTMLTableRowElement).style.background = '#111';
                  }}
                  onMouseLeave={(e) => {
                    (e.currentTarget as HTMLTableRowElement).style.background = token.active ? '#cc000008' : 'transparent';
                  }}
                >
                  <td style={{ ...tdStyle, fontFamily: 'monospace', fontSize: '11px', color: '#888' }}>
                    {token.id}
                  </td>
                  <td style={{ ...tdStyle, fontWeight: 600 }}>
                    {token.user}
                  </td>
                  <td style={{ ...tdStyle, fontFamily: 'monospace', fontSize: '10px', color: '#666' }}>
                    {token.sid}
                  </td>
                  <td style={tdStyle}>
                    <span style={integrityBadge(token.integrity)}>{token.integrity}</span>
                  </td>
                  <td style={tdStyle}>
                    <span style={typeBadge(token.tokenType)}>{token.tokenType}</span>
                  </td>
                  <td style={tdStyle}>
                    {token.active ? (
                      <span style={{ color: '#44cc44', fontSize: '11px', fontWeight: 600 }}>ACTIVE</span>
                    ) : (
                      <span style={{ color: '#555', fontSize: '11px' }}>--</span>
                    )}
                  </td>
                  <td style={{ ...tdStyle, textAlign: 'right' }}>
                    {!token.active && (
                      <button
                        style={{ ...btnStyle, fontSize: '11px', padding: '2px 8px' }}
                        onClick={() => handleImpersonate(token)}
                      >
                        Impersonate
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Make Token Dialog */}
      {showMakeToken && (
        <div style={dialogOverlayStyle} onClick={() => setShowMakeToken(false)}>
          <div style={dialogStyle} onClick={(e) => e.stopPropagation()}>
            <div style={{ fontSize: '14px', fontWeight: 600, color: '#cc0000', marginBottom: '14px' }}>
              Make Token
            </div>

            <div style={fieldStyle}>
              <label style={labelStyle}>Domain</label>
              <input
                type="text"
                placeholder="WORKGROUP"
                value={makeTokenForm.domain}
                onChange={(e) => setMakeTokenForm({ ...makeTokenForm, domain: e.target.value })}
                style={{ ...inputStyle, width: '100%', boxSizing: 'border-box' }}
                onFocus={(e) => { e.currentTarget.style.borderColor = '#cc0000'; }}
                onBlur={(e) => { e.currentTarget.style.borderColor = '#333'; }}
              />
            </div>

            <div style={fieldStyle}>
              <label style={labelStyle}>Username *</label>
              <input
                type="text"
                placeholder="Administrator"
                value={makeTokenForm.username}
                onChange={(e) => setMakeTokenForm({ ...makeTokenForm, username: e.target.value })}
                style={{ ...inputStyle, width: '100%', boxSizing: 'border-box' }}
                autoFocus
                onFocus={(e) => { e.currentTarget.style.borderColor = '#cc0000'; }}
                onBlur={(e) => { e.currentTarget.style.borderColor = '#333'; }}
              />
            </div>

            <div style={fieldStyle}>
              <label style={labelStyle}>Password *</label>
              <input
                type="password"
                placeholder="password"
                value={makeTokenForm.password}
                onChange={(e) => setMakeTokenForm({ ...makeTokenForm, password: e.target.value })}
                onKeyDown={(e) => { if (e.key === 'Enter') handleMakeToken(); }}
                style={{ ...inputStyle, width: '100%', boxSizing: 'border-box' }}
                onFocus={(e) => { e.currentTarget.style.borderColor = '#cc0000'; }}
                onBlur={(e) => { e.currentTarget.style.borderColor = '#333'; }}
              />
            </div>

            <div style={{ display: 'flex', gap: '8px', justifyContent: 'flex-end', marginTop: '14px' }}>
              <button style={btnStyle} onClick={() => setShowMakeToken(false)}>
                Cancel
              </button>
              <button style={btnAccentStyle} onClick={handleMakeToken}>
                Create
              </button>
            </div>
          </div>
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
        <span>{tokens.length} tokens</span>
        <span>
          {tokens.find((t) => t.active)
            ? `Active: ${tokens.find((t) => t.active)!.user}`
            : 'No impersonation active'}
        </span>
      </div>
    </div>
  );
}
