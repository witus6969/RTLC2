// ═══════════════════════════════════════════════════════════════
//  RTLC2 Campaign Management Panel
//  Create, manage, and assign agents to campaigns.
// ═══════════════════════════════════════════════════════════════

import { useState, useEffect } from 'react';
import { useCampaignStore } from '../../store/campaignStore';
import { useAgentStore } from '../../store/agentStore';

const STATUS_COLORS: Record<string, string> = {
  active: '#00cc44',
  completed: '#cc9900',
  archived: '#666',
};

export default function CampaignPanel() {
  const {
    campaigns,
    selectedCampaign,
    loading,
    fetch,
    create,
    update,
    remove,
    select,
    clearSelection,
    addAgent,
    removeAgent: removeAgentFromCampaign,
  } = useCampaignStore();
  const { agents } = useAgentStore();

  const [showForm, setShowForm] = useState(false);
  const [formName, setFormName] = useState('');
  const [formDesc, setFormDesc] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [deleteConfirmId, setDeleteConfirmId] = useState<string | null>(null);
  const [addAgentId, setAddAgentId] = useState('');

  useEffect(() => {
    fetch();
  }, [fetch]);

  const handleCreate = async () => {
    if (!formName.trim()) {
      setError('Campaign name is required');
      return;
    }
    setError(null);
    try {
      await create(formName.trim(), formDesc.trim());
      setFormName('');
      setFormDesc('');
      setShowForm(false);
    } catch (err: any) {
      setError(err.message || 'Failed to create campaign');
    }
  };

  const handleDelete = async (id: string) => {
    try {
      await remove(id);
      setDeleteConfirmId(null);
    } catch (err: any) {
      setError(err.message || 'Failed to delete campaign');
    }
  };

  const handleAddAgent = async () => {
    if (!selectedCampaign || !addAgentId) return;
    try {
      await addAgent(selectedCampaign.id, addAgentId);
      setAddAgentId('');
    } catch (err: any) {
      setError(err.message || 'Failed to add agent');
    }
  };

  const handleRemoveAgent = async (agentId: string) => {
    if (!selectedCampaign) return;
    try {
      await removeAgentFromCampaign(selectedCampaign.id, agentId);
    } catch (err: any) {
      setError(err.message || 'Failed to remove agent');
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
    width: '100%',
    padding: '6px 10px',
    background: '#0a0a0a',
    border: '1px solid #333',
    borderRadius: '3px',
    color: '#e0e0e0',
    fontSize: '12px',
    fontFamily: 'inherit',
    outline: 'none',
    boxSizing: 'border-box',
  };

  const selectStyle: React.CSSProperties = {
    ...inputStyle,
    cursor: 'pointer',
    appearance: 'none',
    backgroundImage:
      'url("data:image/svg+xml;charset=utf-8,%3Csvg xmlns=%27http://www.w3.org/2000/svg%27 width=%2712%27 height=%278%27%3E%3Cpath fill=%27%23888%27 d=%27M6 8L0 0h12z%27/%3E%3C/svg%3E")',
    backgroundRepeat: 'no-repeat',
    backgroundPosition: 'right 10px center',
    paddingRight: '30px',
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

  const formContainerStyle: React.CSSProperties = {
    padding: '14px 16px',
    background: '#0d0d0d',
    borderBottom: '1px solid #222',
    flexShrink: 0,
  };

  const labelStyle: React.CSSProperties = {
    display: 'block',
    fontSize: '10px',
    color: '#666',
    marginBottom: '4px',
    textTransform: 'uppercase',
    letterSpacing: '0.5px',
    fontFamily: 'monospace',
  };

  const fieldStyle: React.CSSProperties = {
    marginBottom: '10px',
  };

  const statusBadge = (status: string): React.CSSProperties => ({
    display: 'inline-block',
    padding: '2px 8px',
    borderRadius: '3px',
    fontSize: '10px',
    fontWeight: 600,
    textTransform: 'uppercase',
    background: (STATUS_COLORS[status] || '#444') + '22',
    color: STATUS_COLORS[status] || '#888',
    border: `1px solid ${(STATUS_COLORS[status] || '#444')}44`,
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

  // If a campaign is selected, show detail view
  if (selectedCampaign) {
    const campaignAgents = selectedCampaign.agents || [];
    const availableAgents = agents.filter((a) => !campaignAgents.includes(a.id));

    return (
      <div style={containerStyle}>
        <div style={toolbarStyle}>
          <button style={btnStyle} onClick={clearSelection}>
            &lt; Back
          </button>
          <span style={{ fontSize: '13px', fontWeight: 600, color: '#cc0000' }}>
            {selectedCampaign.name}
          </span>
          <span style={statusBadge(selectedCampaign.status)}>{selectedCampaign.status}</span>
          <div style={{ flex: 1 }} />
          {['active', 'completed', 'archived'].map((s) => (
            <button
              key={s}
              style={selectedCampaign.status === s ? btnAccentStyle : btnStyle}
              onClick={() => update(selectedCampaign.id, { status: s })}
            >
              {s.charAt(0).toUpperCase() + s.slice(1)}
            </button>
          ))}
        </div>

        {selectedCampaign.description && (
          <div style={{ padding: '8px 12px', fontSize: '12px', color: '#888', borderBottom: '1px solid #1a1a1a' }}>
            {selectedCampaign.description}
          </div>
        )}

        {/* Add agent */}
        <div style={{ padding: '8px 12px', display: 'flex', gap: '8px', alignItems: 'center', borderBottom: '1px solid #1a1a1a' }}>
          <label style={{ fontSize: '10px', color: '#666', textTransform: 'uppercase', fontFamily: 'monospace' }}>
            Add Agent:
          </label>
          <select
            style={{ ...selectStyle, width: '200px' }}
            value={addAgentId}
            onChange={(e) => setAddAgentId(e.target.value)}
          >
            <option value="">-- Select Agent --</option>
            {availableAgents.map((a) => (
              <option key={a.id} value={a.id}>{a.hostname} ({a.id.slice(0, 8)})</option>
            ))}
          </select>
          <button style={btnAccentStyle} onClick={handleAddAgent} disabled={!addAgentId}>
            Add
          </button>
        </div>

        {/* Agent list */}
        <div style={{ flex: 1, overflow: 'auto' }}>
          {campaignAgents.length === 0 ? (
            <div style={{ ...emptyStyle, height: '200px' }}>
              <span>No agents in this campaign</span>
            </div>
          ) : (
            <table style={tableStyle}>
              <thead>
                <tr>
                  <th style={thStyle}>Agent ID</th>
                  <th style={thStyle}>Hostname</th>
                  <th style={thStyle}>OS</th>
                  <th style={thStyle}>Status</th>
                  <th style={{ ...thStyle, textAlign: 'right' }}>Actions</th>
                </tr>
              </thead>
              <tbody>
                {campaignAgents.map((agentId) => {
                  const agent = agents.find((a) => a.id === agentId);
                  return (
                    <tr
                      key={agentId}
                      onMouseEnter={(e) => { (e.currentTarget as HTMLTableRowElement).style.background = '#111'; }}
                      onMouseLeave={(e) => { (e.currentTarget as HTMLTableRowElement).style.background = 'transparent'; }}
                    >
                      <td style={{ ...tdStyle, fontFamily: 'monospace', fontSize: '11px' }}>{agentId.slice(0, 8)}</td>
                      <td style={tdStyle}>{agent?.hostname || 'Unknown'}</td>
                      <td style={tdStyle}>{agent?.os || '-'}</td>
                      <td style={tdStyle}>
                        <span className={agent?.alive ? 'status-alive' : 'status-dead'}>
                          {agent?.alive ? 'ALIVE' : 'DEAD'}
                        </span>
                      </td>
                      <td style={{ ...tdStyle, textAlign: 'right' }}>
                        <button
                          style={{ ...btnDangerStyle, fontSize: '11px', padding: '2px 8px' }}
                          onClick={() => handleRemoveAgent(agentId)}
                        >
                          Remove
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )}
        </div>
      </div>
    );
  }

  // ── List View ──────────────────────────────────────────────

  return (
    <div style={containerStyle}>
      {/* Toolbar */}
      <div style={toolbarStyle}>
        <span style={{ fontSize: '13px', fontWeight: 600, color: '#cc0000' }}>
          Campaigns
        </span>
        <span style={{ fontSize: '11px', color: '#555' }}>
          ({campaigns.length} campaigns)
        </span>
        <div style={{ flex: 1 }} />
        <button
          style={showForm ? btnStyle : btnAccentStyle}
          onClick={() => {
            if (showForm) {
              setFormName('');
              setFormDesc('');
            }
            setShowForm(!showForm);
          }}
        >
          {showForm ? 'Cancel' : 'Create Campaign'}
        </button>
        <button style={btnStyle} onClick={fetch} disabled={loading}>
          {loading ? 'Loading...' : 'Refresh'}
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

      {/* Create Form */}
      {showForm && (
        <div style={formContainerStyle}>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 2fr', gap: '10px' }}>
            <div style={fieldStyle}>
              <label style={labelStyle}>Name</label>
              <input
                type="text"
                placeholder="Campaign name"
                value={formName}
                onChange={(e) => setFormName(e.target.value)}
                style={inputStyle}
                autoFocus
                onFocus={(e) => { e.currentTarget.style.borderColor = '#cc0000'; }}
                onBlur={(e) => { e.currentTarget.style.borderColor = '#333'; }}
              />
            </div>
            <div style={fieldStyle}>
              <label style={labelStyle}>Description</label>
              <input
                type="text"
                placeholder="Optional description"
                value={formDesc}
                onChange={(e) => setFormDesc(e.target.value)}
                style={inputStyle}
                onFocus={(e) => { e.currentTarget.style.borderColor = '#cc0000'; }}
                onBlur={(e) => { e.currentTarget.style.borderColor = '#333'; }}
              />
            </div>
          </div>
          <div style={{ display: 'flex', gap: '8px', justifyContent: 'flex-end' }}>
            <button style={btnAccentStyle} onClick={handleCreate}>
              Create Campaign
            </button>
          </div>
        </div>
      )}

      {/* Campaign Table */}
      {campaigns.length === 0 ? (
        <div style={emptyStyle}>
          <span style={{ fontSize: '32px', opacity: 0.3 }}>[C]</span>
          <span>No campaigns created</span>
          <span style={{ fontSize: '11px', color: '#333' }}>
            Create a campaign to organize and track agent groups
          </span>
        </div>
      ) : (
        <div style={{ flex: 1, overflow: 'auto' }}>
          <table style={tableStyle}>
            <thead>
              <tr>
                <th style={thStyle}>Name</th>
                <th style={thStyle}>Description</th>
                <th style={thStyle}>Status</th>
                <th style={thStyle}>Agents</th>
                <th style={thStyle}>Created</th>
                <th style={{ ...thStyle, textAlign: 'right' }}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {campaigns.map((c) => (
                <tr
                  key={c.id}
                  onMouseEnter={(e) => { (e.currentTarget as HTMLTableRowElement).style.background = '#111'; }}
                  onMouseLeave={(e) => { (e.currentTarget as HTMLTableRowElement).style.background = 'transparent'; }}
                  style={{ cursor: 'pointer' }}
                  onClick={() => select(c.id)}
                >
                  <td style={{ ...tdStyle, fontWeight: 600 }}>{c.name}</td>
                  <td style={{ ...tdStyle, color: '#888', fontSize: '11px' }}>{c.description || '-'}</td>
                  <td style={tdStyle}>
                    <span style={statusBadge(c.status)}>{c.status}</span>
                  </td>
                  <td style={{ ...tdStyle, fontFamily: 'monospace' }}>{c.agent_count}</td>
                  <td style={{ ...tdStyle, fontSize: '11px', color: '#888' }}>{c.created_at}</td>
                  <td style={{ ...tdStyle, textAlign: 'right' }} onClick={(e) => e.stopPropagation()}>
                    <div style={{ display: 'flex', gap: '4px', justifyContent: 'flex-end' }}>
                      {deleteConfirmId === c.id ? (
                        <>
                          <button
                            style={{ ...btnDangerStyle, fontSize: '11px', padding: '2px 8px' }}
                            onClick={() => handleDelete(c.id)}
                          >
                            Confirm
                          </button>
                          <button
                            style={{ ...btnStyle, fontSize: '11px', padding: '2px 8px' }}
                            onClick={() => setDeleteConfirmId(null)}
                          >
                            No
                          </button>
                        </>
                      ) : (
                        <button
                          style={{ ...btnDangerStyle, fontSize: '11px', padding: '2px 8px' }}
                          onClick={() => setDeleteConfirmId(c.id)}
                        >
                          Delete
                        </button>
                      )}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
