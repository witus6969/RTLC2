import { useState, useCallback, useEffect } from 'react';
import { useAgentStore } from '../../store/agentStore';
import { useUIStore } from '../../store/uiStore';
import { useTaskStore } from '../../store/taskStore';
import AgentFilterSidebar from './AgentFilterSidebar';
import type { Agent } from '../../types';

type SortField = keyof Agent;
type SortDir = 'asc' | 'desc';
type GroupBy = 'none' | 'os' | 'listener_id' | 'integrity';

interface ContextMenuState {
  x: number;
  y: number;
  agent: Agent;
  submenu: string | null;
}

export default function AgentTable() {
  const {
    agents,
    selectedAgentId,
    selectAgent,
    removeAgent,
    filteredAgents,
    selectedAgents,
    toggleAgentSelection,
    selectAllFiltered,
    clearSelection,
  } = useAgentStore();
  const { openAgentTab, openAgentSubTab, setShowLateralWizard } = useUIStore();
  const { sendCommand } = useTaskStore();
  const [sortField, setSortField] = useState<SortField>('hostname');
  const [sortDir, setSortDir] = useState<SortDir>('asc');
  const [contextMenu, setContextMenu] = useState<ContextMenuState | null>(null);
  const [groupBy, setGroupBy] = useState<GroupBy>('none');
  const [bulkSleepValue, setBulkSleepValue] = useState('');

  // Close context menu on click outside
  useEffect(() => {
    const handler = () => setContextMenu(null);
    if (contextMenu) {
      window.addEventListener('click', handler);
      return () => window.removeEventListener('click', handler);
    }
  }, [contextMenu]);

  const handleSort = (field: SortField) => {
    if (sortField === field) {
      setSortDir((d) => (d === 'asc' ? 'desc' : 'asc'));
    } else {
      setSortField(field);
      setSortDir('asc');
    }
  };

  const filtered = filteredAgents();

  const sorted = [...filtered].sort((a, b) => {
    const aVal = String(a[sortField] ?? '');
    const bVal = String(b[sortField] ?? '');
    const cmp = aVal.localeCompare(bVal, undefined, { numeric: true });
    return sortDir === 'asc' ? cmp : -cmp;
  });

  // Group sorted agents
  const grouped: { label: string; agents: Agent[] }[] = [];
  if (groupBy === 'none') {
    grouped.push({ label: '', agents: sorted });
  } else {
    const groups: Record<string, Agent[]> = {};
    for (const a of sorted) {
      const key = String(a[groupBy] || 'Unknown');
      if (!groups[key]) groups[key] = [];
      groups[key].push(a);
    }
    for (const [label, agents] of Object.entries(groups)) {
      grouped.push({ label, agents });
    }
  }

  const handleContextMenu = useCallback((e: React.MouseEvent, agent: Agent) => {
    e.preventDefault();
    setContextMenu({ x: e.clientX, y: e.clientY, agent, submenu: null });
  }, []);

  const handleDoubleClick = useCallback((agent: Agent) => {
    openAgentTab(agent.id, agent.hostname);
  }, [openAgentTab]);

  const execOnAgent = (agentId: string, cmd: string) => {
    openAgentTab(agentId, agents.find(a => a.id === agentId)?.hostname || agentId);
    sendCommand(agentId, cmd);
    setContextMenu(null);
  };

  // Bulk actions
  const handleBulkKill = () => {
    if (!confirm(`Kill ${selectedAgents.length} selected agents?`)) return;
    selectedAgents.forEach((id) => {
      sendCommand(id, 'exit');
    });
    clearSelection();
  };

  const handleBulkSleep = () => {
    if (!bulkSleepValue) return;
    selectedAgents.forEach((id) => {
      sendCommand(id, `sleep ${bulkSleepValue}`);
    });
    setBulkSleepValue('');
  };

  const handleBulkRemove = () => {
    if (!confirm(`Remove ${selectedAgents.length} selected agents?`)) return;
    selectedAgents.forEach((id) => {
      removeAgent(id);
    });
    clearSelection();
  };

  const columns: { key: SortField; label: string; width?: string }[] = [
    { key: 'id', label: 'ID', width: '80px' },
    { key: 'hostname', label: 'Hostname' },
    { key: 'username', label: 'Username' },
    { key: 'os', label: 'OS', width: '80px' },
    { key: 'arch', label: 'Arch', width: '60px' },
    { key: 'process_name', label: 'Process' },
    { key: 'internal_ip', label: 'Internal IP', width: '120px' },
    { key: 'external_ip', label: 'External IP', width: '120px' },
    { key: 'last_seen', label: 'Last Seen', width: '160px' },
    { key: 'alive', label: 'Status', width: '70px' },
  ];

  const rowClass = (agent: Agent) => {
    const classes: string[] = [];
    if (agent.id === selectedAgentId) classes.push('selected');
    if (agent.integrity === 'system') classes.push('integrity-system');
    else if (agent.integrity === 'high') classes.push('integrity-high');
    return classes.join(' ');
  };

  const allFilteredSelected = filtered.length > 0 && filtered.every((a) => selectedAgents.includes(a.id));

  // ── Styles for bulk toolbar ──

  const bulkBarStyle: React.CSSProperties = {
    display: 'flex',
    alignItems: 'center',
    gap: '8px',
    padding: '4px 10px',
    background: '#1a0000',
    borderBottom: '1px solid #330000',
    fontSize: '11px',
    color: '#cc0000',
    flexShrink: 0,
  };

  const smallBtnStyle: React.CSSProperties = {
    padding: '2px 8px',
    background: '#1a1a1a',
    border: '1px solid #333',
    borderRadius: '3px',
    color: '#e0e0e0',
    cursor: 'pointer',
    fontSize: '11px',
    fontFamily: 'inherit',
  };

  const dangerBtnStyle: React.CSSProperties = {
    ...smallBtnStyle,
    color: '#cc0000',
    borderColor: '#440000',
  };

  const smallInputStyle: React.CSSProperties = {
    padding: '2px 6px',
    background: '#0a0a0a',
    border: '1px solid #333',
    borderRadius: '3px',
    color: '#e0e0e0',
    fontSize: '11px',
    fontFamily: 'inherit',
    outline: 'none',
    width: '60px',
  };

  const groupBySelectStyle: React.CSSProperties = {
    padding: '2px 6px',
    background: '#0a0a0a',
    border: '1px solid #333',
    borderRadius: '3px',
    color: '#e0e0e0',
    fontSize: '10px',
    fontFamily: 'inherit',
    cursor: 'pointer',
    outline: 'none',
  };

  return (
    <div style={{ height: '100%', display: 'flex', flexDirection: 'column' }}>
      {/* Filter Sidebar */}
      <AgentFilterSidebar />

      {/* Group By + Counts Bar */}
      <div style={{
        display: 'flex',
        alignItems: 'center',
        gap: '8px',
        padding: '4px 10px',
        background: '#0d0d0d',
        borderBottom: '1px solid #1a1a1a',
        fontSize: '10px',
        color: '#555',
        flexShrink: 0,
      }}>
        <span style={{ fontFamily: 'monospace', textTransform: 'uppercase', letterSpacing: '0.5px' }}>
          Group by:
        </span>
        <select
          style={groupBySelectStyle}
          value={groupBy}
          onChange={(e) => setGroupBy(e.target.value as GroupBy)}
        >
          <option value="none">None</option>
          <option value="os">OS</option>
          <option value="listener_id">Listener</option>
          <option value="integrity">Integrity</option>
        </select>
        <div style={{ flex: 1 }} />
        <span>{filtered.length} of {agents.length} agents</span>
      </div>

      {/* Bulk Action Toolbar */}
      {selectedAgents.length > 0 && (
        <div style={bulkBarStyle}>
          <span style={{ fontWeight: 600 }}>
            {selectedAgents.length} selected
          </span>
          <button style={dangerBtnStyle} onClick={handleBulkKill}>Kill Selected</button>
          <div style={{ display: 'flex', gap: '3px', alignItems: 'center' }}>
            <span style={{ color: '#888' }}>Sleep:</span>
            <input
              type="text"
              placeholder="sec"
              value={bulkSleepValue}
              onChange={(e) => setBulkSleepValue(e.target.value)}
              style={smallInputStyle}
            />
            <button style={smallBtnStyle} onClick={handleBulkSleep} disabled={!bulkSleepValue}>
              Set
            </button>
          </div>
          <button style={dangerBtnStyle} onClick={handleBulkRemove}>Remove</button>
          <div style={{ flex: 1 }} />
          <button style={smallBtnStyle} onClick={clearSelection}>Deselect All</button>
        </div>
      )}

      {/* Table */}
      <div style={{ flex: 1, overflow: 'auto' }}>
        <table className="rtl-table">
          <thead>
            <tr>
              <th style={{ width: '30px', textAlign: 'center' }}>
                <input
                  type="checkbox"
                  checked={allFilteredSelected}
                  onChange={() => {
                    if (allFilteredSelected) clearSelection();
                    else selectAllFiltered();
                  }}
                  style={{ cursor: 'pointer', accentColor: '#cc0000' }}
                />
              </th>
              {columns.map((col) => (
                <th
                  key={col.key}
                  className={sortField === col.key ? 'sorted' : ''}
                  style={{ width: col.width }}
                  onClick={() => handleSort(col.key)}
                >
                  {col.label}
                  {sortField === col.key && (
                    <span style={{ marginLeft: '4px', fontSize: '10px' }}>
                      {sortDir === 'asc' ? '\u25B2' : '\u25BC'}
                    </span>
                  )}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {grouped.map((group, gi) => (
              <GroupRows
                key={gi}
                label={group.label}
                agents={group.agents}
                columns={columns}
                rowClass={rowClass}
                selectedAgents={selectedAgents}
                selectAgent={selectAgent}
                toggleAgentSelection={toggleAgentSelection}
                handleDoubleClick={handleDoubleClick}
                handleContextMenu={handleContextMenu}
                showGroupHeader={groupBy !== 'none'}
              />
            ))}
            {sorted.length === 0 && (
              <tr>
                <td colSpan={columns.length + 1} style={{ textAlign: 'center', color: '#444', padding: '24px' }}>
                  No agents matching filters
                </td>
              </tr>
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
          <div className="context-menu__item" onClick={() => { handleDoubleClick(contextMenu.agent); setContextMenu(null); }}>
            Interact
          </div>
          <div className="context-menu__separator" />

          <div className="context-menu__label">Reconnaissance</div>
          <div className="context-menu__item" onClick={() => execOnAgent(contextMenu.agent.id, 'ps')}>Process List</div>
          <div className="context-menu__item" onClick={() => execOnAgent(contextMenu.agent.id, 'whoami')}>Whoami</div>
          <div className="context-menu__item" onClick={() => execOnAgent(contextMenu.agent.id, 'ipconfig')}>Network Info</div>
          <div className="context-menu__separator" />

          <div className="context-menu__label">Credential Access</div>
          <div className="context-menu__item" onClick={() => execOnAgent(contextMenu.agent.id, 'hashdump')}>Hashdump</div>
          <div className="context-menu__item" onClick={() => execOnAgent(contextMenu.agent.id, 'token list')}>Token List</div>
          <div className="context-menu__separator" />

          <div className="context-menu__label">Collection</div>
          <div className="context-menu__item" onClick={() => execOnAgent(contextMenu.agent.id, 'screenshot')}>Screenshot</div>
          <div className="context-menu__item" onClick={() => execOnAgent(contextMenu.agent.id, 'keylog start')}>Keylogger</div>
          <div className="context-menu__item" onClick={() => execOnAgent(contextMenu.agent.id, 'clipboard start')}>Clipboard Monitor</div>
          <div className="context-menu__separator" />

          <div className="context-menu__label">Viewers</div>
          <div className="context-menu__item" onClick={() => { openAgentSubTab(contextMenu.agent.id, contextMenu.agent.hostname, 'screenshot'); setContextMenu(null); }}>View Screenshots</div>
          <div className="context-menu__item" onClick={() => { openAgentSubTab(contextMenu.agent.id, contextMenu.agent.hostname, 'keylogger'); setContextMenu(null); }}>View Keylog</div>
          <div className="context-menu__item" onClick={() => { openAgentSubTab(contextMenu.agent.id, contextMenu.agent.hostname, 'socks'); setContextMenu(null); }}>SOCKS Proxies</div>
          <div className="context-menu__item" onClick={() => { openAgentSubTab(contextMenu.agent.id, contextMenu.agent.hostname, 'tokens'); setContextMenu(null); }}>Token Manager</div>
          <div className="context-menu__separator" />

          <div className="context-menu__label">Lateral Movement</div>
          <div className="context-menu__item" onClick={() => { setShowLateralWizard(true, contextMenu.agent.id); setContextMenu(null); }}>Lateral Movement Wizard</div>
          <div className="context-menu__separator" />

          <div className="context-menu__label">Actions</div>
          <div className="context-menu__item" onClick={() => {
            const secs = prompt('Sleep interval (seconds):', '5');
            if (secs) execOnAgent(contextMenu.agent.id, `sleep ${secs}`);
          }}>Sleep</div>
          <div className="context-menu__item context-menu__item--danger" onClick={() => execOnAgent(contextMenu.agent.id, 'exit')}>
            Exit Agent
          </div>
          <div className="context-menu__item context-menu__item--danger" onClick={() => execOnAgent(contextMenu.agent.id, 'selfdestruct')}>
            Self-Destruct
          </div>
          <div className="context-menu__separator" />
          <div className="context-menu__item" onClick={() => {
            navigator.clipboard.writeText(contextMenu.agent.id);
            setContextMenu(null);
          }}>Copy Agent ID</div>
          <div className="context-menu__item context-menu__item--danger" onClick={() => {
            if (confirm('Remove this agent?')) {
              removeAgent(contextMenu.agent.id);
            }
            setContextMenu(null);
          }}>Remove Agent</div>
        </div>
      )}
    </div>
  );
}

// ── Group Rows Sub-Component ──

interface GroupRowsProps {
  label: string;
  agents: Agent[];
  columns: { key: keyof Agent; label: string; width?: string }[];
  rowClass: (agent: Agent) => string;
  selectedAgents: string[];
  selectAgent: (id: string) => void;
  toggleAgentSelection: (id: string) => void;
  handleDoubleClick: (agent: Agent) => void;
  handleContextMenu: (e: React.MouseEvent, agent: Agent) => void;
  showGroupHeader: boolean;
}

function GroupRows({
  label,
  agents,
  columns,
  rowClass,
  selectedAgents,
  selectAgent,
  toggleAgentSelection,
  handleDoubleClick,
  handleContextMenu,
  showGroupHeader,
}: GroupRowsProps) {
  return (
    <>
      {showGroupHeader && (
        <tr>
          <td
            colSpan={columns.length + 1}
            style={{
              background: '#111',
              color: '#cc0000',
              padding: '4px 10px',
              fontSize: '10px',
              fontWeight: 700,
              textTransform: 'uppercase',
              letterSpacing: '0.5px',
              borderBottom: '1px solid #222',
            }}
          >
            {label} ({agents.length})
          </td>
        </tr>
      )}
      {agents.map((agent) => (
        <tr
          key={agent.id}
          className={rowClass(agent)}
          onClick={() => selectAgent(agent.id)}
          onDoubleClick={() => handleDoubleClick(agent)}
          onContextMenu={(e) => handleContextMenu(e, agent)}
          style={{ cursor: 'pointer' }}
        >
          <td style={{ textAlign: 'center', width: '30px' }} onClick={(e) => e.stopPropagation()}>
            <input
              type="checkbox"
              checked={selectedAgents.includes(agent.id)}
              onChange={() => toggleAgentSelection(agent.id)}
              style={{ cursor: 'pointer', accentColor: '#cc0000' }}
            />
          </td>
          <td style={{ fontFamily: 'var(--font-mono)', fontSize: '11px' }}>
            {agent.id.slice(0, 8)}
          </td>
          <td>{agent.hostname}</td>
          <td>{agent.username}</td>
          <td>{agent.os}</td>
          <td>{agent.arch}</td>
          <td>{agent.process_name}</td>
          <td style={{ fontFamily: 'var(--font-mono)' }}>{agent.internal_ip}</td>
          <td style={{ fontFamily: 'var(--font-mono)' }}>{agent.external_ip}</td>
          <td style={{ fontFamily: 'var(--font-mono)', fontSize: '11px' }}>{agent.last_seen}</td>
          <td>
            <span className={agent.alive ? 'status-alive' : 'status-dead'}>
              {agent.alive ? 'ALIVE' : 'DEAD'}
            </span>
          </td>
        </tr>
      ))}
    </>
  );
}
