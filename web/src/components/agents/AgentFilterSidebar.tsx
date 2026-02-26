// ═══════════════════════════════════════════════════════════════
//  RTLC2 Agent Filter Sidebar
//  OS filters, status toggle, text search, tag filter, and filter presets.
// ═══════════════════════════════════════════════════════════════

import { useState, useEffect, useMemo } from 'react';
import { useAgentStore } from '../../store/agentStore';
import type { AgentFilter } from '../../store/agentStore';

const OS_OPTIONS = ['Windows', 'Linux', 'macOS'];
const STATUS_OPTIONS: Array<AgentFilter['status']> = ['all', 'alive', 'dead'];

interface FilterPreset {
  name: string;
  filter: AgentFilter;
}

const PRESET_KEY = 'rtlc2_agent_filter_presets';

function loadPresets(): FilterPreset[] {
  try {
    const raw = localStorage.getItem(PRESET_KEY);
    return raw ? JSON.parse(raw) : [];
  } catch {
    return [];
  }
}

function savePresets(presets: FilterPreset[]) {
  localStorage.setItem(PRESET_KEY, JSON.stringify(presets));
}

export default function AgentFilterSidebar() {
  const { filter, setFilter, resetFilter, filteredAgents } = useAgentStore();
  const agents = useAgentStore((s) => s.agents);
  const [collapsed, setCollapsed] = useState(false);
  const [presets, setPresets] = useState<FilterPreset[]>([]);
  const [presetName, setPresetName] = useState('');

  useEffect(() => {
    setPresets(loadPresets());
  }, []);

  const filtered = filteredAgents();

  // Derive all available tags from agents
  const allTags = useMemo(() => {
    const tagSet = new Set<string>();
    agents.forEach(a => (a.tags || []).forEach(t => tagSet.add(t)));
    return Array.from(tagSet).sort();
  }, [agents]);

  const toggleOs = (os: string) => {
    const current = filter.os;
    if (current.includes(os)) {
      setFilter({ os: current.filter((o) => o !== os) });
    } else {
      setFilter({ os: [...current, os] });
    }
  };

  const toggleTag = (tag: string) => {
    const current = filter.tags;
    if (current.includes(tag)) {
      setFilter({ tags: current.filter((t) => t !== tag) });
    } else {
      setFilter({ tags: [...current, tag] });
    }
  };

  const handleSavePreset = () => {
    if (!presetName.trim()) return;
    const newPresets = [...presets, { name: presetName.trim(), filter: { ...filter } }];
    setPresets(newPresets);
    savePresets(newPresets);
    setPresetName('');
  };

  const handleLoadPreset = (preset: FilterPreset) => {
    setFilter(preset.filter);
  };

  const handleDeletePreset = (index: number) => {
    const newPresets = presets.filter((_, i) => i !== index);
    setPresets(newPresets);
    savePresets(newPresets);
  };

  const handleClearAll = () => {
    resetFilter();
  };

  // ── Styles ──────────────────────────────────────────────────

  const containerStyle: React.CSSProperties = {
    background: '#0d0d0d',
    borderBottom: '1px solid #1a1a1a',
    flexShrink: 0,
    overflow: 'hidden',
  };

  const headerStyle: React.CSSProperties = {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
    padding: '6px 10px',
    cursor: 'pointer',
    fontSize: '11px',
    color: '#888',
    background: '#111',
    borderBottom: collapsed ? 'none' : '1px solid #1a1a1a',
  };

  const bodyStyle: React.CSSProperties = {
    display: collapsed ? 'none' : 'flex',
    gap: '16px',
    padding: '8px 12px',
    alignItems: 'flex-start',
    flexWrap: 'wrap',
  };

  const sectionStyle: React.CSSProperties = {
    display: 'flex',
    flexDirection: 'column',
    gap: '4px',
  };

  const labelStyle: React.CSSProperties = {
    fontSize: '9px',
    color: '#555',
    textTransform: 'uppercase',
    letterSpacing: '0.5px',
    fontFamily: 'monospace',
  };

  const checkboxLabelStyle = (checked: boolean): React.CSSProperties => ({
    display: 'flex',
    alignItems: 'center',
    gap: '4px',
    padding: '2px 8px',
    background: checked ? '#cc000022' : '#1a1a1a',
    border: `1px solid ${checked ? '#cc0000' : '#333'}`,
    borderRadius: '3px',
    cursor: 'pointer',
    fontSize: '11px',
    color: checked ? '#cc0000' : '#888',
    transition: 'all 0.15s',
  });

  const statusBtnStyle = (active: boolean): React.CSSProperties => ({
    padding: '2px 8px',
    background: active ? '#cc000022' : '#1a1a1a',
    border: `1px solid ${active ? '#cc0000' : '#333'}`,
    borderRadius: '3px',
    cursor: 'pointer',
    fontSize: '11px',
    color: active ? '#cc0000' : '#888',
    fontFamily: 'inherit',
    transition: 'all 0.15s',
  });

  const inputStyle: React.CSSProperties = {
    padding: '4px 8px',
    background: '#0a0a0a',
    border: '1px solid #333',
    borderRadius: '3px',
    color: '#e0e0e0',
    fontSize: '11px',
    fontFamily: 'inherit',
    outline: 'none',
    width: '160px',
  };

  const smallBtnStyle: React.CSSProperties = {
    padding: '2px 8px',
    background: '#1a1a1a',
    border: '1px solid #333',
    borderRadius: '3px',
    color: '#888',
    cursor: 'pointer',
    fontSize: '10px',
    fontFamily: 'inherit',
  };

  // ── Render ──────────────────────────────────────────────────

  const hasActiveFilters = filter.os.length > 0 || filter.status !== 'all' || filter.search !== '' || filter.tags.length > 0;

  return (
    <div style={containerStyle}>
      <div
        style={headerStyle}
        onClick={() => setCollapsed(!collapsed)}
      >
        <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
          <span style={{ fontFamily: 'monospace' }}>{collapsed ? '[+]' : '[-]'}</span>
          <span style={{ textTransform: 'uppercase', letterSpacing: '0.5px', fontWeight: 600 }}>
            Filters
          </span>
          {hasActiveFilters && (
            <span style={{
              padding: '1px 6px',
              background: '#cc000022',
              border: '1px solid #cc000044',
              borderRadius: '3px',
              fontSize: '9px',
              color: '#cc0000',
            }}>
              ACTIVE
            </span>
          )}
          <span style={{ fontSize: '10px', color: '#444' }}>
            ({filtered.length} matching)
          </span>
        </div>
      </div>

      <div style={bodyStyle}>
        {/* OS Filter */}
        <div style={sectionStyle}>
          <span style={labelStyle}>OS</span>
          <div style={{ display: 'flex', gap: '4px' }}>
            {OS_OPTIONS.map((os) => (
              <label
                key={os}
                style={checkboxLabelStyle(filter.os.includes(os))}
                onClick={() => toggleOs(os)}
              >
                <span style={{ fontFamily: 'monospace' }}>
                  {filter.os.includes(os) ? '[x]' : '[ ]'}
                </span>
                {os}
              </label>
            ))}
          </div>
        </div>

        {/* Status Filter */}
        <div style={sectionStyle}>
          <span style={labelStyle}>Status</span>
          <div style={{ display: 'flex', gap: '4px' }}>
            {STATUS_OPTIONS.map((s) => (
              <button
                key={s}
                style={statusBtnStyle(filter.status === s)}
                onClick={() => setFilter({ status: s })}
              >
                {s.charAt(0).toUpperCase() + s.slice(1)}
              </button>
            ))}
          </div>
        </div>

        {/* Tag Filter */}
        {allTags.length > 0 && (
          <div style={sectionStyle}>
            <span style={labelStyle}>Tags</span>
            <div style={{ display: 'flex', gap: '4px', flexWrap: 'wrap' }}>
              {allTags.map((tag) => (
                <button
                  key={tag}
                  style={statusBtnStyle(filter.tags.includes(tag))}
                  onClick={() => toggleTag(tag)}
                >
                  {tag}
                </button>
              ))}
            </div>
          </div>
        )}

        {/* Search */}
        <div style={sectionStyle}>
          <span style={labelStyle}>Search</span>
          <input
            type="text"
            placeholder="hostname, user, IP..."
            value={filter.search}
            onChange={(e) => setFilter({ search: e.target.value })}
            style={inputStyle}
            onFocus={(e) => { e.currentTarget.style.borderColor = '#cc0000'; }}
            onBlur={(e) => { e.currentTarget.style.borderColor = '#333'; }}
          />
        </div>

        {/* Presets */}
        <div style={sectionStyle}>
          <span style={labelStyle}>Presets</span>
          <div style={{ display: 'flex', gap: '4px', alignItems: 'center', flexWrap: 'wrap' }}>
            {presets.map((p, i) => (
              <div key={i} style={{ display: 'flex', gap: '2px', alignItems: 'center' }}>
                <button
                  style={smallBtnStyle}
                  onClick={() => handleLoadPreset(p)}
                  title={`Load: ${p.name}`}
                >
                  {p.name}
                </button>
                <button
                  style={{ ...smallBtnStyle, color: '#cc0000', padding: '2px 4px' }}
                  onClick={() => handleDeletePreset(i)}
                  title="Delete preset"
                >
                  x
                </button>
              </div>
            ))}
            <div style={{ display: 'flex', gap: '2px', alignItems: 'center' }}>
              <input
                type="text"
                placeholder="Name"
                value={presetName}
                onChange={(e) => setPresetName(e.target.value)}
                style={{ ...inputStyle, width: '70px', padding: '2px 6px', fontSize: '10px' }}
              />
              <button
                style={smallBtnStyle}
                onClick={handleSavePreset}
                disabled={!presetName.trim()}
              >
                Save
              </button>
            </div>
          </div>
        </div>

        {/* Clear */}
        {hasActiveFilters && (
          <div style={{ ...sectionStyle, justifyContent: 'flex-end' }}>
            <span style={labelStyle}>&nbsp;</span>
            <button
              style={{ ...smallBtnStyle, color: '#cc0000', borderColor: '#440000' }}
              onClick={handleClearAll}
            >
              Clear All
            </button>
          </div>
        )}
      </div>
    </div>
  );
}
