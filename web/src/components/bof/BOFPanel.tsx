import { useState, useEffect, useCallback, useRef } from 'react';
import { api } from '../../api/client';
import { useAgentStore } from '../../store/agentStore';
import type { BOF } from '../../types';

interface Props {
  onClose: () => void;
}

type CategoryFilter = 'all' | 'recon' | 'credential' | 'lateral' | 'evasion' | 'persistence' | 'dotnet' | 'favorites';
type PlatformFilter = 'all' | 'windows' | 'linux';

const OPSEC_MAP: Record<string, { color: string; label: string }> = {
  safe: { color: '#22c55e', label: 'Safe' },
  low: { color: '#22c55e', label: 'Safe' },
  moderate: { color: '#eab308', label: 'Moderate' },
  medium: { color: '#eab308', label: 'Moderate' },
  noisy: { color: '#ef4444', label: 'Noisy' },
  high: { color: '#ef4444', label: 'Noisy' },
};

const CATEGORY_LABELS: Record<CategoryFilter, string> = {
  all: 'All',
  recon: 'Recon',
  credential: 'Credential',
  lateral: 'Lateral',
  evasion: 'Evasion',
  persistence: 'Persistence',
  dotnet: '.NET',
  favorites: 'Favorites',
};

const FAVORITES_KEY = 'rtlc2_bof_favorites';

function loadFavorites(): Set<string> {
  try {
    const raw = localStorage.getItem(FAVORITES_KEY);
    return new Set(raw ? JSON.parse(raw) : []);
  } catch { return new Set(); }
}

function saveFavorites(favs: Set<string>) {
  localStorage.setItem(FAVORITES_KEY, JSON.stringify([...favs]));
}

function getOpsecInfo(opsec: string): { color: string; label: string } {
  const key = (opsec || '').toLowerCase().trim();
  return OPSEC_MAP[key] || { color: '#eab308', label: opsec || 'Unknown' };
}

export default function BOFPanel({ onClose }: Props) {
  const agents = useAgentStore((s) => s.agents);
  const [bofs, setBofs] = useState<BOF[]>([]);
  const [selectedAgents, setSelectedAgents] = useState<string[]>([]);
  const [selectedBof, setSelectedBof] = useState<BOF | null>(null);
  const [args, setArgs] = useState<Record<string, string>>({});
  const [output, setOutput] = useState<string[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const [categoryFilter, setCategoryFilter] = useState<CategoryFilter>('all');
  const [platformFilter, setPlatformFilter] = useState<PlatformFilter>('all');
  const [search, setSearch] = useState('');
  const [favorites, setFavorites] = useState<Set<string>>(loadFavorites);
  const outputRef = useRef<HTMLDivElement>(null);
  const pollRefs = useRef<ReturnType<typeof setInterval>[]>([]);

  useEffect(() => {
    api.getBOFs().then((res) => setBofs(res.bofs || [])).catch(() => {});
  }, []);

  // Cleanup all polling intervals on unmount
  useEffect(() => {
    return () => {
      pollRefs.current.forEach((id) => clearInterval(id));
      pollRefs.current = [];
    };
  }, []);

  useEffect(() => {
    if (outputRef.current) {
      outputRef.current.scrollTop = outputRef.current.scrollHeight;
    }
  }, [output]);

  const toggleFavorite = useCallback((name: string) => {
    setFavorites((prev) => {
      const next = new Set(prev);
      if (next.has(name)) next.delete(name);
      else next.add(name);
      saveFavorites(next);
      return next;
    });
  }, []);

  const toggleAgent = useCallback((agentId: string) => {
    setSelectedAgents((prev) =>
      prev.includes(agentId)
        ? prev.filter((id) => id !== agentId)
        : [...prev, agentId]
    );
  }, []);

  const filteredBofs = bofs.filter((b) => {
    // Category filter
    if (categoryFilter === 'favorites') {
      if (!favorites.has(b.name)) return false;
    } else if (categoryFilter !== 'all') {
      if (b.category.toLowerCase() !== categoryFilter) return false;
    }
    // Platform filter
    if (platformFilter !== 'all') {
      const plats = (b.platforms || []).map((p) => p.toLowerCase());
      if (!plats.includes(platformFilter)) return false;
    }
    // Search filter
    if (search.trim()) {
      const term = search.toLowerCase();
      if (!b.name.toLowerCase().includes(term) && !b.description.toLowerCase().includes(term)) return false;
    }
    return true;
  });

  const categories = [...new Set(filteredBofs.map((b) => b.category))].sort();

  const categoryCounts: Record<string, number> = {};
  for (const b of bofs) {
    const cat = b.category.toLowerCase();
    categoryCounts[cat] = (categoryCounts[cat] || 0) + 1;
  }

  const handleExecute = async () => {
    if (selectedAgents.length === 0 || !selectedBof) return;
    setIsLoading(true);
    const ts = new Date().toLocaleTimeString('en-US', { hour12: false });

    for (const agentId of selectedAgents) {
      setOutput((prev) => [...prev, `[${ts}] Executing BOF: ${selectedBof.name} on agent ${agentId.slice(0, 8)}...`]);

      try {
        const res = await api.executeBOF(agentId, selectedBof.name, args);
        setOutput((prev) => [...prev, `[${ts}] Task queued: ${res.task_id} (agent ${agentId.slice(0, 8)})`]);

        // Poll for result (tracked for cleanup on unmount)
        const poll = setInterval(async () => {
          try {
            const result = await api.getTaskResult(res.task_id);
            if (result.status >= 2) {
              clearInterval(poll);
              pollRefs.current = pollRefs.current.filter((id) => id !== poll);
              const out = result.output ? atob(result.output) : '(no output)';
              const t2 = new Date().toLocaleTimeString('en-US', { hour12: false });
              setOutput((prev) => [...prev,
                result.status === 2
                  ? `[${t2}] [SUCCESS] [${agentId.slice(0, 8)}] ${out}`
                  : `[${t2}] [ERROR] [${agentId.slice(0, 8)}] ${out}`,
              ]);
            }
          } catch { /* not ready */ }
        }, 2000);
        pollRefs.current.push(poll);

        setTimeout(() => {
          clearInterval(poll);
          pollRefs.current = pollRefs.current.filter((id) => id !== poll);
        }, 60000);
      } catch (err: unknown) {
        const message = err instanceof Error ? err.message : String(err);
        setOutput((prev) => [...prev, `[${ts}] [ERROR] [${agentId.slice(0, 8)}] ${message}`]);
      }
    }
    setIsLoading(false);
  };

  const handleUpload = async () => {
    const input = document.createElement('input');
    input.type = 'file';
    input.accept = '.o,.obj';
    input.onchange = async () => {
      const file = input.files?.[0];
      if (!file) return;
      const reader = new FileReader();
      reader.onload = async () => {
        const b64 = btoa(String.fromCharCode(...new Uint8Array(reader.result as ArrayBuffer)));
        try {
          await api.uploadBOF(b64, file.name);
          const ts = new Date().toLocaleTimeString('en-US', { hour12: false });
          setOutput((prev) => [...prev, `[${ts}] [SUCCESS] BOF uploaded: ${file.name}`]);
          const res = await api.getBOFs();
          setBofs(res.bofs || []);
        } catch (err: unknown) {
          const message = err instanceof Error ? err.message : String(err);
          setOutput((prev) => [...prev, `[ERROR] Upload failed: ${message}`]);
        }
      };
      reader.readAsArrayBuffer(file);
    };
    input.click();
  };

  const copyOutput = () => {
    navigator.clipboard.writeText(output.join('\n')).catch(() => {});
  };

  return (
    <div className="dialog-overlay" onClick={onClose}>
      <div
        className="dialog"
        style={{ width: '1050px', height: '85vh', display: 'flex', flexDirection: 'column' }}
        onClick={(e) => e.stopPropagation()}
      >
        <div className="dialog__header">
          <span className="dialog__title">BOF / Post-Exploitation Modules</span>
          <button className="dialog__close" onClick={onClose}>x</button>
        </div>

        {/* Category filter tabs */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 0, borderBottom: '1px solid #1a1a1a', padding: '0 12px', flexShrink: 0 }}>
          {(Object.keys(CATEGORY_LABELS) as CategoryFilter[]).map((cat) => (
            <button
              key={cat}
              onClick={() => setCategoryFilter(cat)}
              style={{
                padding: '8px 14px',
                background: 'transparent',
                border: 'none',
                borderBottom: categoryFilter === cat ? '2px solid #cc0000' : '2px solid transparent',
                color: categoryFilter === cat ? '#cc0000' : '#666',
                fontSize: 11,
                fontWeight: 600,
                cursor: 'pointer',
                textTransform: 'uppercase',
                letterSpacing: '0.3px',
                transition: 'all 0.15s',
              }}
            >
              {CATEGORY_LABELS[cat]}
              {cat !== 'all' && cat !== 'favorites' && categoryCounts[cat] ? ` (${categoryCounts[cat]})` : ''}
              {cat === 'favorites' ? ` (${favorites.size})` : ''}
            </button>
          ))}
        </div>

        {/* Search bar + Platform filter */}
        <div style={{ display: 'flex', gap: 10, padding: '8px 12px', borderBottom: '1px solid #1a1a1a', alignItems: 'center', flexShrink: 0 }}>
          <input
            className="input"
            placeholder="Search BOFs by name or description..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            style={{ flex: 1 }}
          />
          <div style={{ display: 'flex', gap: 4 }}>
            {(['all', 'windows', 'linux'] as PlatformFilter[]).map((p) => (
              <button
                key={p}
                onClick={() => setPlatformFilter(p)}
                style={{
                  padding: '4px 10px',
                  background: platformFilter === p ? '#1a0000' : '#111',
                  border: `1px solid ${platformFilter === p ? '#cc0000' : '#222'}`,
                  borderRadius: 3,
                  color: platformFilter === p ? '#cc0000' : '#777',
                  fontSize: 10,
                  fontWeight: 600,
                  cursor: 'pointer',
                  textTransform: 'uppercase',
                }}
              >
                {p === 'all' ? 'All Platforms' : p === 'windows' ? 'Windows' : 'Linux'}
              </button>
            ))}
          </div>
          <button className="btn btn--small" onClick={handleUpload}>Upload BOF</button>
        </div>

        <div style={{ flex: 1, display: 'flex', overflow: 'hidden' }}>
          {/* Left: BOF list */}
          <div style={{ width: '320px', borderRight: '1px solid #1a1a1a', overflow: 'auto', padding: '10px 12px' }}>
            <div style={{ color: '#888', fontSize: 11, fontWeight: 700, textTransform: 'uppercase', marginBottom: 8 }}>
              BOF Collection ({filteredBofs.length})
            </div>

            {categories.map((cat) => {
              const catBofs = filteredBofs.filter((b) => b.category === cat);
              if (catBofs.length === 0) return null;
              return (
                <div key={cat} style={{ marginBottom: 12 }}>
                  <div style={{
                    color: '#cc0000',
                    fontSize: 10,
                    fontWeight: 700,
                    textTransform: 'uppercase',
                    letterSpacing: '0.5px',
                    marginBottom: 4,
                    padding: '4px 0',
                    borderBottom: '1px solid #1a1a1a',
                    display: 'flex',
                    justifyContent: 'space-between',
                  }}>
                    <span>{cat}</span>
                    <span style={{ color: '#555' }}>{catBofs.length}</span>
                  </div>
                  {catBofs.map((bof) => {
                    const opsecInfo = getOpsecInfo(bof.opsec);
                    return (
                      <div
                        key={bof.name}
                        onClick={() => {
                          setSelectedBof(bof);
                          const defaultArgs: Record<string, string> = {};
                          bof.args?.forEach((a) => { defaultArgs[a.name] = a.default_value || ''; });
                          setArgs(defaultArgs);
                        }}
                        style={{
                          padding: '6px 8px',
                          cursor: 'pointer',
                          color: selectedBof?.name === bof.name ? '#cc0000' : '#c0c0c0',
                          background: selectedBof?.name === bof.name ? '#1a0000' : 'transparent',
                          borderRadius: 3,
                          fontSize: 12,
                          transition: 'all 0.1s',
                          display: 'flex',
                          alignItems: 'center',
                          justifyContent: 'space-between',
                          gap: 6,
                        }}
                      >
                        <div style={{ display: 'flex', alignItems: 'center', gap: 6, minWidth: 0, flex: 1 }}>
                          {/* OPSEC indicator */}
                          <span style={{
                            width: 7,
                            height: 7,
                            borderRadius: '50%',
                            background: opsecInfo.color,
                            flexShrink: 0,
                          }} />
                          <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                            {bof.name}
                          </span>
                        </div>
                        {/* Favorite star */}
                        <span
                          onClick={(e) => {
                            e.stopPropagation();
                            toggleFavorite(bof.name);
                          }}
                          style={{
                            cursor: 'pointer',
                            color: favorites.has(bof.name) ? '#eab308' : '#333',
                            fontSize: 14,
                            flexShrink: 0,
                            lineHeight: 1,
                          }}
                          title={favorites.has(bof.name) ? 'Remove from favorites' : 'Add to favorites'}
                        >
                          {favorites.has(bof.name) ? '\u2605' : '\u2606'}
                        </span>
                      </div>
                    );
                  })}
                </div>
              );
            })}

            {filteredBofs.length === 0 && (
              <div style={{ color: '#444', textAlign: 'center', padding: '20px', fontSize: 12 }}>
                {bofs.length === 0 ? 'No BOFs loaded. Upload a .o file.' : 'No BOFs match the current filters.'}
              </div>
            )}
          </div>

          {/* Right: BOF details + args + agents + output */}
          <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
            {selectedBof ? (
              <>
                {/* BOF details header */}
                <div style={{ padding: '12px', borderBottom: '1px solid #1a1a1a' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 4 }}>
                    <div style={{ fontSize: 14, fontWeight: 700, color: '#e0e0e0' }}>{selectedBof.name}</div>
                    {/* Category badge */}
                    <span style={{
                      padding: '2px 8px',
                      background: '#1a0000',
                      border: '1px solid #cc0000',
                      borderRadius: 3,
                      color: '#cc0000',
                      fontSize: 9,
                      fontWeight: 700,
                      textTransform: 'uppercase',
                    }}>
                      {selectedBof.category}
                    </span>
                    {/* OPSEC indicator */}
                    {(() => {
                      const info = getOpsecInfo(selectedBof.opsec);
                      return (
                        <span style={{
                          display: 'flex',
                          alignItems: 'center',
                          gap: 4,
                          fontSize: 10,
                          color: info.color,
                          fontWeight: 600,
                        }}>
                          <span style={{ width: 8, height: 8, borderRadius: '50%', background: info.color }} />
                          OPSEC: {info.label}
                        </span>
                      );
                    })()}
                    {/* Platform icons */}
                    <div style={{ display: 'flex', gap: 4 }}>
                      {(selectedBof.platforms || []).map((p) => (
                        <span key={p} style={{
                          padding: '1px 6px',
                          background: '#111',
                          border: '1px solid #222',
                          borderRadius: 2,
                          color: '#888',
                          fontSize: 9,
                          textTransform: 'uppercase',
                        }}>
                          {p}
                        </span>
                      ))}
                    </div>
                  </div>
                  <div style={{ color: '#888', fontSize: 12, marginTop: 4 }}>{selectedBof.description}</div>
                  <div style={{ display: 'flex', gap: 16, marginTop: 6, fontSize: 11 }}>
                    <span style={{ color: '#666' }}>Author: <span style={{ color: '#c0c0c0' }}>{selectedBof.author}</span></span>
                    <span style={{ color: '#666' }}>Compiled: <span style={{ color: selectedBof.compiled ? '#22c55e' : '#ef4444' }}>{selectedBof.compiled ? 'Yes' : 'No'}</span></span>
                  </div>
                </div>

                {/* Arguments */}
                {selectedBof.args && selectedBof.args.length > 0 && (
                  <div style={{ padding: '10px 12px', borderBottom: '1px solid #1a1a1a' }}>
                    <div style={{ color: '#888', fontSize: 11, fontWeight: 700, marginBottom: 6, textTransform: 'uppercase' }}>
                      Arguments
                    </div>
                    <div style={{ display: 'grid', gridTemplateColumns: 'auto 1fr', gap: '5px 10px', alignItems: 'center' }}>
                      {selectedBof.args.map((arg) => (
                        <div key={arg.name} style={{ display: 'contents' }}>
                          <label style={{ color: '#808080', fontSize: 12, display: 'flex', alignItems: 'center', gap: 4 }}>
                            {arg.name}
                            {arg.required && <span style={{ color: '#cc0000', fontSize: 10 }}>*</span>}
                            <span style={{ color: '#444', fontSize: 9 }}>({arg.type})</span>:
                          </label>
                          <input
                            className="input"
                            value={args[arg.name] || ''}
                            onChange={(e) => setArgs((p) => ({ ...p, [arg.name]: e.target.value }))}
                            placeholder={arg.description}
                            style={{
                              borderColor: arg.required && !args[arg.name]?.trim() ? '#cc0000' : undefined,
                            }}
                          />
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Multi-agent selector */}
                <div style={{ padding: '10px 12px', borderBottom: '1px solid #1a1a1a' }}>
                  <div style={{ color: '#888', fontSize: 11, fontWeight: 700, marginBottom: 6, textTransform: 'uppercase' }}>
                    Target Agents ({selectedAgents.length} selected)
                  </div>
                  <div style={{ maxHeight: 100, overflow: 'auto', display: 'flex', flexDirection: 'column', gap: 2 }}>
                    {agents.filter((a) => a.alive).map((a) => (
                      <label key={a.id} style={{
                        display: 'flex',
                        alignItems: 'center',
                        gap: 8,
                        cursor: 'pointer',
                        padding: '3px 6px',
                        borderRadius: 3,
                        background: selectedAgents.includes(a.id) ? '#1a0000' : 'transparent',
                        fontSize: 11,
                        color: selectedAgents.includes(a.id) ? '#e0e0e0' : '#888',
                      }}>
                        <input
                          type="checkbox"
                          checked={selectedAgents.includes(a.id)}
                          onChange={() => toggleAgent(a.id)}
                          style={{ accentColor: '#cc0000' }}
                        />
                        {a.hostname} ({a.id.slice(0, 8)}) - {a.os}
                      </label>
                    ))}
                    {agents.filter((a) => a.alive).length === 0 && (
                      <span style={{ color: '#444', fontSize: 11 }}>No alive agents</span>
                    )}
                  </div>
                </div>

                {/* Execute button */}
                <div style={{ padding: '10px 12px', borderBottom: '1px solid #1a1a1a' }}>
                  <button
                    className="btn btn--primary"
                    onClick={handleExecute}
                    disabled={selectedAgents.length === 0 || isLoading}
                  >
                    {isLoading ? 'Executing...' : `Execute BOF on ${selectedAgents.length} agent(s)`}
                  </button>
                </div>
              </>
            ) : (
              <div style={{ padding: '40px', textAlign: 'center', color: '#444' }}>
                Select a BOF from the list to view details
              </div>
            )}

            {/* Output */}
            <div style={{
              flex: 1,
              overflow: 'hidden',
              display: 'flex',
              flexDirection: 'column',
            }}>
              <div style={{
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
                padding: '6px 12px',
                borderBottom: '1px solid #111',
              }}>
                <span style={{ color: '#555', fontSize: 10, fontWeight: 700, textTransform: 'uppercase' }}>Output</span>
                <div style={{ display: 'flex', gap: 6 }}>
                  <button
                    className="btn btn--small"
                    onClick={copyOutput}
                    style={{ fontSize: 10 }}
                  >
                    Copy
                  </button>
                  <button
                    className="btn btn--small"
                    onClick={() => setOutput([])}
                    style={{ fontSize: 10 }}
                  >
                    Clear
                  </button>
                </div>
              </div>
              <div
                ref={outputRef}
                style={{
                  flex: 1,
                  overflow: 'auto',
                  padding: '8px 12px',
                  background: '#080808',
                  fontFamily: 'var(--font-mono)',
                  fontSize: 11,
                  lineHeight: 1.6,
                }}
              >
                {output.length === 0 ? (
                  <span style={{ color: '#444' }}>BOF output will appear here...</span>
                ) : (
                  output.map((line, i) => (
                    <div key={i} style={{
                      color: line.includes('[ERROR]') ? '#ff3333'
                        : line.includes('[SUCCESS]') ? '#00cc00'
                        : '#a0a0a0',
                    }}>
                      {line}
                    </div>
                  ))
                )}
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
