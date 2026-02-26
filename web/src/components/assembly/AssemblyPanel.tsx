import { useState, useCallback, useRef, useEffect } from 'react';
import { api } from '../../api/client';
import { useAgentStore } from '../../store/agentStore';

interface AssemblyHistory {
  id: string;
  name: string;
  args: string;
  timestamp: string;
  agentId: string;
  status: 'success' | 'error' | 'pending';
}

const HISTORY_KEY = 'rtlc2_assembly_history';

function loadHistory(): AssemblyHistory[] {
  try {
    const raw = localStorage.getItem(HISTORY_KEY);
    return raw ? JSON.parse(raw) : [];
  } catch { return []; }
}

function saveHistory(items: AssemblyHistory[]) {
  localStorage.setItem(HISTORY_KEY, JSON.stringify(items.slice(0, 20)));
}

export default function AssemblyPanel() {
  const agents = useAgentStore((s) => s.agents);
  const [selectedAgent, setSelectedAgent] = useState('');
  const [assemblyData, setAssemblyData] = useState('');
  const [assemblyName, setAssemblyName] = useState('');
  const [args, setArgs] = useState('');
  const [runtime, setRuntime] = useState('v4.0.30319');
  const [fork, setFork] = useState(false);
  const [amsiBypass, setAmsiBypass] = useState(true);
  const [output, setOutput] = useState<string[]>([]);
  const [isExecuting, setIsExecuting] = useState(false);
  const [history, setHistory] = useState<AssemblyHistory[]>(loadHistory);
  const [isDragOver, setIsDragOver] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const outputRef = useRef<HTMLDivElement>(null);
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);

  useEffect(() => {
    return () => {
      if (pollRef.current) clearInterval(pollRef.current);
    };
  }, []);

  useEffect(() => {
    if (outputRef.current) {
      outputRef.current.scrollTop = outputRef.current.scrollHeight;
    }
  }, [output]);

  const ts = () => new Date().toLocaleTimeString('en-US', { hour12: false });

  const handleFileRead = useCallback((file: File) => {
    const reader = new FileReader();
    reader.onload = () => {
      const bytes = new Uint8Array(reader.result as ArrayBuffer);
      let binary = '';
      for (let i = 0; i < bytes.length; i++) {
        binary += String.fromCharCode(bytes[i]);
      }
      setAssemblyData(btoa(binary));
      setAssemblyName(file.name);
      setOutput((prev) => [...prev, `[${ts()}] Loaded assembly: ${file.name} (${bytes.length} bytes)`]);
    };
    reader.readAsArrayBuffer(file);
  }, []);

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setIsDragOver(false);
    const file = e.dataTransfer.files[0];
    if (file) handleFileRead(file);
  }, [handleFileRead]);

  const handleDragOver = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setIsDragOver(true);
  }, []);

  const handleDragLeave = useCallback(() => {
    setIsDragOver(false);
  }, []);

  const handleFileSelect = () => {
    const input = fileInputRef.current;
    if (!input?.files?.[0]) return;
    handleFileRead(input.files[0]);
    input.value = '';
  };

  const handleExecute = async () => {
    if (!selectedAgent || !assemblyData) return;
    setIsExecuting(true);
    setOutput((prev) => [...prev, `[${ts()}] Executing assembly: ${assemblyName} on agent ${selectedAgent.slice(0, 8)}...`]);

    const historyEntry: AssemblyHistory = {
      id: Date.now().toString(36),
      name: assemblyName,
      args,
      timestamp: new Date().toISOString(),
      agentId: selectedAgent,
      status: 'pending',
    };

    try {
      const res = await api.executeAssembly(selectedAgent, assemblyData, args, {
        runtime,
        fork,
        amsi: amsiBypass,
      });
      setOutput((prev) => [...prev, `[${ts()}] Task queued: ${res.task_id}`]);

      // Poll for result
      let elapsed = 0;
      pollRef.current = setInterval(async () => {
        elapsed += 2000;
        if (elapsed > 60000) {
          if (pollRef.current) clearInterval(pollRef.current);
          pollRef.current = null;
          setOutput((prev) => [...prev, `[${ts()}] [TIMEOUT] No result after 60s`]);
          historyEntry.status = 'error';
          const updated = [historyEntry, ...loadHistory()].slice(0, 20);
          saveHistory(updated);
          setHistory(updated);
          setIsExecuting(false);
          return;
        }
        try {
          const result = await api.getTaskResult(res.task_id);
          if (result.status >= 2) {
            if (pollRef.current) clearInterval(pollRef.current);
            pollRef.current = null;
            const out = result.output ? atob(result.output) : '(no output)';
            const t2 = new Date().toLocaleTimeString('en-US', { hour12: false });
            const isSuccess = result.status === 2;
            setOutput((prev) => [...prev,
              isSuccess ? `[${t2}] [SUCCESS] ${out}` : `[${t2}] [ERROR] ${out}`,
            ]);
            historyEntry.status = isSuccess ? 'success' : 'error';
            const updated = [historyEntry, ...loadHistory()].slice(0, 20);
            saveHistory(updated);
            setHistory(updated);
            setIsExecuting(false);
          }
        } catch {
          // not ready yet
        }
      }, 2000);
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : String(err);
      setOutput((prev) => [...prev, `[${ts()}] [ERROR] ${message}`]);
      historyEntry.status = 'error';
      const updated = [historyEntry, ...loadHistory()].slice(0, 20);
      saveHistory(updated);
      setHistory(updated);
      setIsExecuting(false);
    }
  };

  const clearOutput = () => setOutput([]);

  const clearHistory = () => {
    saveHistory([]);
    setHistory([]);
  };

  const copyOutput = () => {
    navigator.clipboard.writeText(output.join('\n')).catch(() => {});
  };

  const cardStyle: React.CSSProperties = {
    background: '#0d0d0d',
    border: '1px solid #1a1a1a',
    borderRadius: 6,
    padding: 14,
  };

  const labelStyle: React.CSSProperties = {
    color: '#888',
    fontSize: 11,
    fontWeight: 700,
    textTransform: 'uppercase' as const,
    letterSpacing: '0.5px',
    marginBottom: 6,
  };

  return (
    <div style={{ height: '100%', overflow: 'auto', padding: 16 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
        <span style={{ color: '#cc0000', fontSize: 14, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.5px' }}>
          .NET Assembly Execution
        </span>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16, height: 'calc(100% - 50px)' }}>
        {/* Left Column: Config */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 12, overflow: 'auto' }}>
          {/* Drop Zone */}
          <div
            onDrop={handleDrop}
            onDragOver={handleDragOver}
            onDragLeave={handleDragLeave}
            onClick={() => fileInputRef.current?.click()}
            style={{
              ...cardStyle,
              border: isDragOver ? '2px dashed #cc0000' : '2px dashed #333',
              textAlign: 'center',
              cursor: 'pointer',
              padding: 24,
              transition: 'border-color 0.2s',
            }}
          >
            <input
              ref={fileInputRef}
              type="file"
              accept=".exe,.dll"
              style={{ display: 'none' }}
              onChange={handleFileSelect}
            />
            <div style={{ color: isDragOver ? '#cc0000' : '#555', fontSize: 24, marginBottom: 8 }}>
              {assemblyName ? '\u2713' : '\u21EA'}
            </div>
            <div style={{ color: assemblyName ? '#e0e0e0' : '#666', fontSize: 12 }}>
              {assemblyName || 'Drag & drop a .NET assembly (.exe/.dll) or click to browse'}
            </div>
            {assemblyData && (
              <div style={{ color: '#555', fontSize: 10, marginTop: 4 }}>
                {Math.round(assemblyData.length * 0.75 / 1024)} KB loaded
              </div>
            )}
          </div>

          {/* Agent Selector */}
          <div style={cardStyle}>
            <div style={labelStyle}>Target Agent</div>
            <select
              className="select"
              value={selectedAgent}
              onChange={(e) => setSelectedAgent(e.target.value)}
              style={{ width: '100%' }}
            >
              <option value="">-- Select Agent --</option>
              {agents.filter((a) => a.alive).map((a) => (
                <option key={a.id} value={a.id}>{a.hostname} ({a.id.slice(0, 8)}) - {a.os}</option>
              ))}
            </select>
          </div>

          {/* Arguments */}
          <div style={cardStyle}>
            <div style={labelStyle}>Arguments</div>
            <input
              className="input"
              value={args}
              onChange={(e) => setArgs(e.target.value)}
              placeholder="e.g. -group=all --full"
              style={{ width: '100%' }}
            />
          </div>

          {/* Runtime Version */}
          <div style={cardStyle}>
            <div style={labelStyle}>Runtime Version</div>
            <div style={{ display: 'flex', gap: 16 }}>
              <label style={{ color: '#c0c0c0', fontSize: 12, display: 'flex', alignItems: 'center', gap: 6, cursor: 'pointer' }}>
                <input
                  type="radio"
                  name="runtime"
                  checked={runtime === 'v4.0.30319'}
                  onChange={() => setRuntime('v4.0.30319')}
                  style={{ accentColor: '#cc0000' }}
                />
                v4.0.30319 (.NET 4.x)
              </label>
              <label style={{ color: '#c0c0c0', fontSize: 12, display: 'flex', alignItems: 'center', gap: 6, cursor: 'pointer' }}>
                <input
                  type="radio"
                  name="runtime"
                  checked={runtime === 'v2.0.50727'}
                  onChange={() => setRuntime('v2.0.50727')}
                  style={{ accentColor: '#cc0000' }}
                />
                v2.0.50727 (.NET 2.x/3.x)
              </label>
            </div>
          </div>

          {/* Execution Mode */}
          <div style={cardStyle}>
            <div style={labelStyle}>Execution Mode</div>
            <div style={{ display: 'flex', gap: 16 }}>
              <label style={{ color: '#c0c0c0', fontSize: 12, display: 'flex', alignItems: 'center', gap: 6, cursor: 'pointer' }}>
                <input
                  type="radio"
                  name="execmode"
                  checked={!fork}
                  onChange={() => setFork(false)}
                  style={{ accentColor: '#cc0000' }}
                />
                In-Process
              </label>
              <label style={{ color: '#c0c0c0', fontSize: 12, display: 'flex', alignItems: 'center', gap: 6, cursor: 'pointer' }}>
                <input
                  type="radio"
                  name="execmode"
                  checked={fork}
                  onChange={() => setFork(true)}
                  style={{ accentColor: '#cc0000' }}
                />
                Fork &amp; Run
              </label>
            </div>
          </div>

          {/* AMSI Bypass */}
          <div style={cardStyle}>
            <label style={{ color: '#c0c0c0', fontSize: 12, display: 'flex', alignItems: 'center', gap: 8, cursor: 'pointer' }}>
              <input
                type="checkbox"
                checked={amsiBypass}
                onChange={(e) => setAmsiBypass(e.target.checked)}
                style={{ accentColor: '#cc0000' }}
              />
              AMSI Bypass (patch amsi.dll before loading)
            </label>
          </div>

          {/* Execute Button */}
          <button
            className="btn btn--primary"
            onClick={handleExecute}
            disabled={!selectedAgent || !assemblyData || isExecuting}
            style={{ width: '100%' }}
          >
            {isExecuting ? 'Executing...' : 'Execute Assembly'}
          </button>
        </div>

        {/* Right Column: Output + History */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 12, overflow: 'hidden' }}>
          {/* Output Console */}
          <div style={{ ...cardStyle, flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
              <span style={labelStyle}>Output Console</span>
              <div style={{ display: 'flex', gap: 6 }}>
                <button className="btn btn--small" onClick={copyOutput}>Copy</button>
                <button className="btn btn--small" onClick={clearOutput}>Clear</button>
              </div>
            </div>
            <div
              ref={outputRef}
              style={{
                flex: 1,
                overflow: 'auto',
                background: '#080808',
                borderRadius: 4,
                padding: '8px 10px',
                fontFamily: 'var(--font-mono)',
                fontSize: 11,
                lineHeight: 1.6,
              }}
            >
              {output.length === 0 ? (
                <span style={{ color: '#444' }}>Assembly output will appear here...</span>
              ) : (
                output.map((line, i) => (
                  <div key={i} style={{
                    color: line.includes('[ERROR]') || line.includes('[TIMEOUT]') ? '#ff3333'
                      : line.includes('[SUCCESS]') ? '#00cc00'
                      : '#a0a0a0',
                  }}>
                    {line}
                  </div>
                ))
              )}
            </div>
          </div>

          {/* History */}
          <div style={{ ...cardStyle, maxHeight: 200, overflow: 'auto' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
              <span style={labelStyle}>Execution History ({history.length})</span>
              {history.length > 0 && (
                <button className="btn btn--small" onClick={clearHistory}>Clear</button>
              )}
            </div>
            {history.length === 0 ? (
              <div style={{ color: '#444', fontSize: 11, textAlign: 'center', padding: 8 }}>No history</div>
            ) : (
              history.map((h) => (
                <div
                  key={h.id}
                  style={{
                    display: 'flex',
                    justifyContent: 'space-between',
                    alignItems: 'center',
                    padding: '4px 8px',
                    borderBottom: '1px solid #111',
                    fontSize: 11,
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    <span style={{
                      width: 8,
                      height: 8,
                      borderRadius: '50%',
                      background: h.status === 'success' ? '#22c55e' : h.status === 'error' ? '#ef4444' : '#eab308',
                      flexShrink: 0,
                    }} />
                    <span style={{ color: '#e0e0e0', fontWeight: 600 }}>{h.name}</span>
                    {h.args && <span style={{ color: '#666' }}>{h.args}</span>}
                  </div>
                  <div style={{ color: '#555', fontSize: 10 }}>
                    {new Date(h.timestamp).toLocaleTimeString('en-US', { hour12: false })}
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
