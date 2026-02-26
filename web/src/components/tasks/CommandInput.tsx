import { useState, useRef, useEffect, type KeyboardEvent } from 'react';
import { useTaskStore } from '../../store/taskStore';

interface Props {
  agentId: string;
}

const COMMANDS = [
  { cmd: 'shell', desc: 'Execute a shell command (e.g. shell whoami)' },
  { cmd: 'upload', desc: 'Upload a file to the agent (e.g. upload /tmp/payload.bin)' },
  { cmd: 'download', desc: 'Download a file from the agent (e.g. download /etc/passwd)' },
  { cmd: 'sleep', desc: 'Set sleep interval in seconds (e.g. sleep 10)' },
  { cmd: 'exit', desc: 'Gracefully exit the agent process' },
  { cmd: 'inject', desc: 'Inject shellcode into a process by PID (e.g. inject 1234)' },
  { cmd: 'bof', desc: 'Execute a Beacon Object File module (e.g. bof whoami.o)' },
  { cmd: 'assembly', desc: 'Execute a .NET assembly in-memory (e.g. assembly Seatbelt.exe -group=all)' },
  { cmd: 'screenshot', desc: 'Capture a screenshot of the current desktop' },
  { cmd: 'keylog', desc: 'Start or stop the keylogger (e.g. keylog start|stop)' },
  { cmd: 'ps', desc: 'List all running processes with PID, name, and user' },
  { cmd: 'ls', desc: 'List directory contents (e.g. ls /tmp)' },
  { cmd: 'cd', desc: 'Change working directory (e.g. cd /home/user)' },
  { cmd: 'pwd', desc: 'Print the current working directory path' },
  { cmd: 'whoami', desc: 'Display current username, domain, and privileges' },
  { cmd: 'ipconfig', desc: 'Show network interfaces, IPs, and routing info' },
  { cmd: 'hashdump', desc: 'Dump credential hashes from SAM/LSASS (requires admin)' },
  { cmd: 'token', desc: 'Token manipulation: list, steal <pid>, or make <user> <pass>' },
  { cmd: 'pivot', desc: 'Set up a pivot/reverse-port-forward tunnel (e.g. pivot 8080:10.0.0.5:445)' },
  { cmd: 'portscan', desc: 'Scan ports on a target host (e.g. portscan 10.0.0.5 1-1024)' },
  { cmd: 'socks', desc: 'Start a SOCKS5 proxy on the agent (e.g. socks 1080)' },
  { cmd: 'selfdestruct', desc: 'Remove the agent binary and all artifacts from disk' },
  { cmd: 'module', desc: 'Execute PE/assembly/shellcode module (module <pe|assembly|shellcode> [args])' },
  { cmd: 'clipboard', desc: 'Start or stop clipboard monitoring (e.g. clipboard start|stop)' },
  { cmd: 'regwrite', desc: 'Write registry value: regwrite <hive> <path> <name> <type> <value>' },
  { cmd: 'service', desc: 'Service control: service <create|start|stop|delete> <name> [binpath]' },
  { cmd: 'jobs', desc: 'List or kill background jobs (e.g. jobs list|kill <id>)' },
  { cmd: 'persist', desc: 'Install persistence: persist <method> [args]' },
  { cmd: 'unpersist', desc: 'Remove persistence: unpersist <method>' },
  { cmd: 'privesc', desc: 'Privilege escalation: privesc <check|exploit> [technique]' },
  { cmd: 'file-copy', desc: 'Copy file: file-copy <src> <dst>' },
  { cmd: 'file-move', desc: 'Move/rename file: file-move <src> <dst>' },
  { cmd: 'file-delete', desc: 'Delete file: file-delete <path>' },
  { cmd: 'mkdir', desc: 'Create directory: mkdir <path>' },
  { cmd: 'reg-query', desc: 'Query registry: reg-query <hive> <path> [value]' },
  { cmd: 'env', desc: 'Environment vars: env <get|set|list> [name] [value]' },
  { cmd: 'rportfwd', desc: 'Reverse port forward: rportfwd <start|stop|list> [port] [host:port]' },
  { cmd: 'runas', desc: 'Run as user: runas <user> <password> <command>' },
  { cmd: 'powershell', desc: 'PowerShell: powershell <script>' },
  { cmd: 'lolbas', desc: 'LOLBAS exec: lolbas <binary> <args>' },
  { cmd: 'help', desc: 'Show this list of available commands' },
  { cmd: 'clear', desc: 'Clear the console output history' },
];

export default function CommandInput({ agentId }: Props) {
  const [input, setInput] = useState('');
  const [historyIdx, setHistoryIdx] = useState(-1);
  const [suggestions, setSuggestions] = useState<typeof COMMANDS>([]);
  const [selectedSuggestion, setSelectedSuggestion] = useState(0);
  const [showSuggestions, setShowSuggestions] = useState(false);
  const sendCommand = useTaskStore((s) => s.sendCommand);
  const getHistory = useTaskStore((s) => s.getHistory);
  const inputRef = useRef<HTMLInputElement>(null);
  const suggestionsRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!input.trim() || input.includes(' ')) {
      setShowSuggestions(false);
      return;
    }
    const matches = COMMANDS.filter(c => c.cmd.startsWith(input.toLowerCase()));
    setSuggestions(matches);
    setSelectedSuggestion(0);
    setShowSuggestions(matches.length > 0 && input.length > 0);
  }, [input]);

  const applySuggestion = (cmd: string) => {
    setInput(cmd + ' ');
    setShowSuggestions(false);
    inputRef.current?.focus();
  };

  const handleKeyDown = (e: KeyboardEvent) => {
    if (showSuggestions) {
      if (e.key === 'Tab') {
        e.preventDefault();
        if (suggestions.length > 0) {
          applySuggestion(suggestions[selectedSuggestion].cmd);
        }
        return;
      }
      if (e.key === 'ArrowDown') {
        e.preventDefault();
        setSelectedSuggestion(i => (i + 1) % suggestions.length);
        return;
      }
      if (e.key === 'ArrowUp') {
        e.preventDefault();
        setSelectedSuggestion(i => (i - 1 + suggestions.length) % suggestions.length);
        return;
      }
      if (e.key === 'Escape') {
        setShowSuggestions(false);
        return;
      }
    }

    if (e.key === 'Enter' && input.trim()) {
      sendCommand(agentId, input.trim());
      setInput('');
      setHistoryIdx(-1);
      setShowSuggestions(false);
    } else if (e.key === 'ArrowUp' && !showSuggestions) {
      e.preventDefault();
      const history = getHistory(agentId);
      if (history.length === 0) return;
      const newIdx = historyIdx < history.length - 1 ? historyIdx + 1 : historyIdx;
      setHistoryIdx(newIdx);
      setInput(history[history.length - 1 - newIdx] || '');
    } else if (e.key === 'ArrowDown' && !showSuggestions) {
      e.preventDefault();
      if (historyIdx <= 0) {
        setHistoryIdx(-1);
        setInput('');
      } else {
        const history = getHistory(agentId);
        const newIdx = historyIdx - 1;
        setHistoryIdx(newIdx);
        setInput(history[history.length - 1 - newIdx] || '');
      }
    }
  };

  return (
    <div style={{
      position: 'relative',
      display: 'flex',
      alignItems: 'center',
      borderTop: '1px solid #1a1a1a',
      background: '#0a0a0a',
      padding: '0 12px',
    }}>
      {/* Autocomplete dropdown */}
      {showSuggestions && (
        <div
          ref={suggestionsRef}
          style={{
            position: 'absolute',
            bottom: '100%',
            left: '0',
            right: '0',
            background: '#111',
            border: '1px solid #1a1a1a',
            borderBottom: 'none',
            maxHeight: '200px',
            overflowY: 'auto',
            zIndex: 100,
          }}
        >
          {suggestions.map((s, i) => (
            <div
              key={s.cmd}
              onClick={() => applySuggestion(s.cmd)}
              style={{
                padding: '6px 12px',
                cursor: 'pointer',
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
                background: i === selectedSuggestion ? '#1a0000' : 'transparent',
                borderLeft: i === selectedSuggestion ? '2px solid #cc0000' : '2px solid transparent',
              }}
            >
              <span style={{
                fontFamily: 'var(--font-mono)',
                fontSize: '12px',
                color: i === selectedSuggestion ? '#cc0000' : '#e0e0e0',
                fontWeight: 600,
              }}>
                {s.cmd}
              </span>
              <span style={{ color: '#555', fontSize: '11px', marginLeft: '16px' }}>
                {s.desc}
              </span>
            </div>
          ))}
        </div>
      )}

      <span style={{
        color: '#cc0000',
        fontFamily: 'var(--font-mono)',
        fontSize: '12px',
        fontWeight: 700,
        marginRight: '8px',
        whiteSpace: 'nowrap',
      }}>
        RTLC2 &gt;
      </span>
      <input
        ref={inputRef}
        value={input}
        onChange={(e) => setInput(e.target.value)}
        onKeyDown={handleKeyDown}
        onBlur={() => setTimeout(() => setShowSuggestions(false), 150)}
        placeholder="Type a command... (Tab to autocomplete)"
        autoFocus
        style={{
          flex: 1,
          background: 'transparent',
          border: 'none',
          color: '#e0e0e0',
          fontFamily: 'var(--font-mono)',
          fontSize: '12px',
          padding: '10px 0',
          outline: 'none',
        }}
      />
    </div>
  );
}
