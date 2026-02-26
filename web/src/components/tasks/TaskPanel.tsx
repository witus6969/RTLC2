import { useEffect, useRef } from 'react';
import { useTaskStore } from '../../store/taskStore';
import { usePolling } from '../../hooks/usePolling';
import CommandInput from './CommandInput';

interface Props {
  agentId: string;
}

export default function TaskPanel({ agentId }: Props) {
  const entries = useTaskStore((s) => s.agentTasks[agentId]?.entries || []);
  const pollPendingTasks = useTaskStore((s) => s.pollPendingTasks);
  const addEntry = useTaskStore((s) => s.addEntry);
  const outputRef = useRef<HTMLDivElement>(null);

  // Add welcome message on mount
  useEffect(() => {
    if (entries.length === 0) {
      addEntry(agentId, {
        type: 'info',
        text: `Connected to agent ${agentId.slice(0, 8)}. Type "help" for available commands.`,
      });
    }
  }, [agentId]);

  // Poll pending tasks
  usePolling(() => pollPendingTasks(agentId), 2000);

  // Auto-scroll to bottom
  useEffect(() => {
    if (outputRef.current) {
      outputRef.current.scrollTop = outputRef.current.scrollHeight;
    }
  }, [entries]);

  const colorMap: Record<string, string> = {
    input: '#00cccc',
    output: '#e0e0e0',
    error: '#ff3333',
    info: '#808080',
    success: '#00cc00',
  };

  return (
    <div style={{ height: '100%', display: 'flex', flexDirection: 'column', background: '#080808' }}>
      {/* Output area */}
      <div
        ref={outputRef}
        style={{
          flex: 1,
          overflowY: 'auto',
          padding: '12px',
          fontFamily: 'var(--font-mono)',
          fontSize: '12px',
          lineHeight: 1.6,
        }}
      >
        {entries.map((entry) => (
          <div key={entry.id} style={{ marginBottom: '2px' }}>
            <span style={{ color: '#444' }}>[{entry.timestamp}]</span>{' '}
            <span style={{ color: colorMap[entry.type] || '#e0e0e0', whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}>
              {entry.text}
            </span>
          </div>
        ))}
      </div>

      {/* Command input */}
      <CommandInput agentId={agentId} />
    </div>
  );
}
