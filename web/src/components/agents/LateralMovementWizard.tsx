// ═══════════════════════════════════════════════════════════════
//  RTLC2 Lateral Movement Wizard
//  Step-based modal wizard: Target -> Method -> Command ->
//  Credentials -> Review & Execute.
// ═══════════════════════════════════════════════════════════════

import { useState, useEffect } from 'react';
import { useTaskStore } from '../../store/taskStore';
import { useCredentialStore } from '../../store/credentialStore';
import type { Credential } from '../../types';

interface LateralMovementWizardProps {
  agentId: string;
  onClose: () => void;
}

const METHODS = [
  { value: 'psexec', label: 'PsExec', description: 'Remote service creation via SMB (admin share + SCM)' },
  { value: 'wmi', label: 'WMI', description: 'Windows Management Instrumentation process creation' },
  { value: 'winrm', label: 'WinRM', description: 'Windows Remote Management (WSMan)' },
  { value: 'dcom', label: 'DCOM', description: 'Distributed COM object execution' },
  { value: 'scshell', label: 'SCShell', description: 'Service configuration change (fileless)' },
] as const;

const TOTAL_STEPS = 5;
const STEP_LABELS = ['Target', 'Method', 'Command', 'Credentials', 'Review'];

export default function LateralMovementWizard({ agentId, onClose }: LateralMovementWizardProps) {
  const { sendCommand } = useTaskStore();
  const { credentials, fetch: fetchCredentials } = useCredentialStore();

  const [step, setStep] = useState(1);
  const [target, setTarget] = useState('');
  const [method, setMethod] = useState<string>(METHODS[0].value);
  const [command, setCommand] = useState('');
  const [selectedCredId, setSelectedCredId] = useState<string | null>(null);
  const [isExecuting, setIsExecuting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetchCredentials();
  }, [fetchCredentials]);

  const selectedCred: Credential | undefined = credentials.find(
    (c) => c.id === selectedCredId
  );

  const canProceed = (): boolean => {
    switch (step) {
      case 1:
        return target.trim().length > 0;
      case 2:
        return method.length > 0;
      case 3:
        return command.trim().length > 0;
      case 4:
        return true; // Credentials are optional
      case 5:
        return true;
      default:
        return false;
    }
  };

  const handleExecute = async () => {
    setIsExecuting(true);
    setError(null);

    try {
      // Build the lateral movement command string
      // Format: pivot <method> <target> <command> [domain\user password]
      let cmdStr = `pivot ${method} ${target.trim()} ${command.trim()}`;

      if (selectedCred) {
        const credPart = selectedCred.domain
          ? `${selectedCred.domain}\\${selectedCred.username}`
          : selectedCred.username;
        cmdStr += ` ${credPart} ${selectedCred.value}`;
      }

      await sendCommand(agentId, cmdStr);
      onClose();
    } catch (err: any) {
      setError(err.message || 'Failed to execute lateral movement');
      setIsExecuting(false);
    }
  };

  // ── Styles ──────────────────────────────────────────────────

  const backdropStyle: React.CSSProperties = {
    position: 'fixed',
    top: 0,
    left: 0,
    right: 0,
    bottom: 0,
    background: 'rgba(0,0,0,0.8)',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    zIndex: 9999,
  };

  const dialogStyle: React.CSSProperties = {
    background: '#111',
    border: '1px solid #333',
    borderRadius: '6px',
    width: '560px',
    maxWidth: '90vw',
    maxHeight: '85vh',
    display: 'flex',
    flexDirection: 'column',
    overflow: 'hidden',
    boxShadow: '0 8px 32px rgba(0,0,0,0.6)',
  };

  const headerStyle: React.CSSProperties = {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
    padding: '12px 16px',
    borderBottom: '1px solid #222',
    background: '#0d0d0d',
  };

  const stepBarStyle: React.CSSProperties = {
    display: 'flex',
    gap: '0',
    padding: '0 16px',
    background: '#0a0a0a',
    borderBottom: '1px solid #222',
  };

  const stepItemStyle = (idx: number): React.CSSProperties => ({
    flex: 1,
    padding: '8px 4px',
    textAlign: 'center',
    fontSize: '10px',
    fontWeight: 600,
    textTransform: 'uppercase',
    letterSpacing: '0.5px',
    color: idx + 1 === step ? '#cc0000' : idx + 1 < step ? '#44cc44' : '#444',
    borderBottom: idx + 1 === step ? '2px solid #cc0000' : '2px solid transparent',
    cursor: idx + 1 < step ? 'pointer' : 'default',
    transition: 'color 0.15s, border-color 0.15s',
  });

  const bodyStyle: React.CSSProperties = {
    padding: '20px 16px',
    overflow: 'auto',
    flex: 1,
    minHeight: '200px',
  };

  const footerStyle: React.CSSProperties = {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
    padding: '10px 16px',
    borderTop: '1px solid #222',
    background: '#0d0d0d',
  };

  const labelStyle: React.CSSProperties = {
    display: 'block',
    fontSize: '11px',
    color: '#888',
    marginBottom: '6px',
    fontFamily: 'monospace',
    textTransform: 'uppercase',
    letterSpacing: '0.5px',
  };

  const inputStyle: React.CSSProperties = {
    width: '100%',
    padding: '8px 10px',
    background: '#0a0a0a',
    border: '1px solid #333',
    borderRadius: '3px',
    color: '#e0e0e0',
    fontSize: '13px',
    fontFamily: 'inherit',
    outline: 'none',
    boxSizing: 'border-box',
  };

  const btnStyle: React.CSSProperties = {
    padding: '6px 16px',
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

  const methodCardStyle = (selected: boolean): React.CSSProperties => ({
    padding: '10px 12px',
    background: selected ? '#cc000011' : '#0d0d0d',
    border: `1px solid ${selected ? '#cc0000' : '#222'}`,
    borderRadius: '4px',
    cursor: 'pointer',
    marginBottom: '8px',
    transition: 'border-color 0.15s, background 0.15s',
  });

  const credRowStyle = (selected: boolean): React.CSSProperties => ({
    padding: '8px 10px',
    background: selected ? '#cc000011' : 'transparent',
    border: `1px solid ${selected ? '#cc0000' : '#1a1a1a'}`,
    borderRadius: '3px',
    cursor: 'pointer',
    marginBottom: '4px',
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
    fontSize: '12px',
    transition: 'border-color 0.15s',
  });

  const reviewRowStyle: React.CSSProperties = {
    display: 'flex',
    justifyContent: 'space-between',
    padding: '6px 0',
    borderBottom: '1px solid #1a1a1a',
    fontSize: '12px',
  };

  const closeBtnStyle: React.CSSProperties = {
    background: 'none',
    border: 'none',
    color: '#666',
    cursor: 'pointer',
    fontSize: '18px',
    fontFamily: 'monospace',
    padding: '0 4px',
    lineHeight: 1,
  };

  // ── Step Renderers ──────────────────────────────────────────

  const renderStep1 = () => (
    <div>
      <label style={labelStyle}>Target IP / Hostname</label>
      <input
        type="text"
        placeholder="192.168.1.100 or DC01.domain.local"
        value={target}
        onChange={(e) => setTarget(e.target.value)}
        style={inputStyle}
        autoFocus
        onFocus={(e) => { e.currentTarget.style.borderColor = '#cc0000'; }}
        onBlur={(e) => { e.currentTarget.style.borderColor = '#333'; }}
      />
      <div style={{ marginTop: '10px', fontSize: '11px', color: '#555' }}>
        Enter the target machine's IP address or hostname for lateral movement.
      </div>
    </div>
  );

  const renderStep2 = () => (
    <div>
      <label style={labelStyle}>Lateral Movement Method</label>
      {METHODS.map((m) => (
        <div
          key={m.value}
          style={methodCardStyle(method === m.value)}
          onClick={() => setMethod(m.value)}
          onMouseEnter={(e) => {
            if (method !== m.value) (e.currentTarget as HTMLDivElement).style.borderColor = '#444';
          }}
          onMouseLeave={(e) => {
            (e.currentTarget as HTMLDivElement).style.borderColor = method === m.value ? '#cc0000' : '#222';
          }}
        >
          <div style={{ fontSize: '13px', fontWeight: 600, color: method === m.value ? '#cc0000' : '#e0e0e0' }}>
            {m.label}
          </div>
          <div style={{ fontSize: '11px', color: '#666', marginTop: '2px' }}>
            {m.description}
          </div>
        </div>
      ))}
    </div>
  );

  const renderStep3 = () => (
    <div>
      <label style={labelStyle}>Command / Payload</label>
      <textarea
        placeholder="cmd.exe /c whoami&#10;or&#10;C:\temp\payload.exe"
        value={command}
        onChange={(e) => setCommand(e.target.value)}
        style={{
          ...inputStyle,
          minHeight: '100px',
          resize: 'vertical',
          fontFamily: '"Cascadia Code", "Fira Code", "Consolas", monospace',
          fontSize: '12px',
        }}
        autoFocus
        onFocus={(e) => { e.currentTarget.style.borderColor = '#cc0000'; }}
        onBlur={(e) => { e.currentTarget.style.borderColor = '#333'; }}
      />
      <div style={{ marginTop: '10px', fontSize: '11px', color: '#555' }}>
        The command or payload to execute on the target machine via {method}.
      </div>
    </div>
  );

  const renderStep4 = () => (
    <div>
      <label style={labelStyle}>Select Credentials (Optional)</label>

      {/* No cred option */}
      <div
        style={credRowStyle(selectedCredId === null)}
        onClick={() => setSelectedCredId(null)}
      >
        <span style={{ color: '#888' }}>Use current token (no explicit credentials)</span>
      </div>

      {credentials.length === 0 ? (
        <div style={{ padding: '12px', textAlign: 'center', color: '#444', fontSize: '12px' }}>
          No credentials in store. Credentials can be collected via hashdump, mimikatz, or manual entry.
        </div>
      ) : (
        credentials.map((cred) => (
          <div
            key={cred.id}
            style={credRowStyle(selectedCredId === cred.id)}
            onClick={() => setSelectedCredId(cred.id)}
          >
            <div>
              <span style={{ color: '#e0e0e0', fontWeight: 600 }}>
                {cred.domain ? `${cred.domain}\\` : ''}{cred.username}
              </span>
              <span style={{ marginLeft: '8px', fontSize: '10px', color: '#555' }}>
                [{cred.type}]
              </span>
            </div>
            <span style={{ fontFamily: 'monospace', fontSize: '10px', color: '#444' }}>
              {cred.value.length > 20 ? cred.value.slice(0, 20) + '...' : cred.value}
            </span>
          </div>
        ))
      )}
    </div>
  );

  const renderStep5 = () => {
    const methodInfo = METHODS.find((m) => m.value === method);
    return (
      <div>
        <div style={{ fontSize: '13px', fontWeight: 600, color: '#cc0000', marginBottom: '14px' }}>
          Review Lateral Movement
        </div>

        <div style={reviewRowStyle}>
          <span style={{ color: '#666' }}>Target</span>
          <span style={{ fontFamily: 'monospace', color: '#e0e0e0' }}>{target}</span>
        </div>
        <div style={reviewRowStyle}>
          <span style={{ color: '#666' }}>Method</span>
          <span style={{ color: '#e0e0e0' }}>{methodInfo?.label || method}</span>
        </div>
        <div style={reviewRowStyle}>
          <span style={{ color: '#666' }}>Command</span>
          <span style={{ fontFamily: 'monospace', fontSize: '11px', color: '#e0e0e0', maxWidth: '300px', wordBreak: 'break-all' }}>
            {command}
          </span>
        </div>
        <div style={reviewRowStyle}>
          <span style={{ color: '#666' }}>Credentials</span>
          <span style={{ color: '#e0e0e0' }}>
            {selectedCred
              ? `${selectedCred.domain ? selectedCred.domain + '\\' : ''}${selectedCred.username}`
              : 'Current token'}
          </span>
        </div>

        {/* Final command preview */}
        <div style={{ marginTop: '16px' }}>
          <label style={labelStyle}>Command Preview</label>
          <div
            style={{
              background: '#0a0a0a',
              border: '1px solid #222',
              borderRadius: '4px',
              padding: '10px',
              fontFamily: '"Cascadia Code", "Fira Code", "Consolas", monospace',
              fontSize: '11px',
              color: '#cc0000',
              wordBreak: 'break-all',
              lineHeight: 1.5,
            }}
          >
            pivot {method} {target} {command}
            {selectedCred && (
              <span style={{ color: '#888' }}>
                {' '}
                {selectedCred.domain ? `${selectedCred.domain}\\` : ''}
                {selectedCred.username} {'*'.repeat(8)}
              </span>
            )}
          </div>
        </div>

        {error && (
          <div
            style={{
              marginTop: '12px',
              padding: '8px 10px',
              background: '#1a0000',
              border: '1px solid #330000',
              borderRadius: '3px',
              color: '#cc0000',
              fontSize: '12px',
            }}
          >
            {error}
          </div>
        )}
      </div>
    );
  };

  const renderCurrentStep = () => {
    switch (step) {
      case 1: return renderStep1();
      case 2: return renderStep2();
      case 3: return renderStep3();
      case 4: return renderStep4();
      case 5: return renderStep5();
      default: return null;
    }
  };

  // ── Render ──────────────────────────────────────────────────

  return (
    <div style={backdropStyle} onClick={onClose}>
      <div style={dialogStyle} onClick={(e) => e.stopPropagation()}>
        {/* Header */}
        <div style={headerStyle}>
          <span style={{ fontSize: '14px', fontWeight: 600, color: '#cc0000' }}>
            Lateral Movement Wizard
          </span>
          <button
            style={closeBtnStyle}
            onClick={onClose}
            onMouseEnter={(e) => { (e.currentTarget as HTMLButtonElement).style.color = '#cc0000'; }}
            onMouseLeave={(e) => { (e.currentTarget as HTMLButtonElement).style.color = '#666'; }}
          >
            X
          </button>
        </div>

        {/* Step Bar */}
        <div style={stepBarStyle}>
          {STEP_LABELS.map((label, idx) => (
            <div
              key={label}
              style={stepItemStyle(idx)}
              onClick={() => {
                if (idx + 1 < step) setStep(idx + 1);
              }}
            >
              {idx + 1}. {label}
            </div>
          ))}
        </div>

        {/* Body */}
        <div style={bodyStyle}>{renderCurrentStep()}</div>

        {/* Footer */}
        <div style={footerStyle}>
          <button style={btnStyle} onClick={onClose}>
            Cancel
          </button>
          <div style={{ display: 'flex', gap: '8px' }}>
            {step > 1 && (
              <button style={btnStyle} onClick={() => setStep(step - 1)}>
                Back
              </button>
            )}
            {step < TOTAL_STEPS ? (
              <button
                style={canProceed() ? btnAccentStyle : { ...btnAccentStyle, opacity: 0.5, cursor: 'not-allowed' }}
                onClick={() => {
                  if (canProceed()) setStep(step + 1);
                }}
                disabled={!canProceed()}
              >
                Next
              </button>
            ) : (
              <button
                style={btnAccentStyle}
                onClick={handleExecute}
                disabled={isExecuting}
              >
                {isExecuting ? 'Executing...' : 'Execute'}
              </button>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
