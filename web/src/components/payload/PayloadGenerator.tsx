import { useState, useMemo, useCallback } from 'react';
import { useListenerStore } from '../../store/listenerStore';
import { useArtifactStore } from '../../store/artifactStore';
import { useUIStore } from '../../store/uiStore';
import { api } from '../../api/client';
import EvasionTabs from './EvasionTabs';
import {
  ALL_FORMATS, ALL_ARCHS, ALL_SHELLCODE_FORMATS,
  EVASION_CATEGORIES,
} from './payloadData';

interface Props {
  onClose: () => void;
}

interface LogEntry {
  time: string;
  level: 'INFO' | 'SUCCESS' | 'ERROR';
  message: string;
}

export default function PayloadGenerator({ onClose }: Props) {
  const listeners = useListenerStore((s) => s.listeners);

  // Target config
  const [os, setOS] = useState('windows');
  const [formatKey, setFormatKey] = useState('exe');
  const [archKey, setArchKey] = useState('x64');
  const [listenerId, setListenerId] = useState('');
  const [callbackHost, setCallbackHost] = useState('127.0.0.1');

  // Agent config
  const [sleep, setSleep] = useState(5);
  const [jitter, setJitter] = useState(10);
  const [userAgent, setUserAgent] = useState(
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
  );

  // Encryption
  const [transportEnc, setTransportEnc] = useState('aes');
  const [payloadEnc, setPayloadEnc] = useState('none');
  const [encKey, setEncKey] = useState(() => {
    const bytes = new Uint8Array(32);
    crypto.getRandomValues(bytes);
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
  });
  const [shellcodeEncoder, setShellcodeEncoder] = useState('none');

  // OPSEC
  const [opsec, setOpsec] = useState({
    sleep_mask: true, stack_spoof: true, module_stomping: false,
    etw_patch: true, unhook_ntdll: false, thread_stack_spoof: false,
    heap_encryption: false, syscall_method: 'none',
  });

  // Evasion
  const [evasionState, setEvasionState] = useState<Record<string, Record<string, boolean>>>({});

  // Shellcode format
  const [shellcodeFormatKey, setShellcodeFormatKey] = useState('raw');

  // Output
  const [outputFile, setOutputFile] = useState('agent-win-x64.exe');
  const [buildLog, setBuildLog] = useState<LogEntry[]>([]);
  const [progress, setProgress] = useState(0);
  const [progressText, setProgressText] = useState('');
  const [isBuilding, setIsBuilding] = useState(false);

  // Filtered options based on OS
  const formats = useMemo(() => ALL_FORMATS.filter(f => f.supportedOS.includes(os)), [os]);
  const archs = useMemo(() => ALL_ARCHS.filter(a => a.supportedOS.includes(os)), [os]);
  const shellcodeFormats = useMemo(() => ALL_SHELLCODE_FORMATS.filter(f => f.supportedOS.includes(os)), [os]);
  const isWindows = os === 'windows';

  // Update output filename when OS/arch/format/listener changes
  const getListenerName = useCallback(() => {
    const l = listeners.find(x => x.id === listenerId);
    if (!l) return '';
    if (l.config?.name) return l.config.name;
    if (l.config?.bind_host || l.config?.bind_port) return `${l.config.bind_host || '0.0.0.0'}_${l.config.bind_port || 0}`;
    return l.id.slice(0, 8);
  }, [listeners, listenerId]);

  const updateOutputFile = useCallback((newOS: string, newArch: string, newFormat: string, lName?: string, scFmt?: string) => {
    const osShort = newOS === 'windows' ? 'win' : newOS === 'linux' ? 'lin' : 'mac';
    const ln = lName ?? getListenerName();
    const prefix = ln ? `agent-${ln}-${osShort}` : `agent-${osShort}`;

    // If format is shellcode, use shellcode format extension
    if (newFormat === 'shellcode') {
      const scKey = scFmt ?? shellcodeFormatKey;
      const scExtMap: Record<string, string> = { raw: '.bin', c_array: '.h', python: '.py', csharp: '.cs', powershell: '.ps1' };
      setOutputFile(`${prefix}-${newArch}${scExtMap[scKey] || '.bin'}`);
    } else {
      const fmt = ALL_FORMATS.find(f => f.key === newFormat && f.supportedOS.includes(newOS));
      setOutputFile(`${prefix}-${newArch}${fmt?.extension || ''}`);
    }
  }, [getListenerName, shellcodeFormatKey]);

  const handleOSChange = (newOS: string) => {
    setOS(newOS);
    // Reset format to first available
    const newFormats = ALL_FORMATS.filter(f => f.supportedOS.includes(newOS));
    const newFormat = newFormats[0]?.key || 'shellcode';
    setFormatKey(newFormat);
    // Reset arch to first available
    const newArchs = ALL_ARCHS.filter(a => a.supportedOS.includes(newOS));
    const newArch = newArchs.find(a => a.key === archKey) ? archKey : (newArchs[0]?.key || 'x64');
    setArchKey(newArch);
    // Reset shellcode format
    const newSCFormats = ALL_SHELLCODE_FORMATS.filter(f => f.supportedOS.includes(newOS));
    if (!newSCFormats.find(f => f.key === shellcodeFormatKey)) {
      setShellcodeFormatKey(newSCFormats[0]?.key || 'raw');
    }
    // Reset Windows-only OPSEC
    if (newOS !== 'windows') {
      setOpsec(prev => ({
        ...prev,
        stack_spoof: false, module_stomping: false, etw_patch: false,
        unhook_ntdll: false, thread_stack_spoof: false, syscall_method: 'none',
      }));
    }
    // Reset Windows-only evasion
    if (newOS !== 'windows') {
      const cleared: Record<string, Record<string, boolean>> = { ...evasionState };
      EVASION_CATEGORIES.filter(c => c.windowsOnly).forEach(cat => {
        cleared[cat.key] = {};
        cat.techniques.forEach(t => { cleared[cat.key][t.field] = false; });
      });
      setEvasionState(cleared);
    }
    updateOutputFile(newOS, newArch, newFormat);
    log('INFO', `Target OS changed to ${newOS}`);
  };

  const log = (level: LogEntry['level'], message: string) => {
    setBuildLog(prev => [...prev, {
      time: new Date().toLocaleTimeString('en-US', { hour12: false }),
      level,
      message,
    }]);
  };

  const generateKey = () => {
    const bytes = new Uint8Array(32);
    crypto.getRandomValues(bytes);
    setEncKey(Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join(''));
    log('INFO', 'New encryption key generated');
  };

  const handleEvasionToggle = (category: string, field: string, value: boolean) => {
    setEvasionState(prev => ({
      ...prev,
      [category]: { ...prev[category], [field]: value },
    }));
  };

  const buildEvasionConfig = () => {
    const config: Record<string, Record<string, boolean>> = {};
    for (const cat of EVASION_CATEGORIES) {
      config[cat.key] = {};
      for (const tech of cat.techniques) {
        if (cat.windowsOnly && !isWindows) {
          config[cat.key][tech.field] = false;
        } else {
          config[cat.key][tech.field] = evasionState[cat.key]?.[tech.field] ?? tech.defaultOn;
        }
      }
    }
    return config;
  };

  const handleBuild = async (shellcodeOnly: boolean, overrideArch?: string) => {
    if (!listenerId) {
      log('ERROR', 'No listener selected. Create a listener first.');
      return;
    }
    const buildArch = overrideArch || archKey;
    const lName = getListenerName() || 'unknown';
    const osShort = os === 'windows' ? 'win' : os === 'linux' ? 'lin' : 'mac';
    const prefix = lName !== 'unknown' ? `agent-${lName}-${osShort}-${buildArch}` : `agent-${osShort}-${buildArch}`;

    // Determine extension based on format (shellcode uses shellcode format ext)
    let ext: string;
    const buildFormat = shellcodeOnly ? 'shellcode' : formatKey;
    if (buildFormat === 'shellcode') {
      const scExtMap: Record<string, string> = { raw: '.bin', c_array: '.h', python: '.py', csharp: '.cs', powershell: '.ps1' };
      ext = scExtMap[shellcodeFormatKey] || '.bin';
    } else {
      const fmt = ALL_FORMATS.find(f => f.key === formatKey && f.supportedOS.includes(os));
      ext = fmt?.extension || '';
    }
    const buildFilename = `${prefix}${ext}`;

    setIsBuilding(true);
    setProgress(0);
    setProgressText(shellcodeOnly ? 'Generating shellcode...' : `Building ${buildArch}...`);
    log('INFO', '----------------------------------------------------');
    log('INFO', shellcodeOnly ? 'Starting shellcode-only build...' : 'Starting payload build...');
    log('INFO', `  Format:     ${buildFormat}${shellcodeOnly ? ` (${shellcodeFormatKey})` : ''}`);
    log('INFO', `  Arch:       ${buildArch}`);
    log('INFO', `  OS:         ${os}`);
    log('INFO', `  Listener:   ${lName}`);
    log('INFO', `  Callback:   ${callbackHost}`);
    log('INFO', `  Sleep:      ${sleep}s (jitter ${jitter}%)`);

    // Count evasion techniques
    let totalEnabled = 0;
    for (const cat of EVASION_CATEGORIES) {
      if (cat.windowsOnly && !isWindows) continue;
      for (const tech of cat.techniques) {
        if (evasionState[cat.key]?.[tech.field] ?? tech.defaultOn) totalEnabled++;
      }
    }
    log('INFO', `  Evasion:    ${totalEnabled} techniques enabled`);

    setProgress(15);

    const config = {
      format: shellcodeOnly ? 'shellcode' : formatKey,
      arch: buildArch,
      os_target: os,
      listener_id: listenerId,
      callback_host: callbackHost,
      sleep,
      jitter,
      shellcode_format: shellcodeFormatKey,
      evasion: buildEvasionConfig(),
      encryption: {
        transport_type: transportEnc,
        payload_type: payloadEnc,
        key: encKey,
      },
      opsec,
    };

    setProgress(30);
    log('INFO', 'Build request sent to teamserver...');

    try {
      const result = await api.generatePayload(config);
      setProgress(80);
      log('SUCCESS', 'Payload compiled successfully');

      if (result.data) {
        const binary = atob(result.data);
        const size = binary.length;
        log('SUCCESS', `Payload size: ${size} bytes (${(size / 1024).toFixed(1)} KB)`);

        setProgress(90);

        // Save to artifacts store
        useArtifactStore.getState().addArtifact({
          id: Date.now().toString(36) + Math.random().toString(36).slice(2, 6),
          name: buildFilename,
          listenerName: lName,
          os,
          arch: buildArch,
          format: shellcodeOnly ? 'shellcode' : formatKey,
          size,
          hash: result.hash || '',
          data: result.data,
          createdAt: new Date().toLocaleString('en-US', { hour12: false }),
          shellcodeOnly,
        });

        // Switch to artifacts tab
        useUIStore.getState().setActiveBottomTab('artifacts');

        setProgress(100);
        setProgressText('Build complete!');
        log('SUCCESS', `Artifact saved: ${buildFilename}`);
        log('SUCCESS', 'Go to the Artifacts tab to download.');
      } else {
        log('ERROR', 'Received empty payload data from server');
      }
    } catch (err: any) {
      log('ERROR', `BUILD FAILED: ${err.message}`);
      setProgress(0);
      setProgressText('Build failed');
    } finally {
      setIsBuilding(false);
      log('INFO', '----------------------------------------------------');
    }
  };

  const levelColor = { INFO: '#888', SUCCESS: '#00cc00', ERROR: '#cc0000' };

  return (
    <div className="dialog-overlay" onClick={onClose}>
      <div
        className="dialog"
        style={{ width: '95vw', maxWidth: '1200px', height: '90vh', display: 'flex', flexDirection: 'column' }}
        onClick={(e) => e.stopPropagation()}
      >
        <div className="dialog__header">
          <div>
            <span className="dialog__title">Payload Generator</span>
            <div style={{ color: '#666', fontSize: '11px', marginTop: '2px' }}>
              Generate agent payloads with evasion techniques, encryption, and OPSEC options
            </div>
          </div>
          <button className="dialog__close" onClick={onClose}>×</button>
        </div>

        <div style={{ flex: 1, overflow: 'auto', padding: '16px' }}>
          {/* Two-column layout */}
          <div style={{ display: 'flex', gap: '16px', minHeight: '400px' }}>
            {/* LEFT COLUMN */}
            <div style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: '12px' }}>
              {/* Target Configuration */}
              <div className="group-box">
                <div className="group-box__title">Target Configuration</div>
                <div className="group-box__grid">
                  <span className="group-box__label">Format:</span>
                  <select className="select" value={formatKey} onChange={(e) => {
                    setFormatKey(e.target.value);
                    updateOutputFile(os, archKey, e.target.value);
                  }}>
                    {formats.map(f => <option key={f.key} value={f.key}>{f.display}</option>)}
                  </select>

                  <span className="group-box__label">Architecture:</span>
                  <select className="select" value={archKey} onChange={(e) => {
                    setArchKey(e.target.value);
                    updateOutputFile(os, e.target.value, formatKey);
                  }}>
                    {archs.map(a => <option key={a.key} value={a.key}>{a.display}</option>)}
                  </select>

                  <span className="group-box__label">Operating System:</span>
                  <select className="select" value={os} onChange={(e) => handleOSChange(e.target.value)}>
                    <option value="windows">Windows</option>
                    <option value="linux">Linux</option>
                    <option value="macos">macOS</option>
                  </select>

                  <span className="group-box__label">Listener:</span>
                  <select className="select" value={listenerId} onChange={(e) => {
                    setListenerId(e.target.value);
                    const l = listeners.find(x => x.id === e.target.value);
                    const lName = l?.config?.name || '';
                    updateOutputFile(os, archKey, formatKey, lName);
                    // Auto-populate callback host from listener bind_host
                    const bindHost = l?.config?.bind_host || '0.0.0.0';
                    if (bindHost === '0.0.0.0' || bindHost === '::') {
                      setCallbackHost('127.0.0.1');
                    } else {
                      setCallbackHost(bindHost);
                    }
                  }}>
                    <option value="">-- Select Listener --</option>
                    {listeners.map(l => (
                      <option key={l.id} value={l.id}>
                        {l.config?.name || l.id} ({l.config?.bind_host}:{l.config?.bind_port})
                      </option>
                    ))}
                  </select>

                  <span className="group-box__label">Callback Host:</span>
                  <input className="input" value={callbackHost} onChange={(e) => setCallbackHost(e.target.value)}
                    placeholder="IP/hostname the agent connects back to"
                    title="The IP or hostname the agent will use to connect back to the teamserver. Change this from 127.0.0.1 if the agent runs on a different machine." />
                </div>
              </div>

              {/* Agent Configuration */}
              <div className="group-box">
                <div className="group-box__title">Agent Configuration</div>
                <div className="group-box__grid">
                  <span className="group-box__label">Sleep (s):</span>
                  <input className="input" type="number" min={1} max={3600} value={sleep} onChange={(e) => setSleep(Number(e.target.value))} />

                  <span className="group-box__label">Jitter (%):</span>
                  <input className="input" type="number" min={0} max={100} value={jitter} onChange={(e) => setJitter(Number(e.target.value))} />

                  <span className="group-box__label">User-Agent:</span>
                  <input className="input" value={userAgent} onChange={(e) => setUserAgent(e.target.value)} />
                </div>
              </div>

              {/* Encryption Options */}
              <div className="group-box">
                <div className="group-box__title">Encryption Options</div>
                <div className="group-box__grid">
                  <span className="group-box__label">Transport:</span>
                  <select className="select" value={transportEnc} onChange={(e) => setTransportEnc(e.target.value)}>
                    <option value="aes">AES (default)</option>
                    <option value="xor">XOR</option>
                    <option value="rc4">RC4</option>
                  </select>

                  <span className="group-box__label">Payload:</span>
                  <select className="select" value={payloadEnc} onChange={(e) => setPayloadEnc(e.target.value)}>
                    <option value="none">None</option>
                    <option value="xor">XOR</option>
                    <option value="aes">AES</option>
                    <option value="rc4">RC4</option>
                  </select>

                  <span className="group-box__label">Key:</span>
                  <div style={{ display: 'flex', gap: '6px' }}>
                    <input className="input" value={encKey} onChange={(e) => setEncKey(e.target.value)} style={{ flex: 1, fontFamily: 'var(--font-mono)', fontSize: '10px' }} />
                    <button className="btn btn--small" onClick={generateKey}>Generate</button>
                  </div>

                  <span className="group-box__label">SC Encoder:</span>
                  <select className="select" value={shellcodeEncoder} onChange={(e) => setShellcodeEncoder(e.target.value)}>
                    <option value="none">None</option>
                    <option value="xor">XOR</option>
                    <option value="aes">AES</option>
                    <option value="rc4">RC4</option>
                    <option value="custom">Custom</option>
                  </select>
                </div>
              </div>

              {/* OPSEC Options */}
              <div className="group-box">
                <div className="group-box__title">OPSEC Options</div>
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '8px' }}>
                  <label className="checkbox-wrapper">
                    <input type="checkbox" checked={opsec.sleep_mask} onChange={(e) => setOpsec(p => ({ ...p, sleep_mask: e.target.checked }))} />
                    Sleep Mask
                  </label>
                  <label className={`checkbox-wrapper ${!isWindows ? 'disabled' : ''}`}>
                    <input type="checkbox" checked={opsec.stack_spoof} disabled={!isWindows} onChange={(e) => setOpsec(p => ({ ...p, stack_spoof: e.target.checked }))} />
                    Stack Spoofing
                  </label>
                  <label className={`checkbox-wrapper ${!isWindows ? 'disabled' : ''}`}>
                    <input type="checkbox" checked={opsec.module_stomping} disabled={!isWindows} onChange={(e) => setOpsec(p => ({ ...p, module_stomping: e.target.checked }))} />
                    Module Stomping
                  </label>
                  <label className={`checkbox-wrapper ${!isWindows ? 'disabled' : ''}`}>
                    <input type="checkbox" checked={opsec.etw_patch} disabled={!isWindows} onChange={(e) => setOpsec(p => ({ ...p, etw_patch: e.target.checked }))} />
                    ETW Patching
                  </label>
                  <label className={`checkbox-wrapper ${!isWindows ? 'disabled' : ''}`}>
                    <input type="checkbox" checked={opsec.unhook_ntdll} disabled={!isWindows} onChange={(e) => setOpsec(p => ({ ...p, unhook_ntdll: e.target.checked }))} />
                    Unhook NTDLL
                  </label>
                  <label className={`checkbox-wrapper ${!isWindows ? 'disabled' : ''}`}>
                    <input type="checkbox" checked={opsec.thread_stack_spoof} disabled={!isWindows} onChange={(e) => setOpsec(p => ({ ...p, thread_stack_spoof: e.target.checked }))} />
                    Thread Stack Spoof
                  </label>
                  <label className="checkbox-wrapper">
                    <input type="checkbox" checked={opsec.heap_encryption} onChange={(e) => setOpsec(p => ({ ...p, heap_encryption: e.target.checked }))} />
                    Heap Encryption
                  </label>
                </div>
                <div style={{ display: 'grid', gridTemplateColumns: 'auto 1fr', gap: '8px 12px', alignItems: 'center', marginTop: '10px' }}>
                  <span className="group-box__label">Syscall Method:</span>
                  <select className="select" value={opsec.syscall_method} disabled={!isWindows}
                    onChange={(e) => setOpsec(p => ({ ...p, syscall_method: e.target.value }))}>
                    <option value="none">None</option>
                    {isWindows && <option value="direct">Direct Syscalls</option>}
                    {isWindows && <option value="indirect">Indirect Syscalls</option>}
                  </select>
                </div>
              </div>
            </div>

            {/* RIGHT COLUMN: Evasion Tabs */}
            <div style={{ flex: 1, background: '#111', border: '1px solid #1a1a1a', borderRadius: '4px', display: 'flex', flexDirection: 'column' }}>
              <div style={{ padding: '8px 12px', borderBottom: '1px solid #1a1a1a' }}>
                <span style={{ color: '#cc0000', fontWeight: 700, fontSize: '12px', textTransform: 'uppercase', letterSpacing: '0.5px' }}>
                  Evasion Techniques (100)
                </span>
              </div>
              <div style={{ flex: 1, overflow: 'hidden' }}>
                <EvasionTabs os={os} evasionState={evasionState} onToggle={handleEvasionToggle} />
              </div>
            </div>
          </div>

          {/* OUTPUT SECTION */}
          <div className="group-box" style={{ marginTop: '12px' }}>
            <div className="group-box__title">Output</div>
            <div className="group-box__grid">
              {formatKey === 'shellcode' && (
                <>
                  <span className="group-box__label">SC Format:</span>
                  <select className="select" value={shellcodeFormatKey} onChange={(e) => {
                    setShellcodeFormatKey(e.target.value);
                    updateOutputFile(os, archKey, formatKey, undefined, e.target.value);
                  }}>
                    {shellcodeFormats.map(f => <option key={f.key} value={f.key}>{f.display}</option>)}
                  </select>
                </>
              )}

              <span className="group-box__label">Output File:</span>
              <input className="input" value={outputFile} onChange={(e) => setOutputFile(e.target.value)} />
            </div>

            {formatKey === 'shellcode' ? (
              /* Shellcode format selected: only shellcode build makes sense */
              <div style={{ marginTop: '12px' }}>
                <button
                  className="btn btn--orange btn--large"
                  style={{ width: '100%' }}
                  disabled={isBuilding}
                  onClick={() => handleBuild(true)}
                >
                  {isBuilding ? 'GENERATING...' : 'GENERATE SHELLCODE'}
                </button>
              </div>
            ) : (
              /* Binary format selected: show both build options */
              <>
                <div style={{ display: 'flex', gap: '12px', marginTop: '12px' }}>
                  <button
                    className="btn btn--primary btn--large"
                    style={{ flex: 1 }}
                    disabled={isBuilding}
                    onClick={() => handleBuild(false)}
                  >
                    {isBuilding ? 'BUILDING...' : 'BUILD PAYLOAD'}
                  </button>
                  <div style={{ flex: 1, display: 'flex', gap: '6px' }}>
                    <select className="select" value={shellcodeFormatKey} onChange={(e) => setShellcodeFormatKey(e.target.value)}
                      style={{ width: '100px', flexShrink: 0, fontSize: '11px' }}>
                      {shellcodeFormats.map(f => <option key={f.key} value={f.key}>{f.display}</option>)}
                    </select>
                    <button
                      className="btn btn--orange btn--large"
                      style={{ flex: 1 }}
                      disabled={isBuilding}
                      onClick={() => handleBuild(true)}
                    >
                      {isBuilding ? 'GENERATING...' : 'SHELLCODE ONLY'}
                    </button>
                  </div>
                </div>
                <button
                  className="btn btn--large"
                  style={{ width: '100%', marginTop: '8px', background: '#1a1a2e', borderColor: '#333', color: '#a0a0ff' }}
                  disabled={isBuilding}
                  onClick={async () => {
                    for (const arch of archs) {
                      await handleBuild(false, arch.key);
                    }
                  }}
                >
                  BUILD ALL ARCHS ({archs.map(a => a.key).join(', ')})
                </button>
              </>
            )}
          </div>

          {/* BUILD LOG */}
          <div style={{ marginTop: '12px' }}>
            <div style={{ color: '#888', fontSize: '11px', fontWeight: 700, textTransform: 'uppercase', marginBottom: '4px' }}>
              Build Log
            </div>
            <div style={{
              background: '#080808',
              border: '1px solid #1a1a1a',
              borderRadius: '4px',
              padding: '8px',
              maxHeight: '150px',
              overflowY: 'auto',
              fontFamily: 'var(--font-mono)',
              fontSize: '11px',
              lineHeight: 1.6,
            }}>
              {buildLog.length === 0 ? (
                <span style={{ color: '#444' }}>Payload generator initialized. Ready to build.</span>
              ) : (
                buildLog.map((entry, i) => (
                  <div key={i}>
                    <span style={{ color: '#444' }}>[{entry.time}]</span>{' '}
                    <span style={{ color: levelColor[entry.level], fontWeight: 700 }}>[{entry.level}]</span>{' '}
                    <span style={{ color: levelColor[entry.level] }}>{entry.message}</span>
                  </div>
                ))
              )}
            </div>
          </div>

          {/* Progress bar */}
          <div className="progress-bar" style={{ marginTop: '8px' }}>
            <div className="progress-bar__fill" style={{ width: `${progress}%` }} />
            <div className="progress-bar__text">{progressText || `${progress}%`}</div>
          </div>
        </div>
      </div>
    </div>
  );
}
