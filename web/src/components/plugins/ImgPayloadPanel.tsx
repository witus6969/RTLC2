import { useState, useRef } from 'react';
import { api } from '../../api/client';
import { useArtifactStore } from '../../store/artifactStore';

type Mode = 'embed' | 'extract';

interface LogEntry {
  time: string;
  level: 'INFO' | 'SUCCESS' | 'ERROR';
  msg: string;
}

export default function ImgPayloadPanel() {
  const [mode, setMode] = useState<Mode>('embed');

  // Embed state
  const [imageName, setImageName] = useState('');
  const [imageB64, setImageB64] = useState('');
  const [imagePreview, setImagePreview] = useState('');
  const [scSource, setScSource] = useState<'artifact' | 'file'>('artifact');
  const [scArtifactId, setScArtifactId] = useState('');
  const [scFileB64, setScFileB64] = useState('');
  const [scFileName, setScFileName] = useState('');
  const [outFormat, setOutFormat] = useState('png');
  const [resultPreview, setResultPreview] = useState('');
  const [resultB64, setResultB64] = useState('');
  const [resultName, setResultName] = useState('');

  // Extract state
  const [exImageName, setExImageName] = useState('');
  const [exImageB64, setExImageB64] = useState('');
  const [exImagePreview, setExImagePreview] = useState('');
  const [extractedB64, setExtractedB64] = useState('');
  const [extractedSize, setExtractedSize] = useState(0);

  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [busy, setBusy] = useState(false);
  const imgInputRef = useRef<HTMLInputElement>(null);
  const scInputRef = useRef<HTMLInputElement>(null);
  const exInputRef = useRef<HTMLInputElement>(null);

  const artifacts = useArtifactStore((s) => s.artifacts);

  const log = (level: LogEntry['level'], msg: string) => {
    setLogs((p) => [...p, { time: new Date().toLocaleTimeString('en-US', { hour12: false }), level, msg }]);
  };

  // ── File helpers ──
  const readFileAsB64 = (file: File): Promise<string> =>
    new Promise((resolve, reject) => {
      const r = new FileReader();
      r.onload = () => {
        const arr = new Uint8Array(r.result as ArrayBuffer);
        let binary = '';
        for (let i = 0; i < arr.length; i++) binary += String.fromCharCode(arr[i]);
        resolve(btoa(binary));
      };
      r.onerror = reject;
      r.readAsArrayBuffer(file);
    });

  const readFileAsDataURL = (file: File): Promise<string> =>
    new Promise((resolve, reject) => {
      const r = new FileReader();
      r.onload = () => resolve(r.result as string);
      r.onerror = reject;
      r.readAsDataURL(file);
    });

  const downloadBlob = (b64: string, name: string) => {
    const bin = atob(b64);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    const blob = new Blob([bytes], { type: 'application/octet-stream' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = name;
    a.click();
    URL.revokeObjectURL(url);
  };

  // ── Embed flow ──
  const handleSelectImage = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    setImageName(file.name);
    setImageB64(await readFileAsB64(file));
    setImagePreview(await readFileAsDataURL(file));
    log('INFO', `Image loaded: ${file.name} (${(file.size / 1024).toFixed(1)} KB)`);
  };

  const handleSelectSCFile = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    setScFileName(file.name);
    setScFileB64(await readFileAsB64(file));
    log('INFO', `Shellcode file loaded: ${file.name} (${(file.size / 1024).toFixed(1)} KB)`);
  };

  const handleEmbed = async () => {
    if (!imageB64) { log('ERROR', 'Select a cover image first.'); return; }

    let shellcode = '';
    if (scSource === 'artifact') {
      const a = artifacts.find((x) => x.id === scArtifactId);
      if (!a) { log('ERROR', 'Select an artifact containing shellcode.'); return; }
      shellcode = a.data;
      log('INFO', `Using artifact: ${a.name} (${(a.size / 1024).toFixed(1)} KB)`);
    } else {
      if (!scFileB64) { log('ERROR', 'Select a shellcode file.'); return; }
      shellcode = scFileB64;
      log('INFO', `Using shellcode file: ${scFileName}`);
    }

    setBusy(true);
    log('INFO', 'Embedding shellcode into image via LSB steganography...');

    try {
      const res = await api.imgPayloadEmbed(imageB64, shellcode, outFormat);
      setResultB64(res.data);
      const outName = imageName.replace(/\.[^.]+$/, '') + `_stego.${outFormat}`;
      setResultName(outName);

      // Build a preview data URL
      const mime = outFormat === 'bmp' ? 'image/bmp' : 'image/png';
      setResultPreview(`data:${mime};base64,${res.data}`);

      log('SUCCESS', `Shellcode embedded successfully!`);
      log('SUCCESS', `  Output: ${outName} (${(res.size / 1024).toFixed(1)} KB)`);
      log('SUCCESS', `  Shellcode size: ${res.shellcode_size} bytes embedded`);
    } catch (err: any) {
      log('ERROR', `Embed failed: ${err.message}`);
    } finally {
      setBusy(false);
    }
  };

  const handleDownloadResult = () => {
    if (resultB64) downloadBlob(resultB64, resultName);
  };

  // ── Extract flow ──
  const handleSelectExImage = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    setExImageName(file.name);
    setExImageB64(await readFileAsB64(file));
    setExImagePreview(await readFileAsDataURL(file));
    log('INFO', `Stego image loaded: ${file.name} (${(file.size / 1024).toFixed(1)} KB)`);
  };

  const handleExtract = async () => {
    if (!exImageB64) { log('ERROR', 'Select a steganized image first.'); return; }

    setBusy(true);
    log('INFO', 'Extracting shellcode from image...');

    try {
      const res = await api.imgPayloadExtract(exImageB64);
      setExtractedB64(res.data);
      setExtractedSize(res.size);
      log('SUCCESS', `Shellcode extracted: ${res.size} bytes`);
    } catch (err: any) {
      log('ERROR', `Extract failed: ${err.message}`);
    } finally {
      setBusy(false);
    }
  };

  const handleDownloadExtracted = () => {
    if (extractedB64) downloadBlob(extractedB64, exImageName.replace(/\.[^.]+$/, '') + '_extracted.bin');
  };

  const levelColor: Record<string, string> = { INFO: '#888', SUCCESS: '#00cc00', ERROR: '#cc0000' };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
      {/* Header */}
      <div style={{
        display: 'flex', alignItems: 'center', justifyContent: 'space-between',
        padding: '10px 16px', background: '#0d0d0d', borderBottom: '1px solid #1a1a1a',
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <span style={{ color: '#cc0000', fontWeight: 700, fontSize: '13px' }}>ImgPayload</span>
          <span style={{ color: '#555', fontSize: '11px' }}>LSB Steganography — embed shellcode into images</span>
        </div>
        <div style={{ display: 'flex', gap: '4px' }}>
          <button
            className={`btn btn--small ${mode === 'embed' ? 'btn--primary' : ''}`}
            onClick={() => setMode('embed')}
          >
            Embed
          </button>
          <button
            className={`btn btn--small ${mode === 'extract' ? 'btn--primary' : ''}`}
            onClick={() => setMode('extract')}
          >
            Extract
          </button>
        </div>
      </div>

      <div style={{ padding: '0 16px 16px', display: 'flex', gap: '16px' }}>
        {/* Left: Controls */}
        <div style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: '12px' }}>
          {mode === 'embed' ? (
            <>
              {/* Cover Image */}
              <div className="group-box">
                <div className="group-box__title">Cover Image (PNG / BMP)</div>
                <input ref={imgInputRef} type="file" accept="image/png,image/bmp,.png,.bmp"
                  style={{ display: 'none' }} onChange={handleSelectImage} />
                <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
                  <button className="btn btn--small" onClick={() => imgInputRef.current?.click()}>
                    Select Image
                  </button>
                  <span style={{ color: imageName ? '#e0e0e0' : '#555', fontSize: '12px', fontFamily: 'var(--font-mono)' }}>
                    {imageName || 'No image selected'}
                  </span>
                </div>
                {imagePreview && (
                  <img src={imagePreview} alt="cover" style={{
                    marginTop: '8px', maxWidth: '200px', maxHeight: '120px',
                    border: '1px solid #1a1a1a', borderRadius: '4px',
                  }} />
                )}
              </div>

              {/* Shellcode Source */}
              <div className="group-box">
                <div className="group-box__title">Shellcode Source</div>
                <div style={{ display: 'flex', gap: '8px', marginBottom: '8px' }}>
                  <button
                    className={`btn btn--small ${scSource === 'artifact' ? 'btn--primary' : ''}`}
                    onClick={() => setScSource('artifact')}
                  >
                    From Artifacts
                  </button>
                  <button
                    className={`btn btn--small ${scSource === 'file' ? 'btn--primary' : ''}`}
                    onClick={() => setScSource('file')}
                  >
                    Upload File
                  </button>
                </div>

                {scSource === 'artifact' ? (
                  <select className="select" value={scArtifactId}
                    onChange={(e) => setScArtifactId(e.target.value)}>
                    <option value="">-- Select Generated Artifact --</option>
                    {artifacts.map((a) => (
                      <option key={a.id} value={a.id}>
                        {a.name} ({(a.size / 1024).toFixed(1)} KB)
                      </option>
                    ))}
                  </select>
                ) : (
                  <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
                    <input ref={scInputRef} type="file" accept=".bin,.raw,.sc,.shellcode"
                      style={{ display: 'none' }} onChange={handleSelectSCFile} />
                    <button className="btn btn--small" onClick={() => scInputRef.current?.click()}>
                      Select File
                    </button>
                    <span style={{ color: scFileName ? '#e0e0e0' : '#555', fontSize: '12px', fontFamily: 'var(--font-mono)' }}>
                      {scFileName || 'No file selected'}
                    </span>
                  </div>
                )}
              </div>

              {/* Options */}
              <div className="group-box">
                <div className="group-box__title">Output Options</div>
                <div className="group-box__grid">
                  <span className="group-box__label">Format:</span>
                  <select className="select" value={outFormat} onChange={(e) => setOutFormat(e.target.value)}>
                    <option value="png">PNG</option>
                    <option value="bmp">BMP</option>
                  </select>
                </div>
              </div>

              {/* Embed Button */}
              <button className="btn btn--primary btn--large" disabled={busy} onClick={handleEmbed}>
                {busy ? 'EMBEDDING...' : 'EMBED SHELLCODE INTO IMAGE'}
              </button>

              {/* Result */}
              {resultB64 && (
                <div className="group-box">
                  <div className="group-box__title">Steganized Image</div>
                  <div style={{ display: 'flex', gap: '12px', alignItems: 'flex-start' }}>
                    {resultPreview && (
                      <img src={resultPreview} alt="result" style={{
                        maxWidth: '200px', maxHeight: '120px',
                        border: '1px solid #1a1a1a', borderRadius: '4px',
                      }} />
                    )}
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                      <span style={{ color: '#e0e0e0', fontSize: '12px', fontFamily: 'var(--font-mono)' }}>
                        {resultName}
                      </span>
                      <button className="btn btn--primary btn--small" onClick={handleDownloadResult}>
                        Download
                      </button>
                    </div>
                  </div>
                </div>
              )}
            </>
          ) : (
            <>
              {/* Extract Mode */}
              <div className="group-box">
                <div className="group-box__title">Steganized Image</div>
                <input ref={exInputRef} type="file" accept="image/png,image/bmp,.png,.bmp"
                  style={{ display: 'none' }} onChange={handleSelectExImage} />
                <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
                  <button className="btn btn--small" onClick={() => exInputRef.current?.click()}>
                    Select Image
                  </button>
                  <span style={{ color: exImageName ? '#e0e0e0' : '#555', fontSize: '12px', fontFamily: 'var(--font-mono)' }}>
                    {exImageName || 'No image selected'}
                  </span>
                </div>
                {exImagePreview && (
                  <img src={exImagePreview} alt="stego" style={{
                    marginTop: '8px', maxWidth: '200px', maxHeight: '120px',
                    border: '1px solid #1a1a1a', borderRadius: '4px',
                  }} />
                )}
              </div>

              <button className="btn btn--primary btn--large" disabled={busy} onClick={handleExtract}>
                {busy ? 'EXTRACTING...' : 'EXTRACT SHELLCODE FROM IMAGE'}
              </button>

              {extractedB64 && (
                <div className="group-box">
                  <div className="group-box__title">Extracted Shellcode</div>
                  <div style={{ display: 'flex', gap: '12px', alignItems: 'center' }}>
                    <span style={{ color: '#00cc00', fontSize: '12px', fontFamily: 'var(--font-mono)' }}>
                      {extractedSize} bytes extracted
                    </span>
                    <button className="btn btn--primary btn--small" onClick={handleDownloadExtracted}>
                      Download .bin
                    </button>
                  </div>
                </div>
              )}
            </>
          )}
        </div>

        {/* Right: Log */}
        <div style={{ width: '340px', display: 'flex', flexDirection: 'column' }}>
          <div style={{ color: '#888', fontSize: '11px', fontWeight: 700, textTransform: 'uppercase', marginBottom: '4px' }}>
            Log
          </div>
          <div style={{
            flex: 1, background: '#080808', border: '1px solid #1a1a1a', borderRadius: '4px',
            padding: '8px', overflowY: 'auto', fontFamily: 'var(--font-mono)', fontSize: '11px',
            lineHeight: 1.6, minHeight: '200px',
          }}>
            {logs.length === 0 ? (
              <span style={{ color: '#444' }}>ImgPayload ready.</span>
            ) : (
              logs.map((e, i) => (
                <div key={i}>
                  <span style={{ color: '#444' }}>[{e.time}]</span>{' '}
                  <span style={{ color: levelColor[e.level], fontWeight: 700 }}>[{e.level}]</span>{' '}
                  <span style={{ color: levelColor[e.level] }}>{e.msg}</span>
                </div>
              ))
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
