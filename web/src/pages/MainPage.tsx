import { useState, useCallback, useRef, useEffect } from 'react';
import Sidebar from '../components/layout/Sidebar';
import StatusBar from '../components/layout/StatusBar';
import AgentTable from '../components/agents/AgentTable';
import AgentGraph from '../components/agents/AgentGraph';
import BottomTabs from '../components/layout/BottomTabs';
import PayloadGenerator from '../components/payload/PayloadGenerator';
import BOFPanel from '../components/bof/BOFPanel';
import DownloadCradleDialog from '../components/tools/DownloadCradleDialog';
import LateralMovementWizard from '../components/agents/LateralMovementWizard';
import ToastContainer from '../components/ui/ToastContainer';
import { useUIStore } from '../store/uiStore';
import { useAgentStore } from '../store/agentStore';
import { useListenerStore } from '../store/listenerStore';
import { useEventStore } from '../store/eventStore';
import { usePolling } from '../hooks/usePolling';
import { useWebSocket } from '../hooks/useWebSocket';
import { useKeyboardShortcuts } from '../hooks/useKeyboardShortcuts';

export default function MainPage() {
  const {
    showPayloadGenerator, setShowPayloadGenerator,
    showBOFPanel, setShowBOFPanel,
    showCradleDialog, setShowCradleDialog,
    showLateralWizard, setShowLateralWizard, lateralWizardAgentId,
  } = useUIStore();
  const fetchAgents = useAgentStore((s) => s.fetch);
  const fetchListeners = useListenerStore((s) => s.fetch);
  const fetchEvents = useEventStore((s) => s.fetch);

  // Real-time updates via WebSocket
  useWebSocket();

  // Keyboard shortcuts
  useKeyboardShortcuts();

  // Polling as fallback
  usePolling(fetchAgents, 5000);
  usePolling(fetchListeners, 5000);
  usePolling(fetchEvents, 10000);

  // Toggle between table and graph view
  const [viewMode, setViewMode] = useState<'table' | 'graph'>('table');

  // Resizable splitter state
  const [topHeight, setTopHeight] = useState(45); // percentage
  const containerRef = useRef<HTMLDivElement>(null);
  const isDragging = useRef(false);

  const onMouseDown = useCallback(() => {
    isDragging.current = true;
    document.body.style.cursor = 'row-resize';
    document.body.style.userSelect = 'none';
  }, []);

  useEffect(() => {
    const onMouseMove = (e: MouseEvent) => {
      if (!isDragging.current || !containerRef.current) return;
      const rect = containerRef.current.getBoundingClientRect();
      const pct = ((e.clientY - rect.top) / rect.height) * 100;
      setTopHeight(Math.min(Math.max(pct, 15), 85));
    };
    const onMouseUp = () => {
      isDragging.current = false;
      document.body.style.cursor = '';
      document.body.style.userSelect = '';
    };
    window.addEventListener('mousemove', onMouseMove);
    window.addEventListener('mouseup', onMouseUp);
    return () => {
      window.removeEventListener('mousemove', onMouseMove);
      window.removeEventListener('mouseup', onMouseUp);
    };
  }, []);

  return (
    <div style={{ display: 'flex', height: '100vh', overflow: 'hidden' }}>
      <Sidebar />

      <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
        {/* Main content area with resizable splitter */}
        <div ref={containerRef} style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
          {/* Top pane: Agent Table or Graph */}
          <div style={{ height: `${topHeight}%`, overflow: 'auto', borderBottom: '1px solid #1a1a1a', position: 'relative' }}>
            {/* View toggle buttons */}
            <div style={{
              position: 'absolute', top: '8px', right: '12px', zIndex: 10,
              display: 'flex', gap: '4px', background: '#0d0d0d', borderRadius: '4px',
              padding: '2px', border: '1px solid #1a1a1a',
            }}>
              <button
                onClick={() => setViewMode('table')}
                style={{
                  padding: '4px 10px', fontSize: '11px', border: 'none', cursor: 'pointer',
                  borderRadius: '3px', fontFamily: 'var(--font-mono)',
                  background: viewMode === 'table' ? '#cc0000' : 'transparent',
                  color: viewMode === 'table' ? '#fff' : '#808080',
                }}
              >Table</button>
              <button
                onClick={() => setViewMode('graph')}
                style={{
                  padding: '4px 10px', fontSize: '11px', border: 'none', cursor: 'pointer',
                  borderRadius: '3px', fontFamily: 'var(--font-mono)',
                  background: viewMode === 'graph' ? '#cc0000' : 'transparent',
                  color: viewMode === 'graph' ? '#fff' : '#808080',
                }}
              >Graph</button>
            </div>
            {viewMode === 'table' ? <AgentTable /> : <AgentGraph />}
          </div>

          {/* Splitter handle */}
          <div
            onMouseDown={onMouseDown}
            style={{
              height: '4px',
              background: '#1a1a1a',
              cursor: 'row-resize',
              flexShrink: 0,
              transition: 'background 0.15s',
            }}
            onMouseEnter={(e) => (e.currentTarget.style.background = '#cc0000')}
            onMouseLeave={(e) => { if (!isDragging.current) e.currentTarget.style.background = '#1a1a1a'; }}
          />

          {/* Bottom pane: Tabs */}
          <div style={{ height: `${100 - topHeight}%`, overflow: 'hidden' }}>
            <BottomTabs />
          </div>
        </div>

        {/* Status Bar */}
        <StatusBar />
      </div>

      {/* Modals */}
      {showPayloadGenerator && <PayloadGenerator onClose={() => setShowPayloadGenerator(false)} />}
      {showBOFPanel && <BOFPanel onClose={() => setShowBOFPanel(false)} />}
      {showCradleDialog && <DownloadCradleDialog onClose={() => setShowCradleDialog(false)} />}
      {showLateralWizard && lateralWizardAgentId && (
        <LateralMovementWizard agentId={lateralWizardAgentId} onClose={() => setShowLateralWizard(false, '')} />
      )}

      {/* Toast Notifications */}
      <ToastContainer />
    </div>
  );
}
