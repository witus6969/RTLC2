// ═══════════════════════════════════════════════════════════════
//  RTLC2 WebSocket Hook for Real-time Events
// ═══════════════════════════════════════════════════════════════

import { useEffect, useRef, useCallback } from 'react';
import { useAuthStore } from '../store/authStore';
import { useAgentStore } from '../store/agentStore';
import { useEventStore } from '../store/eventStore';
import { useCredentialStore } from '../store/credentialStore';
import { useChatStore } from '../store/chatStore';
import { useToastStore } from '../store/toastStore';
import { useListenerStore } from '../store/listenerStore';
import { useUIStore } from '../store/uiStore';
import type { WSEvent, Agent, Credential, ChatMessage } from '../types';

const RECONNECT_BASE_MS = 1000;
const RECONNECT_MAX_MS = 30000;
const HEARTBEAT_INTERVAL_MS = 30000;

export function useWebSocket() {
  const token = useAuthStore((s) => s.token);
  const isAuthenticated = useAuthStore((s) => s.isAuthenticated);
  const wsRef = useRef<WebSocket | null>(null);
  const reconnectTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const heartbeatTimer = useRef<ReturnType<typeof setInterval> | null>(null);
  const reconnectAttempts = useRef(0);
  const mountedRef = useRef(true);

  const handleEvent = useCallback((event: WSEvent) => {
    switch (event.type) {
      case 'agent_checkin': {
        const agent = event.data as Agent;
        const store = useAgentStore.getState();
        const existing = store.agents.find((a) => a.id === agent.id);
        if (existing) {
          useAgentStore.setState({
            agents: store.agents.map((a) => (a.id === agent.id ? { ...a, ...agent } : a)),
          });
        } else {
          useAgentStore.setState({ agents: [...store.agents, agent] });
          // Toast for new agent
          useToastStore.getState().addToast(
            'success',
            'New Agent Callback',
            `${agent.hostname} (${agent.username}@${agent.os}) - ${agent.internal_ip}`
          );
        }
        break;
      }

      case 'agent_dead': {
        const { agent_id, message } = event.data as { agent_id: string; message?: string };
        const store = useAgentStore.getState();
        const deadAgent = store.agents.find((a) => a.id === agent_id);
        useAgentStore.setState({
          agents: store.agents.map((a) =>
            a.id === agent_id ? { ...a, alive: false } : a
          ),
        });
        useToastStore.getState().addToast(
          'warning',
          'Agent Went Dark',
          message || `Agent ${deadAgent?.hostname || agent_id.slice(0, 8)} is no longer responding`
        );
        break;
      }

      case 'agent_task_complete': {
        const { agent_id, message } = event.data as { agent_id: string; message?: string };
        useEventStore.getState().fetch();
        const agents = useAgentStore.getState().agents;
        const a = agents.find((x) => x.id === agent_id);
        useToastStore.getState().addToast(
          'info',
          'Task Completed',
          message || `Task completed on ${a?.hostname || agent_id.slice(0, 8)}`
        );
        break;
      }

      case 'credential_added': {
        const cred = event.data as Credential;
        const credStore = useCredentialStore.getState();
        const exists = credStore.credentials.some((c) => c.id === cred.id);
        if (!exists) {
          useCredentialStore.setState({
            credentials: [...credStore.credentials, cred],
          });
          useToastStore.getState().addToast(
            'success',
            'Credential Found',
            `${cred.type}: ${cred.domain ? cred.domain + '\\' : ''}${cred.username}`
          );
        }
        break;
      }

      case 'chat_message': {
        const msg = event.data as ChatMessage;
        useChatStore.getState().addMessage(msg);
        break;
      }

      case 'listener_started':
      case 'listener_stopped': {
        useListenerStore.getState().fetch();
        break;
      }

      default:
        // Unknown event type -- silently ignore
        break;
    }
  }, []);

  const connect = useCallback(() => {
    if (!token || !isAuthenticated) return;
    if (wsRef.current?.readyState === WebSocket.OPEN) return;

    // Build WebSocket URL from current location
    const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${proto}//${window.location.host}/api/v1/ws/events?token=${encodeURIComponent(token)}`;

    try {
      const ws = new WebSocket(wsUrl);
      wsRef.current = ws;

      ws.onopen = () => {
        if (!mountedRef.current) return;
        reconnectAttempts.current = 0;
        useChatStore.getState().setConnected(true);
        useUIStore.getState().setWsConnected(true);

        // Start heartbeat
        heartbeatTimer.current = setInterval(() => {
          if (ws.readyState === WebSocket.OPEN) {
            ws.send(JSON.stringify({ type: 'ping' }));
          }
        }, HEARTBEAT_INTERVAL_MS);
      };

      ws.onmessage = (e) => {
        if (!mountedRef.current) return;
        try {
          const event: WSEvent = JSON.parse(e.data);
          handleEvent(event);
        } catch {
          // Malformed message -- ignore
        }
      };

      ws.onerror = () => {
        // Error triggers close event, reconnect handled there
      };

      ws.onclose = () => {
        if (!mountedRef.current) return;
        useChatStore.getState().setConnected(false);
        useUIStore.getState().setWsConnected(false);

        // Clear heartbeat
        if (heartbeatTimer.current) {
          clearInterval(heartbeatTimer.current);
          heartbeatTimer.current = null;
        }

        // Schedule reconnect with exponential backoff
        const delay = Math.min(
          RECONNECT_BASE_MS * Math.pow(2, reconnectAttempts.current),
          RECONNECT_MAX_MS
        );
        reconnectAttempts.current += 1;
        reconnectTimer.current = setTimeout(() => {
          if (mountedRef.current) connect();
        }, delay);
      };
    } catch {
      // Failed to construct WebSocket -- schedule retry
      const delay = Math.min(
        RECONNECT_BASE_MS * Math.pow(2, reconnectAttempts.current),
        RECONNECT_MAX_MS
      );
      reconnectAttempts.current += 1;
      reconnectTimer.current = setTimeout(() => {
        if (mountedRef.current) connect();
      }, delay);
    }
  }, [token, isAuthenticated, handleEvent]);

  useEffect(() => {
    mountedRef.current = true;
    connect();

    return () => {
      mountedRef.current = false;

      if (reconnectTimer.current) {
        clearTimeout(reconnectTimer.current);
        reconnectTimer.current = null;
      }
      if (heartbeatTimer.current) {
        clearInterval(heartbeatTimer.current);
        heartbeatTimer.current = null;
      }
      if (wsRef.current) {
        wsRef.current.onclose = null; // prevent reconnect on unmount
        wsRef.current.close();
        wsRef.current = null;
      }
    };
  }, [connect]);

  return {
    connected: wsRef.current?.readyState === WebSocket.OPEN,
  };
}
