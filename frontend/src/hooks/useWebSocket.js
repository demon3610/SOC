import { useEffect, useRef, useCallback, useState } from 'react';
import { WS_BASE, request } from '../lib/api';

export function useWebSocket(projectId, onEvent) {
  const wsRef = useRef(null);
  const cbRef = useRef(onEvent);
  const mountedRef = useRef(true);
  const retryRef = useRef(null);
  const pollRef = useRef(null);
  const seenRef = useRef(new Set());
  const failRef = useRef(0);
  const [connected, setConnected] = useState(false);
  cbRef.current = onEvent;

  const deliver = useCallback((event) => {
    if (!event || typeof event !== 'object' || event.id == null) return;
    if (seenRef.current.has(event.id)) return;
    if (seenRef.current.size > 5000) seenRef.current.clear();
    seenRef.current.add(event.id);
    cbRef.current(event);
  }, []);

  const poll = useCallback(async (pid) => {
    try {
      const res = await request(`/projects/${pid}/events?size=25`);
      (res.events || []).forEach(deliver);
      if (mountedRef.current) setConnected(true);
    } catch {}
  }, [deliver]);

  const stopPolling = useCallback(() => {
    if (pollRef.current) {
      clearInterval(pollRef.current);
      pollRef.current = null;
    }
  }, []);

  const startPolling = useCallback((pid) => {
    if (pollRef.current) return;
    poll(pid);
    pollRef.current = setInterval(() => poll(pid), 4000);
  }, [poll]);

  const reconnect = useCallback(() => {
    if (!projectId || !mountedRef.current) return;
    const token = localStorage.getItem('soc_token');
    if (!token) return;

    // Close any existing connection
    if (wsRef.current) {
      wsRef.current.onclose = null;
      wsRef.current.close();
    }

    const ws = new WebSocket(`${WS_BASE}/ws/projects/${projectId}/live?token=${token}`);

    ws.onopen = () => {
      if (!mountedRef.current) return;
      failRef.current = 0;
      stopPolling();
      setConnected(true);
    };

    ws.onmessage = (msg) => {
      try {
        const parsed = JSON.parse(msg.data);
        // Support both flat event dicts and wrapped {type, data} format
        const event = parsed?.type === 'event' && parsed?.data ? parsed.data : parsed;
        deliver(event);
      } catch {}
    };

    ws.onerror = () => {
      setConnected(false);
    };

    ws.onclose = () => {
      setConnected(false);
      if (!mountedRef.current) return;
      failRef.current += 1;
      if (failRef.current >= 2) {
        failRef.current = 0;
        startPolling(projectId);
      }
      retryRef.current = setTimeout(reconnect, 3000);
    };

    wsRef.current = ws;
  }, [projectId, deliver, startPolling, stopPolling]);

  useEffect(() => {
    mountedRef.current = true;
    if (!projectId) return;
    reconnect();
    return () => {
      mountedRef.current = false;
      clearTimeout(retryRef.current);
      stopPolling();
      seenRef.current.clear();
      if (wsRef.current) {
        wsRef.current.onopen = null;
        wsRef.current.onmessage = null;
        wsRef.current.onerror = null;
        wsRef.current.onclose = null;
        if (wsRef.current.readyState === WebSocket.OPEN) wsRef.current.close();
        wsRef.current = null;
      }
      setConnected(false);
    };
  }, [projectId, reconnect, stopPolling]);

  return { connected };
}
