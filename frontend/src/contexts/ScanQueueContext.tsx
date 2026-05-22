import { createContext, useContext, useState, useRef, useCallback, ReactNode } from 'react';
import { api } from '@/lib/api';

export interface QueueItem {
  id: string;
  target: string;
  profile: string;
  status: 'queued' | 'scanning' | 'done' | 'failed' | 'cancelled';
  scanId: string;
  progress: number;
  currentPhase: string;
  etaRemainingSeconds: number | null;
  etaLowerSeconds: number | null;
  etaUpperSeconds: number | null;
}

export interface ScanNotification {
  id: string;
  message: string;
  link: string;
  timestamp: Date;
  scanId?: string;
}

interface ScanQueueContextType {
  queue: QueueItem[];
  isRunning: boolean;
  minimized: boolean;
  scanProfile: string;
  notifications: ScanNotification[];
  logs: string[];
  latestCompletedScanId: string | null;
  startQueue: (targets: string[], profile: string) => void;
  cancelQueue: () => void;
  removeQueueItem: (itemId: string) => void;
  toggleMinimize: () => void;
  setMinimized: (v: boolean) => void;
  queueComplete: 'success' | 'failed' | 'cancelled' | null;
}

const phases = ['Discovery', 'TLS Probing', 'PQC Classification', 'CBOM Generation', 'Certification'];

function mapStageToPhase(stage: string | undefined): string {
  if (!stage) return phases[0];
  const s = stage.toLowerCase();
  if (s.includes('discover') || s.includes('enumerat')) return 'Discovery';
  if (s.includes('tls') || s.includes('probe') || s.includes('handshake')) return 'TLS Probing';
  if (s.includes('pqc') || s.includes('classif') || s.includes('quantum')) return 'PQC Classification';
  if (s.includes('cbom') || s.includes('bill') || s.includes('generat')) return 'CBOM Generation';
  if (s.includes('cert') || s.includes('final') || s.includes('complet')) return 'Certification';
  return phases[0];
}

function phaseProgress(phase: string): number {
  const idx = phases.indexOf(phase);
  if (idx < 0) return 0;
  return Math.round(((idx + 1) / phases.length) * 100);
}

function formatEtaLabel(lower: number | null, upper: number | null): string | null {
  if (lower === null && upper === null) return null;
  const l = Math.max(0, Math.round((lower ?? upper ?? 0) / 60));
  const u = Math.max(l, Math.round((upper ?? lower ?? 0) / 60));
  if (u <= 1) return '<1 min';
  if (l === u) return `~${u} min`;
  return `${l}-${u} min`;
}

function stageDisplayName(stage: string | null | undefined): string {
  if (!stage) return 'Discovery';
  const normalized = stage.toLowerCase();
  if (normalized.includes('enumerat')) return 'Discovery';
  if (normalized.includes('validating_dns')) return 'DNS Validation';
  if (normalized.includes('scanning_ports')) return 'Port Scanning';
  if (normalized.includes('probing_tls')) return 'TLS Probing';
  if (normalized.includes('persisting_assets')) return 'Persistence';
  if (normalized.includes('preparing')) return 'Preparing';
  if (normalized.includes('completed')) return 'Completed';
  if (normalized.includes('failed')) return 'Failed';
  return stage;
}

const ScanQueueContext = createContext<ScanQueueContextType | undefined>(undefined);

export const ScanQueueProvider = ({ children }: { children: ReactNode }) => {
  const [queue, setQueue] = useState<QueueItem[]>([]);
  const [isRunning, setIsRunning] = useState(false);
  const [minimized, setMinimized] = useState(false);
  const [scanProfile, setScanProfile] = useState('standard');
  const [notifications, setNotifications] = useState<ScanNotification[]>([]);
  const [logs, setLogs] = useState<string[]>([]);
  const [latestCompletedScanId, setLatestCompletedScanId] = useState<string | null>(null);
  const [queueComplete, setQueueComplete] = useState<'success' | 'failed' | 'cancelled' | null>(null);

  const queueRef = useRef<QueueItem[]>([]);
  const cancelledRef = useRef(false);
  const cancelledItemsRef = useRef<Set<string>>(new Set());
  const runningRef = useRef(false);
  const activeItemIdRef = useRef<string | null>(null);
  const queueItemCounterRef = useRef(0);
  const queueCompleteTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const lastStageSnapshotRef = useRef<Map<string, string>>(new Map());
  const seenRuntimeEventsRef = useRef<Map<string, Set<string>>>(new Map());

  const addLog = useCallback((msg: string) => {
    setLogs((prev) => {
      const next = [...prev, `[${new Date().toLocaleTimeString()}] ${msg}`];
      return next.length > 1000 ? next.slice(next.length - 1000) : next;
    });
  }, []);

  const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

  const updateQueue = useCallback((updater: QueueItem[] | ((prev: QueueItem[]) => QueueItem[])) => {
    const next = typeof updater === 'function' ? updater(queueRef.current) : updater;
    queueRef.current = next;
    setQueue(next);
  }, []);

  const finishQueue = useCallback((status: 'success' | 'failed' | 'cancelled' | false) => {
    activeItemIdRef.current = null;
    runningRef.current = false;
    setIsRunning(false);
    setMinimized(false);

    if (queueCompleteTimeoutRef.current) {
      clearTimeout(queueCompleteTimeoutRef.current);
      queueCompleteTimeoutRef.current = null;
    }

    if (status !== false) {
      updateQueue([]);
      setQueueComplete(status);
      addLog(`Queue complete: ${status}`);
      queueCompleteTimeoutRef.current = setTimeout(() => setQueueComplete(null), 4000);
    }
  }, [addLog, updateQueue]);

  const buildQueueItems = useCallback((targets: string[], profile: string): QueueItem[] => {
    return targets.map((target) => {
      queueItemCounterRef.current += 1;
      const id = `queue-item-${queueItemCounterRef.current}`;
      return {
        id,
        target,
        profile,
        status: 'queued',
        scanId: `pending-${id}`,
        progress: 0,
        currentPhase: '',
        etaRemainingSeconds: null,
        etaLowerSeconds: null,
        etaUpperSeconds: null,
      };
    });
  }, []);

  const processNext = useCallback(() => {
    if (cancelledRef.current || activeItemIdRef.current) return;

    const nextItem = queueRef.current.find((item) => item.status === 'queued');
    if (!nextItem) {
      if (runningRef.current) {
        finishQueue(true);
      }
      return;
    }

    activeItemIdRef.current = nextItem.id;
    updateQueue((prev) => prev.map((item) => (
      item.id === nextItem.id
        ? { ...item, status: 'scanning', currentPhase: phases[0], progress: 0 }
        : item
    )));
    addLog(`Starting scan: ${nextItem.target}`);

    void (async () => {
      let scanId = nextItem.scanId;

      try {
        const { scan_id } = await api.createScan(nextItem.target, {
          scan_profile: nextItem.profile,
          initiated_by: 'frontend_scan_queue',
        });
        scanId = scan_id;

        if (cancelledRef.current || cancelledItemsRef.current.has(nextItem.id)) {
          return;
        }

        updateQueue((prev) => prev.map((item) => (
          item.id === nextItem.id
            ? { ...item, scanId: scan_id }
            : item
        )));
        seenRuntimeEventsRef.current.set(scan_id, new Set());
        addLog(`Scan created: ${scanId}`);

        let done = false;
        while (!done && !cancelledRef.current && !cancelledItemsRef.current.has(nextItem.id)) {
          await sleep(3000);
          if (cancelledRef.current || cancelledItemsRef.current.has(nextItem.id)) break;

          try {
            const status = await api.getScanStatus(scanId);
            const phase = mapStageToPhase((status as any).stage ?? (status as any).current_stage);
            const prog = phaseProgress(phase);

            updateQueue((prev) => prev.map((item) => (
              item.id === nextItem.id
                ? {
                  ...item,
                  currentPhase: phase,
                  progress: prog,
                  etaRemainingSeconds: status.estimated_remaining_seconds ?? null,
                  etaLowerSeconds: status.estimated_remaining_lower_seconds ?? null,
                  etaUpperSeconds: status.estimated_remaining_upper_seconds ?? null,
                }
                : item
            )));

            const etaLabel = formatEtaLabel(
              status.estimated_remaining_lower_seconds ?? null,
              status.estimated_remaining_upper_seconds ?? null,
            );
            const detail = status.stage_detail ?? nextItem.target;
            const stageName = stageDisplayName(status.stage);
            const assetsDiscovered = status.progress?.assets_discovered ?? 0;
            const snapshot = `${stageName}|${detail}|${etaLabel ?? 'n/a'}|${assetsDiscovered}`;
            const previous = lastStageSnapshotRef.current.get(scanId);
            if (snapshot !== previous) {
              lastStageSnapshotRef.current.set(scanId, snapshot);
              addLog(
                `${stageName}: ${detail}${etaLabel ? ` (ETA ${etaLabel})` : ''} · assets discovered: ${assetsDiscovered}`,
              );
            }

            const seenKeys = seenRuntimeEventsRef.current.get(scanId) ?? new Set<string>();
            for (const event of status.events ?? []) {
              const kind = (event.kind || 'info').toLowerCase();
              const eventKey = kind === 'error'
                ? `${kind}|${event.message}`
                : `${event.timestamp}|${event.kind}|${event.message}`;
              if (seenKeys.has(eventKey)) continue;
              seenKeys.add(eventKey);
              if (kind === 'degraded' || kind === 'error' || kind === 'success' || kind === 'stage') {
                addLog(`${kind.toUpperCase()}: ${event.message}`);
              }
            }
            seenRuntimeEventsRef.current.set(scanId, seenKeys);

            if (status.status === 'completed') {
              done = true;
              updateQueue((prev) => prev.map((item) => (
                item.id === nextItem.id
                  ? { ...item, status: 'done', progress: 100, currentPhase: 'Complete' }
                  : item
              )));
              setLatestCompletedScanId(scanId);
              addLog(`Scan complete: ${nextItem.target}`);
              lastStageSnapshotRef.current.delete(scanId);
              seenRuntimeEventsRef.current.delete(scanId);

              const assetsFound = status.progress?.assets_discovered ?? 0;
              setNotifications((prev) => [...prev, {
                id: scanId,
                message: `Scan complete: ${nextItem.target} · ${assetsFound} assets found`,
                link: '/dashboard/history',
                timestamp: new Date(),
                scanId,
              }]);
            } else if (status.status === 'failed') {
              done = true;
              updateQueue((prev) => prev.map((item) => (
                item.id === nextItem.id
                  ? { ...item, status: 'failed', currentPhase: 'Failed' }
                  : item
              )));
              addLog(`Scan failed: ${nextItem.target}`);
              lastStageSnapshotRef.current.delete(scanId);
              seenRuntimeEventsRef.current.delete(scanId);
            }
          } catch (pollErr) {
            addLog(`Poll error for ${nextItem.target}: ${pollErr}`);
          }
        }
      } catch (err) {
        if (!cancelledRef.current && !cancelledItemsRef.current.has(nextItem.id)) {
          updateQueue((prev) => prev.map((item) => (
            item.id === nextItem.id
              ? { ...item, status: 'failed', currentPhase: 'Failed' }
              : item
          )));
          addLog(`Failed to start scan for ${nextItem.target}: ${err}`);
        }
      } finally {
        if (cancelledItemsRef.current.has(nextItem.id)) {
          cancelledItemsRef.current.delete(nextItem.id);
        }

        activeItemIdRef.current = null;

        if (cancelledRef.current) {
          finishQueue('cancelled');
          return;
        }

        const hasQueuedItems = queueRef.current.some((item) => item.status === 'queued');
        if (hasQueuedItems) {
          processNext();
          return;
        }

        let overallStatus: 'success' | 'failed' | 'cancelled' = 'success';
        const hasFailed = queueRef.current.some((i) => i.status === 'failed');
        const hasSuccess = queueRef.current.some((i) => i.status === 'done');
        const hasCancelled = queueRef.current.some((i) => i.status === 'cancelled');

        if (hasFailed) overallStatus = 'failed';
        else if (hasCancelled && !hasSuccess) overallStatus = 'cancelled';

        finishQueue(overallStatus);
      }
    })();
  }, [addLog, finishQueue, updateQueue]);

  const startQueue = useCallback((targets: string[], profile: string) => {
    const normalizedTargets = [...new Set(targets.map((target) => target.trim()).filter(Boolean))];
    if (normalizedTargets.length === 0) return;
    const requestedTarget = normalizedTargets[0];
    if (!requestedTarget) return;

    cancelledRef.current = false;
    setScanProfile(profile);
    setQueueComplete(null);

    if (queueCompleteTimeoutRef.current) {
      clearTimeout(queueCompleteTimeoutRef.current);
      queueCompleteTimeoutRef.current = null;
    }

    const activeTargets = new Set(
      queueRef.current
        .filter((item) => item.status === 'queued' || item.status === 'scanning')
        .map((item) => item.target.toLowerCase()),
    );

    if (activeTargets.has(requestedTarget.toLowerCase())) {
      addLog('Requested target is already in the queue');
      return;
    }

    const items = buildQueueItems([requestedTarget], profile);

    if (!runningRef.current) {
      runningRef.current = true;
      setIsRunning(true);
      setLogs([]);
      updateQueue(items);
      addLog(`Scan started (${profile})`);
      processNext();
      return;
    }

    updateQueue((prev) => [...prev, ...items]);
    addLog(`Added scan request for ${requestedTarget}`);
    processNext();
  }, [addLog, buildQueueItems, processNext, updateQueue]);

  const cancelQueue = useCallback(() => {
    cancelledRef.current = true;
    updateQueue((prev) => prev.map((item) => (
      item.status === 'queued' || item.status === 'scanning'
        ? { ...item, status: 'cancelled', currentPhase: 'Cancelled', progress: 0 }
        : item
    )));
    addLog('Queue cancelled');
    finishQueue('cancelled');
  }, [addLog, finishQueue, updateQueue]);

  const removeQueueItem = useCallback((itemId: string) => {
    const targetItem = queueRef.current.find((item) => item.id === itemId);
    if (!targetItem) return;
    if (targetItem.status === 'done' || targetItem.status === 'failed' || targetItem.status === 'cancelled') return;

    updateQueue((prev) => prev.map((item) => (
      item.id === itemId
        ? { ...item, status: 'cancelled', currentPhase: 'Cancelled', progress: 0 }
        : item
    )));

    if (targetItem.status === 'scanning') {
      cancelledItemsRef.current.add(itemId);
      addLog(`Ended scan: ${targetItem.target}`);
      return;
    }

    addLog(`Removed queued target: ${targetItem.target}`);
    processNext();
  }, [addLog, processNext, updateQueue]);

  const toggleMinimize = useCallback(() => setMinimized((value) => !value), []);

  return (
    <ScanQueueContext.Provider
      value={{
        queue,
        isRunning,
        minimized,
        scanProfile,
        notifications,
        logs,
        latestCompletedScanId,
        startQueue,
        cancelQueue,
        removeQueueItem,
        toggleMinimize,
        setMinimized,
        queueComplete,
      }}
    >
      {children}
    </ScanQueueContext.Provider>
  );
};

export const useScanQueue = () => {
  const ctx = useContext(ScanQueueContext);
  if (!ctx) throw new Error('useScanQueue must be used within ScanQueueProvider');
  return ctx;
};
