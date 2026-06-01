import { useState, useEffect, useRef } from 'react';
import { Outlet, useNavigate, useLocation } from 'react-router-dom';
import { useScanContext } from '@/contexts/ScanContext';
import { useScanQueue } from '@/contexts/ScanQueueContext';
import { useSelectedScan } from '@/contexts/SelectedScanContext';
import DashboardTopBar from '@/components/dashboard/DashboardTopBar';
import DashboardSidebar from '@/components/dashboard/DashboardSidebar';
import GlassTabBar from '@/components/dashboard/GlassTabBar';
import CommandPalette from '@/components/dashboard/CommandPalette';
import PageNavButtons from '@/components/dashboard/PageNavButtons';
import OnboardingWizard from '@/components/dashboard/OnboardingWizard';
import { AnimatePresence, motion } from 'framer-motion';
import { Button } from '@/components/ui/button';
import { Progress } from '@/components/ui/progress';
import { X, Maximize2, Minimize2, CheckCircle2, Loader2, Clock, XCircle, StopCircle } from 'lucide-react';
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription } from '@/components/ui/dialog';
import { cn } from '@/lib/utils';

function formatEtaRange(lowerSeconds: number | null, upperSeconds: number | null): string | null {
  if (lowerSeconds === null && upperSeconds === null) return null;
  const lower = Math.max(0, Math.round((lowerSeconds ?? upperSeconds ?? 0) / 60));
  const upper = Math.max(lower, Math.round((upperSeconds ?? lowerSeconds ?? 0) / 60));

  if (upper <= 1) return 'ETA < 1 min';
  if (lower === upper) return `ETA ~${upper} min`;
  return `ETA ${lower}-${upper} min`;
}

const DashboardLayout = () => {
  const navigate = useNavigate();
  const location = useLocation();
  const { setScannedDomain } = useScanContext();
  const { queue, isRunning, minimized, setMinimized, toggleMinimize, cancelQueue, removeQueueItem, logs, queueComplete, latestCompletedScanId } = useScanQueue();
  const { setSelectedScanId } = useSelectedScan();
  const [cancelConfirm, setCancelConfirm] = useState(false);
  const lastSyncedCompletedScanId = useRef<string | null>(null);

  const pathname = location.pathname;

  const getActiveNav = () => {
    if (pathname === '/scanner') return 'scanner';
    if (pathname.includes('/discovery')) return 'discovery';
    if (pathname.includes('/inventory')) return 'discovery';
    if (pathname.includes('/cbom')) return 'cbom';
    if (pathname.includes('/pqc')) return 'pqc';
    if (pathname.includes('/rating')) return 'rating';
    if (pathname.includes('/remediation')) return 'remediation';
    if (pathname.includes('/reporting')) return 'reporting';
    if (pathname.includes('/system-health')) return 'system-health';
    if (pathname.includes('/settings')) return 'settings';
    if (pathname.includes('/history')) return 'history';
    return 'dashboard';
  };

  const handleNavClick = (item: string) => {
    const routeMap: Record<string, string> = {
      'dashboard': '/dashboard',
      'scanner': '/scanner',
      'discovery': '/dashboard/discovery',
      'discovery:domains': '/dashboard/discovery',
      'discovery:inventory': '/dashboard/discovery?tab=inventory',
      'discovery:ip subnets': '/dashboard/discovery?tab=ip',
      'discovery:ssl certificates': '/dashboard/discovery?tab=ssl',
      'discovery:software & services': '/dashboard/discovery?tab=software',
      'discovery:network graph': '/dashboard/discovery?tab=network',
      'discovery:shadow it': '/dashboard/discovery?tab=shadow',
      'inventory': '/dashboard/discovery?tab=inventory',
      'cbom': '/dashboard/cbom',
      'cbom:overview': '/dashboard/cbom',
      'cbom:per-asset': '/dashboard/cbom/per-asset',
      'cbom:export center': '/dashboard/cbom/export',
      'pqc': '/dashboard/pqc/compliance',
      'pqc:compliance': '/dashboard/pqc/compliance',
      'pqc:hndl intel': '/dashboard/pqc/hndl',
      'pqc:quantum debt': '/dashboard/pqc/quantum-debt',
      'rating': '/dashboard/rating/enterprise',
      'rating:q-score overview': '/dashboard/rating/enterprise',
      'rating:per-asset': '/dashboard/rating/per-asset',
      'rating:tier classification': '/dashboard/rating/tiers',
      'remediation': '/dashboard/remediation/action-plan',
      'remediation:action plan': '/dashboard/remediation/action-plan',
      'remediation:patch generator': '/dashboard/remediation/patch',
      'remediation:migration roadmap': '/dashboard/remediation/roadmap',
      'reporting': '/dashboard/reporting/executive',
      'reporting:executive reports': '/dashboard/reporting/executive',
      'reporting:scheduled reports': '/dashboard/reporting/scheduled',
      'reporting:on-demand builder': '/dashboard/reporting/on-demand',
      'history': '/dashboard/history',
      'system-health': '/dashboard/system-health',
      'settings': '/dashboard/settings/scan-config',
    };
    const route = routeMap[item] || '/dashboard';
    navigate(route);
  };

  const handleScan = (domain: string) => {
    const trimmedDomain = domain.trim();
    if (!trimmedDomain) return;
    setScannedDomain(trimmedDomain);
    navigate('/scanner', {
      state: {
        target: trimmedDomain,
        autoStart: true,
        profile: 'Quick + Bounded Port Scan + No Enumeration',
      },
    });
  };

  useEffect(() => {
    if (!latestCompletedScanId) return;
    if (lastSyncedCompletedScanId.current === latestCompletedScanId) return;

    lastSyncedCompletedScanId.current = latestCompletedScanId;
    setSelectedScanId(latestCompletedScanId);
  }, [latestCompletedScanId, setSelectedScanId]);

  const resolvedCount = queue.filter((item) => item.status === 'done' || item.status === 'failed' || item.status === 'cancelled').length;
  const scanningItem = queue.find((item) => item.status === 'scanning');
  const overallProgress = queue.length > 0 ? Math.round((resolvedCount / queue.length) * 100) : 0;
  const runningEtaLabel = scanningItem
    ? formatEtaRange(scanningItem.etaLowerSeconds, scanningItem.etaUpperSeconds)
    : null;

  const phases = ['Discovery', 'TLS Probing', 'PQC Classification', 'CBOM Generation', 'Certification'];

  return (
    <div className="flex flex-col min-h-screen bg-background relative">
      <DashboardTopBar hasScanned={pathname !== '/scanner'} />
      <DashboardSidebar activeItem={getActiveNav()} onItemClick={handleNavClick} />
      <CommandPalette />
      <OnboardingWizard />
      <PageNavButtons />

      <div className="flex-1 overflow-y-auto pb-24 ml-[3.05rem]">
        <motion.div key="content" initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.4 }} className="p-5 pt-14">
          <Outlet />
        </motion.div>
      </div>

      <GlassTabBar hasScanned onScan={handleScan} isLoading={false} showScannerPrompt={pathname !== '/dashboard'} />

      {isRunning && !minimized && (
        <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="fixed inset-0 z-[100] bg-background/95 backdrop-blur-sm flex flex-col items-center justify-center p-8">
          <div className="w-full max-w-2xl space-y-6">
            <div className="flex items-center justify-between">
              <h2 className="font-body text-lg font-semibold">
                Scan Running{runningEtaLabel ? ` (ETA ${runningEtaLabel.replace('ETA ', '')})` : ''}
              </h2>
              <Button variant="ghost" size="sm" onClick={toggleMinimize}><Minimize2 className="w-4 h-4" /></Button>
            </div>
            <div className="space-y-2">
              {queue.map((item) => (
                <div key={item.id} className={`p-3 rounded-lg border ${item.status === 'scanning' ? 'border-[hsl(var(--accent-amber))] bg-[hsl(var(--accent-amber)/0.05)]' : 'border-border'}`}>
                  <div className="flex items-center gap-3">
                    {item.status === 'queued' && <Clock className="w-4 h-4 text-muted-foreground" />}
                    {item.status === 'scanning' && <Loader2 className="w-4 h-4 text-[hsl(var(--accent-amber))] animate-spin" />}
                    {item.status === 'done' && <CheckCircle2 className="w-4 h-4 text-[hsl(var(--status-safe))]" />}
                    {item.status === 'failed' && <XCircle className="w-4 h-4 text-[hsl(var(--status-critical))]" />}
                    {item.status === 'cancelled' && <StopCircle className="w-4 h-4 text-muted-foreground" />}
                    <span className="font-mono text-sm flex-1">{item.target}</span>
                    <span className="text-[10px] font-mono text-muted-foreground capitalize">{item.status}</span>
                    {(item.status === 'queued' || item.status === 'scanning') && (
                      <Button
                        variant="ghost"
                        size="sm"
                        className="h-7 px-2 text-[10px] text-muted-foreground hover:text-[hsl(var(--status-critical))]"
                        onClick={() => removeQueueItem(item.id)}
                      >
                        End
                      </Button>
                    )}
                  </div>
                  {item.status === 'scanning' && (
                    <div className="mt-3 space-y-2">
                      <div className="flex gap-1">
                        {phases.map((phase, phaseIndex) => (
                          <div key={phase} className={`flex-1 h-1.5 rounded-full ${phases.indexOf(item.currentPhase) >= phaseIndex ? 'bg-[hsl(var(--accent-amber))]' : 'bg-[hsl(var(--bg-sunken))]'}`} />
                        ))}
                      </div>
                      <p className="text-[10px] font-mono text-muted-foreground">{item.currentPhase}</p>
                    </div>
                  )}
                </div>
              ))}
            </div>
            <div className="bg-[hsl(var(--bg-sunken))] rounded-lg p-3 max-h-72 overflow-y-auto">
              <p className="text-[10px] font-mono text-muted-foreground uppercase mb-2">Live Log</p>
              {logs.map((line, index) => (
                <p key={index} className="text-[10px] font-mono text-foreground/80">{line}</p>
              ))}
            </div>
          </div>
        </motion.div>
      )}

      {isRunning && minimized && (
        <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} className="fixed bottom-24 right-6 z-[9999] bg-popover border border-border rounded-xl shadow-lg p-3 min-w-[280px]">
          <div className="flex items-center gap-2 mb-2">
            <Loader2 className="w-3.5 h-3.5 text-[hsl(var(--accent-amber))] animate-spin" />
            <span className="text-xs font-body">
              Scanning {scanningItem?.target} - {scanningItem?.currentPhase}...
              {scanningItem ? ` ${formatEtaRange(scanningItem.etaLowerSeconds, scanningItem.etaUpperSeconds) ?? ''}` : ''}
            </span>
            <div className="flex-1" />
            <button onClick={toggleMinimize} className="p-0.5"><Maximize2 className="w-3 h-3 text-muted-foreground" /></button>
            <button onClick={() => setCancelConfirm(true)} className="p-0.5"><X className="w-3 h-3 text-muted-foreground" /></button>
          </div>
          <Progress value={overallProgress} className="h-1.5" />
        </motion.div>
      )}

      {queueComplete && (
        <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0 }} className={cn(
          "fixed bottom-24 right-6 z-[90] border rounded-xl p-3",
          queueComplete === 'success' ? "bg-[hsl(var(--status-safe)/0.1)] border-[hsl(var(--status-safe)/0.3)]" :
          queueComplete === 'failed' ? "bg-[hsl(var(--status-critical)/0.1)] border-[hsl(var(--status-critical)/0.3)]" :
          "bg-[hsl(var(--border-default)/0.5)] border-[hsl(var(--border-strong))]"
        )}>
          <div className="flex items-center gap-2">
            {queueComplete === 'success' && <CheckCircle2 className="w-4 h-4 text-[hsl(var(--status-safe))]" />}
            {queueComplete === 'failed' && <XCircle className="w-4 h-4 text-[hsl(var(--status-critical))]" />}
            {queueComplete === 'cancelled' && <StopCircle className="w-4 h-4 text-muted-foreground" />}
            
            <span className={cn(
              "text-xs font-body font-semibold",
              queueComplete === 'success' ? "text-[hsl(var(--status-safe))]" :
              queueComplete === 'failed' ? "text-[hsl(var(--status-critical))]" :
              "text-muted-foreground"
            )}>
              {queueComplete === 'success' ? 'Scan Queue Complete' :
               queueComplete === 'failed' ? 'Scan Queue Failed' :
               'Scan Queue Cancelled'}
            </span>
          </div>
        </motion.div>
      )}

      <Dialog open={cancelConfirm} onOpenChange={setCancelConfirm}>
        <DialogContent className="max-w-sm">
          <DialogHeader>
            <DialogTitle className="font-body">Cancel Scan Queue?</DialogTitle>
            <DialogDescription className="text-xs">This will stop all remaining scans. Completed scans will be preserved.</DialogDescription>
          </DialogHeader>
          <div className="flex gap-2 justify-end">
            <Button variant="outline" size="sm" onClick={() => setCancelConfirm(false)}>Keep Running</Button>
            <Button variant="destructive" size="sm" onClick={() => { cancelQueue(); setCancelConfirm(false); }}>Cancel Queue</Button>
          </div>
        </DialogContent>
      </Dialog>
    </div>
  );
};

export default DashboardLayout;
