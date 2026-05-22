import { useEffect, useRef, useState } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import { AlertTriangle, CheckCircle2 } from 'lucide-react';
import { useScanContext } from '@/contexts/ScanContext';
import { useScanQueue } from '@/contexts/ScanQueueContext';
import { useSelectedScan } from '@/contexts/SelectedScanContext';
import RainingLetters from '@/components/ui/raining-letters';
import { GradientText } from '@/components/ui/gradient-text';
import { Button } from '@/components/ui/button';
import { cn } from '@/lib/utils';

const scanProfiles = [
  {
    key: 'Quick',
    title: 'Quick Scan',
    tagline: 'Lightning Fast',
    description: 'Results in 10-30 seconds. Scans standard ports (HTTP, HTTPS) for the exact domain you entered without aggressive subdomain hunting.',
    features: ['Bounded port scan', 'Exact domain only', 'Core TLS posture'],
  },
  {
    key: 'Deep',
    title: 'Deep Scan',
    tagline: 'Comprehensive',
    description: 'Heavy-duty discovery. Runs a full port scan (1-65535) and aggressively hunts for subdomains.',
    features: ['All 65,535 TCP ports', 'Full subdomain brute-force', 'Expanded attack surface'],
  },
] as const;


const Scanner = () => {
  const [targetInput, setTargetInput] = useState('');
  const [scanProfile, setScanProfile] = useState<string>('Quick');
  const startedFromScannerRef = useRef(false);
  const lastRedirectedScanIdRef = useRef<string | null>(null);

  const navigate = useNavigate();
  const location = useLocation();
  const { setScannedDomain } = useScanContext();
  const { startQueue, latestCompletedScanId, isRunning } = useScanQueue();
  const { setSelectedScanId } = useSelectedScan();
  const autoLaunchHandledRef = useRef(false);

  const startSingleTargetScan = () => {
    const target = targetInput.trim();
    if (!target) return;

    startedFromScannerRef.current = true;
    setScannedDomain(target);
    startQueue([target], scanProfile);
  };

  useEffect(() => {
    const state = location.state as { target?: string; autoStart?: boolean; profile?: string } | null;
    if (!state?.target) return;

    const incomingTarget = state.target.trim();
    if (!incomingTarget) return;

    setTargetInput(incomingTarget);
    const validProfile = state.profile && scanProfiles.some(p => p.key === state.profile) ? state.profile : 'Quick';
    setScanProfile(validProfile);

    if (!state.autoStart || autoLaunchHandledRef.current || isRunning) return;

    autoLaunchHandledRef.current = true;
    startedFromScannerRef.current = true;
    setScannedDomain(incomingTarget);
    startQueue([incomingTarget], validProfile);
    navigate(location.pathname, { replace: true, state: null });
  }, [isRunning, location.pathname, location.state, navigate, setScannedDomain, startQueue]);

  useEffect(() => {
    if (!startedFromScannerRef.current) return;
    if (isRunning) return;
    if (!latestCompletedScanId) return;
    if (lastRedirectedScanIdRef.current === latestCompletedScanId) return;

    lastRedirectedScanIdRef.current = latestCompletedScanId;
    startedFromScannerRef.current = false;
    setSelectedScanId(latestCompletedScanId);
    navigate('/dashboard', { state: { bypassPrompt: true } });
  }, [isRunning, latestCompletedScanId, navigate, setSelectedScanId]);

  const handleInputKeyDown = (event: React.KeyboardEvent<HTMLInputElement>) => {
    if (event.key === 'Enter') {
      event.preventDefault();
      startSingleTargetScan();
    }
  };

  return (
    <div className="relative flex flex-col items-center justify-center min-h-[calc(100vh-8.5rem)] px-4 md:px-6 pb-8">
      <RainingLetters />
      <div className="relative z-10 w-full max-w-6xl">
        <div className="text-center mb-7 bg-background/85 backdrop-blur-sm px-6 py-4 rounded-xl">
          <GradientText as="h1" className="font-body font-bold text-3xl lg:text-5xl mb-4 tracking-tight">Quantum Readiness Scanner</GradientText>
          <p className="font-body text-base text-muted-foreground max-w-3xl mx-auto">
            Enter one domain and choose how broad the discovery should be. Profiles dictate the scan depth and analysis behavior natively.
          </p>
        </div>

        <div className="w-full rounded-xl border border-[hsl(var(--border-default))] bg-background/80 backdrop-blur-md px-3 py-2.5 focus-within:ring-2 focus-within:ring-[hsl(var(--accent-amber))] transition-shadow mb-3">
          <input
            value={targetInput}
            onChange={(event) => setTargetInput(event.target.value)}
            onKeyDown={handleInputKeyDown}
            placeholder="Enter a single target domain (e.g. example.com)"
            className="w-full bg-transparent font-mono text-sm text-foreground placeholder:text-muted-foreground outline-none py-1"
          />
        </div>


        {/* 3 Clean Modes Selection */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-6">
          {scanProfiles.map((profile) => {
            const isSelected = scanProfile === profile.key;
            return (
              <div
                key={profile.key}
                onClick={() => setScanProfile(profile.key)}
                className={cn(
                  "relative flex flex-col rounded-xl border p-4 cursor-pointer transition-all duration-200",
                  isSelected
                    ? "border-[hsl(var(--brand-primary))] bg-[hsl(var(--brand-primary)/0.08)] backdrop-blur-md shadow-sm"
                    : "border-[hsl(var(--border-default))] bg-[hsl(var(--bg-sunken)/0.7)] backdrop-blur-md hover:border-[hsl(var(--border-strong))]"
                )}
              >
                <div className="flex justify-between items-start mb-2">
                  <div>
                    <h3 className={cn("text-sm font-semibold font-body", isSelected ? "text-[hsl(var(--brand-primary))]" : "text-foreground")}>
                      {profile.title}
                    </h3>
                    <p className="text-[10px] uppercase font-bold tracking-wider text-muted-foreground mt-0.5">{profile.tagline}</p>
                  </div>
                  <div className={cn("w-4 h-4 rounded-full border flex items-center justify-center transition-colors", isSelected ? "border-[hsl(var(--brand-primary))] bg-[hsl(var(--brand-primary))]" : "border-muted-foreground/30")}>
                    {isSelected && <div className="w-1.5 h-1.5 rounded-full bg-white" />}
                  </div>
                </div>
                <p className="text-xs font-body text-muted-foreground mb-4 flex-grow">
                  {profile.description}
                </p>
                <ul className="space-y-1.5 mt-auto">
                  {profile.features.map(feature => (
                    <li key={feature} className="flex items-center gap-2 text-[11px] font-body text-muted-foreground">
                      <CheckCircle2 className={cn("w-3 h-3", isSelected ? "text-[hsl(var(--brand-primary))]" : "text-muted-foreground/50")} />
                      {feature}
                    </li>
                  ))}
                </ul>
              </div>
            );
          })}
        </div>

        <div className="flex items-start gap-2 rounded-lg border border-[hsl(var(--status-warn)/0.35)] bg-[hsl(var(--status-warn)/0.1)] px-3 py-2.5 mb-5">
          <AlertTriangle className="w-4 h-4 text-[hsl(var(--status-warn))] mt-0.5 flex-shrink-0" />
          <p className="text-xs font-body text-[hsl(var(--status-warn))]">
            Scans can take time depending on host responsiveness and DNS complexity. Deep scans will run significantly longer due to full port enumeration.
          </p>
        </div>

        <Button onClick={startSingleTargetScan} className="w-full text-sm" disabled={!targetInput.trim()}>
          Start Scan
        </Button>
      </div>
    </div>
  );
};

export default Scanner;
