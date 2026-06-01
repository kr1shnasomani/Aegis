/**
 * AssetDiscovery.tsx — Page shell
 *
 * Owns: routing state, data fetching, memoised derivations, panel state.
 * Delegates: all rendering to AssetTabContent; all data transforms to assetDiscoveryUtils.
 */

import { useMemo, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { cn } from '@/lib/utils';
import { useScanContext } from '@/contexts/ScanContext';
import { useSelectedScan } from '@/contexts/SelectedScanContext';
import { api } from '@/lib/api';
import { adaptScanHistory, adaptScanResults } from '@/lib/adapters';
import DataContextBadge from '@/components/dashboard/DataContextBadge';
import { Globe, Key, Server, Cpu, Share2, AlertTriangle, Search, Filter, Package } from 'lucide-react';
import { Input } from '@/components/ui/input';
import { Button } from '@/components/ui/button';
import {
  domainRecords as demoDomainRecords,
  ipRecords as demoIpRecords,
  softwareRecords as demoSoftwareRecords,
  shadowITAlerts as demoShadowITAlerts,
  assets as demoAssets,
} from '@/data/demoData';
import type { DomainRecord, IPRecord, SoftwareRecord, Asset } from '@/data/demoData';
import AssetTabContent from '@/components/AssetDiscovery/AssetTabContent';
import {
  toObservedAssets,
  toObservedDnsRecords,
  latestAssets,
  buildDomainRecords,
  buildIPRecords,
  buildSoftwareRecords,
  buildShadowAlerts,
  hasCertificateDetails,
  includesSearch,
  MAX_ALL_TIME_SCANS,
  type ObservedAsset,
  type DiscoveryQueryResult,
} from '@/components/AssetDiscovery/assetDiscoveryUtils';

// ── Tab definitions ───────────────────────────────────────────────────────────

const tabDefs = [
  { id: 'domains', label: 'Domains', icon: Globe },
  { id: 'inventory', label: 'Asset Inventory', icon: Package },
  { id: 'ssl', label: 'SSL Certificates', icon: Key },
  { id: 'ip', label: 'IP / Subnets', icon: Server },
  { id: 'software', label: 'Software & Services', icon: Cpu },
  { id: 'network', label: 'Network Graph', icon: Share2 },
  { id: 'shadow', label: 'Shadow IT', icon: AlertTriangle },
];

type ScopeMode = 'this-scan' | 'all-time';

// ── Page component ────────────────────────────────────────────────────────────

const AssetDiscovery = () => {
  const [searchParams, setSearchParams] = useSearchParams();
  const activeTab = searchParams.get('tab') || 'domains';
  const [search, setSearch] = useState('');
  const { rootDomain } = useScanContext();
  const {
    selectedAssets,
    selectedScanId,
    selectedScan,
    selectedScanResults,
    selectedAssetResults,
    selectedDnsRecords,
    isLoading: selectedScanLoading,
  } = useSelectedScan();
  const d = rootDomain || 'target.com';
  const [scopeMode, setScopeMode] = useState<ScopeMode>('this-scan');
  const [panelOpen, setPanelOpen] = useState(false);
  const [panelType, setPanelType] = useState<'domain' | 'ssl' | 'ip' | 'software'>('domain');
  const [selectedDomain, setSelectedDomain] = useState<DomainRecord | undefined>();
  const [selectedAssetForPanel, setSelectedAssetForPanel] = useState<Asset | undefined>();
  const [selectedIP, setSelectedIP] = useState<IPRecord | undefined>();
  const [selectedSoftware, setSelectedSoftware] = useState<SoftwareRecord | undefined>();

  // ── All-time data query ─────────────────────────────────────────────────────

  const { data: discoveryData, isLoading: allTimeLoading } = useQuery<DiscoveryQueryResult>({
    queryKey: ['asset-discovery-all-time', scopeMode],
    enabled: scopeMode === 'all-time',
    queryFn: async () => {
      const historyResponse = await api.getScanHistory({ limit: 400 });
      const adaptedHistory = adaptScanHistory(historyResponse);
      const completedItems = historyResponse.items.filter(
        (item) => item.status.toLowerCase() === 'completed',
      );
      const cappedCompletedItems = completedItems.slice(0, MAX_ALL_TIME_SCANS);

      const settledResults = await Promise.allSettled(cappedCompletedItems.map(async (item) => {
        const result = await api.getScanResults(item.scan_id);
        const observedAt = result.completed_at ?? result.created_at;
        return {
          scanId: item.scan_id,
          target: item.target,
          observedAt,
          assets: adaptScanResults(result),
          rawAssets: result.assets,
          dnsRecords: result.dns_records,
        };
      }));

      const successfulResults = settledResults.flatMap((result) => (
        result.status === 'fulfilled' ? [result.value] : []
      ));

      return {
        history: adaptedHistory,
        completedHistory: adaptScanHistory({ items: completedItems }),
        totalCompletedScanCount: completedItems.length,
        loadedCompletedScanCount: successfulResults.length,
        observedAssets: successfulResults.flatMap((result) => toObservedAssets(
          result.assets, result.scanId, result.target, result.rawAssets, result.observedAt,
        )),
        observedDnsRecords: successfulResults.flatMap((result) => toObservedDnsRecords(
          result.dnsRecords, result.scanId, result.target, result.observedAt,
        )),
      };
    },
    staleTime: 30000,
  });

  // ── Derived observations ────────────────────────────────────────────────────

  const selectedHistoryEntry = useMemo(
    () => discoveryData?.history.find((entry) => entry.id === selectedScanId) ?? selectedScan,
    [discoveryData, selectedScan, selectedScanId],
  );

  const selectedObservedAt = selectedScanResults?.completed_at ?? selectedScanResults?.created_at ?? null;

  const currentObservedAssets = useMemo(
    () => toObservedAssets(
      selectedAssets, selectedScanId,
      selectedHistoryEntry?.target ?? d,
      selectedAssetResults, selectedObservedAt,
    ),
    [selectedAssets, selectedScanId, selectedHistoryEntry, d, selectedAssetResults, selectedObservedAt],
  );

  const currentObservedDnsRecords = useMemo(
    () => selectedObservedAt
      ? toObservedDnsRecords(selectedDnsRecords, selectedScanId, selectedHistoryEntry?.target ?? d, selectedObservedAt)
      : [],
    [selectedDnsRecords, selectedScanId, selectedHistoryEntry, d, selectedObservedAt],
  );

  const allTimeObservedAssets = discoveryData?.observedAssets ?? [];
  const allTimeObservedDnsRecords = discoveryData?.observedDnsRecords ?? [];
  const totalCompletedScanCount = discoveryData?.totalCompletedScanCount ?? 0;
  const loadedCompletedScanCount = discoveryData?.loadedCompletedScanCount ?? 0;
  const liveAllTimeAvailable = loadedCompletedScanCount > 0
    || allTimeObservedAssets.length > 0
    || allTimeObservedDnsRecords.length > 0;

  const activeObservedAssets: ObservedAsset[] = scopeMode === 'this-scan'
    ? currentObservedAssets
    : liveAllTimeAvailable ? allTimeObservedAssets : [];

  const activeObservedDnsRecords = scopeMode === 'this-scan'
    ? currentObservedDnsRecords
    : liveAllTimeAvailable ? allTimeObservedDnsRecords : [];

  const scopedSslAssets = useMemo(
    () => (scopeMode === 'this-scan'
      ? selectedAssets
      : liveAllTimeAvailable ? latestAssets(allTimeObservedAssets) : demoAssets),
    [scopeMode, selectedAssets, liveAllTimeAvailable, allTimeObservedAssets],
  );

  // ── Record builders ─────────────────────────────────────────────────────────

  const domainData = useMemo(
    () => (scopeMode === 'this-scan'
      ? buildDomainRecords(currentObservedAssets, currentObservedDnsRecords)
      : liveAllTimeAvailable
        ? buildDomainRecords(allTimeObservedAssets, allTimeObservedDnsRecords)
        : demoDomainRecords),
    [scopeMode, currentObservedAssets, currentObservedDnsRecords, liveAllTimeAvailable, allTimeObservedAssets, allTimeObservedDnsRecords],
  );

  const ipData = useMemo(
    () => (scopeMode === 'this-scan'
      ? buildIPRecords(currentObservedAssets)
      : liveAllTimeAvailable ? buildIPRecords(allTimeObservedAssets) : demoIpRecords),
    [scopeMode, currentObservedAssets, liveAllTimeAvailable, allTimeObservedAssets],
  );

  const softwareData = useMemo(
    () => (scopeMode === 'this-scan'
      ? buildSoftwareRecords(currentObservedAssets)
      : liveAllTimeAvailable ? buildSoftwareRecords(allTimeObservedAssets) : demoSoftwareRecords),
    [scopeMode, currentObservedAssets, liveAllTimeAvailable, allTimeObservedAssets],
  );

  const shadowData = useMemo(
    () => (scopeMode === 'this-scan'
      ? buildShadowAlerts(currentObservedAssets)
      : liveAllTimeAvailable ? buildShadowAlerts(allTimeObservedAssets) : demoShadowITAlerts),
    [scopeMode, currentObservedAssets, liveAllTimeAvailable, allTimeObservedAssets],
  );

  // ── Filtered records ────────────────────────────────────────────────────────

  const filteredDomains = domainData.filter((r) =>
    includesSearch([r.domain, r.registrar, r.company, r.status, r.detectionDate], search));

  const filteredSslAssets = scopedSslAssets
    .filter((a) => hasCertificateDetails(a))
    .filter((a) => includesSearch([a.domain, a.certInfo.subject_cn, a.certInfo.certificate_authority, a.certInfo.signature_algorithm, a.certInfo.key_type, a.tls, a.cipher], search));

  const filteredInventoryAssets = scopedSslAssets
    .filter((a) => includesSearch([a.domain, a.ip, a.type, a.businessCriticality, a.tls, a.cipher, a.keyExchange, a.complianceTier], search));

  const filteredIPs = ipData.filter((r) =>
    includesSearch([r.ip, r.subnet, r.asn, r.city, r.reverseDns, r.risk], search));

  const filteredSoftware = softwareData.filter((r) =>
    includesSearch([r.product, r.version, r.type, r.hostname, r.eolStatus], search));

  const filteredShadow = shadowData.filter((r) =>
    includesSearch([r.asset, r.assetType, r.howDiscovered, r.riskLevel], search));

  // ── Derived stats ───────────────────────────────────────────────────────────

  const highRiskDomains = domainData.filter((r) => r.riskScore >= 75).length;
  const newDomains = domainData.filter((r) => r.status === 'new').length;
  const lowerRiskDomains = domainData.filter((r) => r.riskScore < 25).length;
  const criticalIP = ipData.find((r) => r.risk === 'critical') ?? ipData[0];
  const nonStandardPortIPs = ipData.filter((r) => r.portsOpen.some((p) => ![80, 443].includes(p))).length;

  // ── Panel selection state ───────────────────────────────────────────────────

  const selectedDomainDnsEntries = useMemo(
    () => selectedDomain
      ? activeObservedDnsRecords.filter((item) => item.record.hostname === selectedDomain.domain).map((item) => item.record)
      : [],
    [selectedDomain, activeObservedDnsRecords],
  );

  const selectedIpAssetResults = useMemo(
    () => selectedIP
      ? activeObservedAssets.filter((item) => item.asset.ip === selectedIP.ip).map((item) => item.rawAsset).filter((item): item is NonNullable<typeof item> => item !== null)
      : [],
    [selectedIP, activeObservedAssets],
  );

  const selectedSoftwareAssetResults = useMemo(
    () => selectedSoftware
      ? activeObservedAssets
          .filter((item) => item.asset.domain === selectedSoftware.hostname && item.asset.port === selectedSoftware.port && ((item.rawAsset?.server_software ?? item.asset.software?.product ?? '') === selectedSoftware.product))
          .map((item) => item.rawAsset)
          .filter((item): item is NonNullable<typeof item> => item !== null)
      : [],
    [selectedSoftware, activeObservedAssets],
  );

  const panelAssetResults = panelType === 'ip'
    ? selectedIpAssetResults
    : panelType === 'software' ? selectedSoftwareAssetResults : [];

  const countMap: Record<string, number> = {
    domains: filteredDomains.length,
    inventory: filteredInventoryAssets.length,
    ssl: filteredSslAssets.length,
    ip: filteredIPs.length,
    software: filteredSoftware.length,
    network: 0,
    shadow: filteredShadow.length,
  };

  const setTab = (tab: string) => setSearchParams({ tab });

  // ── Render ─────────────────────────────────────────────────────────────────

  return (
    <div className="space-y-5">
      <DataContextBadge />
      <div>
        <h1 className="font-display text-2xl italic text-brand-primary">Asset Discovery</h1>
        <p className="text-xs font-body text-muted-foreground mt-0.5">
          Unified reconnaissance surface for domains, inventory, certificates, network exposure, and shadow assets.
        </p>
      </div>

      {/* Scope toggle */}
      <div className="flex items-center gap-2">
        <div className="flex gap-0 p-0.5 rounded-lg bg-[hsl(var(--bg-sunken))] border border-border w-fit">
          <button
            onClick={() => setScopeMode('this-scan')}
            className={cn("px-3 py-1.5 rounded-md text-xs font-body transition-all", scopeMode === 'this-scan' ? "bg-white shadow-sm text-brand-primary font-semibold" : "text-muted-foreground hover:text-foreground")}
          >📡 This Scan</button>
          <button
            onClick={() => setScopeMode('all-time')}
            className={cn("px-3 py-1.5 rounded-md text-xs font-body transition-all", scopeMode === 'all-time' ? "bg-white shadow-sm text-brand-primary font-semibold" : "text-muted-foreground hover:text-foreground")}
          >🕐 All Time</button>
        </div>
      </div>

      {scopeMode === 'this-scan' && (
        <p className="text-[11px] font-body text-muted-foreground">
          Showing results from <span className="font-mono font-semibold text-foreground">{selectedScanId}</span>
          {selectedHistoryEntry ? <> · {selectedHistoryEntry.target}</> : null}
          {' '}· <button onClick={() => setScopeMode('all-time')} className="text-brand-primary hover:underline">Switch to All Time</button> for full history.
          {selectedScanLoading && <span className="ml-2">Loading selected scan data...</span>}
        </p>
      )}

      {scopeMode === 'all-time' && (
        <p className="text-[11px] font-body text-muted-foreground">
          {allTimeLoading
            ? 'Loading aggregated discovery history across all scans...'
            : liveAllTimeAvailable
              ? loadedCompletedScanCount < totalCompletedScanCount
                ? `Showing aggregated discovery across ${loadedCompletedScanCount} of ${totalCompletedScanCount} completed scans.`
                : `Showing aggregated discovery across ${loadedCompletedScanCount} completed scans.`
              : 'Live discovery history is unavailable, so this view is using the local demo fallback.'}
        </p>
      )}

      {/* Tab strip + search */}
      <div className="flex items-center justify-between">
        <div className="flex gap-1 p-1 rounded-xl bg-[hsl(var(--bg-sunken))] w-fit">
          {tabDefs.map(t => {
            const count = countMap[t.id];
            return (
              <button key={t.id} onClick={() => setTab(t.id)} className={cn(
                "flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-body transition-all",
                activeTab === t.id ? "bg-white shadow-sm text-brand-primary font-semibold" : "text-muted-foreground hover:text-foreground"
              )}>
                <t.icon className="w-3.5 h-3.5" />{t.label}{count > 0 ? ` (${count})` : ''}
              </button>
            );
          })}
        </div>
        <div className="flex items-center gap-2">
          <div className="relative">
            <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-muted-foreground" />
            <Input value={search} onChange={(e) => setSearch(e.target.value)} placeholder="Search assets..." className="pl-8 h-8 w-56 text-xs" />
          </div>
          <Button variant="outline" size="sm" className="h-8 text-xs gap-1"><Filter className="w-3 h-3" />Filters</Button>
        </div>
      </div>

      {/* Tab content — fully delegated */}
      <AssetTabContent
        activeTab={activeTab}
        scopeMode={scopeMode}
        filteredDomains={filteredDomains}
        filteredInventoryAssets={filteredInventoryAssets}
        filteredSslAssets={filteredSslAssets}
        filteredIPs={filteredIPs}
        filteredSoftware={filteredSoftware}
        filteredShadow={filteredShadow}
        shadowData={shadowData}
        newDomains={newDomains}
        highRiskDomains={highRiskDomains}
        lowerRiskDomains={lowerRiskDomains}
        criticalIP={criticalIP}
        nonStandardPortIPs={nonStandardPortIPs}
        rootDomain={d}
        panelOpen={panelOpen}
        onPanelOpenChange={setPanelOpen}
        panelType={panelType}
        selectedDomain={selectedDomain}
        selectedAssetForPanel={selectedAssetForPanel}
        selectedIP={selectedIP}
        selectedSoftware={selectedSoftware}
        selectedDomainDnsEntries={selectedDomainDnsEntries}
        panelAssetResults={panelAssetResults}
        onDomainClick={(domain) => { setSelectedDomain(domain); setPanelType('domain'); setPanelOpen(true); }}
        onSslClick={(a) => { setSelectedAssetForPanel(a); setPanelType('ssl'); setPanelOpen(true); }}
        onIPClick={(r) => { setSelectedIP(r); setPanelType('ip'); setPanelOpen(true); }}
        onSoftwareClick={(s) => { setSelectedSoftware(s); setPanelType('software'); setPanelOpen(true); }}
      />
    </div>
  );
};

export default AssetDiscovery;
