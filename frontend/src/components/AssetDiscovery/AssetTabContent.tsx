/**
 * AssetTabContent.tsx
 *
 * Renders the content for each tab in the Asset Discovery page.
 * Receives filtered data and callbacks from the parent page — no data
 * fetching happens here; this component is purely presentational.
 */

import { cn } from '@/lib/utils';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import NetworkGraph from '@/components/dashboard/NetworkGraph';
import DiscoveryDetailPanel from '@/components/dashboard/DiscoveryDetailPanel';
import { getStatusColor, getStatusLabel } from '@/data/demoData';
import type { DomainRecord, IPRecord, SoftwareRecord, Asset, ShadowITAlert } from '@/data/demoData';
import type { AssetResultResponse } from '@/lib/api';
import { useNavigate } from 'react-router-dom';
import { normalizeDisplayValue } from './assetDiscoveryUtils';

// ── Risk badge helper ─────────────────────────────────────────────────────────

const riskBadge = (score: number) => {
  if (score >= 75) return <Badge variant="destructive" className="text-[10px]">Critical</Badge>;
  if (score >= 50) return <Badge className="bg-[hsl(var(--status-warn))] text-white text-[10px]">High</Badge>;
  if (score >= 25) return <Badge className="bg-[hsl(var(--accent-amber))] text-white text-[10px]">Medium</Badge>;
  return <Badge className="bg-[hsl(var(--status-safe))] text-white text-[10px]">Low</Badge>;
};

// ── Prop types ────────────────────────────────────────────────────────────────

interface AssetTabContentProps {
  activeTab: string;
  scopeMode: 'this-scan' | 'all-time';

  // Filtered data
  filteredDomains: DomainRecord[];
  filteredInventoryAssets: Asset[];
  filteredSslAssets: Asset[];
  filteredIPs: IPRecord[];
  filteredSoftware: SoftwareRecord[];
  filteredShadow: ShadowITAlert[];
  shadowData: ShadowITAlert[];

  // Derived stats
  newDomains: number;
  highRiskDomains: number;
  lowerRiskDomains: number;
  criticalIP: IPRecord | undefined;
  nonStandardPortIPs: number;
  rootDomain: string;

  // Panel state
  panelOpen: boolean;
  onPanelOpenChange: (open: boolean) => void;
  panelType: 'domain' | 'ssl' | 'ip' | 'software';
  selectedDomain: DomainRecord | undefined;
  selectedAssetForPanel: Asset | undefined;
  selectedIP: IPRecord | undefined;
  selectedSoftware: SoftwareRecord | undefined;
  selectedDomainDnsEntries: import('@/lib/api').DNSRecordResponse[];
  panelAssetResults: AssetResultResponse[];

  // Row-click handlers
  onDomainClick: (d: DomainRecord) => void;
  onSslClick: (a: Asset) => void;
  onIPClick: (r: IPRecord) => void;
  onSoftwareClick: (s: SoftwareRecord) => void;
}

// ── Component ─────────────────────────────────────────────────────────────────

const AssetTabContent = ({
  activeTab,
  scopeMode,
  filteredDomains,
  filteredInventoryAssets,
  filteredSslAssets,
  filteredIPs,
  filteredSoftware,
  filteredShadow,
  shadowData,
  newDomains,
  highRiskDomains,
  lowerRiskDomains,
  criticalIP,
  nonStandardPortIPs,
  rootDomain: d,
  panelOpen,
  onPanelOpenChange,
  panelType,
  selectedDomain,
  selectedAssetForPanel,
  selectedIP,
  selectedSoftware,
  selectedDomainDnsEntries,
  panelAssetResults,
  onDomainClick,
  onSslClick,
  onIPClick,
  onSoftwareClick,
}: AssetTabContentProps) => {
  const navigate = useNavigate();

  return (
    <>
      {/* Domains tab */}
      {activeTab === 'domains' && (
        <div className="grid grid-cols-1 lg:grid-cols-[1fr_280px] gap-5">
          <Card className="shadow-[0_8px_30px_-12px_hsl(var(--brand-primary)/0.15)]">
            <CardContent className="p-0">
              <div className="overflow-x-auto">
                <table className="w-full text-xs font-body">
                  <thead><tr className="border-b border-border bg-[hsl(var(--bg-sunken))]">
                    <th className="text-left px-3 py-2.5 font-medium text-muted-foreground">Detection</th>
                    <th className="text-left px-3 py-2.5 font-medium text-muted-foreground">Domain</th>
                    <th className="text-left px-3 py-2.5 font-medium text-muted-foreground">Registered</th>
                    <th className="text-left px-3 py-2.5 font-medium text-muted-foreground">Expiry</th>
                    <th className="text-left px-3 py-2.5 font-medium text-muted-foreground">Registrar</th>
                    <th className="text-left px-3 py-2.5 font-medium text-muted-foreground">Status</th>
                    <th className="text-left px-3 py-2.5 font-medium text-muted-foreground">Risk</th>
                  </tr></thead>
                  <tbody>
                    {filteredDomains.map((domain, i) => (
                      <tr
                        key={domain.domain}
                        onClick={() => onDomainClick(domain)}
                        className={cn("border-b border-border/50 cursor-pointer hover:bg-[hsl(var(--bg-sunken))] transition-colors", i % 2 === 0 && "bg-[hsl(var(--bg-sunken)/0.3)]")}
                      >
                        <td className="px-3 py-2 font-mono text-muted-foreground">{domain.detectionDate}</td>
                        <td className="px-3 py-2 font-mono font-medium text-foreground">{domain.domain}</td>
                        <td className="px-3 py-2 font-mono text-muted-foreground">{domain.registrationDate}</td>
                        <td className="px-3 py-2 font-mono text-muted-foreground">{domain.expiryDate}</td>
                        <td className="px-3 py-2 text-muted-foreground">{domain.registrar}</td>
                        <td className="px-3 py-2">
                          <Badge variant={domain.status === 'new' ? 'default' : 'secondary'} className="text-[10px]">{domain.status}</Badge>
                        </td>
                        <td className="px-3 py-2">{riskBadge(domain.riskScore)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </CardContent>
          </Card>
          <Card className="shadow-[0_8px_30px_-12px_hsl(var(--brand-primary)/0.15)] h-fit">
            <CardHeader className="pb-2"><CardTitle className="text-sm font-body">Smart Insights</CardTitle></CardHeader>
            <CardContent className="space-y-3 text-xs font-body">
              <div className="p-2.5 rounded-lg bg-[hsl(var(--status-warn)/0.08)] border border-[hsl(var(--status-warn)/0.2)]">
                <p className="font-medium text-[hsl(var(--status-warn))]">{newDomains} newly observed domains</p>
                <p className="text-muted-foreground mt-0.5">Domains seen only once in the current scope may need validation.</p>
              </div>
              <div className="p-2.5 rounded-lg bg-[hsl(var(--status-critical)/0.08)] border border-[hsl(var(--status-critical)/0.2)]">
                <p className="font-medium text-[hsl(var(--status-critical))]">{highRiskDomains} high-risk domains</p>
                <p className="text-muted-foreground mt-0.5">These domains map to the weakest observed cryptographic posture.</p>
              </div>
              <div className="p-2.5 rounded-lg bg-[hsl(var(--status-safe)/0.08)] border border-[hsl(var(--status-safe)/0.2)]">
                <p className="font-medium text-[hsl(var(--status-safe))]">{lowerRiskDomains} lower-risk domains</p>
                <p className="text-muted-foreground mt-0.5">Domains in this bucket currently have the strongest observed posture.</p>
              </div>
            </CardContent>
          </Card>
        </div>
      )}

      {/* Asset Inventory tab */}
      {activeTab === 'inventory' && (
        <Card className="shadow-[0_8px_30px_-12px_hsl(var(--brand-primary)/0.15)]">
          <CardContent className="p-0">
            <div className="overflow-x-auto">
              <table className="w-full text-xs font-body">
                <thead><tr className="border-b border-border bg-[hsl(var(--bg-sunken))]">
                  <th className="text-left px-3 py-2.5 font-medium text-muted-foreground">Asset</th>
                  <th className="text-left px-3 py-2.5 font-medium text-muted-foreground">IP</th>
                  <th className="text-left px-3 py-2.5 font-medium text-muted-foreground">Type</th>
                  <th className="text-left px-3 py-2.5 font-medium text-muted-foreground">Criticality</th>
                  <th className="text-left px-3 py-2.5 font-medium text-muted-foreground">TLS</th>
                  <th className="text-left px-3 py-2.5 font-medium text-muted-foreground">Cipher</th>
                  <th className="text-left px-3 py-2.5 font-medium text-muted-foreground">Key Exchange</th>
                  <th className="text-left px-3 py-2.5 font-medium text-muted-foreground">Status</th>
                  <th className="text-left px-3 py-2.5 font-medium text-muted-foreground">Q-Score</th>
                </tr></thead>
                <tbody>
                  {filteredInventoryAssets.map((asset, index) => (
                    <tr
                      key={`${asset.id}:${asset.port}`}
                      className={cn(
                        'border-b border-border/50 hover:bg-[hsl(var(--bg-sunken))] transition-colors cursor-pointer',
                        index % 2 === 0 && 'bg-[hsl(var(--bg-sunken)/0.3)]',
                      )}
                      onClick={() => navigate(`/dashboard/assets/${asset.domain.replace(/\./g, '-')}?port=${asset.port}`)}
                    >
                      <td className="px-3 py-2 font-mono font-medium text-foreground">{asset.domain}</td>
                      <td className="px-3 py-2 font-mono text-muted-foreground">{asset.ip || 'n/a'}</td>
                      <td className="px-3 py-2"><Badge variant="secondary" className="text-[10px]">{asset.type}</Badge></td>
                      <td className="px-3 py-2"><Badge variant="outline" className="text-[10px]">{asset.businessCriticality.replace('_', ' ')}</Badge></td>
                      <td className="px-3 py-2 font-mono text-muted-foreground">{asset.tls}</td>
                      <td className="px-3 py-2 font-mono text-muted-foreground max-w-[180px] truncate">{asset.cipher}</td>
                      <td className="px-3 py-2 font-mono text-muted-foreground max-w-[180px] truncate">{asset.keyExchange}</td>
                      <td className="px-3 py-2">
                        <span
                          className="text-[10px] font-mono font-semibold px-1.5 py-0.5 rounded"
                          style={{ color: getStatusColor(asset.status), backgroundColor: `${getStatusColor(asset.status)}15` }}
                        >
                          {getStatusLabel(asset.status)}
                        </span>
                      </td>
                      <td className="px-3 py-2 font-mono">{asset.qScore}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </CardContent>
        </Card>
      )}

      {/* SSL Certificates tab */}
      {activeTab === 'ssl' && (
        <Card className="shadow-[0_8px_30px_-12px_hsl(var(--brand-primary)/0.15)]">
          <CardContent className="p-0">
            <div className="overflow-x-auto">
              <table className="w-full text-xs font-body">
                <thead><tr className="border-b border-border bg-[hsl(var(--bg-sunken))]">
                  <th className="text-left px-3 py-2.5 font-medium text-muted-foreground">CN</th>
                  <th className="text-left px-3 py-2.5 font-medium text-muted-foreground">SANs</th>
                  <th className="text-left px-3 py-2.5 font-medium text-muted-foreground">CA</th>
                  <th className="text-left px-3 py-2.5 font-medium text-muted-foreground">Algo</th>
                  <th className="text-left px-3 py-2.5 font-medium text-muted-foreground">Key</th>
                  <th className="text-left px-3 py-2.5 font-medium text-muted-foreground">Valid Until</th>
                  <th className="text-left px-3 py-2.5 font-medium text-muted-foreground">Days Left</th>
                </tr></thead>
                <tbody>
                  {filteredSslAssets.map((a, i) => (
                    <tr
                      key={a.id}
                      onClick={() => onSslClick(a)}
                      className={cn("border-b border-border/50 cursor-pointer hover:bg-[hsl(var(--bg-sunken))] transition-colors", i % 2 === 0 && "bg-[hsl(var(--bg-sunken)/0.3)]")}
                    >
                      <td className="px-3 py-2 font-mono font-medium">{a.certInfo.subject_cn}</td>
                      <td className="px-3 py-2 text-muted-foreground max-w-[120px] truncate">{a.certInfo.subject_alt_names.join(', ') || 'Unavailable'}</td>
                      <td className="px-3 py-2 text-muted-foreground">{normalizeDisplayValue(a.certInfo.certificate_authority)}</td>
                      <td className="px-3 py-2 font-mono">{normalizeDisplayValue(a.certInfo.signature_algorithm).substring(0, 16)}</td>
                      <td className="px-3 py-2 font-mono">{a.certInfo.key_type}-{a.certInfo.key_size || 'PQC'}</td>
                      <td className="px-3 py-2 font-mono text-muted-foreground">{normalizeDisplayValue(a.certInfo.valid_until)}</td>
                      <td className="px-3 py-2">
                        <div className="flex items-center gap-2">
                          <div className="w-16 h-1.5 rounded-full bg-[hsl(var(--bg-sunken))]">
                            <div className="h-full rounded-full" style={{
                              width: `${Math.min(100, Math.max(a.certInfo.days_remaining, 0) / 365 * 100)}%`,
                              backgroundColor: a.certInfo.days_remaining <= 30 ? 'hsl(var(--status-critical))' : a.certInfo.days_remaining <= 90 ? 'hsl(var(--accent-amber))' : 'hsl(var(--status-safe))'
                            }} />
                          </div>
                          <span className={cn("font-mono", a.certInfo.days_remaining <= 30 ? "text-[hsl(var(--status-critical))]" : "text-muted-foreground")}>
                            {a.certInfo.days_remaining < 0 ? 'Expired' : `${a.certInfo.days_remaining}d`}
                          </span>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </CardContent>
        </Card>
      )}

      {/* IP / Subnets tab */}
      {activeTab === 'ip' && (
        <div className="space-y-4">
          <div className="flex gap-3">
            <Card className="flex-1 p-3 shadow-sm"><p className="text-[10px] text-muted-foreground font-body">CRITICAL FINDING</p><p className="text-xs font-body font-medium text-[hsl(var(--status-critical))] mt-1">{criticalIP ? `${criticalIP.ip} - highest observed risk in this scope${criticalIP.reverseDns ? ` (${criticalIP.reverseDns})` : ''}` : `No internet-facing IP findings for ${d}.`}</p></Card>
            <Card className="flex-1 p-3 shadow-sm"><p className="text-[10px] text-muted-foreground font-body">ALERT</p><p className="text-xs font-body font-medium text-[hsl(var(--status-warn))] mt-1">{nonStandardPortIPs > 0 ? `${nonStandardPortIPs} IPs expose non-standard public ports in this scope.` : 'No non-standard public ports observed in this scope.'}</p></Card>
          </div>
          <Card className="shadow-[0_8px_30px_-12px_hsl(var(--brand-primary)/0.15)]">
            <CardContent className="p-0">
              <div className="overflow-x-auto">
                <table className="w-full text-xs font-body">
                  <thead><tr className="border-b border-border bg-[hsl(var(--bg-sunken))]">
                    <th className="text-left px-3 py-2.5 font-medium text-muted-foreground">IP</th>
                    <th className="text-left px-3 py-2.5 font-medium text-muted-foreground">Ports</th>
                    <th className="text-left px-3 py-2.5 font-medium text-muted-foreground">Subnet</th>
                    <th className="text-left px-3 py-2.5 font-medium text-muted-foreground">ASN</th>
                    <th className="text-left px-3 py-2.5 font-medium text-muted-foreground">Location</th>
                    <th className="text-left px-3 py-2.5 font-medium text-muted-foreground">rDNS</th>
                    <th className="text-left px-3 py-2.5 font-medium text-muted-foreground">Risk</th>
                  </tr></thead>
                  <tbody>
                    {filteredIPs.map((r, i) => (
                      <tr
                        key={r.ip}
                        onClick={() => onIPClick(r)}
                        className={cn("border-b border-border/50 cursor-pointer hover:bg-[hsl(var(--bg-sunken))]", i % 2 === 0 && "bg-[hsl(var(--bg-sunken)/0.3)]")}
                      >
                        <td className="px-3 py-2 font-mono font-medium">{r.ip}</td>
                        <td className="px-3 py-2 font-mono text-muted-foreground">{r.portsOpen.join(', ')}</td>
                        <td className="px-3 py-2 font-mono text-muted-foreground">{r.subnet}</td>
                        <td className="px-3 py-2 text-muted-foreground">{r.asn}</td>
                        <td className="px-3 py-2 text-muted-foreground">{r.city}</td>
                        <td className="px-3 py-2 font-mono text-muted-foreground">{r.reverseDns}</td>
                        <td className="px-3 py-2"><Badge variant={r.risk === 'critical' ? 'destructive' : 'secondary'} className="text-[10px]">{r.risk}</Badge></td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </CardContent>
          </Card>
        </div>
      )}

      {/* Software tab */}
      {activeTab === 'software' && (
        <Card className="shadow-[0_8px_30px_-12px_hsl(var(--brand-primary)/0.15)]">
          <CardContent className="p-0">
            <div className="overflow-x-auto">
              <table className="w-full text-xs font-body">
                <thead><tr className="border-b border-border bg-[hsl(var(--bg-sunken))]">
                  <th className="text-left px-3 py-2.5 font-medium text-muted-foreground">Product</th>
                  <th className="text-left px-3 py-2.5 font-medium text-muted-foreground">Version</th>
                  <th className="text-left px-3 py-2.5 font-medium text-muted-foreground">Type</th>
                  <th className="text-left px-3 py-2.5 font-medium text-muted-foreground">Host</th>
                  <th className="text-left px-3 py-2.5 font-medium text-muted-foreground">EOL Status</th>
                  <th className="text-left px-3 py-2.5 font-medium text-muted-foreground">CVEs</th>
                  <th className="text-left px-3 py-2.5 font-medium text-muted-foreground">PQC</th>
                </tr></thead>
                <tbody>
                  {filteredSoftware.map((s, i) => (
                    <tr
                      key={`${s.product}-${s.hostIp}`}
                      onClick={() => onSoftwareClick(s)}
                      className={cn("border-b border-border/50 cursor-pointer hover:bg-[hsl(var(--bg-sunken))]", i % 2 === 0 && "bg-[hsl(var(--bg-sunken)/0.3)]")}
                    >
                      <td className="px-3 py-2 font-medium">{s.product}</td>
                      <td className="px-3 py-2 font-mono text-muted-foreground">{s.version}</td>
                      <td className="px-3 py-2 text-muted-foreground">{s.type}</td>
                      <td className="px-3 py-2 font-mono text-muted-foreground">{s.hostname}</td>
                      <td className="px-3 py-2">
                        <Badge className={cn("text-[10px]", s.eolStatus === 'end_of_life' ? 'bg-[hsl(var(--status-critical))] text-white' : s.eolStatus === 'eol_soon' ? 'bg-[hsl(var(--accent-amber))] text-white' : 'bg-[hsl(var(--status-safe))] text-white')}>
                          {s.eolStatus === 'end_of_life' ? 'EOL' : s.eolStatus === 'eol_soon' ? 'EOL Soon' : 'Supported'}
                        </Badge>
                      </td>
                      <td className="px-3 py-2">{s.cveCount > 0 ? <Badge variant="destructive" className="text-[10px]">{s.cveCount} CVEs</Badge> : <span className="text-muted-foreground">0</span>}</td>
                      <td className="px-3 py-2">
                        {s.pqcSupport === 'native' ? <span className="text-[hsl(var(--status-safe))]">Native</span> : s.pqcSupport === 'plugin' ? <span className="text-[hsl(var(--accent-amber))]">Plugin</span> : <span className="text-[hsl(var(--status-critical))]">None</span>}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Network Graph tab */}
      {activeTab === 'network' && <NetworkGraph />}

      {/* Shadow IT tab */}
      {activeTab === 'shadow' && (
        <div className="space-y-4">
          <Card className="p-3 shadow-sm border-[hsl(var(--status-warn)/0.3)] bg-[hsl(var(--status-warn)/0.05)]">
            <p className="text-xs font-body font-medium text-[hsl(var(--status-warn))]">⚠ {shadowData.length} Shadow IT assets detected — not in official inventory</p>
            <p className="text-[10px] text-muted-foreground mt-1">
              Count is computed from live scan assets in the selected scope ({scopeMode === 'this-scan' ? 'This Scan' : 'All Time'}).
            </p>
          </Card>
          <Card className="shadow-[0_8px_30px_-12px_hsl(var(--brand-primary)/0.15)]">
            <CardContent className="p-0">
              <div className="overflow-x-auto">
                <table className="w-full text-xs font-body">
                  <thead><tr className="border-b border-border bg-[hsl(var(--bg-sunken))]">
                    <th className="text-left px-3 py-2.5 font-medium text-muted-foreground">Discovered</th>
                    <th className="text-left px-3 py-2.5 font-medium text-muted-foreground">Asset</th>
                    <th className="text-left px-3 py-2.5 font-medium text-muted-foreground">Type</th>
                    <th className="text-left px-3 py-2.5 font-medium text-muted-foreground">Detection</th>
                    <th className="text-left px-3 py-2.5 font-medium text-muted-foreground">Risk</th>
                    <th className="text-left px-3 py-2.5 font-medium text-muted-foreground">Actions</th>
                  </tr></thead>
                  <tbody>
                    {filteredShadow.map((s, i) => (
                      <tr key={s.asset} className={cn("border-b border-border/50 hover:bg-[hsl(var(--bg-sunken))]", i % 2 === 0 && "bg-[hsl(var(--bg-sunken)/0.3)]")}>
                        <td className="px-3 py-2 font-mono text-muted-foreground">{s.discoveryDate}</td>
                        <td className="px-3 py-2 font-mono font-medium">{s.asset}</td>
                        <td className="px-3 py-2 text-muted-foreground">{s.assetType}</td>
                        <td className="px-3 py-2 text-muted-foreground">{s.howDiscovered}</td>
                        <td className="px-3 py-2"><Badge variant={s.riskLevel === 'critical' ? 'destructive' : 'secondary'} className="text-[10px]">{s.riskLevel}</Badge></td>
                        <td className="px-3 py-2 flex gap-1">
                          <Button variant="outline" size="sm" className="h-6 text-[10px] px-2">Add to Inventory</Button>
                          <Button variant="ghost" size="sm" className="h-6 text-[10px] px-2">Scan</Button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </CardContent>
          </Card>
        </div>
      )}

      {/* Detail panel (shared across all tabs) */}
      <DiscoveryDetailPanel
        open={panelOpen}
        onOpenChange={onPanelOpenChange}
        type={panelType}
        domainRecord={selectedDomain}
        asset={selectedAssetForPanel}
        ipRecord={selectedIP}
        softwareRecord={selectedSoftware}
        dnsEntries={selectedDomainDnsEntries}
        relatedAssetResults={panelAssetResults}
      />
    </>
  );
};

export default AssetTabContent;
