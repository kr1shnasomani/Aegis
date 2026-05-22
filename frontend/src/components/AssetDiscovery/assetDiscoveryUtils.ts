/**
 * assetDiscoveryUtils.ts
 *
 * Pure data-transform functions for the Asset Discovery page.
 * No React imports — these are plain TypeScript utilities that
 * can be imported by the page and independently unit-tested.
 */

import type { AssetResultResponse, DNSRecordResponse } from '@/lib/api';
import type {
  DomainRecord,
  IPRecord,
  SoftwareRecord,
  Asset,
  ScanHistoryEntry,
  ShadowITAlert,
} from '@/data/demoData';

// ── Shared local interfaces ───────────────────────────────────────────────────

export interface ObservedAsset {
  asset: Asset;
  rawAsset: AssetResultResponse | null;
  observedAt: string;
  scanId: string;
  target: string;
}

export interface ObservedDNSRecord {
  record: DNSRecordResponse;
  observedAt: string;
  scanId: string;
  target: string;
}

export interface DiscoveryQueryResult {
  history: ScanHistoryEntry[];
  completedHistory: ScanHistoryEntry[];
  totalCompletedScanCount: number;
  loadedCompletedScanCount: number;
  observedAssets: ObservedAsset[];
  observedDnsRecords: ObservedDNSRecord[];
}

// ── Type narrowing helpers ────────────────────────────────────────────────────

export const asRecord = (value: unknown): Record<string, unknown> | null =>
  typeof value === 'object' && value !== null && !Array.isArray(value)
    ? value as Record<string, unknown>
    : null;

export const nestedRecord = (root: Record<string, unknown> | null, key: string): Record<string, unknown> | null =>
  root ? asRecord(root[key]) : null;

export const stringValue = (root: Record<string, unknown> | null, key: string): string | null => {
  if (!root) return null;
  const value = root[key];
  return typeof value === 'string' && value.trim() ? value : null;
};

export const stringArray = (root: Record<string, unknown> | null, key: string): string[] => {
  if (!root) return [];
  const value = root[key];
  if (!Array.isArray(value)) return [];
  return value.filter((entry): entry is string => typeof entry === 'string');
};

// ── Display formatters ────────────────────────────────────────────────────────

export const formatDateCell = (value: string | null | undefined): string => {
  if (!value) return 'Unavailable';
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) return value;
  return parsed.toISOString().slice(0, 10);
};

export const normalizeDisplayValue = (value: string | null | undefined): string => {
  if (!value) return 'Unavailable';
  const normalized = value.trim();
  if (!normalized || normalized === '—' || normalized.toLowerCase() === 'unknown') {
    return 'Unavailable';
  }
  return normalized;
};

// ── Asset predicates and scorers ──────────────────────────────────────────────

export const hasCertificateDetails = (asset: Asset): boolean => {
  if (!asset.certInfo) return false;
  return Boolean(
    (asset.certInfo.subject_cn && asset.certInfo.subject_cn !== 'unknown') ||
    (asset.certInfo.valid_until && asset.certInfo.valid_until !== 'Unavailable') ||
    (asset.certInfo.sha256_fingerprint && asset.certInfo.sha256_fingerprint.length > 10),
  );
};

export const getObservedTime = (value: string): number => {
  const parsed = new Date(value).getTime();
  return Number.isNaN(parsed) ? 0 : parsed;
};

export const assetRiskScore = (asset: Asset): number => Math.max(0, Math.min(100, 100 - asset.qScore));

export const assetRiskLevel = (asset: Asset): IPRecord['risk'] => {
  if (asset.status === 'critical') return 'critical';
  if (asset.status === 'unknown') return 'high';
  if (asset.status === 'vulnerable') return 'high';
  if (
    asset.status === 'standard' ||
    asset.status === 'transitioning' ||
    asset.status === 'safe' ||
    asset.complianceTier === 'PQC_TRANSITIONING'
  ) return 'medium';
  return 'low';
};

export const includesSearch = (values: Array<string | number | null | undefined>, search: string): boolean => {
  if (!search) return true;
  const needle = search.toLowerCase();
  return values.some((value) => String(value ?? '').toLowerCase().includes(needle));
};

// ── Observation constructors ──────────────────────────────────────────────────

export const MAX_ALL_TIME_SCANS = 40;

export const toObservedAssets = (
  items: Asset[],
  scanId: string,
  target: string,
  rawAssets: AssetResultResponse[] = [],
  observedAtOverride?: string | null,
): ObservedAsset[] => {
  const rawById = new Map(rawAssets.map((asset) => [asset.asset_id, asset]));
  return items.map((asset) => ({
    asset,
    rawAsset: rawById.get(asset.id) ?? null,
    observedAt: observedAtOverride ?? asset.lastScanned,
    scanId,
    target,
  }));
};

export const toObservedDnsRecords = (
  records: DNSRecordResponse[],
  scanId: string,
  target: string,
  observedAt: string,
): ObservedDNSRecord[] =>
  records.map((record) => ({
    record,
    observedAt,
    scanId,
    target,
  }));

// ── Record builders ───────────────────────────────────────────────────────────

export const latestObservedAssets = (observedAssets: ObservedAsset[]): ObservedAsset[] => {
  const latest = new Map<string, ObservedAsset>();
  observedAssets.forEach((item) => {
    const key = `${item.asset.domain}|${item.asset.port}|${item.asset.type}`;
    const existing = latest.get(key);
    if (!existing || getObservedTime(item.observedAt) > getObservedTime(existing.observedAt)) {
      latest.set(key, item);
    }
  });
  return [...latest.values()].sort((a, b) => {
    const timeDelta = getObservedTime(b.observedAt) - getObservedTime(a.observedAt);
    return timeDelta !== 0 ? timeDelta : a.asset.domain.localeCompare(b.asset.domain);
  });
};

export const latestAssets = (observedAssets: ObservedAsset[]): Asset[] =>
  latestObservedAssets(observedAssets).map((item) => item.asset);

export const buildDomainRecords = (
  observedAssets: ObservedAsset[],
  observedDnsRecords: ObservedDNSRecord[] = [],
): DomainRecord[] => {
  const grouped = new Map<string, { assets: ObservedAsset[]; dns: ObservedDNSRecord[] }>();

  observedAssets.forEach((item) => {
    const key = item.asset.domain;
    const existing = grouped.get(key) ?? { assets: [], dns: [] };
    existing.assets.push(item);
    grouped.set(key, existing);
  });

  observedDnsRecords.forEach((item) => {
    const key = item.record.hostname;
    const existing = grouped.get(key) ?? { assets: [], dns: [] };
    existing.dns.push(item);
    grouped.set(key, existing);
  });

  return [...grouped.entries()].map(([domain, groupedItems]) => {
    const assetItems = groupedItems.assets;
    const dnsItems = groupedItems.dns;
    const allObservedAt = [
      ...assetItems.map((item) => item.observedAt),
      ...dnsItems.map((item) => item.observedAt),
    ].sort((a, b) => getObservedTime(a) - getObservedTime(b));
    const latestAsset = [...assetItems].sort(
      (a, b) => getObservedTime(a.observedAt) - getObservedTime(b.observedAt),
    )[assetItems.length - 1];
    const seenInScans = new Set([
      ...assetItems.map((item) => item.scanId),
      ...dnsItems.map((item) => item.scanId),
    ]).size;

    return {
      detectionDate: formatDateCell(allObservedAt[0]),
      domain,
      registrationDate: (() => {
        const metadata = nestedRecord(asRecord(latestAsset?.rawAsset?.asset_metadata ?? null), 'domain_enrichment');
        return normalizeDisplayValue(
          stringValue(metadata, 'registration_date')
          ?? latestAsset?.asset.certInfo.valid_from
          ?? null,
        );
      })(),
      expiryDate: (() => {
        const metadata = nestedRecord(asRecord(latestAsset?.rawAsset?.asset_metadata ?? null), 'domain_enrichment');
        return normalizeDisplayValue(
          stringValue(metadata, 'expiry_date')
          ?? latestAsset?.asset.certInfo.valid_until
          ?? null,
        );
      })(),
      registrar: (() => {
        const metadata = nestedRecord(asRecord(latestAsset?.rawAsset?.asset_metadata ?? null), 'domain_enrichment');
        return normalizeDisplayValue(stringValue(metadata, 'registrar'));
      })(),
      company: latestAsset && latestAsset.asset.ownerTeam !== 'Unassigned'
        ? latestAsset.asset.ownerTeam
        : 'Unassigned',
      status: seenInScans > 1 ? 'confirmed' : 'new',
      riskScore: assetItems.length > 0 ? Math.max(...assetItems.map((item) => assetRiskScore(item.asset))) : 0,
      nameservers: (() => {
        const metadata = nestedRecord(asRecord(latestAsset?.rawAsset?.asset_metadata ?? null), 'domain_enrichment');
        const values = stringArray(metadata, 'nameservers');
        return values.length > 0 ? values : [];
      })(),
    };
  }).sort((a, b) => a.domain.localeCompare(b.domain));
};

export const buildIPRecords = (observedAssets: ObservedAsset[]): IPRecord[] => {
  const grouped = new Map<string, ObservedAsset[]>();
  observedAssets.filter((item) => item.asset.ip).forEach((item) => {
    const key = item.asset.ip;
    grouped.set(key, [...(grouped.get(key) ?? []), item]);
  });

  return [...grouped.entries()].map(([ip, items]) => {
    const sorted = [...items].sort((a, b) => getObservedTime(a.observedAt) - getObservedTime(b.observedAt));
    const latest = sorted[sorted.length - 1];
    const portsOpen = [...new Set([
      ...items.flatMap((item) => {
        if (!Array.isArray(item.rawAsset?.open_ports)) return [];
        return item.rawAsset.open_ports
          .map((portEntry) => {
            if (typeof portEntry !== 'object' || portEntry === null) return Number.NaN;
            const rawPort = (portEntry as Record<string, unknown>).port;
            return typeof rawPort === 'number' ? rawPort : Number(rawPort);
          })
          .filter((port): port is number => Number.isFinite(port));
      }),
      ...items.map((item) => item.asset.port),
    ])].sort((a, b) => a - b);
    const risks = items.map((item) => assetRiskLevel(item.asset));
    const risk = risks.includes('critical')
      ? 'critical'
      : risks.includes('high')
        ? 'high'
        : risks.includes('medium')
          ? 'medium'
          : 'low';

    const networkMetadata = nestedRecord(asRecord(latest.rawAsset?.asset_metadata ?? null), 'network_enrichment');
    const city = stringValue(networkMetadata, 'city');
    const country = stringValue(networkMetadata, 'country');
    const composedLocation = [city, country].filter(Boolean).join(', ');

    return {
      detectionDate: formatDateCell(sorted[0]?.observedAt),
      ip,
      portsOpen,
      subnet: normalizeDisplayValue(stringValue(networkMetadata, 'subnet')),
      asn: normalizeDisplayValue(stringValue(networkMetadata, 'asn')),
      netname: normalizeDisplayValue(stringValue(networkMetadata, 'netname')),
      city: normalizeDisplayValue(composedLocation),
      isp: normalizeDisplayValue(stringValue(networkMetadata, 'isp')),
      reverseDns: normalizeDisplayValue(stringValue(networkMetadata, 'reverse_dns') ?? latest.asset.domain),
      risk,
    };
  }).sort((a, b) => a.ip.localeCompare(b.ip));
};

export const buildSoftwareRecords = (observedAssets: ObservedAsset[]): SoftwareRecord[] => {
  const latest = new Map<string, SoftwareRecord & { observedAt: string }>();

  observedAssets.forEach((item) => {
    const fallbackServiceName = (() => {
      if (!Array.isArray(item.rawAsset?.open_ports)) return null;
      const withService = item.rawAsset.open_ports.find((entry) => {
        if (typeof entry !== 'object' || entry === null) return false;
        const serviceName = (entry as Record<string, unknown>).service_name;
        return typeof serviceName === 'string' && serviceName.trim().length > 0;
      }) as Record<string, unknown> | undefined;
      const value = withService?.service_name;
      return typeof value === 'string' && value.trim() ? value.trim() : null;
    })();

    const software = item.asset.software ?? {
      product: item.rawAsset?.server_software
        || (fallbackServiceName === 'https'
          ? `HTTPS Service (${item.asset.port})`
          : fallbackServiceName === 'http'
            ? `HTTP Service (${item.asset.port})`
            : fallbackServiceName)
        || (item.asset.type === 'web'
          ? 'HTTPS Endpoint'
          : item.asset.type === 'api'
            ? 'API Service'
            : item.asset.type === 'vpn'
              ? 'VPN Gateway'
              : 'Network Service'),
      version: '',
      type: item.asset.type === 'web'
        ? 'Web Service'
        : item.asset.type === 'api'
          ? 'API Service'
          : item.asset.type === 'vpn'
            ? 'VPN Service'
            : 'Network Service',
      eolDate: null,
      cveCount: 0,
      pqcNativeSupport: false,
    };
    const eolDate = software.eolDate;
    const eolTime = eolDate ? new Date(eolDate).getTime() : Number.NaN;
    const now = Date.now();
    const eolStatus: SoftwareRecord['eolStatus'] = !eolDate
      ? 'supported'
      : Number.isNaN(eolTime)
        ? 'supported'
        : eolTime < now
          ? 'end_of_life'
          : eolTime - now <= 180 * 24 * 60 * 60 * 1000
            ? 'eol_soon'
            : 'supported';

    const record = {
      detectionDate: formatDateCell(item.observedAt),
      product: software.product,
      version: software.version || 'Unavailable',
      type: software.type,
      port: item.asset.port,
      hostIp: item.asset.ip || 'Unavailable',
      hostname: item.asset.domain,
      eolStatus,
      eolDate: software.eolDate,
      cveCount: software.cveCount,
      pqcSupport: software.pqcNativeSupport ? 'native' : 'none',
      observedAt: item.observedAt,
    } satisfies SoftwareRecord & { observedAt: string };

    const key = `${record.hostname}|${record.product}|${record.version}|${record.port}`;
    const existing = latest.get(key);
    if (!existing || getObservedTime(record.observedAt) > getObservedTime(existing.observedAt)) {
      latest.set(key, record);
    }
  });

  return [...latest.values()]
    .sort((a, b) => a.hostname.localeCompare(b.hostname) || a.product.localeCompare(b.product))
    .map(({ observedAt, ...record }) => record);
};

export const buildShadowAlerts = (observedAssets: ObservedAsset[]): ShadowITAlert[] =>
  latestObservedAssets(observedAssets)
    .filter((item) => item.rawAsset?.is_shadow_it || item.asset.status === 'unknown')
    .map((item) => ({
      discoveryDate: formatDateCell(item.observedAt),
      asset: item.asset.domain || item.asset.ip,
      assetType: item.asset.type.toUpperCase(),
      howDiscovered: item.rawAsset?.discovery_source
        ? `Detected via ${item.rawAsset.discovery_source}`
        : 'Inferred from scan results',
      riskLevel: assetRiskLevel(item.asset),
      registeredOwner: item.asset.ownerTeam === 'Unassigned' ? 'Unknown' : item.asset.ownerTeam,
      recommendedAction: 'Investigate ownership and either add to inventory or decommission.',
    }));
