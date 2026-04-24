/**
 * API client for qmdl2-backend (FastAPI)
 */

function getApiBase() {
  if (process.env.NEXT_PUBLIC_API_URL) return process.env.NEXT_PUBLIC_API_URL;
  if (typeof window !== "undefined") {
    return `http://${window.location.hostname}:8000`;
  }
  return process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";
}

export interface UploadResponse {
  jobId: string;
  status: string;
  message: string;
}

export interface JobStatus {
  jobId: string;
  status:
    | "queued"
    | "scat_decoding"
    | "tshark_parsing"
    | "normalizing"
    | "complete"
    | "error";
  filename: string;
  fileSizeMB: number;
  createdAt: string;
  progress: number;
  error: string | null;
  logCount: number;
  cellInfo: CellInfo[];
}

export interface CellInfo {
  type: string;
  radio: number;
  technology: string;
  raw: string;
  arfcn?: string;
  band?: string;
  pci?: string;
  mcc?: string;
  mnc?: string;
  bandwidth?: string;
}

export interface BackendLogEntry {
  id: string;
  timestamp: string;
  timestampMs: number;
  protocol: string;
  eventType: string;
  severity: string;
  message: string;
  details: Record<string, string>;
  metadata: {
    frameNumber: number;
    arfcn: number;
    gsmtapType: string;
    gsmtapSubType: string;
  };
}

export interface LogsResponse {
  metadata: Record<string, unknown>;
  total: number;
  offset: number;
  limit: number;
  logs: BackendLogEntry[];
}

export interface SummaryResponse {
  jobId: string;
  totalLogs: number;
  protocolCounts: Record<string, number>;
  severityCounts: Record<string, number>;
  eventCounts: Record<string, number>;
  cellInfo: CellInfo[];
}

/** NAS decryption key configuration */
export interface NasKeys {
  nasEncKey?: string;
  nasIntKey?: string;
  nasEncAlgo?: string;
  nasIntAlgo?: string;
  lteNasEncKey?: string;
  lteNasIntKey?: string;
}

/** Upload a QMDL2 file with optional NAS decryption keys */
export async function uploadFile(file: File, nasKeys?: NasKeys): Promise<UploadResponse> {
  const form = new FormData();
  form.append("file", file);

  if (nasKeys?.nasEncKey) form.append("nas_enc_key", nasKeys.nasEncKey);
  if (nasKeys?.nasIntKey) form.append("nas_int_key", nasKeys.nasIntKey);
  if (nasKeys?.nasEncAlgo) form.append("nas_enc_algo", nasKeys.nasEncAlgo);
  if (nasKeys?.nasIntAlgo) form.append("nas_int_algo", nasKeys.nasIntAlgo);
  if (nasKeys?.lteNasEncKey) form.append("lte_nas_enc_key", nasKeys.lteNasEncKey);
  if (nasKeys?.lteNasIntKey) form.append("lte_nas_int_key", nasKeys.lteNasIntKey);

  const res = await fetch(`${getApiBase()}/api/upload`, {
    method: "POST",
    body: form,
  });

  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(err.detail || "Upload failed");
  }

  return res.json();
}

/** Poll job status */
export async function getJobStatus(jobId: string): Promise<JobStatus> {
  const res = await fetch(`${getApiBase()}/api/jobs/${jobId}`);
  if (!res.ok) throw new Error("Failed to fetch job status");
  return res.json();
}

/** Fetch decoded logs */
export async function getLogs(
  jobId: string,
  params?: {
    offset?: number;
    limit?: number;
    protocol?: string;
    severity?: string;
    search?: string;
  }
): Promise<LogsResponse> {
  const query = new URLSearchParams();
  if (params?.offset != null) query.set("offset", String(params.offset));
  if (params?.limit != null) query.set("limit", String(params.limit));
  if (params?.protocol) query.set("protocol", params.protocol);
  if (params?.severity) query.set("severity", params.severity);
  if (params?.search) query.set("search", params.search);

  const res = await fetch(`${getApiBase()}/api/logs/${jobId}?${query}`);
  if (!res.ok) throw new Error("Failed to fetch logs");
  return res.json();
}

/** Fetch log summary */
export async function getSummary(jobId: string): Promise<SummaryResponse> {
  const res = await fetch(`${getApiBase()}/api/logs/${jobId}/summary`);
  if (!res.ok) throw new Error("Failed to fetch summary");
  return res.json();
}

/** Fetch diagnostic analysis */
export interface DiagnosisResponse {
  jobId: string;
  filename: string;
  healthScore: number;
  totalIssues: number;
  severityCounts: Record<string, number>;
  categoryCounts: Record<string, number>;
  issues: {
    id: string;
    category: string;
    title: string;
    severity: "critical" | "warning" | "info";
    description: string;
    recommendation: string;
    count: number;
    firstSeen: string;
    lastSeen: string;
    affectedLogs: string[];
  }[];
  cellInfo?: CellInfo[];
}

export async function getDiagnosis(jobId: string): Promise<DiagnosisResponse> {
  const res = await fetch(`${getApiBase()}/api/logs/${jobId}/diagnose`);
  if (!res.ok) throw new Error("Failed to fetch diagnosis");
  return res.json();
}
