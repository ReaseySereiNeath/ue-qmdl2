import type { LogEntry, Protocol, Severity } from "@/types/log";

const EVENT_TYPES = [
  "Registration Request",
  "Registration Accept",
  "Registration Reject",
  "Authentication Request",
  "Authentication Response",
  "Authentication Failure",
  "Security Mode Command",
  "Security Mode Complete",
  "RRC Setup Request",
  "RRC Setup",
  "RRC Reconfiguration",
  "RRC Release",
  "PDU Session Establish Request",
  "PDU Session Establish Accept",
  "PDU Session Reject",
  "Handover Command",
  "Handover Complete",
  "Handover Failure",
  "UL Grant",
  "DL Assignment",
  "RACH Attempt",
  "RACH Success",
  "Measurement Report",
  "SCell Addition",
  "SCell Release",
  "Detach Request",
  "Deregistration Request",
];

const IMSIS = [
  "440101234567890",
  "440101234567891",
  "440101234567892",
  "440109876543210",
  "440109876543211",
];

const GNB_IDS = ["gNB-001-Tokyo-A", "gNB-002-Tokyo-B", "gNB-003-Osaka-C"];
const PCIS = [100, 201, 302, 150, 275];

const CAUSE_MESSAGES: Record<string, string[]> = {
  "Registration Reject": [
    "#5 IMEI not accepted",
    "#11 PLMN not allowed",
    "#22 Congestion",
  ],
  "Authentication Failure": [
    "MAC failure",
    "Synch failure",
    "Non-EPS authentication unacceptable",
  ],
  "PDU Session Reject": [
    "#27 Missing or unknown DNN",
    "#29 User authentication failed",
    "#31 Request rejected",
  ],
  "Handover Failure": [
    "T304 expired",
    "Target cell not available",
    "RLF during handover",
  ],
};

function getProtocol(eventType: string): Protocol | string {
  if (
    eventType.includes("RRC") ||
    eventType.includes("Handover") ||
    eventType.includes("Measurement") ||
    eventType.includes("SCell")
  ) {
    return Math.random() > 0.3 ? "NR-RRC" : "LTE-RRC";
  }
  if (
    eventType.includes("Registration") ||
    eventType.includes("Authentication") ||
    eventType.includes("Security") ||
    eventType.includes("PDU") ||
    eventType.includes("Detach") ||
    eventType.includes("Deregistration")
  ) {
    return Math.random() > 0.2 ? "NAS-5GS" : "LTE-NAS";
  }
  if (
    eventType.includes("UL Grant") ||
    eventType.includes("DL Assignment") ||
    eventType.includes("RACH")
  ) {
    return "NR-MAC";
  }
  const protocols: Protocol[] = [
    "NAS-5GS",
    "NR-RRC",
    "NR-MAC",
    "NR-PDCP",
    "NR-PHY",
    "LTE-RRC",
    "LTE-NAS",
  ];
  return protocols[Math.floor(Math.random() * protocols.length)];
}

function getSeverity(eventType: string): Severity {
  const isError =
    eventType.includes("Reject") || eventType.includes("Failure");
  const isWarning =
    eventType.includes("Release") ||
    eventType.includes("Detach") ||
    eventType.includes("Deregistration");

  if (isError) return Math.random() > 0.3 ? "error" : "critical";
  if (isWarning) return "warning";
  return "info";
}

export function generateMockLogs(count = 200): LogEntry[] {
  const baseTime = new Date("2026-03-11T09:00:00Z").getTime();
  const logs: LogEntry[] = [];

  for (let i = 0; i < count; i++) {
    const ts = baseTime + i * (Math.random() * 3000 + 500);
    const eventType =
      EVENT_TYPES[Math.floor(Math.random() * EVENT_TYPES.length)];
    const severity = getSeverity(eventType);
    const protocol = getProtocol(eventType);
    const imsiIdx = Math.floor(Math.random() * IMSIS.length);
    const causes = CAUSE_MESSAGES[eventType];
    const causeStr = causes
      ? causes[Math.floor(Math.random() * causes.length)]
      : "";

    const imsi = IMSIS[imsiIdx];
    const gNBId = GNB_IDS[Math.floor(Math.random() * GNB_IDS.length)];
    const pci = PCIS[Math.floor(Math.random() * PCIS.length)];

    logs.push({
      id: `log-${String(i).padStart(5, "0")}`,
      timestamp: new Date(ts).toISOString(),
      timestampMs: ts,
      protocol,
      eventType,
      severity,
      imsi,
      supi: `imsi-${imsi}`,
      gNBId,
      pci,
      message: causeStr
        ? `${eventType}: ${causeStr}`
        : `${eventType} processed successfully`,
      details: {
        ...(causeStr ? { cause: causeStr } : {}),
        imsi,
        supi: `imsi-${imsi}`,
        gNBId,
        pci: String(pci),
      },
      metadata: {
        arfcn: Math.floor(Math.random() * 100000) + 600000,
        rsrp: -(Math.floor(Math.random() * 40) + 70),
        sinr: Math.floor(Math.random() * 25) + 5,
      },
    });
  }

  return logs.sort((a, b) => a.timestampMs - b.timestampMs);
}
