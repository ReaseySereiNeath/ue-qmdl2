const HUES: Record<string, number> = {
  "NAS-5GS": 280,
  "NR-RRC": 200,
  "NR-MAC": 160,
  "NR-PDCP": 140,
  "NR-PHY": 120,
  "LTE-RRC": 30,
  "LTE-NAS": 50,
};

export function ProtocolBadge({ protocol }: { protocol: string }) {
  const hue = HUES[protocol] || 0;
  return (
    <span
      className="inline-block font-[var(--font-mono)] text-[10px] font-semibold tracking-wide"
      style={{
        padding: "2px 7px",
        borderRadius: 3,
        background: `hsla(${hue},70%,50%,0.12)`,
        color: `hsl(${hue},70%,65%)`,
        border: `1px solid hsla(${hue},70%,50%,0.2)`,
      }}
    >
      {protocol}
    </span>
  );
}
