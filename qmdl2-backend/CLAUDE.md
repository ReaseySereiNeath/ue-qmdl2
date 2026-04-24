# QMDL2 Backend

Qualcomm QMDL2 UE diagnostic log decoder — FastAPI backend.

## Stack

- **Language**: Python 3.12+
- **Framework**: FastAPI (async)
- **Entry point**: `main.py` (single-file, ~2200 lines)
- **External tools**: signalcat (SCAT), tshark (Wireshark CLI)

## Architecture

Everything lives in `main.py`. The processing pipeline is:

```
QMDL2 file → SCAT decode → PCAP → tshark parse → JSON → normalize → structured logs
```

### Key sections in main.py

- **Config** (~line 44): Host, port, CORS, upload limits (500 MB max)
- **Job store** (~line 76): In-memory dict tracking job status
- **SCAT decoder** (~line 134): QMDL2 → PCAP via signalcat library
- **tshark parser** (~line 195): PCAP → JSON protocol dissection
- **Normalizer** (~line 261): tshark JSON → unified log schema
- **Protocol parsers** (~line 474): NAS-5GS, NR-RRC, LTE-RRC, LTE-NAS, MAC/PDCP/RLC
- **SCAT console parser** (~line 1706): ML1 PHY measurements (0xB17F, 0xB97F)
- **Diagnostic engine** (~line 806): 8+ analyzers (registration, auth, RRC, handover, RF, PDU, abnormal patterns)

### API Endpoints

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/` | Service info |
| POST | `/api/upload` | Upload QMDL2 file, returns jobId |
| GET | `/api/jobs/{job_id}` | Poll job status/progress |
| GET | `/api/logs/{job_id}` | Fetch decoded logs (filterable, paginated) |
| GET | `/api/logs/{job_id}/summary` | Protocol/severity/event counts |
| GET | `/api/logs/{job_id}/diagnose` | Diagnostic analysis + health score |
| GET | `/api/logs/{job_id}/pcap` | Download intermediate PCAP |
| DELETE | `/api/jobs/{job_id}` | Delete job and files |

### Job statuses

`queued` → `scat_decoding` → `tshark_parsing` → `normalizing` → `complete` | `error`

## Commands

```bash
# Setup & run (checks deps, starts dev server)
./run.sh

# Or manually:
pip install -r requirements.txt
fastapi dev main.py --host 0.0.0.0 --port 8000

# Docker:
docker build -t qmdl2-backend .
docker run -p 8000:8000 qmdl2-backend
```

## System dependencies

- **tshark**: `sudo apt install tshark` (Ubuntu/Debian) or `brew install wireshark` (macOS)
- **signalcat**: installed via pip (`signalcat>=1.5.0`)

## Environment

Config in `.env`:
```
HOST=0.0.0.0
PORT=8000
CORS_ORIGINS=http://localhost:3000
```

## Log entry schema

```json
{
  "id": "log-00001",
  "timestamp": "ISO-8601",
  "timestampMs": 1234567890,
  "protocol": "NAS-5GS|NR-RRC|LTE-RRC|LTE-NAS|NR-MAC|...",
  "eventType": "Registration Accept|RRC Setup|...",
  "severity": "info|warning|error|critical",
  "message": "human-readable summary",
  "details": {},
  "metadata": { "frameNumber", "arfcn", "gsmtapType", "gsmtapSubType" }
}
```
