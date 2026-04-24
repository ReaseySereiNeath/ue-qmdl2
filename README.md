# ue-qmdl2

`ue-qmdl2` is a full-stack Qualcomm UE diagnostic log decoder and viewer. It turns raw modem capture files into structured 4G/5G signaling data, then presents the result in a browser dashboard for analysis.

## Highlights

- Upload `.qmdl2`, `.qmdl`, `.dlf`, and `.qdb` files
- Decode with SCAT/signalcat into PCAP, then with `tshark` into JSON
- Normalize packets into a unified log schema for frontend consumption
- Explore data in log table, timeline, anomaly, and diagnostics views
- Download the intermediate PCAP for inspection in Wireshark
- Run summary and health-score style diagnostics on completed jobs

## How It Works

`QMDL2/QMDL/DLF/QDB -> SCAT (-C --events) -> PCAP -> tshark -> JSON -> normalization -> diagnostics + UI`

The backend classifies a wide range of UE signaling and radio layers, including NAS-5GS, NR-RRC, LTE-RRC, LTE-NAS, LTE/NR MAC, PDCP, RLC, ML1 measurements, and Qualcomm diagnostic events.

## Repository Layout

- `qmdl2-backend/`: FastAPI service that accepts uploads, runs the decode pipeline, normalizes logs, and exposes APIs
- `qmdl2-frontend/`: Next.js dashboard for upload, polling job status, filtering logs, charting, and diagnostics
- `README.md`: project overview and local setup

## Prerequisites

- Python 3.12+ recommended for the backend
- A recent Node.js version for the Next.js frontend
- `tshark` installed on the host machine
- Bash if you want to use `qmdl2-backend/run.sh` directly

`signalcat` is installed from `qmdl2-backend/requirements.txt`.

### Install `tshark`

```bash
# Ubuntu / Debian
sudo apt install tshark

# macOS
brew install wireshark
```

On Windows, install Wireshark and make sure `tshark` is available on `PATH`.

## Quick Start

### 1. Start the backend

```bash
cd qmdl2-backend
python -m venv .venv
# Windows PowerShell
. .venv/Scripts/Activate.ps1
# macOS / Linux
# source .venv/bin/activate

pip install -r requirements.txt
fastapi dev main.py --host 0.0.0.0 --port 8000
```

If you are on macOS or Linux and prefer the helper script:

```bash
cd qmdl2-backend
./run.sh
```

Optional backend env (`qmdl2-backend/.env`):

```env
HOST=0.0.0.0
PORT=8000
CORS_ORIGINS=http://localhost:3000
```

### 2. Start the frontend

```bash
cd qmdl2-frontend
npm install
npm run dev
```

Optional frontend env (`qmdl2-frontend/.env.local`):

```env
NEXT_PUBLIC_API_URL=http://localhost:8000
```

If `NEXT_PUBLIC_API_URL` is not set, the frontend defaults to `http://<current-host>:8000` in the browser.

### 3. Open the app

- Frontend: `http://localhost:3000`
- Backend API docs: `http://localhost:8000/docs`

## What The UI Includes

- File upload with progress and pipeline status
- Log table view
- Timeline visualization
- Anomaly panel
- Diagnostics panel with health score and issue summaries
- Client-side filtering by protocol, severity, search text, and IMSI

## Backend API

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/` | Service metadata and supported protocol summary |
| `POST` | `/api/upload` | Upload a log file and start a decode job |
| `GET` | `/api/jobs/{job_id}` | Poll job state and progress |
| `GET` | `/api/logs/{job_id}` | Fetch decoded logs with filters and pagination |
| `GET` | `/api/logs/{job_id}/summary` | Get protocol, severity, and event counts |
| `GET` | `/api/logs/{job_id}/diagnose` | Run diagnostic analysis |
| `GET` | `/api/logs/{job_id}/pcap` | Download the intermediate PCAP |
| `DELETE` | `/api/jobs/{job_id}` | Remove a job and its generated files |

Accepted upload types: `.qmdl2`, `.qmdl`, `.dlf`, `.qdb`  
Current backend upload limit: `500 MB`

## Docker

A backend Dockerfile is included:

```bash
cd qmdl2-backend
docker build -t qmdl2-backend .
docker run -p 8000:8000 qmdl2-backend
```

## Project Notes

- Jobs are stored in memory, so backend restarts clear job state.
- Temporary upload and output files are written under the system temp directory in `qmdl2-decoder`.
- The frontend currently fetches up to `5000` log entries per completed job.
- The backend upload API supports optional NAS decryption keys, but the current frontend focuses on file upload and log browsing rather than exposing those inputs directly.

## Troubleshooting

- `tshark not found`: install Wireshark/tshark and confirm it is on `PATH`.
- `SCAT not found`: reinstall backend dependencies in the active Python environment.
- CORS errors between frontend and backend: set `CORS_ORIGINS` to include the frontend URL.
- "No decoded logs found": the input may be empty, corrupted, or contain message types SCAT/tshark could not decode.
