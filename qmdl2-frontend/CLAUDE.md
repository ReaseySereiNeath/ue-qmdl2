# QMDL2 Frontend

Next.js dashboard for visualizing decoded Qualcomm QMDL2 UE diagnostic logs.

## Stack

- **Framework**: Next.js 16 (App Router, Turbopack)
- **Language**: TypeScript
- **Styling**: Tailwind CSS v4 (via `@tailwindcss/postcss`)
- **Charts**: Recharts
- **State**: `useReducer` + custom hook (no external state library)

## Project structure

```
src/
├── app/
│   ├── layout.tsx          # Root layout, metadata
│   ├── page.tsx            # Main SPA — upload screen + dashboard
│   └── globals.css         # Tailwind import + custom animations
├── components/
│   ├── FileUpload.tsx      # Drag-and-drop file upload with progress
│   ├── PipelineStatus.tsx  # Step-by-step processing visualization
│   ├── LogTable.tsx        # Paginated log viewer (50/page)
│   ├── FilterPanel.tsx     # Protocol, severity, IMSI, search filters
│   ├── TimelineView.tsx    # Recharts stacked bar chart (30s buckets)
│   ├── ErrorPanel.tsx      # Anomaly grouping by event type
│   ├── DiagnosticsPanel.tsx # Health score ring + expandable issue cards
│   ├── LogDetail.tsx       # Slide-in detail drawer
│   ├── StatsBar.tsx        # Header statistics summary
│   ├── SeverityBadge.tsx   # Colored severity label
│   └── ProtocolBadge.tsx   # Hue-mapped protocol label
├── hooks/
│   └── useLogStore.ts      # App state reducer, file upload, job polling
├── lib/
│   ├── api.ts              # Backend API client (fetch-based)
│   └── mock-data.ts        # Mock log generator for development
└── types/
    └── log.ts              # LogEntry, FilterState, AppState, actions, diagnostics
```

## Commands

```bash
npm run dev      # Start dev server (port 3000)
npm run build    # Production build
npm run start    # Start production server
npm run lint     # ESLint
```

## Architecture

Single-page app with 4 view modes: **Log Table**, **Timeline**, **Anomalies**, **Diagnostics**.

### Data flow

1. User uploads `.qmdl2` file → `api.uploadFile()` → backend returns `jobId`
2. `useLogStore` polls `api.getJobStatus(jobId)` every 1s
3. On completion, fetches up to 5000 logs via `api.getLogs(jobId)`
4. Logs stored in reducer state, filters applied client-side
5. Diagnostics tab fetches `api.getDiagnosis(jobId)` on demand

### Backend connection

API base URL from `NEXT_PUBLIC_API_URL` env var (default: `http://localhost:8000`).
All endpoints defined in `src/lib/api.ts`.

## Environment

Config in `.env.local`:
```
NEXT_PUBLIC_API_URL=http://localhost:8000
```

## Design

- Dark theme (`#060a14` background)
- Monospace font for data: `var(--font-mono)`
- Color coding: sky=info, amber=warning, red=error/critical, emerald=success
- Animations: fade-up, slide-in, pulse-dot, loading-bar (defined in globals.css)
