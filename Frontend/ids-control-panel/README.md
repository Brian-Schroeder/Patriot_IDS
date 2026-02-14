# IDS Control Panel

Frontend control panel for an Intrusion Detection System (IDS) with configurable data visualizations.

## Features

- **Chart types**: Bar, Line, Dot Plot, Box Plot, Pie Chart
- **Time range selector**: 1h, 6h, 24h, 7d
- **Dashboard**: Summary stats, live chart, recent alerts table
- **Alerts view**: Full alert history with sorting

## Tech Stack

- React 18 + TypeScript + Vite
- Tailwind CSS
- Recharts & Plotly for visualizations
- TanStack Query for data
- Zustand for UI state
- React Router
- Docker + Nginx for deployment

## Development

```bash
npm install
npm run dev
```

Open http://localhost:5173

## Build

```bash
npm run build
```

## Docker

```bash
docker compose build
docker compose up -d
```

Then open http://localhost:3000

## Connecting to Backend

The panel currently uses mock data. To connect to your ML/IDS backend:

1. Uncomment the `/api` location in `nginx.conf`
2. Update `proxy_pass` to your backend URL
3. Replace mock API calls in `src/api/` with real Axios fetches to `/api/...`
