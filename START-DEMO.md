# IDS Demo - Quick Start

## 1. Start Backend (Terminal 1)
```bash
cd Backend/ids_backend
python run.py
```
Wait until you see: `Running on http://0.0.0.0:5000`

## 2. Start Frontend (Terminal 2)
```bash
cd Frontend/ids-control-panel
npm install
npm run dev
```

## 3. Open in Browser
- **http://localhost:5173** (or 5174 if 5173 is in use)
- The dashboard shows live simulated alerts
- Go to **Testing** tab → Demo Mode is ON → click any attack button

## If Frontend Shows "Backend not connected"
- Ensure the backend is running first
- Check backend is on port 5000
- Frontend proxies `/api` to `localhost:5000`
