# TrustLens — Frontend Web Application

React 19 + Vite + Ant Design web console for the TrustLens digital trust & cybersecurity assessment platform.

## Quick Start

### 1. Install Dependencies
```bash
npm install
```

### 2. Configure Environment
Copy `.env.example` to `.env`:
```bash
cp .env.example .env
```

### 3. Run Development Server
```bash
npm run dev
```
The application will launch on `http://localhost:5173`. In development mode, Vite proxies all `/api` requests to the FastAPI backend running on `http://127.0.0.1:8000`.

### 4. Production Build
```bash
npm run build
```
The optimized production bundle is generated in `dist/`.
