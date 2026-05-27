# CuciSec — Frontend

Dashboard React pentru managementul sistemului IPS/Firewall CuciSec.

## Stack

- React 19 + TypeScript + Vite
- Tailwind CSS v4 + shadcn/ui
- TanStack Query (polling 1–2s)
- Recharts (TrafficChart Line, FloodChart Bar)
- React Router v7 + Sonner (toasts)

## Pornire

```bash
pnpm install
pnpm dev        # http://localhost:5173
pnpm build      # dist/ servit automat de FastAPI
```

## Pagini

| Pagină | Componentă principală | Funcție |
|---|---|---|
| Dashboard | MetricCards + TrafficChart + FloodChart | Overview statistici în timp real |
| Rules | RulesTable + AddRuleModal | CRUD reguli L3/L4 cu hot-reload |
| Blacklist | BlacklistTable + AddBanModal | Management IP-uri blocate |
| Logs | LogsTable | Loguri paginate cu filtre |

Documentație completă și diagrame de arhitectură în [`../README.md`](../README.md) și [`../DIAGRAMS.md`](../DIAGRAMS.md).
