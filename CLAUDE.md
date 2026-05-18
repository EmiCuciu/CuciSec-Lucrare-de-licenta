# CLAUDE.md — CuciSec Project Context

> Pune acest fișier în rădăcina repo-ului GitHub.
> Claude Code îl citește automat la fiecare sesiune nouă.

---

## Ce este CuciSec

CuciSec este un sistem hibrid IPS/Firewall pentru Linux, dezvoltat ca lucrare de licență la
Facultatea de Matematică și Informatică, Universitatea Babeș-Bolyai, Cluj-Napoca, 2026.

Sistemul combină filtrarea la nivel de kernel (nftables) cu analiza în userspace (Python/NFQUEUE)
și expune o interfață de management prin REST API (FastAPI) + SPA frontend (React).

**GitHub:** https://github.com/EmiCuciu/CuciSec-Lucrare-de-licenta

---

## Arhitectura generală

```
┌─────────────────────────────────────────────────────────┐
│                    LINUX KERNEL                          │
│  Pachet intră → nftables hook input/forward              │
│    ├─ Rate limiting (ICMP/TCP SYN/UDP flood) → DROP      │
│    ├─ Blacklist O(1) hash set → DROP                     │
│    └─ Restul → NFQUEUE num 1 → userspace                 │
└─────────────────────────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────┐
│                   PYTHON USERSPACE                       │
│  PacketInterceptor._process_packet()                     │
│    1. PacketAnalyzer.analyze()   → PacketInfo            │
│    2. FloodEngine.inspect()      → BAN + DROP dacă flood │
│    3. RuleEngine.evaluate()      → DROP dacă regulă      │
│    4. HoneyportEngine.inspect()  → BAN + DROP dacă trap  │
│    5. DPIEngine.inspect()        → BAN + DROP dacă L7    │
│    6. DEFAULT ACCEPT                                     │
│                                                          │
│  AsyncDBWriter (daemon thread)   → SQLite WAL            │
│  FastAPI (daemon thread)         → port 8000             │
└─────────────────────────────────────────────────────────┘
```

---

## Structura proiectului

```
CuciSec-Lucrare-de-licenta/
├── firewall_main.py              # Entry point — boot sequence
├── scripts/
│   └── nftables_setup.sh         # Initializare ruleset kernel
├── api/
│   ├── api_main.py               # FastAPI factory + static serving
│   ├── dependencies.py           # Dependency injection (RuleEngine, NftablesManager)
│   ├── schemas.py                # Pydantic schemas (Request/Response)
│   └── routes/
│       ├── rules_route.py        # GET/POST /api/rules, DELETE/PATCH /{id}/toggle
│       ├── logs_route.py         # GET /api/logs, GET /api/logs/count
│       ├── blacklist_route.py    # GET/POST /api/blacklist, DELETE /{ip}
│       └── stats_route.py        # GET /api/stats
├── database/
│   ├── setup_db.py               # init_db(), CREATE TABLE, WAL mode, indexes
│   └── mock_db_data.py           # Script resetare manuală DB
├── detectors/
│   ├── dpi.py                    # DPIEngine — regex L7 (SQLi, XSS, path traversal)
│   ├── flood.py                  # FloodEngine — sliding window userspace
│   └── honeyport.py              # HoneyportEngine — trap ports (23, 2323, 3389, 4444, 9999)
├── domain/
│   └── models.py                 # Dataclasses: PacketInfo, RuleModel, LogEntry, BlacklistEntry
├── infrastructure/
│   ├── interceptor.py            # PacketInterceptor — NFQUEUE bind + callback
│   └── nftables_manager.py       # NftablesManager — subprocess nft CLI
├── repository/
│   ├── base.py                   # AsyncDBWriter — Singleton + Producer-Consumer
│   ├── blacklist_repository.py   # BlacklistRepository
│   ├── log_repository.py         # LogRepository
│   ├── rule_repository.py        # RuleRepository
│   └── stats_repository.py       # StatsRepository
├── service/
│   ├── firewall_actions.py       # FirewallActions — accept/drop/ban + logging
│   ├── packet_analyzer.py        # PacketAnalyzer — Scapy dissection IPv4/IPv6/TCP/UDP/ICMP
│   ├── rule_engine.py            # RuleEngine — in-memory rules + CIDR matching
│   └── stats_service.py          # StatsService — parse nft -j JSON counters
├── utils/
│   ├── config.py                 # Config class — QUEUE_NUM, HONEY_PORTS, rate limits
│   └── logger.py                 # Loguru setup — color format + file rotation 5MB
└── frontend-cucisec/             # React 19 + TypeScript + Vite + Tailwind CSS v4
    └── src/
        └── components/           # Dashboard, Rules, Blacklist, Logs
```

---

## Flux de boot (firewall_main.py)

1. `setup_logger()` — Loguru cu format color + fișier `logs/cucisec.log`
2. `init_db()` — CREATE TABLE IF NOT EXISTS + PRAGMA WAL + indexes
3. `NftablesManager.setup(script_path)` — flush + recreează tabela `inet cucisec`
4. `BlacklistRepository.get_all_ips()` + `NftablesManager.sync_blacklist()` — batch insert IPs din SQLite în kernel
5. `PacketInterceptor(queue_num=1)` — instanțiază toate engine-urile
6. `threading.Thread(target=start_api, daemon=True).start()` — FastAPI pe port 8000
7. `interceptor.start_interceptor()` — binding NFQUEUE, blocking call

---

## Componente cheie — detalii

### AsyncDBWriter (repository/base.py)
- **Pattern:** Singleton + Producer-Consumer
- **Coadă:** `queue.Queue(maxsize=10000)` — non-blocking `put_nowait()`
- **Thread:** daemon, o singură conexiune SQLite pe toată durata procesului
- **Shutdown:** injectare santinelă `None`, `join()` pentru golire completă
- **Comportament la supraîncărcare:** sacrifică logarea, menține viteza de decizie

### RuleEngine (service/rule_engine.py)
- Regulile se încarcă **o singură dată** la boot din DB în `self._rules: List[RuleModel]`
- **Hot-reload** declanșat automat la POST/DELETE/PATCH pe `/api/rules`
- Suportă: wildcard (`*`), IP exact, CIDR (`192.168.1.0/24`), protocol, port
- Evaluare: first-match, returnează `(action, zone)`

### NftablesManager (infrastructure/nftables_manager.py)
- **Toate comenzile nft** prin `subprocess` (CLI), nu prin biblioteca Python nftables
- `setup()` — rulează `scripts/nftables_setup.sh`
- `ban_ip()` — `nft add element inet cucisec blacklist_v{4/6} { ip }`
- `sync_blacklist()` — batch insert via `nft -f -` (stdin pipe)
- `get_stats()` — `nft -j list ruleset` → JSON → `StatsService.parse_flood_counters()`
- `cleanup()` — `nft delete table inet cucisec` la shutdown

### FloodEngine (detectors/flood.py)
- **Dual-layer:** kernel (nftables rate limit) + userspace (sliding window 12s)
- Userspace: `ip_history[ip] = [timestamps]`, curăță timestamps > TIME_WINDOW
- Praguri: TCP > 200 pkts/12s, UDP > 250 pkts/12s, ICMP > 30 pkts/12s
- Lazy cleanup la 60s pentru IP-urile inactive

### DPIEngine (detectors/dpi.py)
- Regex pre-compilate la init: `UNION SELECT`, `DROP TABLE`, `OR 1=1`, `<script>`, `/etc/passwd`, `cmd.exe`, `nmap`, `nikto`
- Inspectează doar pachetele cu payload (Layer 7)
- Payload decodat UTF-8 cu `errors='ignore'`

### HoneyportEngine (detectors/honeyport.py)
- Porturi capcană: `[23, 2323, 3389, 4444, 9999]`
- Ban la **primul hit** — orice conexiune TCP/UDP pe aceste porturi

### FirewallActions (service/firewall_actions.py)
- `_banned_ips: set` — cache în memorie pentru evitarea ban-urilor duplicate
- **BUG ACTIV:** `unban_ip()` din API șterge din SQLite dar NU șterge din kernel set și NU actualizează `_banned_ips` cache-ul din FirewallActions

---

## API Endpoints

| Metodă | Endpoint | Funcție |
|--------|----------|---------|
| GET | `/api/rules/` | Listare toate regulile |
| POST | `/api/rules/` | Adăugare regulă + hot-reload |
| DELETE | `/api/rules/{id}` | Ștergere regulă + hot-reload |
| PATCH | `/api/rules/{id}/toggle?enabled=0\|1` | Enable/disable regulă + hot-reload |
| GET | `/api/logs/` | Loguri paginate cu filtre (protocol, action, ip_src) |
| GET | `/api/logs/count` | Contoare pe minut (ultimele 30 min) — chart |
| GET | `/api/blacklist/` | Lista IP-uri blocate |
| POST | `/api/blacklist/` | Ban manual IP |
| DELETE | `/api/blacklist/{ip}` | Unban IP (INCOMPLET — vezi bug mai jos) |
| GET | `/api/stats/` | Statistici agregat DB + counters kernel |

---

## Baza de date (SQLite + WAL)

```sql
-- Tabele
Rules    (id, ip_src, port, protocol, action, description, enabled, zone)
Logs     (id, timestamp, ip_src, ip_dst, port_src, port_dst, protocol, action_taken, details)
Blacklist (id, ip UNIQUE, reason, timestamp)

-- Indexuri pe Logs
idx_logs_ip_src, idx_logs_timestamp, idx_logs_protocol

-- WAL mode activat la init
PRAGMA journal_mode=WAL;
```

**Locație:** `database/CuciSec.db`

---


## Convenții de cod

- **Python:** PEP 8, type hints pe toate metodele publice, docstring pe fiecare metodă
- **Logging:** Loguru cu prefixe standard: `[BOOT]`, `[PACKET]`, `[INTERCEPTOR]`, `[DPI]`, `[HONEYPORT]`, `[FLOOD]`, `[BAN]`
- **Erori:** toate `except` prind excepții specifice, nu `except Exception` generic — unde e posibil
- **Repository pattern:** scrieri async prin `AsyncDBWriter`, citiri sync cu `sqlite3.connect()` ca context manager
- **Frontend:** React 19 + TypeScript, TanStack Query pentru data fetching, shadcn/ui componente

---


---

## Topologia de test (3 VM-uri)

```
[Kali Attacker]  ←→  [Ubuntu Server — CuciSec (hook forward)]  ←→  [Ubuntu Client]
  10.0.2.5/24              10.0.2.10/24 + 10.0.3.10/24              10.0.3.5/24
```

VM-ul CuciSec are două interfețe de rețea și routează traficul între cele două rețele.
CuciSec se atașează pe `hook forward` pentru a intercepta traficul în tranzit.

---

