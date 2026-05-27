# CuciSec — Firewall (Lucrare de Licenta)

Firewall complet în userspace pentru Linux, scris ca lucrare de licență. Interceptează pachete din kernel via NFQUEUE, le analizează în Python cu Scapy, și oferă un dashboard React pentru management în timp real.

---

## Arhitectura generală

```
Kernel (nftables)
    └── NFQUEUE → PacketInterceptor
                     ├── PacketAnalyzer  (Scapy dissection → PacketInfo)
                     ├── RuleEngine      (reguli admin din RAM, prioritate maximă)
                     ├── FloodEngine     (sliding window DoS/DDoS per-source)
                     ├── HoneyportEngine (porturi capcană)
                     ├── DPIEngine       (Layer 7, regex signatures, HTTP only)
                     └── DEFAULT ACCEPT

FastAPI (port 8000, thread separat)
    ├── /api/rules     → CRUD + hot-reload RuleEngine
    ├── /api/logs      → paginated, filtrate
    ├── /api/blacklist → ban/unban manual
    ├── /api/stats     → DB + nftables counters combinate
    └── /*             → serve React SPA din frontend-cucisec/dist/

SQLite (database/CuciSec.db, WAL mode)
    ├── Rules
    ├── Logs
    ├── Blacklist
    └── KernelCounters (1 singur rând, contoare cumulative nftables)
```

---

## Structura fișierelor

```
firewall_main.py           # Entry point: init DB, nftables, API thread, interceptor
utils/
  config.py                # Config centralizat (thresholds, honeyports, QUEUE_NUM, LAN_SUBNETS)
  logger.py                # Loguru setup cu format custom pe tag-uri

domain/models.py           # Dataclasses: PacketInfo, RuleModel, LogEntry, BlacklistEntry

infrastructure/
  interceptor.py           # PacketInterceptor — leagă NFQUEUE, apelează detectorii în ordine
  nftables_manager.py      # Wrapper nft CLI: ban/unban/sync/get_stats/cleanup/counter thread

service/
  packet_analyzer.py       # Scapy dissection IPv4/IPv6/TCP/UDP/ICMP/ICMPv6
  rule_engine.py           # Reguli în RAM cu RLock; reload_rules() pe hot-reload; zone logic
  firewall_actions.py      # accept/drop/ban — ban dedup cu set in-memory
  stats_service.py         # parse_flood_counters() din nft JSON, compute_delta()

detectors/
  flood.py                 # FloodEngine — sliding window per-(IP, protocol)
  honeyport.py             # HoneyportEngine — porturi capcană → ban imediat
  dpi.py                   # DPIEngine — regex signatures Layer 7 (HTTP ports only)

repository/
  base.py                  # AsyncDBWriter — Singleton Producer-Consumer pentru writes
  log_repository.py        # INSERT async; get_filtered_logs(); get_log_counts_by_minute()
  rule_repository.py       # CRUD complet + toggle enabled; _SELECT constant + _row_to_rule()
  blacklist_repository.py  # add/get_all/delete
  stats_repository.py      # get_db_stats/get_kernel_counters/accumulate_kernel_counters

api/
  api_main.py              # create_app() factory: CORS, routes, serve React dist
  schemas.py               # Pydantic schemas (RuleCreate/Response, Log, Blacklist, Stats)
  dependencies.py          # get_rule_engine(), get_firewall_actions() din app.state
  routes/
    rules_route.py         # GET/POST/DELETE/PUT /api/rules + PATCH toggle
    logs_route.py          # GET /api/logs + GET /api/logs/count
    blacklist_route.py     # GET/POST/DELETE /api/blacklist
    stats_route.py         # GET /api/stats

database/
  setup_db.py              # init_db() — CREATE TABLE IF NOT EXISTS + indexes
  CuciSec.db               # fișierul SQLite actual

frontend-cucisec/          # React SPA
  src/
    api/client.ts          # fetcher() wrapper + api object (toate endpoint-urile)
    types/api.ts           # TypeScript interfaces (Rule, LogEntry, BlacklistEntry, Stats)
    hooks/
      useData.ts           # useRules(2s), useLogs(1.5s), useBlacklist(1.5s)
      useStats.ts          # useStats(1s), useLogCounts(1s)
    pages/
      DashboardPage.tsx    # MetricCards + TrafficChart + FloodChart + ThreatDetections
      RulePage.tsx         # RulesTable + AddRuleModal
      BlacklistPage.tsx    # BlacklistTable + AddBanModal
      LogsPage.tsx         # LogsTable
    components/
      layout/Layout.tsx    # Sidebar nav responsiv (icon-only sub lg, text complet la lg+)
      dashboard/           # MetricCard, TrafficChart (Recharts Line), FloodChart (Bar), ThreatDetections
      rules/               # RulesTable (click pe row = edit), AddRuleModal (create + edit mode)
      blacklist/           # BlacklistTable, AddBanModal
      logss/               # LogsTable cu filtre (protocol, action, IP src+dst)
      ui/                  # shadcn/ui components
    App.tsx                # QueryClientProvider + BrowserRouter + routes
```

---

## Pipeline procesare pachete (ordine exactă în interceptor.py)

```
nftables kernel → NFQUEUE → _process_packet()
```

1. **PacketAnalyzer.analyze()** — disecție Scapy → `PacketInfo`; malformed → DROP imediat
2. **RuleEngine.evaluate()** — reguli administrator din RAM (prioritate maximă):
   - Detectează zona pachetului (`_detect_zone()` → LAN/WAN)
   - Parcurge regulile filtrate după zonă, ip_src, ip_dst, protocol, port
   - Dacă găsește ACCEPT → acceptă și returnează (bypass toate detecțiile)
   - Dacă găsește DROP → dropeaza și returnează (bypass toate detecțiile)
3. **FloodEngine.inspect()** — sliding window per-(IP, protocol):
   - Dacă depășește pragul → DROP + BAN imediat
4. **HoneyportEngine.inspect()** — dacă port_dst e în lista honeyports → DROP + BAN imediat
5. **DPIEngine.inspect()** — pe porturile HTTP (80, 8080, 8000, 8443):
   - Normalizează payload (URL-decode + lowercase)
   - Aplică semnăturile regex
   - Dacă match → DROP + BAN imediat
6. **DEFAULT ACCEPT** — dacă niciun detector nu a prins

**Motiv ordine**: RuleEngine primul = administratorul poate override orice decizie automată (whitelist explicit, sau DROP o adresă indiferent de ce fac detectorii).

---

## Model de thread-uri (concurență)

Sistemul rulează cu 4 thread-uri simultan:

| Thread | Ce face | Tip |
|--------|---------|-----|
| **Main thread** | `interceptor.start_interceptor()` — loop blocant NFQUEUE, procesează pachete | Blocant |
| **API thread** | FastAPI + uvicorn pe port 8000, servește requesturi HTTP | Daemon thread |
| **AsyncDBWriter thread** | Consumer al cozii de scrieri SQLite — un singur writer | Thread intern |
| **KernelCounters thread** | Citește contori nftables la interval 10s, acumulează în DB | Daemon thread |

**Thread-safety**: `RuleEngine` folosește `threading.RLock()` pentru acces la lista de reguli. `FirewallActions._banned_ips` (set in-memory) nu are lock explicit — acces din un singur thread (main).

---

## Secvența de boot (firewall_main.py)

```
1. setup_logger()                         — Loguru cu format custom
2. init_db()                              — CREATE TABLE IF NOT EXISTS + indexuri
3. NftablesManager.setup(script_path)     — flush + recreate inet cucisec via nftables_setup.sh
4. BlacklistRepository.get_all_ips()      — citire blacklist din DB
5. NftablesManager.sync_blacklist()       — repopulare seturi kernel blacklist_v4/v6
6. PacketInterceptor()                    — inițializare toți detectorii + FirewallActions
7. NftablesManager.start_counter_snapshot_thread(interval=10)
8. threading.Thread(target=start_api).start()
9. interceptor.start_interceptor()        — loop blocant (main thread)
```

**Observație critică**: La boot, blacklist-ul din DB este re-sincat în kernel. Dacă nftables-ul e restartat între sesiuni, IP-urile banat anterior nu se pierd.

---

## Config important (utils/config.py)

| Parametru | Valoare | Nivel |
|---|---|---|
| QUEUE_NUM | 1 | Python + nftables |
| HONEY_PORTS | 23, 2323, 3389, 4444, 9999 | Python (+ nftables set) |
| TIME_WINDOW | 12.0s | Python FloodEngine |
| MAX_TCP_NEW | 200 pkts/window | Python FloodEngine |
| MAX_UDP_NEW | 250 pkts/window | Python FloodEngine |
| MAX_ICMP | 30 pkts/window | Python FloodEngine |
| LAN_SUBNETS | 10.0.2.0/24, 10.0.3.0/24, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8, fc00::/7, fe80::/10, ::1/128 | Python RuleEngine |

Limitele globale (SYN flood, UDP flood, ICMP flood) sunt **exclusiv în nftables** (nu în Python Config).

---

## Scheme DB

```sql
Rules(id, ip_src, ip_dst, port, protocol, action, description, enabled, zone)
Logs(id, timestamp, ip_src, ip_dst, port_src, port_dst, protocol, action_taken, details)
Blacklist(id, ip UNIQUE, reason, timestamp)
KernelCounters(id=1, tcp_syn, icmp, udp, blacklist, honeyport, last_updated)
```

Indexuri pe Logs: `ip_src`, `timestamp`, `protocol`.

---

## Detalii cheie de implementare

### AsyncDBWriter — Producer-Consumer pentru SQLite
- Singleton: un singur writer thread, indiferent câte module îl importă
- Queue maxsize=10000 — scrieri non-blocking din main thread (nu blochează procesarea pachetelor)
- Toate INSERT-urile din `LogRepository` și `BlacklistRepository` trec prin el
- Motivul: SQLite nu suportă scrieri concurente; fără AsyncDBWriter, `packet.drop()` ar fi blocat așteptând DB

### RuleEngine — Reguli în RAM cu hot-reload
- La boot: `load_rules()` citește din DB și stochează în `self._rules` (list în RAM)
- `threading.RLock()` permite citiri concurente; write (reload) este exclusiv
- La orice CRUD pe reguli via API: se apelează `rule_engine.reload_rules()` → zero downtime
- **Nu există nicio interacțiune cu DB la fiecare pachet** — evaluarea este pur în-memorie

### FirewallActions.ban_ip() — Flow complet al unui ban
```
1. Verifică self._banned_ips (set in-memory) — dacă IP e deja banat, return imediat
2. Adaugă IP în self._banned_ips (deduplicare pentru sesiunea curentă)
3. NftablesManager.ban_ip(ip) → nft add element inet cucisec blacklist_v4/v6 { ip }
4. BlacklistRepository.add(entry) → AsyncDBWriter.execute(INSERT INTO Blacklist)
```
Ordinea 1→2→3→4 garantează că al doilea pachet din același IP (care vine imediat după primul) nu mai trece prin DB sau nftables.

### FloodEngine — Sliding Window
- Structura: `dict[(ip, proto), list[timestamp]]`
- La fiecare pachet: se elimină timestamp-urile mai vechi de TIME_WINDOW, se adaugă `now`, se numără
- Praguri separate pe protocol: TCP=200, UDP=250, ICMP=30 (în 12 secunde)
- Key = `(ip, proto)` — un IP poate face UDP fără să-și consume limita TCP

### DPIEngine — Inspecție Layer 7
- Activă DOAR pe porturile HTTP: 80, 8080, 8000, 8443
- HTTPS (443) este explicit exclus — payload-ul TLS nu poate fi inspectat
- Normalizare: `urllib.parse.unquote_plus(payload).lower()` — prinde payloade URL-encoded
- 17 semnături regex compilate la import (nu la fiecare pachet): SQLi, XSS, CMDi, Path Traversal, RCE, SSRF, Scanner fingerprints
- Primul match → DROP + BAN (nu continuă să verifice alte semnături)

### KernelCounters — Persistența statisticilor nftables
- Thread background pornit cu `interval=10` secunde
- La fiecare tick: citește toți contoarele din `nft -j list ruleset`, calculează delta față de snapshot anterior
- Delta se acumulează în `KernelCounters` (tabel DB cu un singur rând, UPDATE)
- `StatsService.compute_delta()`: dacă counter scăzut (nftables restartat) → delta = valoarea curentă (nu negativ)
- Rezultat: statisticile flood/blacklist supraviețuiesc restarturilor

### NftablesManager — Wrapper nft CLI
- `setup()`: execută `nftables_setup.sh` via `sudo bash`
- `ban_ip(ip)`: `nft add element inet cucisec blacklist_v4/v6 { ip }` — detectează automat IPv4 vs IPv6
- `unban_ip(ip)`: `nft delete element ...`
- `sync_blacklist()`: populează seturi la boot din DB
- `cleanup()`: la shutdown, șterge tabela `inet cucisec` → trafic normal restaurat
- `get_nft_json()`: `nft -j list ruleset` → JSON parsat de StatsService

### Graceful Shutdown
- `SIGINT`/`SIGTERM` → `_signal_handler()` → `stop_interceptor()`:
  1. `nfqueue.unbind()` — eliberează connection la kernel
  2. `AsyncDBWriter().stop()` — trimite sentinel în coadă, așteaptă terminarea writer thread
  3. `NftablesManager.cleanup()` — șterge tabela nftables → trafic trece liber

---

## Zone Logic (IMPLEMENTATĂ COMPLET)

`RuleEngine._detect_zone(ip_src)` determină zona unui pachet:
- Parcurge `Config.LAN_SUBNETS` (10.0.2.0/24, 10.0.3.0/24, RFC1918, loopback, IPv6 ULA/LL)
- Return `"LAN"` dacă IP-ul sursă aparține unui subnet LAN
- Return `"WAN"` altfel

`RuleEngine.evaluate()` filtrează regulile după zonă:
- Regulă `zone=WAN` → se aplică **doar** pachetelor detectate ca WAN
- Regulă `zone=LAN` → se aplică **doar** pachetelor LAN
- Regulă `zone=ANY` → se aplică tuturor

**Observație importantă despre whitelist nftables**: Traficul din subnets 10.0.2.0/24 și 10.0.3.0/24 este acceptat direct în nftables (`ip saddr @whitelist_v4 accept`) **înainte** de NFQUEUE. Deci traficul LAN nu ajunge deloc la RuleEngine — este oprit la nivel kernel.

---

## scripts/nftables_setup.sh

Script bash care configurează întreg ruleset-ul nftables la boot. Rulat de `NftablesManager.setup()` via `sudo bash`. Creează tabela `inet cucisec` cu:

### Sets definite

| Set | Tip | Descriere |
|---|---|---|
| `honey_ports` | `inet_service` | Porturi capcană: 23, 2323, 3389, 4444, 9999 |
| `blacklist_v4/v6` | ipv4/ipv6_addr | IP-uri banat de userspace — **permanente** (fără timeout, unban doar via API) |
| `whitelist_v4/v6` | interval | Subnets de încredere: 127.0.0.0/8, 10.0.2.0/24, 10.0.3.0/24, ::1 |
| `flood_v4/v6` | dynamic, timeout 1m | Flood tracking **per source IP** (kernel) |
| `flood_dst_syn/udp/icmp_v4/v6` | dynamic, timeout 1m | Flood tracking **per destination IP** (contra --rand-source) |

### Chain `input` (protejează VM-ul CuciSec)
- `lo` → accept
- TCP port 22 (SSH) → accept (ct state new/established/related)
- `ct state established,related` → accept; `invalid` → drop
- Port 8000 (API) doar din `whitelist_v4` → accept; altfel → drop cu counter `mgmt_api_block`

### Chain `forward` (tot traficul în tranzit) — ordine exactă

1. **Invalid drop** — `ct state invalid` → drop
2. **Blacklist instant drop** — `blacklist_v4/v6` → drop cu counter `blacklist_drop`
3. **Whitelist bypass** — `whitelist_v4/v6` → accept direct (ocolește NFQUEUE complet)
4. **Global rate limits (DDoS rand-source)**:
   - TCP SYN > 50/s burst 100 → drop (`global_syn_flood`)
   - UDP > 100/s burst 200 → drop (`global_udp_flood`)
   - ICMP/ICMPv6 > 10/s burst 20 → drop (`global_icmp_flood`)
5. **Per-destination flood** (atacuri spre un host specific):
   - SYN > 30/s burst 50 per daddr → drop (`dst_syn_flood`)
   - UDP > 80/s burst 150 per daddr → drop (`dst_udp_flood`)
   - ICMP > 8/s burst 15 per daddr → drop (`dst_icmp_flood`)
6. **HTTP ports** (80, 8080, 8000, 8443) → queue num 1 (DPI în userspace)
7. **Per-source IP flood**:
   - ICMP > 5/s burst 10 → drop (`icmp_flood`)
   - TCP SYN > 20/s burst 40 per saddr → drop (`tcp_syn_flood`)
   - UDP > 200/s burst 250 per saddr → drop (`udp_flood`)
8. **Honeyports** — `tcp dport @honey_ports` → queue num 1 (`honeyport_drop`)
9. **Default** — tot restul → queue num 1

### Observații importante
- Traficul whitelist este acceptat **înainte** de orice rate limit sau NFQUEUE
- Contorii nftables (comments: `blacklist_drop`, `tcp_syn_flood`, etc.) sunt citiți de `StatsService.parse_flood_counters()` pentru statistici
- Seturi `blacklist_v4/v6` fără timeout = ban permanent până la unban explicit via API

---

## Topologie VM pentru testare

```
[Attacker 10.0.5.5]          [CuciSec]                  [Client 10.0.3.5]
 NAT Network WAN    <->   enp0s8 | enp0s9   <->          NAT Network LAN
  (10.0.5.x)            10.0.5.10 | 10.0.3.10            (10.0.3.x)
                         enp0s3: 10.0.2.x (NAT simplu — internet + SSH PyCharm)
```

Tot traficul Attacker → Client trece **obligatoriu** prin CuciSec (forward chain).

### Interfețe CuciSec
| Interfață | IP | Rol |
|---|---|---|
| enp0s3 | 10.0.2.x | NAT simplu VirtualBox — internet + SSH PyCharm/IDE |
| enp0s8 | 10.0.5.10 | NAT Network WAN — legătură cu Attacker |
| enp0s9 | 10.0.3.10 | NAT Network LAN — legătură cu Client |

### Pornire sistem
```bash
# Pe CuciSec (VM)
sudo venv/bin/python firewall_main.py

# Pe Client — necesită Apache2 pornit pentru testele HTTP
sudo systemctl start apache2
```

---

## Scenarii de testare și rezultate așteptate

### T1 — Ping basic (conectivitate)
```bash
# Pe Attacker
ping 10.0.5.10    # CuciSec WAN — răspunde direct, nu trece prin forward
ping 10.0.3.5     # Client prin CuciSec
```
**Rezultat așteptat**: Ping trece, în Logs apare `10.0.5.5 → 10.0.3.5 ICMP ACCEPT`.

**Observație importantă**: Dacă pingui de pe Client spre Attacker (`ping 10.0.5.5`), în Logs **nu apar** pachetele Client→Attacker (Echo Request de la Client), ci apar Attacker→Client (Echo Reply de la Attacker). Motivul: subrețeaua 10.0.3.0/24 (Client) e în `whitelist_v4` nftables → pachetele de la Client sunt acceptate direct în kernel, fără să ajungă la NFQUEUE. Pachetele de la Attacker (10.0.5.5) nu sunt whitelisted → trec prin NFQUEUE → sunt lograte.

### T2 — HTTP normal
```bash
curl http://10.0.3.5
```
**Rezultat așteptat**: `200 OK`, în Logs apare `10.0.5.5 → 10.0.3.5:80 TCP ACCEPT DEFAULT_ACCEPT`.

### T3 — DDoS SYN flood cu rand-source (nftables)
```bash
sudo hping3 -S -p 80 --flood --rand-source 10.0.3.5
```
**Rezultat așteptat**: Kernel dropează > 50 SYN/s (global_syn_flood). Client nu primește nimic. Counter `tcp_syn_flood_dropped` crește în dashboard. FloodEngine userspace nu e implicat (IP-urile sursă sunt random → nicio sursă nu acumulează 200 pachete în 12s).

### T4 — DoS SYN flood per-IP (FloodEngine userspace)
```bash
sudo hping3 -S -p 80 --flood 10.0.3.5
```
**Rezultat așteptat**: Primele ~50 pachete trec la nivel nftables (burst), următoarele sunt droppate de `tcp_syn_flood`. Dacă totuși unele ajung la NFQUEUE, FloodEngine le numără → după 200 pachete în 12s → BAN → IP-ul apare în Blacklist → toate pachetele ulterioare sunt droppate direct în kernel.

### T5 — SQL Injection via DPI
```bash
curl "http://10.0.3.5/?id=1%20UNION%20SELECT%20*%20FROM%20users"
```
**Rezultat așteptat**: DPI normalizează (`%20` → spațiu), detectează `UNION SELECT` → DROP + BAN. Log: `action_taken=DROP, details=DPI_DROP: DPI HIT: SQLi: UNION SELECT`.

### T6 — Honeyport
```bash
nc 10.0.3.5 4444    # sau telnet 10.0.3.5 23
```
**Rezultat așteptat**: Pachetul ajunge la userspace (queue num 1 din nftables), HoneyportEngine detectează port 4444 → DROP + BAN imediat.

### T7 — Unban manual din dashboard
- Click pe iconița de unban din BlacklistPage sau LogsPage → API DELETE /api/blacklist/{ip}
- **Rezultat așteptat**: IP șters din DB + șters din setul nftables blacklist_v4 → trafic din acel IP trece din nou.

### T8 — Hot-reload reguli (fără restart)
- Adaugă o regulă DROP pe portul 22 din RulesPage → API POST /api/rules
- **Rezultat așteptat**: API apelează `rule_engine.reload_rules()`, noua regulă e activă imediat → SSH-urile ulterioare sunt droppate.

### T9 — SQL Injection cu IP spoofat (hping3)
```bash
# Pe Attacker: creează atac.txt cu request HTTP complet
echo -e "GET /?id=1 UNION SELECT * FROM users HTTP/1.0\r\nHost: 10.0.3.5\r\n\r\n" > atac.txt
sudo hping3 --spoof 1.2.3.4 -p 80 -d $(stat -c %s atac.txt) -E atac.txt -c 1 10.0.3.5
```
**Rezultat așteptat**: DPI detectează SQLi → BAN pe 1.2.3.4 (IP-ul spoofat). Demonstrează că sistemul banează IP-ul perceput ca sursă, nu neapărat cel real.

---

## Observații tehnice interesante (utile pentru teză)

### Dual-layer IPS — kernel + userspace
Sistemul are două straturi independente de detecție flood:
- **Kernel (nftables)**: Global rate limits + per-destination (defeat --rand-source). Rapid, zero overhead Python, dar fără memorie între sesiuni.
- **Userspace (FloodEngine)**: Per-source persistent, cu sliding window. Mai lent, dar poate bana IP-uri și îmbunătăți sesiunile viitoare prin DB sync.

### RuleEngine ca priority override
RuleEngine evaluează **înaintea** oricărui detector automat. Dacă un administrator adaugă o regulă `ACCEPT` pentru un IP, acel IP va fi acceptat chiar dacă ar fi declanșat FloodEngine sau DPI. Invers, o regulă `DROP` are prioritate față de orice altceva.

### AsyncDBWriter vs. SQLite WAL
SQLite în mod implicit blochează la scrieri. WAL mode permite citiri concurente pe durata unui write, dar tot există un singur writer. AsyncDBWriter elimină necesitatea ca thread-ul principal (care procesează pachete la sute/secundă) să aștepte vreodată DB-ul.

### DPI normalizare URL-encoding
Atacatorii trimit frecvent payloade encoded (`%20UNION%20SELECT`). DPI aplică `urllib.parse.unquote_plus()` **înainte** de regex → semnăturile funcționează indiferent de encoding.

### KernelCounters delta cu restart-proof
`compute_delta()` verifică dacă counter-ul actual e mai mic decât cel anterior (semn că nftables a fost restartat). În loc să calculeze un delta negativ, folosește valoarea curentă ca delta. Astfel statisticile nu "sar" la valori negative după restart.

### Blacklist sync la boot
La fiecare pornire, sistemul re-sincronizează blacklist-ul din DB în kernel (`sync_blacklist()`). IP-urile banat în sesiuni anterioare rămân blocate fără nicio intervenție manuală.

### ICMP type în câmpul port
`PacketAnalyzer` stochează ICMP type în `port_dst` și ICMP code în `port_src`. La afișare în frontend, LogsTable recunoaște protocolul ICMP/ICMPv6 și afișează numele tipului (`Echo Request`, `Echo Reply`, `Neighbor Solicitation`) în loc de număr.

---

## Frontend stack

- React 19 + TypeScript + Vite
- TanStack Query (React Query) pentru data fetching + polling
- shadcn/ui (Radix UI primitives + Tailwind CSS v4)
- react-hook-form + zod pentru validare formulare
- Recharts pentru grafice (TrafficChart = Line, FloodChart = Bar)
- React Router v7 pentru routing SPA
- Sonner pentru toast notifications

### Polling intervals
| Hook | Interval |
|---|---|
| useStats | 1000ms |
| useLogCounts | 1000ms |
| useLogs | 1500ms |
| useBlacklist | 1500ms |
| useRules | 2000ms |

---

## Cum se pornește

```bash
# Backend (necesită root pentru nftables + NFQUEUE)
sudo python firewall_main.py

# Frontend dev
cd frontend-cucisec
pnpm dev  # sau pnpm install mai întâi

# Frontend build pentru producție
pnpm build
# după build, FastAPI servește automat din dist/
```

---

## DPI Signatures (detectors/dpi.py)

Inspectează doar porturile HTTP: 80, 8080, 8000, 8443. Sare peste HTTPS (443).

| Categorie | Exemple de semnături |
|---|---|
| SQLi | `UNION SELECT`, `DROP TABLE`, `' OR '1'='1`, `OR condition` |
| XSS | `<script>`, `javascript:`, event handlers (`onclick=`, `onerror=`) |
| Command Injection | `; cat`, `; whoami`, `| wget` |
| Path Traversal | `../../`, `/etc/passwd` |
| RCE | Log4Shell `${jndi:ldap://}`, `system()`, `exec()`, `cmd.exe`, `powershell -` |
| SSRF | `localhost`, `127.0.0.1`, `169.254.169.254` (AWS metadata) |
| Scanner fingerprints | User-Agent: `sqlmap`, `nikto`, `masscan`, `nuclei`, `zgrab`, `nmap` |

Total: 17 semnături regex compilate o singură dată la import.
