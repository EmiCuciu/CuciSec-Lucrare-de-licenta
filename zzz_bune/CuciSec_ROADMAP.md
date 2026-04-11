# CuciSec Firewall — Roadmap

## Rezumat Progress

| Epic | Status | Componente |
|------|--------|------------|
| Epic 1: Infrastructura de Baza | Finalizat | DB schema + nftables script |
| Epic 2: Core Engine | Finalizat | Interceptor, Analyzer, Actions, Boot sync |
| Epic 3: Security Detectors | Finalizat | RuleEngine, Honeyport, FloodEngine, DPI |
| Epic 4: Backend API | Finalizat | FastAPI, toate endpoint-urile, schemas |
| Epic 5: Web UI | In progres | index.html placeholder, structura frontend/ |
| Epic 6: Testare si Topologie | Urmeaza | 3 VM-uri, teste, benchmark |

---

## Epic 1 — Infrastructura de Baza

**Obiectiv:** Fundatia pe care ruleaza intreaga aplicatie.

### Task 1.1: Schema bazei de date SQLite
**Status: Finalizat**
**Fisier:** `database/setup_db.py`

Tabele create: Rules (cu camp `zone` pentru zone-based filtering), Logs, Blacklist.
Indexuri create: `idx_logs_ip_src`, `idx_logs_timestamp`, `idx_logs_protocol`.
Mod WAL activat pentru citiri concurente.

### Task 1.2: Scriptul de initializare nftables
**Status: Finalizat (hook input pentru teste, hook forward pentru Epic 6)**
**Fisier:** `scripts/nftables_setup.sh`

Seturi create: `blacklist_v4/v6` (timeout 24h), `flood_v4/v6` (dynamic, timeout 1m), `honey_ports`.
Reguli implementate: blacklist drop O(1), anti-flood per protocol, honeyport cu counter, Selective DPI (HTTP/8080 mereu in NFQUEUE), SSH cu `established` (payload criptat), catch-all NFQUEUE.
Toate regulile de DROP includ `counter` pentru observabilitate din `/api/stats`.

---

## Epic 2 — Core Engine

**Obiectiv:** Motorul de interceptare si procesare a pachetelor.

### Task 2.1: PacketInterceptor
**Status: Finalizat**
**Fisier:** `infrastructure/interceptor.py`

Binding NFQUEUE cu `max_len=8192`. Fluxul de procesare: FloodEngine -> RuleEngine -> Honeyport -> DPI -> Default Accept. Signal handler SIGINT/SIGTERM cu graceful shutdown (cleanup nftables la oprire).

### Task 2.2: PacketAnalyzer
**Status: Finalizat**
**Fisier:** `service/packet_analyzer.py`

Detectie versiune IP din primul nibble (O(1), inainte de Scapy). Suport dual-stack IPv4/IPv6. Decapsulare Layer 3-7: IP, TCP/UDP/ICMP/ICMPv6, Raw payload pentru DPI.

### Task 2.3: FirewallActions
**Status: Finalizat**
**Fisier:** `service/firewall_actions.py`

Pattern Producer-Consumer pentru async logging (thread daemon). Cache `_banned_ips` preincarca la boot. Toate apelurile subprocess cu liste (nu `shell=True`).

### Task 2.4: AsyncDBWriter Singleton
**Status: Finalizat**
**Fisier:** `repository/base.py`

Singleton cu `threading.Lock()`. O singura conexiune SQLite persistenta pe thread dedicat. Oprire gracefully prin sentinel value. `maxsize=10000` pentru prevenire memory leak.

### Task 2.5: Sincronizare Blacklist la Boot
**Status: Finalizat**
**Fisier:** `firewall_main.py`

Ordinea de boot: DB -> nftables -> sync blacklist -> start interceptor (previne Race Condition). Batch processing: o singura sesiune nft pentru toate IP-urile (O(1) fork vs O(N)).

---

## Epic 3 — Security Detectors

**Obiectiv:** Logica de securitate avansata.

### Task 3.1: RuleEngine (In-Memory)
**Status: Finalizat**
**Fisier:** `service/rule_engine.py`

Reguli incarcate o singura data la boot in RAM. Hot-Reload prin `reload_rules()` fara restart. Suport CIDR (192.168.1.0/24) prin modulul `ipaddress`. Zone-based filtering prin campul `zone`. Returneaza Tuple `(action, zone)` pentru separare clara a responsabilitatilor.

### Task 3.2: HoneyportEngine
**Status: Finalizat**
**Fisier:** `detectors/honeyport.py`

Porturi capcana: 23 (Telnet), 2323 (Mirai), 3389 (RDP), 4444 (Metasploit), 9999. Detectie pe TCP si UDP. Orice atingere -> ban instant.

### Task 3.3: FloodEngine (Behavioral Analysis)
**Status: Finalizat**
**Fisier:** `detectors/flood.py`

Fereastra glisanta de 12 secunde (valoare deliberata pentru observabilitate grafic). Praguri: 200 TCP, 250 UDP, 30 ICMP. Thread-safety cu `threading.Lock()`. Lazy Cleanup la 60 secunde (previne memory leak fara thread separat).

### Task 3.4: DPIEngine
**Status: Finalizat**
**Fisier:** `detectors/dpi.py`

Signature-based detection cu regex pre-compilate la `__init__`. Semnatura detectate: SQLi (UNION SELECT, OR 1=1, DROP TABLE), XSS (script tag), Path Traversal (/etc/passwd), RCE (cmd.exe), scanere (nmap, nikto). Flag `re.IGNORECASE` pentru variante de majuscule.

---

## Epic 4 — Backend API

**Obiectiv:** Expunerea datelor pentru interfata vizuala.

### Task 4.1: FastAPI App
**Status: Finalizat**
**Fisier:** `api/api_main.py`

Factory function `create_app(rule_engine)`. CORS configurat. `app.state.rule_engine` pentru Hot-Reload prin Dependency Injection. `StaticFiles` pentru servirea frontend-ului din acelasi server. API ruleaza in thread daemon paralel cu firewall-ul.

### Task 4.2: Endpoint-uri Rules (CRUD + Hot-Reload)
**Status: Finalizat**
**Fisier:** `api/routes/rules_route.py`

- `GET /api/rules` — lista toate regulile
- `POST /api/rules` — adauga regula noua + Hot-Reload automat
- `DELETE /api/rules/{id}` — sterge regula + Hot-Reload
- `PATCH /api/rules/{id}/toggle` — activeaza/dezactiveaza

### Task 4.3: Endpoint-uri Logs
**Status: Finalizat**
**Fisier:** `api/routes/logs_route.py`

- `GET /api/logs` — logs paginate cu filtre optionale (protocol, action, ip_src, skip, limit)
- `GET /api/logs/count` — numarul de logs grupat pe minute (ultimele 30 minute) pentru graficul live

### Task 4.4: Endpoint-uri Blacklist
**Status: Finalizat**
**Fisier:** `api/routes/blacklist_route.py`

- `GET /api/blacklist` — lista IP-uri blocate
- `POST /api/blacklist` — ban manual
- `DELETE /api/blacklist/{ip}` — unban manual

### Task 4.5: Endpoint-uri Stats
**Status: Finalizat**
**Fisier:** `api/routes/stats_route.py`, `service/stats_service.py`

- `GET /api/stats` — statistici combinate: total/acceptate/droppate din DB + contoare flood din nftables Kernel + ultimele 5 ban-uri

### Task 4.6: Pydantic Schemas
**Status: Finalizat**
**Fisier:** `api/schemas.py`

Validare si normalizare pentru toate endpoint-urile. Validatori custom pentru `action` (ACCEPT/DROP), `protocol` (TCP/UDP/ICMP/ICMPv6), `port` (1-65535). `ConfigDict(from_attributes=True)` pentru compatibilitate cu dataclasses.

---

## Epic 5 — Web UI (Dashboard)

**Obiectiv:** Interfata vizuala pentru administrare si monitorizare.

### Task 5.1: Layout de baza HTML/Bootstrap
**Status: Urmeaza**
**Fisier:** `frontend/index.html`

Structura Bootstrap 5 (CDN):
- Sidebar cu navigare (Dashboard, Reguli, Loguri, Blacklist)
- Card-uri pentru metrici principale (Total logs, Acceptate, Droppate, IP-uri blocate)
- Tabel pentru loguri recente
- Zona grafice

### Task 5.2: Grafice Chart.js (Live Traffic + Flood Spike)
**Status: Urmeaza**
**Fisier:** `frontend/app.js`

Grafic principal (Line Chart): trafic acceptat vs droppat pe minute, date din `GET /api/logs/count`, actualizat la 2 secunde.

Grafic flood (Bar Chart): contoare din `GET /api/stats` -> `flood_counters`, date din Kernel direct (nu din DB), actualizat la 1 secunda. Spike-ul vizual apare in timpul unui atac flood.

Logica de polling diferential pentru toast notifications: daca `banned_ips` creste fata de ultima citire, se afiseaza notificare "IP banned automatically by IPS!".

### Task 5.3: Tabel Reguli cu CRUD
**Status: Urmeaza**
**Fisier:** `frontend/rules.js`

Tabel dinamic cu reguli din `GET /api/rules`. Formular modal pentru adaugare regula noua (IP/CIDR, port, protocol, action, zone, description). Buton toggle enable/disable per regula. Buton stergere cu confirmare.

### Task 5.4: Tabel Loguri cu Filtrare
**Status: Urmeaza**
**Fisier:** `frontend/logs.js`

Tabel cu paginare. Filtre: protocol, action, ip_src. Actualizare automata la interval. Colorare conditionata (rosu pentru DROP, verde pentru ACCEPT).

### Task 5.5: Blacklist Management + BAN Manual
**Status: Urmeaza**
**Fisier:** `frontend/blacklist.js`

Tabel IP-uri blocate cu motivul si timestamp-ul banului. Buton BAN manual (POST /api/blacklist). Buton UNBAN (DELETE /api/blacklist/{ip}).

---

## Epic 6 — Testare, Topologie si Benchmark

**Obiectiv:** Validarea sistemului in conditii reale si documentarea performantei.

### Task 6.1: Configurare Topologie Network IPS (3 VM-uri)
**Status: Urmeaza**
**Mediu:** VirtualBox

Configurare VM-uri:
- VM1 (Firewall - Ubuntu Server): Adapter 1 = NAT Network (WAN/Atacator), Adapter 2 = Internal Network "LAN_Victima" (LAN)
- VM2 (Atacator - Kali Linux): Adapter 1 = NAT Network
- VM3 (Victima - Ubuntu Desktop): Adapter 1 = Internal Network "LAN_Victima"

Modificari cod pentru Network IPS:
- `nftables_setup.sh`: `chain input` -> `chain forward`, adaugare reguli per-interfata (enp0s3 WAN, enp0s8 LAN)
- `firewall_main.py`: activare IP forwarding (`sysctl net.ipv4.ip_forward=1`)

### Task 6.2: Teste Functionale de Securitate (Pen-Test)
**Status: Urmeaza**
**Fisier:** `tests/security_tests.sh`

De pe VM Atacator (Kali Linux):

Test 1 — Honeyport:
```bash
nmap -p 23,2323,3389,4444 <firewall_ip>
# Asteptat: IP-ul Kali apare automat in blacklist
```

Test 2 — DPI (SQL Injection):
```bash
curl "http://<victima_ip>/?id=1+UNION+SELECT+*+FROM+users"
# Asteptat: pachetul e droppat, IP-ul Kali e banat
```

Test 3 — Flood Detection:
```bash
hping3 -S -p 80 --flood <victima_ip>
# Asteptat: graficul Dashboard afiseaza spike, dupa 12s IP-ul e banat definitiv
```

Test 4 — Regula statice zona GUEST:
```bash
# Adauga regula: 192.168.50.0/24 DROP GUEST
# Trimite pachet de la IP din acea retea
# Asteptat: DROP cu label RULE_ENGINE_DROP_GUEST
```

### Task 6.3: Benchmark Performanta (Stress Test)
**Status: Urmeaza**
**Fisier:** `tests/benchmark.sh`

Metodologie:
1. Masoara throughput normal (fara atac): `iperf3 -c <victima_ip>`
2. Lanseaza atac flood: `hping3 -S --flood <victima_ip>`
3. Masoara throughput in timpul atacului (sa demonstreze ca nftables absoarbe atacul, victima ramane accesibila)
4. Masoara latenta: `ping <victima_ip>` inainte/in timpul/dupa atac
5. Monitorizeaza CPU/RAM: `top`, `htop`

Grafice de salvat pentru Capitolul 7 al tezei:
- Throughput (Mbps) in timp: linie stabila + atac flood (drop neglijabil)
- Contoare nftables in timp: spike dramatic la flood, revenire la zero dupa ban
- CPU usage: demonstreaza ca Python-ul nu este suprasolicitata (Kernel absoarbe bulk-ul)

### Task 6.4: Documentarea Capitolelor Practice (Word)
**Status: Urmeaza**

Capitolul 7 (Validare si Testare):
- Descrierea topologiei cu diagrama VirtualBox
- Screenshot-uri cu atacurile si reactiile sistemului
- Graficele de benchmark cu interpretare
- Comparatie throughput cu/fara firewall

Capitolul 8 (Concluzii):
- Limitari curente: un singur CPU core (queue num 1), procesare NFQUEUE single-threaded
- Directii viitoare: Multiple Queues (fanout), Machine Learning pentru anomaly detection, portare pe OpenWrt/Raspberry Pi

---

## Dependente intre Epic-uri

```
Epic 1 (DB + nftables)
    <- Epic 2 (Core Engine, necesita DB si nftables)
        <- Epic 3 (Detectors, necesita Core Engine)
            <- Epic 4 (API, necesita DB si RuleEngine)
                <- Epic 5 (UI, necesita API)
                    <- Epic 6 (Testare, necesita tot)
```

## Note Tehnice

**Schimbarea la Network IPS (Epic 6):**

Singura modificare necesara in scriptul nftables:
```nft
# inainte (Host IPS)
chain input { type filter hook input priority 0; ... }

# dupa (Network IPS)
chain forward { type filter hook forward priority 0; ... }
```

Plus adaugarea regulilor per-interfata pentru zone-based:
```nft
# WAN -> LAN: toata logica de securitate
iifname "enp0s3" oifname "enp0s8" ...

# LAN -> WAN: acceptat direct
iifname "enp0s8" oifname "enp0s3" ct state established,related accept
```

**Endpoint-uri API complete:**

```
GET    /api/rules
POST   /api/rules              + Hot-Reload automat
DELETE /api/rules/{id}         + Hot-Reload automat
PATCH  /api/rules/{id}/toggle  + Hot-Reload automat

GET    /api/logs?limit=50&skip=0&protocol=TCP&action=DROP&ip_src=...
GET    /api/logs/count         <- date pentru graficul live

GET    /api/blacklist
POST   /api/blacklist          <- ban manual
DELETE /api/blacklist/{ip}     <- unban manual

GET    /api/stats              <- DB stats + nftables flood counters + recent bans

GET    /docs                   <- Swagger UI auto-generat de FastAPI
GET    /                       <- Dashboard HTML (servit din frontend/)
GET    /api                    <- health check
```
