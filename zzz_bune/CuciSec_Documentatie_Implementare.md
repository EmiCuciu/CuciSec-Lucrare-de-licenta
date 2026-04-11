# CuciSec — Documentatie Implementare
**Lucrare de Licenta | Cuciurean Emilian-Petrut | UBB Cluj-Napoca**

Acest document urmareste pas cu pas deciziile tehnice si implementarile realizate, incluzand rationamentul din spatele fiecarei decizii arhitecturale. Corespunde structurii practice a lucrarii (Capitolele 4-6).

---

## Arhitectura Generala

### Structura pe Layere (Layered Architecture)

**Rationament:** Orice sistem software care creste in complexitate are nevoie de o separare clara a responsabilitatilor. Fara aceasta separare, un bug intr-un modul de retea ar putea sa afecteze logica de securitate, iar o eroare in baza de date ar putea sa blocheze procesarea pachetelor.

```
cucisec/
├── domain/           # Layer 1: Modele de date pure, fara logica
├── repository/       # Layer 2: Acces la date, doar operatii DB
├── detectors/        # Layer 3: Detectoare de securitate, logica pura
├── service/          # Layer 4: Business Logic (orchestrare)
├── infrastructure/   # Layer 5: Interactiuni cu exteriorul (NFQUEUE, nft)
├── api/              # Layer 6: Prezentare (FastAPI)
├── database/         # Schema si initializare DB
├── scripts/          # Scripturi Kernel (nftables)
└── utils/            # Configurare si logging
```

Fiecare layer cunoaste doar layerul imediat inferior. `service/` apeleaza `repository/`, dar nu cunoaste detaliile SQL. `infrastructure/` apeleaza `service/`, dar nu stie cum sunt stocate datele. Daca schimbi SQLite cu PostgreSQL, modifici doar `repository/`, restul sistemului nu se schimba.

### Separarea Data Plane / Control Plane

**Rationament:** Un firewall software pur (totul in Python) ar fi vulnerabil la atacuri masive — un flood de 100.000 pachete/secunda ar bloca procesul Python, consumand 100% CPU, si serverul ar cadea. Un firewall pur Kernel (doar nftables) ar fi rapid, dar nu ar putea face analiza inteligenta la Layer 7.

**Solutia hibrida adoptata:**

- **Data Plane (Kernel / nftables):** executa decizii instantanee fara overhead. Blocheaza flood-ul direct la placa de retea, mentine blacklist-ul cu lookup O(1) prin hash-table-uri.
- **Control Plane (Userspace / Python):** primeste un flux controlat de pachete prin NFQUEUE, aplica logica inteligenta (RuleEngine, DPI, Honeyport, FloodEngine).

---

## Epic 1 — Infrastructura de Baza

### 1.1 Schema Bazei de Date SQLite

**Fisier:** `database/setup_db.py`

**Rationament pentru SQLite vs SGBD clasic:**

Un SGBD clasic (PostgreSQL) necesita un proces de fundal separat, administrare, configurare de conexiuni. SQLite este serverless, integrat nativ in Python, si ofera performanta excelenta pentru volumul de date specific unui firewall de retea locala. Dezavantajul (scrierile serializate) este rezolvat prin async logging.

**Modul WAL (Write-Ahead Logging):**

Fara WAL, SQLite blocheaza tabelul la fiecare scriere — imposibil de citit logurile din API in timp ce firewall-ul scrie. WAL permite citiri concurente in timp ce o scriere este in curs.

**Tabela `Rules`:**

Campul `zone` (TEXT DEFAULT 'WAN') a fost adaugat pentru a suporta zone-based firewalling (LAN trusted, WAN untrusted, GUEST restrictionat). Campul `enabled` permite dezactivarea temporara fara stergere, util pentru debugging.

| Camp | Tip | Rationament |
|---|---|---|
| `id` | INTEGER PK | Necesar pentru CRUD din API (DELETE /rules/{id}) |
| `ip_src` | TEXT nullable | NULL = wildcard, regula se aplica pentru orice IP, suporta CIDR (192.168.1.0/24) |
| `port` | INTEGER nullable | NULL = orice port |
| `protocol` | TEXT nullable | NULL = orice protocol |
| `action` | TEXT NOT NULL | Strict ACCEPT sau DROP, validat si la nivel Pydantic |
| `description` | TEXT | Documentare regula |
| `enabled` | INTEGER | 1/0, permite dezactivare fara stergere |
| `zone` | TEXT | LAN / WAN / GUEST pentru zone-based filtering |

**Tabela `Logs`:**

Campul `details` este vital pentru DPI. Cand un pachet este blocat cu semnatura SQL Injection, in `details` se stocheaza exact ce semnatura a fost detectata. Fara acest camp, administratorul ar sti ca s-a intamplat un DROP, dar nu de ce.

**Tabela `Blacklist`:**

Constrangerea `UNIQUE` pe `ip` este deliberata — daca acelasi IP este detectat de doua module simultan, `INSERT OR IGNORE` previne dublarea fara eroare.

**Indexuri:**

Query-urile din API filtreaza frecvent dupa `ip_src`, `timestamp` si `protocol`. Fara indexuri, un SELECT cu WHERE pe milioane de loguri face full table scan.

```python
cursor.execute('CREATE INDEX IF NOT EXISTS idx_logs_ip_src ON Logs (ip_src)')
cursor.execute('CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON Logs (timestamp)')
cursor.execute('CREATE INDEX IF NOT EXISTS idx_logs_protocol ON Logs (protocol)')
```

---

### 1.2 Scriptul de Initializare nftables

**Fisier:** `scripts/nftables_setup.sh`

**Rationament pentru nftables vs iptables:**

iptables evalueaza regulile secvential (O(N)). La 100 de reguli si 100.000 pachete/secunda, Kernel-ul face 10 milioane de comparatii pe secunda. nftables foloseste hash-table-uri cu lookup O(1) — indiferent de cate IP-uri sunt in blacklist, verificarea dureaza acelasi timp.

**Formatul declarativ (`nft -f -`):**

Comenzile bash secventiale nu sunt atomice. Daca scriptul esueaza la jumatate, firewall-ul ramane intr-o stare inconsistenta. Formatul declarativ este aplicat atomic: fie totul, fie nimic.

**Seturile definite:**

`blacklist_v4/v6` cu `flags timeout; timeout 24h;` — IP-urile blocate dispar automat dupa 24 ore fara interventie Python. Auto-Unban implementat gratuit de nftables.

`flood_v4/v6` cu `flags dynamic, timeout; timeout 1m;` — seturi dinamice in care Kernel-ul insereaza automat IP-uri care depasesc limita de rata. Dupa 1 minut de inactivitate, intrarea expira.

**Ordinea regulilor si rationamentul:**

```
1. iifname "enp0s8" accept      <- traficul LAN (trusted) acceptat inainte de orice filtrare
2. SSH accept                    <- administratorul nu trebuie blocat de propriile reguli
3. ct state invalid drop         <- pachete malformate, fara analiza suplimentara
4. blacklist drop (O1)           <- IP-uri deja cunoscute ca malitioase, instant drop
5. Anti-flood (ICMP/TCP/UDP)    <- OBLIGATORIU inainte de established (altfel flood pe conexiuni existente trece liber)
6. Honeyport -> NFQUEUE          <- counter propriu pentru /api/stats
7. HTTP/8080 -> NFQUEUE          <- DPI obligatoriu, ignora established
8. ICMP -> NFQUEUE
9. ct state established accept   <- offloading pentru restul traficului
10. catch-all -> NFQUEUE         <- conexiuni noi necunoscute spre Python
```

Anti-flood INAINTE de `established accept` este o decizie critica. Daca floodul ar fi dupa `established`, un atacator cu o conexiune TCP deja stabilita ar putea face flood UDP sau ICMP fara sa fie oprit.

**Selective DPI — de ce SSH trece cu `established` dar HTTP nu:**

`ct state established,related accept` global este o vulnerabilitate. Scenariul: atacatorul face TCP handshake curat (ESTABLISHED), apoi trimite SQL Injection in payload. Daca `established` ar fi inaintea NFQUEUE, DPI nu ar vedea niciodata acest pachet.

Solutia: porturile de mare risc (80, 8080) merg MEREU in NFQUEUE. SSH (22) beneficiaza de `established accept` in Kernel — payload-ul SSH este criptat, DPI nu poate extrage nimic util, inspectia ar consuma CPU fara beneficiu.

**Observabilitate prin `counter`:**

Fiecare regula de DROP include `counter`. Kernel-ul numara pachetele aruncate fara sa le trimita in Python. Endpoint-ul `/api/stats` citeste aceste contoare via `nft -j list ruleset` si le trimite Dashboard-ului. Un atac flood care genereaza milioane de DROP-uri este vizibil pe grafic fara niciun overhead Python.

**Nota pentru trecerea la Network IPS (Epic 6):**

Scriptul actual foloseste `hook input` — intercepteaza doar traficul destinat firewall-ului (Host-Based IPS). Pentru topologia cu 3 VM-uri, schimbarile necesare sunt:

```nft
# SCHIMBARE PENTRU NETWORK IPS:
# hook forward intercepteaza traficul care TRANZITEAZA firewall-ul

chain forward {
    type filter hook forward priority 0; policy accept;

    # WAN -> LAN: toata logica de securitate
    iifname "enp0s3" oifname "enp0s8" ...

    # LAN -> WAN: acceptat direct (trafic initiat din interior)
    iifname "enp0s8" oifname "enp0s3" ct state established,related accept
}
```

Si activarea IP forwarding pe Ubuntu:
```bash
sudo sysctl -w net.ipv4.ip_forward=1
echo "net.ipv4.ip_forward=1" | sudo tee -a /etc/sysctl.conf
```

---

## Epic 2 — Core Engine

### 2.1 PacketInterceptor

**Fisier:** `infrastructure/interceptor.py`

**Rationament pentru Single Responsibility:**

`PacketInterceptor` face un singur lucru: leaga aplicatia de NFQUEUE si orchestreaza fluxul. Nu contine logica de securitate, nu face operatii DB, nu construieste raspunsuri HTTP. Aceasta face codul testabil si usor de intretinut.

**Parametrul `max_len=8192`:**

Valoarea implicita este 1024. Sub atac, coada se umple rapid si Kernel-ul dropa pachete fara niciun log. 8192 ofera o fereastra mai larga fara a consuma excesiv RAM.

**Ordinea detectorilor si rationamentul:**

```
FloodEngine     <- primul, pentru atacatori activi deja cunoscuti
RuleEngine      <- reguli statice din RAM (fara acces la disc)
HoneyportEngine <- detectie porturi capcana
DPIEngine       <- analiza payload (cel mai costisitor, ultimul)
Default Accept  <- daca niciun detector nu a actionat
```

FloodEngine este primul pentru ca, daca un IP face flood, nu are sens sa il treci prin toti ceilalti detectori — decizia este clara.

**Graceful shutdown:**

Fara signal handler, Ctrl+C lasa NFQUEUE legat si nftables activ. Pachetele ar continua sa fie trimise in coada, dar nimeni nu le-ar prelua — traficul de retea ar fi blocat. `NftablesManager.cleanup()` sterge tabela `cucisec` la shutdown, restaurand comportamentul normal al retelei.

### 2.2 PacketAnalyzer

**Fisier:** `service/packet_analyzer.py`

**Rationament pentru detectia versiunii IP din primul nibble:**

```python
version = raw_payload[0] >> 4
```

O optimizare fata de instantierea imediata Scapy. Verificarea nibble-ului superior este O(1) si elimina rapid pachetele non-IP fara overhead Scapy.

**Tratarea ICMP fara porturi:**

ICMP nu are porturi. Campul `port_dst` este reutilizat pentru tipul mesajului ICMP (`type 8` = echo request, `type 0` = echo reply). Aceasta permite RuleEngine-ului sa scrie reguli ICMP folosind acelasi mecanism ca pentru TCP/UDP.

### 2.3 FirewallActions

**Fisier:** `service/firewall_actions.py`

**Rationament pentru Producer-Consumer:**

Daca fiecare pachet ar genera o scriere sincrona in SQLite, la 10.000 pachete/secunda s-ar produce:
1. Scrierile SQLite dureaza ~1ms fiecare
2. Coada NFQUEUE se umple (8192 slots)
3. Kernel-ul dropa pachete fara analiza
4. Firewall-ul devine efectiv inoperabil

Solutia: thread daemon dedicat (`AsyncDBWriter`) preia scrierile dintr-o coada in-memory si le executa asincron. Thread-ul principal returneaza verdictul Kernel-ului **imediat**, fara sa astepte confirmarea scrierii.

**Rationament pentru `maxsize=10000`:**

O coada fara limita este un potential memory leak. La 10.000 de intrari, coada consuma ~5-10MB RAM. Daca se atinge limita, `put_nowait` arunca exceptie (logata), dar verdictul de retea nu este afectat.

**Cache `_banned_ips` in RAM:**

```python
existing = self._blacklist_repo.get_all_ips()
self._banned_ips: set = set(existing)
```

Prevenire duplicate `nft add element` si citiri DB inutile. Verificarea este O(1) pe un `set` Python. Cache-ul este preincarca la boot din DB.

**Securitate Command Injection:**

```python
# CORECT
cmd = ["sudo", "nft", "add", "element", "inet", "cucisec", set_name, f"{{ {ip_address} }}"]
subprocess.run(cmd, check=True)

# PERICULOS - shell=True ar permite injectare comenzi daca ip_address contine ";" sau "|"
subprocess.run(f"nft add element ... {ip_address}", shell=True)  # NICIODATA
```

### 2.4 AsyncDBWriter — Singleton

**Fisier:** `repository/base.py`

**Rationament pentru Singleton:**

`AsyncDBWriter` mentine o singura conexiune SQLite pe thread-ul sau. Daca `LogRepository` si `BlacklistRepository` ar crea instante diferite, am avea doua thread-uri concurente care scriu prin conexiuni diferite — conflict garantat.

**Oprire gracefully prin sentinel value:**

```python
def stop(self):
    self._queue.put(None)  # semnal de oprire
    self._worker.join()    # asteapta golirea cozii
```

Daca am opri thread-ul fortat, toate inregistrarile din coada s-ar pierde.

### 2.5 Sincronizarea la Boot

**Fisier:** `firewall_main.py`

**Rationament pentru ordinea de boot:**

```
1. init_db()                    <- DB trebuie sa existe inainte de orice
2. nft.setup(script_path)       <- Kernel configurat inainte de a accepta pachete
3. sync_blacklist_to_kernel()   <- Blacklist restaurat INAINTE de interceptare
4. interceptor.start()          <- Abia acum incepem sa procesam trafic
```

Pasul 3 inainte de pasul 4 previne Race Condition-ul: fereastra dintre pornirea Kernel-ului si pornirea Python-ului ar putea permite trafic de la atacatori deja blocati daca blacklist-ul nu este restaurat la timp.

**Batch processing la boot:**

In loc de N fork-uri separate, toate IP-urile sunt trimise printr-o singura sesiune nft:

```python
process = subprocess.Popen(["sudo", "nft", "-f", "-"], stdin=subprocess.PIPE, ...)
process.communicate(input=nft_commands)  # toate comenzile odata
```

O(1) fork-uri vs O(N). La sute de IP-uri in blacklist, diferenta este de sute de milisecunde.

---

## Epic 3 — Security Detectors

### 3.1 RuleEngine (In-Memory + CIDR + Zone-Based)

**Fisier:** `service/rule_engine.py`

**Rationament pentru In-Memory:**

La 1000 pachete/secunda, 1000 citiri SQLite/secunda ar introduce 100ms-1s de latenta agregata. Regulile sunt incarcate o singura data la boot in RAM. Evaluarea este O(N) in RAM, fara acces la disc.

**Hot-Reload:**

Fara Hot-Reload, adaugarea unei reguli ar necesita restart. In timpul restart-ului, niciun pachet nu este analizat. `reload_rules()` actualizeaza lista din RAM in timp ce interceptorul continua sa ruleze.

**Suport CIDR pentru zone-based filtering:**

```python
@staticmethod
def is_ip_match(rule_ip: str, packet_ip: str) -> bool:
    if '/' in rule_ip:
        network = ipaddress.ip_network(rule_ip, strict=False)
        return ipaddress.ip_address(packet_ip) in network
    return rule_ip == packet_ip
```

Permite reguli de tipul `ip_src: 192.168.50.0/24, action: DROP, zone: GUEST`. Fara CIDR, ar fi nevoie de o regula per IP.

**Returnarea unui Tuple (actiune, zona):**

In loc de un string concatenat (`"DROP_GUEST_WIFI"`), RuleEngine returneaza doua valori separate:

```python
return rule.action, rule.zone or ""
```

RuleEngine ramane curat si testabil. Formatarea string-ului de log este responsabilitatea interceptorului.

### 3.2 HoneyportEngine

**Fisier:** `detectors/honeyport.py`

**Rationament:**

Un firewall traditional blocheza portul 23 si loga evenimentul. Atacatorul continua scanarea. Honeyport schimba paradigma: portul 23 pare deschis, dar orice conexiune declanseaza ban instant. Atacatorul nu primeste "port inchis" — IP-ul lui este blocat 24h.

Detectia se face pe TCP si UDP — unele scanere trimit probe UDP pe porturile Telnet pentru a detecta filtrarea la nivel de protocol.

### 3.3 FloodEngine (Behavioral Analysis + Observabilitate)

**Fisier:** `detectors/flood.py`

**Rationament pentru arhitectura hibrida:**

Kernel-ul (nftables) limiteaza rata la 20 SYN/secunda — respinge milioanele de pachete direct la placa de retea. Dar limitarea de rata nu este un ban permanent — atacatorul poate continua la infinit 20 pachete/secunda.

FloodEngine primeste aceste 20 pachete/secunda si le numara intr-o fereastra glisanta (Sliding Time Window). Dupa 12 secunde cu 200+ pachete TCP de la acelasi IP, decide ban definitiv.

**Rationament pentru fereastra de 12 secunde — observabilitate:**

Daca banul ar fi dat in prima secunda, graficul de pe Dashboard nu ar afisa spike-ul de atac. Cu 12 secunde:
- Kernel-ul preia socul (reteaua ramane functionala)
- Contoarele nftables cresc dramatic (vizibile pe grafic)
- La secunda 12, FloodEngine baneaza definitiv, graficul revine la zero

Demonstratie vizuala: atac detectat -> sistem reactioneaza automat -> amenintare neutralizata.

**Thread-safety:**

`ip_history` este accesat din thread-ul callback NFQUEUE. Lock previne Race Condition in implementari viitoare multi-threaded.

**Lazy Cleanup:**

In loc de un thread separat care consuma CPU constant, cleanup-ul se face la procesarea fiecarui pachet, verificand daca a trecut CLEANUP_INTERVAL (60 secunde). Consuma CPU doar cand exista trafic.

### 3.4 DPIEngine

**Fisier:** `detectors/dpi.py`

**Rationament pentru Signature-Based vs Anomaly-Based:**

Detectia comportamentala are rata ridicata de false pozitive si necesita training. Detectia pe semnatura este precisa pentru atacuri cunoscute.

**Pre-compilarea regex-urilor:**

```python
def __init__(self):
    self.malicious_signatures = [
        re.compile(r"union\s+select", re.IGNORECASE),
        ...
    ]
```

Compilata o singura data la init, nu la fiecare pachet. La 1000 pachete/secunda, asta elimina 1000 compilari/secunda ale acelorasi pattern-uri.

---

## Epic 4 — Backend API

### 4.1 FastAPI + Rulare in Thread Daemon

**Fisier:** `api/api_main.py`, `firewall_main.py`

**Rationament pentru FastAPI vs Flask:**

Flask este sincron — un request de 50ms blocheza tot. FastAPI este bazat pe ASGI, permite multiple requesturi concurente.

Firewall-ul ruleaza pe thread-ul principal (blocat pe `nfqueue.run()`). API-ul ruleaza in thread daemon. Thread-ul daemon se opreste automat cand procesul principal se termina.

**`app.state.rule_engine` pentru Hot-Reload:**

Referinta la instanta activa de `RuleEngine` este stocata in `app.state`. Cand `POST /rules` adauga o regula, apeleaza `rule_engine.reload_rules()` pe aceeasi instanta care proceseaza pachete — fara restart.

**StaticFiles:**

Frontend-ul HTML/JS/CSS este servit de acelasi server FastAPI. Un singur port, un singur proces, zero configurare suplimentara.

### 4.2 Schemas Pydantic

**Fisier:** `api/schemas.py`

Pydantic valideaza inainte ca requestul sa ajunga la logica aplicatiei. Un request cu `port: "abc"` returneaza automat HTTP 422 cu mesaj clar. Validatorii custom normalizeaza si valideaza simultan — `"accept"`, `"Accept"`, `"ACCEPT"` sunt toate normalizate la `"ACCEPT"`.

### 4.3 StatsService

**Fisier:** `service/stats_service.py`

`nft -j list ruleset` returneaza un JSON cu toata configuratia nftables, inclusiv contoarele per-regula. StatsService identifica regulile dupa campul `comment` (adaugat in scriptul nftables) si agregate valorile:

```python
comment = rule.get("comment")  # "tcp_syn_flood", "icmp_flood", etc.
packets = expr["counter"].get("packets", 0)
counters["tcp_syn_flood_dropped"] += packets
```

### 4.4 Paginare si filtrare Logs

**Fisier:** `repository/log_repository.py`

`WHERE 1=1` permite adaugarea dinamica a conditiilor `AND` fara a verifica daca este primul filtru sau nu.

`get_log_counts_by_minute()` returneaza date pre-agregate pe minute, gata pentru Chart.js:

```sql
SELECT strftime('%H:%M', timestamp) as minute,
       SUM(CASE WHEN action_taken LIKE 'ACCEPT%' THEN 1 ELSE 0 END) as accepted,
       SUM(CASE WHEN action_taken LIKE 'DROP%' THEN 1 ELSE 0 END) as dropped
FROM Logs
WHERE timestamp >= datetime('now', '-30 minutes')
GROUP BY minute
```

---

## Starea Curenta a Sistemului

| Componenta | Fisier | Status |
|---|---|---|
| Schema DB (Rules, Logs, Blacklist, zone) | `database/setup_db.py` | Implementat |
| Script nftables (dual-stack, flood, honeyport, counters) | `scripts/nftables_setup.sh` | Implementat (hook input, hook forward la Epic 6) |
| AsyncDBWriter Singleton Producer-Consumer | `repository/base.py` | Implementat |
| PacketInterceptor (NFQUEUE, graceful shutdown) | `infrastructure/interceptor.py` | Implementat |
| PacketAnalyzer (Scapy, IPv4/IPv6 dual-stack) | `service/packet_analyzer.py` | Implementat |
| FirewallActions (async logging, ban cache, Command Injection safe) | `service/firewall_actions.py` | Implementat |
| Boot sync blacklist (batch processing) | `firewall_main.py` | Implementat |
| RuleEngine (In-Memory, Hot-Reload, CIDR, Zone, Tuple return) | `service/rule_engine.py` | Implementat |
| HoneyportEngine (Active Deception, TCP+UDP) | `detectors/honeyport.py` | Implementat |
| FloodEngine (Behavioral, Sliding Window, Thread-Safe, Lazy Cleanup) | `detectors/flood.py` | Implementat |
| DPIEngine (Regex pre-compilate, Layer 7) | `detectors/dpi.py` | Implementat |
| NftablesManager (ban, sync, cleanup, get_stats JSON) | `infrastructure/nftables_manager.py` | Implementat |
| StatsService (parsare JSON nftables counters) | `service/stats_service.py` | Implementat |
| FastAPI (CORS, StaticFiles, app.state Hot-Reload) | `api/api_main.py` | Implementat |
| Rules CRUD + Hot-Reload | `api/routes/rules_route.py` | Implementat |
| Logs paginate + filtrare + count by minute | `api/routes/logs_route.py` | Implementat |
| Blacklist GET/POST/DELETE | `api/routes/blacklist_route.py` | Implementat |
| Stats combinat DB + nftables | `api/routes/stats_route.py` | Implementat |
| Pydantic Schemas (validare + normalizare) | `api/schemas.py` | Implementat |
| Loguru (format custom, fisier rotativ) | `utils/logger.py` | Implementat |
| Config centralizat | `utils/config.py` | Implementat |
| Web Dashboard HTML/Bootstrap/Chart.js | `frontend/` | Urmeaza (Epic 5) |
| Topologie Network IPS (3 VM-uri, hook forward) | VirtualBox + nftables | Urmeaza (Epic 6) |
| Teste securitate si benchmark | `tests/` | Urmeaza (Epic 6) |
