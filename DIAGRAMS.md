# CuciSec — Diagrame de arhitectură și testare

---

## 1. Arhitectura generală a codului

Relațiile dintre module și direcția fluxurilor principale.

```mermaid
graph TB
    subgraph ENTRY["Entry Point"]
        MAIN["firewall_main.py\nboot sequence"]
    end

    subgraph INFRA["infrastructure/"]
        IC["PacketInterceptor\nNFQUEUE callback loop"]
        NM["NftablesManager\nsubprocess nft CLI"]
    end

    subgraph SVC["service/"]
        PA["PacketAnalyzer\nScapy IPv4/IPv6/TCP/UDP/ICMP"]
        RE["RuleEngine\nRAM rules + RLock + hot-reload"]
        FA["FirewallActions\naccept · drop · ban"]
        SS["StatsService\nnft JSON → flood counters"]
    end

    subgraph DET["detectors/"]
        FL["FloodEngine\nsliding window 12s"]
        HP["HoneyportEngine\nhoney_ports set"]
        DP["DPIEngine\n17 regex signatures Layer 7"]
    end

    subgraph REP["repository/"]
        ADB["AsyncDBWriter\nSingleton · queue 10k · daemon thread"]
        REPOS["Log · Blacklist · Rule · Stats\nRepository"]
    end

    subgraph APIM["api/"]
        AP["FastAPI\ndaemon thread :8000\n+ serve React dist/"]
        RT["routes/ · schemas.py\ndependencies.py"]
    end

    DB[("SQLite WAL\nCuciSec.db")]
    FE["React SPA\nfrontend-cucisec/"]

    MAIN -->|"init + start"| IC & NM & AP

    IC -->|"pipeline"| PA --> RE --> FL --> HP --> DP
    IC --> FA
    FA -->|"nft add element"| NM
    FA -->|"INSERT async"| ADB

    RE -->|"get_enabled()"| REPOS
    REPOS --> ADB & DB
    ADB --> DB

    AP --> RT
    RT -->|"reload_rules()"| RE
    RT -->|"ban / unban"| FA
    RT --> REPOS & SS
    SS -->|"nft -j list"| NM
    NM -->|"snapshot 10s"| REPOS

    FE -->|"REST polling 1–2s"| AP
```

---

## 2. Arhitectura Data Plane / Control Plane

Separarea clară între hot path (procesare pachete) și management.

```mermaid
graph TB
    subgraph DP["DATA PLANE — Hot Path (latency-critical)"]
        subgraph KERN["Kernel Space"]
            NFT["nftables — inet cucisec\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n• blacklist_v4/v6  → drop instant\n• whitelist_v4/v6  → accept, bypass NFQUEUE\n• rate limit global: SYN>50/s, UDP>100/s, ICMP>10/s\n• rate limit per-dest: SYN>30/s, UDP>80/s, ICMP>8/s\n• rate limit per-src:  SYN>20/s, UDP>50/s, ICMP>5/s\n• HTTP ports → queue num 1\n• honeyports  → queue num 1\n• default     → queue num 1"]
        end

        subgraph MT["Main Thread — blocant"]
            P1["1 · PacketAnalyzer\nScapy dissection → PacketInfo"]
            P2["2 · RuleEngine\nadmin rules · prioritate maximă\nzone LAN/WAN detect"]
            P3["3 · FloodEngine\nsliding window per-(IP, proto)"]
            P4["4 · HoneyportEngine\nport capcană → ban imediat"]
            P5["5 · DPIEngine\nHTTP only · regex Layer 7"]
            P6["6 · DEFAULT ACCEPT"]
            P1 --> P2 --> P3 --> P4 --> P5 --> P6
        end

        NFT -->|"NFQUEUE"| P1
        P2 & P3 & P4 & P5 -->|"DROP + BAN\nnft add element blacklist"| NFT
    end

    subgraph CP["CONTROL PLANE — Management"]
        subgraph AT["API Thread — daemon"]
            FAPI["FastAPI :8000\nuvicorn · Pydantic validation\n+ serve React SPA din dist/"]
        end

        subgraph BG["Background Threads"]
            ADB["AsyncDBWriter\nSingleton Producer-Consumer\nqueue.Queue maxsize=10000"]
            KC["KernelCounters Thread\nnft -j list ruleset la 10s\ncompute delta · accumulate DB"]
        end

        DB[("SQLite WAL\nRules · Logs\nBlacklist · KernelCounters")]
        FE["React Dashboard\nTanStack Query\npolling 1–2s"]

        FAPI <-->|"CRUD"| DB
        ADB -->|"INSERT"| DB
        KC -->|"UPDATE KernelCounters"| DB
        FE <-->|"REST"| FAPI
    end

    MT -->|"INSERT Logs / Blacklist\nasync, non-blocking"| ADB
    FAPI -->|"reload_rules()"| P2
    FAPI -->|"ban/unban\nnft add/delete element"| NFT
    KC -->|"nft -j list"| NFT
```

---

## 3. Topologia VM pentru testare

### 3a. Rețeaua de test

```mermaid
graph LR
    subgraph WAN["NAT Network WAN — 10.0.5.0/24"]
        ATT["Kali Linux\nAttacker\n10.0.5.5\nhping3 · curl · nc · nmap"]
    end

    subgraph CS["Ubuntu Server — CuciSec"]
        direction TB
        E8["enp0s8\n10.0.5.10\nWAN interface"]
        FW["━━━━━━━━━━━━━━━━━━━━━━━━\nnftables + Python IPS\nforward chain activ\nIP forwarding ON\n━━━━━━━━━━━━━━━━━━━━━━━━"]
        E9["enp0s9\n10.0.3.10\nLAN interface"]
        E3["enp0s3\n10.0.2.x\nManagement"]
        E8 --- FW --- E9
    end

    subgraph LAN["NAT Network LAN — 10.0.3.0/24"]
        CLI["Ubuntu Client\n10.0.3.5\nApache2 (HTTP target)"]
    end

    subgraph MGMT["NAT VirtualBox — 10.0.2.0/24"]
        DEV["PyCharm / SSH\ndezvoltare"]
        DASH["Browser\nDashboard :8000"]
    end

    ATT <-->|"tot traficul\ntrecpe prin forward chain"| E8
    E9 <--> CLI
    E3 --- DEV
    E3 --- DASH
```

### 3b. Fluxul decizional al unui pachet prin CuciSec

```mermaid
flowchart TD
    IN["Pachet intrat pe CuciSec\nex: 10.0.5.5 → 10.0.3.5"]

    IN --> BL{"blacklist_v4/v6?\nban permanent"}
    BL -->|Da| DK1(["⛔ DROP instant — kernel\nblacklist_drop counter"])
    BL -->|Nu| WL{"whitelist_v4/v6?\nex: 10.0.3.x LAN"}
    WL -->|Da| AK1(["✅ ACCEPT — kernel\nbypass NFQUEUE complet"])
    WL -->|Nu| GL{"Rate limit global\nSYN >50/s · UDP >100/s · ICMP >10/s"}
    GL -->|Depășit| DK2(["⛔ DROP — kernel\nglobal_syn/udp/icmp_flood"])
    GL -->|Ok| PD{"Rate limit per-destinație\nSYN >30/s · UDP >80/s · ICMP >8/s"}
    PD -->|Depășit| DK3(["⛔ DROP — kernel\ndst_syn/udp/icmp_flood"])
    PD -->|Ok| PS{"Rate limit per-sursă\nSYN >20/s · UDP >50/s · ICMP >5/s"}
    PS -->|Depășit| DK4(["⛔ DROP — kernel\ntcp/udp_syn_flood"])
    PS -->|Ok| NFQ["NFQUEUE num 1\n→ userspace Python"]

    NFQ --> ANA["PacketAnalyzer\nScapy dissection → PacketInfo"]
    ANA -->|"malformed / non-IP"| DU0(["⛔ DROP\nMALFORMED_PACKET"])
    ANA -->|ok| RE{"RuleEngine\nregulă admin matchează?"}
    RE -->|ACCEPT| AU1(["✅ ACCEPT\nRULE ENGINE"])
    RE -->|DROP| DU1(["⛔ DROP\nRULE ENGINE"])
    RE -->|"no match"| FE{"FloodEngine\n> prag per-(IP, proto) în 12s?"}
    FE -->|Da| DU2(["⛔ DROP + BAN\nFLOOD — nft + DB + cache"])
    FE -->|Nu| HE{"HoneyportEngine\nport_dst ∈ {23,2323,3389,4444,9999}?"}
    HE -->|Da| DU3(["⛔ DROP + BAN\nHONEYPORT — nft + DB + cache"])
    HE -->|Nu| DE{"DPIEngine\nport ∈ {80,8080,8000,8443}?\n17 semnături regex"}
    DE -->|"Match SQLi/XSS/RCE/..."| DU4(["⛔ DROP + BAN\nDPI HIT — nft + DB + cache"])
    DE -->|"No match / alt port"| AU2(["✅ ACCEPT\nDEFAULT POLICY"])

    style DK1 fill:#e03131,color:#fff,stroke:#c92a2a
    style DK2 fill:#e03131,color:#fff,stroke:#c92a2a
    style DK3 fill:#e03131,color:#fff,stroke:#c92a2a
    style DK4 fill:#e03131,color:#fff,stroke:#c92a2a
    style DU0 fill:#c92a2a,color:#fff,stroke:#a61e1e
    style DU1 fill:#c92a2a,color:#fff,stroke:#a61e1e
    style DU2 fill:#c92a2a,color:#fff,stroke:#a61e1e
    style DU3 fill:#c92a2a,color:#fff,stroke:#a61e1e
    style DU4 fill:#c92a2a,color:#fff,stroke:#a61e1e
    style AK1 fill:#2f9e44,color:#fff,stroke:#2b8a3e
    style AU1 fill:#2f9e44,color:#fff,stroke:#2b8a3e
    style AU2 fill:#2f9e44,color:#fff,stroke:#2b8a3e
    style NFQ fill:#1971c2,color:#fff,stroke:#1864ab
```

---

## 4. Fluxul statisticilor flood — de la kernel la frontend

Arată cum contraoarele nftables (global + per-dest + per-src) sunt agregate, persistate și combinate în răspunsul API.

### 4a. Agregarea counterelor nftables → chei interne

Fiecare protocol are **3 reguli nftables cu `counter`** (global / per-destinație / per-sursă). `parse_flood_counters()` le identifică după câmpul `comment` și le sumează într-un singur counter per protocol.

```mermaid
flowchart LR
    subgraph KERN["Kernel — nftables counters (comment per regulă)"]
        direction TB
        subgraph SYN["TCP SYN flood"]
            GS["global_syn_flood\n> 50/s global"]
            DS["dst_syn_flood\n> 30/s per-dest"]
            PS["tcp_syn_flood\n> 20/s per-src"]
        end
        subgraph UDP["UDP flood"]
            GU["global_udp_flood\n> 100/s global"]
            DU["dst_udp_flood\n> 80/s per-dest"]
            PU["udp_flood\n> 200/s per-src"]
        end
        subgraph ICMP["ICMP flood"]
            GI["global_icmp_flood\n> 10/s global"]
            DI["dst_icmp_flood\n> 8/s per-dest"]
            PI["icmp_flood\n> 5/s per-src"]
        end
        BL["blacklist_drop"]
        HP["honeyport_drop"]
    end

    subgraph KEYS["Chei interne — dict rezultat"]
        K1["tcp_syn_flood_dropped"]
        K2["udp_flood_dropped"]
        K3["icmp_flood_dropped"]
        K4["blacklist_dropped"]
        K5["honeyport_hits"]
    end

    GS & DS & PS -->|"packets SUM"| K1
    GU & DU & PU -->|"packets SUM"| K2
    GI & DI & PI -->|"packets SUM"| K3
    BL --> K4
    HP --> K5
```

### 4b. Circuitul complet al statisticilor — de la nftables la FloodChart

```mermaid
flowchart TD
    NFT["nftables — inet cucisec\n(contoare live în kernel)"]

    subgraph T10["KernelCounters Thread — daemon, interval=10s\n(NftablesManager.start_counter_snapshot_thread)"]
        T1["get_stats()\nnft -j list ruleset"]
        T2["StatsService.parse_flood_counters(json)\ncurrent = {tcp_syn:N, udp:N, icmp:N, ...}"]
        T3["StatsService.compute_delta(current, previous)\ndacă current < previous → delta = current\n(restart-proof)"]
        T4["StatsRepository.accumulate_kernel_counters(delta)\nUPDATE KernelCounters\nSET tcp_syn = tcp_syn + delta.tcp_syn, ..."]
        T5["previous = current"]
        T1 --> T2 --> T3 --> T4 --> T5 -->|"sleep 10s"| T1
    end

    DB[("KernelCounters\n1 singur rând\ntcp_syn · icmp · udp\nblacklist · honeyport\nlast_updated")]

    subgraph BOOT["create_app() — o singură dată la pornire\n(api_main.py)"]
        B1["StatsRepository.get_kernel_counters()\nSELECT tcp_syn, icmp, udp, blacklist, honeyport\nFROM KernelCounters WHERE id=1"]
        B2["app.state.kernel_baseline = result\n← sesiunile anterioare, înghețat la boot"]
        B1 --> B2
    end

    subgraph REQ["GET /api/stats — stats_route.py\n(apelat la fiecare 1s din frontend)"]
        direction TB
        R1["Depends(get_kernel_baseline)\n→ app.state.kernel_baseline\n← sesiuni anterioare boot"]
        R2["NftablesManager.get_stats()\nnft -j list ruleset (live)"]
        R3["StatsService.parse_flood_counters(nft_json)\nlive = contoare sesiune curentă"]
        R4["combined = {k: baseline[k] + live[k]}\npentru fiecare cheie"]
        R5["StatsRepository.get_db_stats()\ntotal_logs, accepted, dropped, banned_ips"]
        R6["StatsResponse\nflood_counters=combined\ntotal_intercepted = db_logs + kernel_only_drops"]
        R1 --> R4
        R2 --> R3 --> R4
        R4 --> R6
        R5 --> R6
    end

    subgraph FE["React Frontend"]
        F1["useStats()\napi.getStats() — polling 1000ms\nrefetchIntervalInBackground: false"]
        F2["DashboardPage\nstats.flood_counters"]
        F3["FloodChart\n(Recharts Bar)\nSYN · UDP · ICMP · Blacklist · Honeyport"]
        F4["MetricCards\ntotal_intercepted · total_logs\naccepted · dropped · banned_ips"]
        F1 --> F2 --> F3 & F4
    end

    NFT -->|"nft -j list (10s)"| T1
    T4 -->|"UPDATE"| DB
    DB -->|"SELECT la boot"| B1
    NFT -->|"nft -j list (live, per request)"| R2
    R6 -->|"JSON HTTP response"| F1
```

**Observații cheie:**
- `kernel_baseline` este citit **o singură dată la boot** și nu se actualizează pe parcursul sesiunii. Reprezintă tot ce s-a acumulat în sesiunile anterioare.
- `live` reprezintă counterele nftables din **sesiunea curentă** (de la ultimul `nftables_setup.sh`).
- `combined = baseline + live` → totalul corect fără dublări.
- Thread-ul KernelCounters asigură că la **următorul boot**, `baseline` va include și sesiunea curentă.
- `compute_delta()` protejează împotriva valorilor negative dacă nftables este restartat în timpul unei sesiuni.

---

## Diagrame recomandate în plus

Acestea nu sunt incluse mai sus, dar ar fi utile pentru teză sau documentație:

| Diagramă | Tip Mermaid | Ce arată |
|---|---|---|
| **Thread model** | `graph LR` | Cele 4 thread-uri (main, API, AsyncDBWriter, KernelCounters) și ce partajează |
| **Secvența de boot** | `sequenceDiagram` | Ordinea exactă a inițializărilor: DB → nftables → sync blacklist → interceptor → API |
| **Flow-ul unui ban** | `sequenceDiagram` | Detector → FirewallActions → NftablesManager + AsyncDBWriter în paralel |
| **Schema DB** | `erDiagram` | Tabelele Rules/Logs/Blacklist/KernelCounters și câmpurile lor |
| **Componente frontend** | `graph TD` | Ierarhia React: pages → components → hooks → api/client.ts |
