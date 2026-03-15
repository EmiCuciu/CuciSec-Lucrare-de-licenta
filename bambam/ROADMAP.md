# 🔒 CuciSec Firewall - Project Roadmap

## 📊 Progress Summary
| Epic | Status | Progress |
|------|--------|----------|
| Epic 1: Infrastructura de Bază | 🟨 In Progress | 1/2 (50%) |
| Epic 2: Core Engine | ⏳ Pending | 0/4 (0%) |
| Epic 3: Security Detectors | ⏳ Pending | 0/4 (0%) |
| Epic 4: Backend API | ⏳ Pending | 0/3 (0%) |
| Epic 5: Interfața Web | ⏳ Pending | 0/3 (0%) |
| Epic 6: Testare & Documentare | ⏳ Pending | 0/3 (0%) |
| **TOTAL** | **🟨** | **1/19 (5%)** |

---

## 📌 Epic 1: Infrastructura de Bază și Reguli Kernel
**Fundația pe care va rula Python-ul**

**Status:** 🟨 In Progress (1/2)

### ✅ Task 1.1: Crearea schemei bazei de date SQLite
- **Status:** ✅ DONE
- **File:** `database/db.py`
- **Descriere:** Implementarea fișierului care generează tabelele Rules, Logs, Blacklist și indexurile necesare.
- **Notes:** Deja gata!

### ⏳ Task 1.2: Crearea scriptului de inițializare nftables
- **Status:** ⏳ TODO
- **File:** `scripts/nft_setup.sh`
- **Descriere:** Script bash care:
  - Curăță regulile vechi
  - Creează tabela `cucisec`
  - Setul dinamic `blacklist`
  - Regula care trimite traficul necunoscut în NFQUEUE num 1
- **Dependencies:** Task 1.1 (✅ DONE)
- **Priority:** 🔴 HIGH

---

## 📌 Epic 2: Core Engine (Motorul de Interceptare)
**Crearea „inimii" aplicației, urmând principiile OOP**

**Status:** ⏳ Pending (0/4)

### ⏳ Task 2.1: Implementarea clasei PacketInterceptor
- **Status:** ⏳ TODO
- **File:** `core/interceptor.py`
- **Descriere:** Folosirea NetfilterQueue pentru a prelua pachetele din Kernel
- **Dependencies:** Task 1.2
- **Priority:** 🔴 HIGH

### ⏳ Task 2.2: Implementarea clasei PacketAnalyzer
- **Status:** ⏳ TODO
- **File:** `core/analyzer.py`
- **Descriere:** Integrarea Scapy pentru a diseca pachetul brut și extrage IP, Port, Protocol, Payload
- **Dependencies:** Task 2.1
- **Priority:** 🔴 HIGH

### ⏳ Task 2.3: Implementarea modulului FirewallActions
- **Status:** ⏳ TODO
- **File:** `core/actions.py`
- **Descriere:** Funcții de interacțiune OS:
  - `accept_packet()`
  - `drop_packet()`
  - `ban_ip(ip, reason)` - adaugă IP în nftables și loghează în DB
- **Dependencies:** Task 2.1, Task 2.2
- **Priority:** 🔴 HIGH

### ⏳ Task 2.4: Mecanismul de Sincronizare la Boot
- **Status:** ⏳ TODO
- **File:** `run_firewall.py`
- **Descriere:** La pornire:
  - Citește tabela Blacklist din SQLite
  - Încarc automat IP-urile blocate înapoi în nftables
- **Dependencies:** Task 1.1, Task 2.3
- **Priority:** 🟡 MEDIUM

---

## 📌 Epic 3: Security Detectors (Sistemul Imunitar)
**Logica de securitate avansată - Aici va străluci licența ta! ⭐**

**Status:** ⏳ Pending (0/4)

### ⏳ Task 3.1: Dezvoltarea RuleEngine
- **Status:** ⏳ TODO
- **File:** `core/rule_engine.py`
- **Descriere:** Modulul care compară pachetele cu regulile statice din tabela Rules
  - Ex: "Blochează IP-ul X pe portul Y"
- **Dependencies:** Task 2.2, Task 1.1
- **Priority:** 🟡 MEDIUM

### ⏳ Task 3.2: Implementarea HoneyportDetector
- **Status:** ⏳ TODO
- **File:** `detectors/honeyport.py`
- **Descriere:** Monitorizarea porturilor capcană (ex. 23, 2323)
  - Orice pachet → declanșează ban_ip()
- **Dependencies:** Task 2.3, Task 2.2
- **Priority:** 🟡 MEDIUM

### ⏳ Task 3.3: Implementarea IPSDetector
- **Status:** ⏳ TODO
- **File:** `detectors/ips.py`
- **Descriere:** Sistem de detecție Flood:
  - Salvează în dict numrul de pachete/sec per IP
  - Pragul: 100 pps → declanșează ban_ip()
- **Dependencies:** Task 2.3, Task 2.2
- **Priority:** 🟡 MEDIUM

### ⏳ Task 3.4: Implementarea DPIInspector
- **Status:** ⏳ TODO
- **File:** `detectors/dpi.py`
- **Descriere:** Deep Packet Inspection:
  - Extrage stratul Raw (Payload) cu Scapy
  - Caută semnături malițioase: `UNION SELECT`, `<script>`, etc.
- **Dependencies:** Task 2.2
- **Priority:** 🟡 MEDIUM

---

## 📌 Epic 4: Backend API (FastAPI)
**Expunerea datelor pentru interfața vizuală**

**Status:** ⏳ Pending (0/3)

### ⏳ Task 4.1: Configurarea serverului FastAPI
- **Status:** ⏳ TODO
- **File:** `api/main.py`
- **Descriere:** Inițializarea framework-ului și configurarea CORS
- **Dependencies:** Task 1.1
- **Priority:** 🟡 MEDIUM

### ⏳ Task 4.2: Endpoint-uri pentru Log-uri și Blacklist
- **Status:** ⏳ TODO
- **File:** `api/routes.py`
- **Descriere:** Rutele GET:
  - `/api/logs` → returnează logs din SQLite (JSON)
  - `/api/blacklist` → returnează blacklist-ul (JSON)
- **Dependencies:** Task 4.1, Task 1.1
- **Priority:** 🟡 MEDIUM

### ⏳ Task 4.3: Endpoint-uri pentru gestionarea Regulilor
- **Status:** ⏳ TODO
- **File:** `api/routes.py`
- **Descriere:** Rutele CRUD pentru `/api/rules`:
  - GET - lista reguli
  - POST - adaugă reguli
  - PUT - actualizează reguli
  - DELETE - șterge reguli
- **Dependencies:** Task 4.1, Task 1.1
- **Priority:** 🟡 MEDIUM

---

## 📌 Epic 5: Interfața Web (Dashboard)
**Transformarea codului invizibil într-un produs atrăgător**

**Status:** ⏳ Pending (0/3)

### ⏳ Task 5.1: Layout-ul de bază HTML/CSS
- **Status:** ⏳ TODO
- **File:** `web/dashboard.html`
- **Descriere:** Structura Bootstrap:
  - Meniu lateral
  - Card-uri pentru metrici
  - Tabele pentru reguli
- **Dependencies:** Task 4.1
- **Priority:** 🟢 LOW

### ⏳ Task 5.2: Tabelul dinamic și AJAX
- **Status:** ⏳ TODO
- **File:** `web/app.js`
- **Descriere:** Conectare frontend → API FastAPI
  - Populate dinamice: Logs, Blacklist, Reguli
- **Dependencies:** Task 5.1, Task 4.2, Task 4.3
- **Priority:** 🟢 LOW

### ⏳ Task 5.3: Integrarea Chart.js
- **Status:** ⏳ TODO
- **File:** `web/app.js`
- **Descriere:** Grafice live:
  - Pachete acceptate vs. blocate
  - Trafic per protocol
- **Dependencies:** Task 5.2
- **Priority:** 🟢 LOW

---

## 📌 Epic 6: Testare și Documentare (Pentru Nota 10)
**Validarea și demonstrarea performanțelor sistemului**

**Status:** ⏳ Pending (0/3)

### ⏳ Task 6.1: Teste funcționale de Securitate
- **Status:** ⏳ TODO
- **File:** `tests/security_tests.sh`
- **Descriere:** Din Kali Linux:
  - Nmap port scan → să lovească Honeyport-ul
  - Atac SQLi → să testeze DPI-ul
  - Verifică blocarea
- **Dependencies:** Toate Epic-urile
- **Priority:** 🟢 LOW

### ⏳ Task 6.2: Benchmark de Performanță (Stress Test)
- **Status:** ⏳ TODO
- **File:** `tests/benchmark.sh`
- **Descriere:** Stress test cu hping3:
  - 5000+ pachete/sec (SYN Flood)
  - Măsoară CPU, memorie
  - Demonstrează eficiență nftables sets
  - Salvează date pentru graficele tezei
- **Dependencies:** Toate Epic-urile
- **Priority:** 🟢 LOW

### ⏳ Task 6.3: Redactarea capitolelor practice din teza
- **Status:** ⏳ TODO
- **Descriere:** Documentare:
  - Arhitectura OOP
  - Procesul sincronizare DB → Kernel
  - Interpretare rezultate stress test
  - Screenshots și grafice
- **Dependencies:** Task 6.1, Task 6.2
- **Priority:** 🟢 LOW

---

## 📋 Legend

| Icon | Meaning |
|------|---------|
| ✅ | Completed |
| 🟨 | In Progress |
| ⏳ | Pending (Not Started) |
| 🔴 | High Priority (Complete First) |
| 🟡 | Medium Priority |
| 🟢 | Low Priority (UI/Documentation) |

---

## 🎯 Next Steps
1. **Immediate:** Task 1.2 (nftables setup script) - **HIGH PRIORITY**
2. **Then:** Tasks 2.1-2.3 (Core Engine foundation)
3. **After:** Tasks 3.1-3.4 (Security Detectors)
4. **Finally:** Frontend & Testing

---

## 📝 How to Update Progress

When you complete a task:
1. Change the status from `⏳ TODO` to `✅ DONE`
2. Update the Epic's progress counter
3. Update the overall progress in the summary table
4. You can add completion date or notes if needed

Example:
```
### ✅ Task 1.2: Crearea scriptului de inițializare nftables
- **Status:** ✅ DONE (2026-03-15)
- ...
```

