📌 Epic 1: Infrastructura de Bază și Reguli Kernel
Fundația pe care va rula Python-ul.

[x] Task 1.1: Crearea schemei bazei de date SQLite (Acesta e deja gata!)

Descriere: Implementarea fișierului database/db.py care generează tabelele Rules, Logs, Blacklist și indexurile necesare.

[ ] Task 1.2: Crearea scriptului de inițializare nftables (scripts/nft_setup.sh)

Descriere: Script bash care curăță regulile vechi, creează tabela cucisec, setul dinamic blacklist și regula care trimite traficul necunoscut în NFQUEUE num 1.

📌 Epic 2: Core Engine (Motorul de Interceptare)
Crearea „inimii” aplicației, urmând principiile OOP.

[ ] Task 2.1: Implementarea clasei PacketInterceptor (core/interceptor.py)

Descriere: Folosirea NetfilterQueue pentru a prelua pachetele din Kernel și a le trimite mai departe către analizator.

[ ] Task 2.2: Implementarea clasei PacketAnalyzer (core/analyzer.py)

Descriere: Integrarea Scapy pentru a "diseca" pachetul brut și a extrage IP, Port, Protocol și Payload.

[ ] Task 2.3: Implementarea modulului FirewallActions (core/actions.py)

Descriere: Funcțiile care interacționează cu sistemul de operare: accept_packet(), drop_packet() și cel mai important: ban_ip(ip, reason), care va executa comanda de adăugare în setul nftables și va loga în DB.

[ ] Task 2.4: Mecanismul de Sincronizare la Boot (run_firewall.py)

Descriere: La pornirea aplicației, scriptul trebuie să citească tabela Blacklist din SQLite și să încarce automat toate IP-urile blocate înapoi în nftables.

📌 Epic 3: Security Detectors (Sistemul Imunitar)
Logica de securitate avansată (Aici va străluci licența ta).

[ ] Task 3.1: Dezvoltarea RuleEngine (core/rule_engine.py)

Descriere: Modulul care compară pachetul curent cu regulile statice definite de utilizator în tabela Rules (ex. "Blochează IP-ul X pe portul Y").

[ ] Task 3.2: Implementarea HoneyportDetector (detectors/honeyport.py)

Descriere: Monitorizarea porturilor capcană (ex. 23, 2323). Orice pachet primit aici declanșează funcția ban_ip().

[ ] Task 3.3: Implementarea IPSDetector (detectors/ips.py)

Descriere: Sistem de detecție Flood. Salvarea în memorie (dicționar) a numărului de pachete/secundă per IP. Dacă IP-ul depășește pragul (ex. 100 pps), declanșează ban_ip().

[ ] Task 3.4: Implementarea DPIInspector (detectors/dpi.py)

Descriere: Extragerea stratului Raw (Payload) folosind Scapy și căutarea de semnături malițioase (ex. UNION SELECT, <script>).

📌 Epic 4: Backend API (FastAPI)
Expunerea datelor pentru interfața vizuală.

[ ] Task 4.1: Configurarea serverului FastAPI (api/main.py)

Descriere: Inițializarea framework-ului și configurarea CORS pentru a permite cereri de la frontend.

[ ] Task 4.2: Endpoint-uri pentru Log-uri și Blacklist (api/routes.py)

Descriere: Crearea rutelor GET /api/logs și GET /api/blacklist care returnează datele din SQLite în format JSON.

[ ] Task 4.3: Endpoint-uri pentru gestionarea Regulilor

Descriere: Crearea rutelor GET, POST, DELETE și PUT pentru endpoint-ul /api/rules, permițând interfeței web să adauge sau să dezactiveze reguli în timp real.

📌 Epic 5: Interfața Web (Dashboard)
Transformarea codului invizibil într-un produs atrăgător.

[ ] Task 5.1: Layout-ul de bază HTML/CSS (web/dashboard.html)

Descriere: Crearea structurii folosind Bootstrap (Meniu lateral, Card-uri pentru metrici, Tabele pentru reguli).

[ ] Task 5.2: Tabelul dinamic și preluarea datelor via AJAX (web/app.js)

Descriere: Conectarea frontend-ului la API-ul FastAPI pentru a popula tabelele de Logs, Blacklist și Reguli.

[ ] Task 5.3: Integrarea Chart.js pentru metrici vizuale

Descriere: Desenarea unui grafic live (ex. pachete acceptate vs. pachete blocate / trafic per protocol).

📌 Epic 6: Testare și Documentare (Pentru Nota 10)
Validarea și demonstrarea performanțelor sistemului.

[ ] Task 6.1: Teste funcționale de Securitate

Descriere: Rularea unui port scan cu Nmap (pentru a lovi Honeyport-ul) și a unui atac cu SQLi (pentru a testa DPI-ul) din mașina Kali Linux. Verificarea blocării.

[ ] Task 6.2: Benchmark de Performanță (Stress Test)

Descriere: Folosirea hping3 pentru a trimite 5000+ pachete/secundă (SYN Flood). Măsurarea consumului de CPU și demonstrarea eficienței nftables sets. Salvarea datelor pentru graficele din licență.

[ ] Task 6.3: Redactarea capitolelor practice din teza de licență

Descriere: Documentarea arhitecturii OOP, a procesului de sincronizare DB -> Kernel și interpretarea rezultatelor de la testul de stres.