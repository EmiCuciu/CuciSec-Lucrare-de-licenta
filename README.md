# Sistem de Management și Interceptare a Traficului de Rețea

Acest proiect reprezintă o lucrare de licență ce vizează dezvoltarea unui firewall software capabil să intercepteze pachete direct din Kernel-ul Linux, să le analizeze logic în Userspace folosind Python și să ofere o interfață web pentru administrare vizuală.

---

## Obiectiv Principal

Dezvoltarea unei soluții care depășește limitările firewall-urilor statice, oferind inspecție la nivel de aplicație (Deep Packet Inspection) și răspuns automatizat la amenințări în timp real.

---

## Arhitectură și Tehnologii

Sistemul este structurat pe patru niveluri fundamentale:

* **Nivelul Rețea (Kernel):** Bazat pe `Ubuntu Server` (cu potențial de portare pe OpenWrt/Raspberry Pi), utilizează mecanismele `iptables/nftables` și `NFQUEUE` pentru extragerea pachetelor din fluxul standard al sistemului.

* **Nivelul Logic (Core Engine):** Implementat în `Python 3`, utilizează librăria `Scapy` pentru analiza detaliată și `NetfilterQueue` pentru procesarea pachetelor și emiterea verdictului de tip `ACCEPT` sau `DROP`.

* **Nivelul Date:** Utilizarea `SQLite` pentru stocarea eficientă a log-urilor de trafic și a regulilor de filtrare.

* **Nivelul Interfață (Web UI):** Backend dezvoltat în `Flask` (REST API) și frontend realizat cu `HTML5`, `Bootstrap` și `Chart.js` pentru monitorizare grafică.

---

## Diagramă de Funcționare

```mermaid
graph TD;
    A[Internet/Rețea] -->|Pachet| B(Linux Kernel / iptables);
    B -->|NFQUEUE| C{Interceptor Python};
    C -->|Analiză cu Scapy| D[Motor de Decizie];
    D -->|Logare| E[(Bază de Date SQLite)];
    D -->|Verdict: ACCEPT/DROP| B;
    F[Dashboard Web] <-->|REST API| G[Backend Flask];
    G <-->|Interogare/Actualizare| E;
```

---

## Elemente de Inovație și Proces de Gândire

### Inspecție Layer 7 Lite (Deep Packet Inspection)

**Concept:** Filtrare pe baza conținutului (payload), nu doar IP/Port.

**Raționament:** Firewall-urile clasice analizează doar antetul (header). Proiectul vizează detectarea atacurilor mascate în porturi permise (ex. SQL Injection pe portul 80) prin scanarea activă a conținutului pachetului.

---

### Securitate Reactivă (IPS - Intrusion Prevention System)

**Concept:** Crearea automată de reguli în urma unui comportament suspect detectat.

**Raționament:** Automatizarea apărării pentru a contracara atacuri de tip Flood. La depășirea unui prag critic de pachete/secundă, sistemul blochează sursa fără intervenție umană.

---

### Mecanism Honeyport (Capcană)

**Concept:** Expunerea unor porturi false pentru identificarea timpurie a atacatorilor.

**Raționament:** Utilizatorii legitimi accesează doar serviciile reale. Orice tentativă asupra acestor porturi "momeală" indică un bot sau un scaner, permițând blocarea proactivă a IP-ului.

---

### Vizualizarea Real-Time a Amenințărilor

**Concept:** Transformarea jurnalelor de tip text în indicatori vizuali dinamici.

**Raționament:** Monitorizarea securității prin terminal este ineficientă în timpul unui atac masiv. Un dashboard permite identificarea instantanee a anomaliilor prin vârfuri de grafic.

---

## Mecanisme Firewall Implementate

* **Filtrarea pachetelor:** Gestionarea traficului pe baza protocolului, adresei IP și a portului (Layer 3/4).

* **Inspecția de stare (Stateful Inspection):** Monitorizarea conexiunilor pentru a distinge între cereri noi și sesiuni deja stabilite.

* **Management NAT / DNAT:** Facilitarea rutării traficului și a serviciilor de Port Forwarding către rețeaua internă.

* **Userspace Interception:** Preluarea granulară a controlului prin redirecționarea pachetelor către logica de aplicație via NFQUEUE.

---

## Mediu de Testare

Validarea sistemului a fost realizată într-un mediu virtualizat (VirtualBox) compus din:

* **VM 1 (Firewall):** Ubuntu Server - nucleul central al aplicației.

* **VM 2 (Atacator):** Kali Linux - utilizat pentru simularea atacurilor (scanări cu Nmap, flood cu Hping3).

* **VM 3 (Client/Victimă):** Ubuntu Desktop - pentru generarea traficului legitim și verificarea conectivității.




## Diagrame:

1. Flow-ul Pachetului (Activity Diagram)

Aceasta arată logica exactă pe care o vei programa în scriptul tău Python.


```mermaid
flowchart TD
    Start([Pachet nou intră în interfață]) --> Iptables{Regulă iptables}
    Iptables -- "Nu ne interesează" --> KernelAccept[Kernel: ACCEPT direct]
    Iptables -- "Trafic de interceptat" --> Queue[Trimite în NFQUEUE]
    
    Queue --> Python[Script Python preia pachetul]
    Python --> Parse[Scapy: Extrage IP, Port, Payload]
    
    Parse --> CheckBlacklist{IP-ul e în Blacklist?}
    CheckBlacklist -- DA --> Drop([Verdict: DROP])
    CheckBlacklist -- NU --> CheckHoneyport{Trafic spre Honeyport?}
    
    CheckHoneyport -- DA --> AddBlacklist[Adaugă IP în SQLite Blacklist]
    AddBlacklist --> Drop
    CheckHoneyport -- NU --> CheckIPS{Frecvență prea mare? IPS}
    
    CheckIPS -- DA --> BlockTemp[Blocare temporară IP]
    BlockTemp --> Drop
    CheckIPS -- NU --> CheckDPI{Payload periculos? DPI}
    
    CheckDPI -- DA --> Drop
    CheckDPI -- NU --> Accept([Verdict: ACCEPT])
    
    Drop --> Log[Salvează eveniment în SQLite]
    Accept --> Log
```


2. Arhitectura Sistemului (Component Diagram)
Arată cum comunică modulele între ele.

```mermaid
graph LR
    subgraph Kernel Space
        NIC[Placă de rețea] <--> IPT[iptables / nftables]
    end

    subgraph Userspace Logic
        NFQ[NetfilterQueue] <--> Engine[Python Core Engine]
        Engine <--> Scapy[Modul Scapy DPI]
    end

    subgraph Persistență & Web UI
        DB[(SQLite Database)]
        API[FastAPI Backend]
        UI[Frontend HTML/Chart.js]
    end

    IPT -- Pachete --> NFQ
    Engine -- Scrie Log-uri/Reguli --> DB
    API -- Citește/Scrie --> DB
    UI -- REST/WebSockets --> API
```


3. UML Use Case Diagram
Aceasta arată ce pot face actorii implicați în sistem (Administratorul vs. Atacatorul).

```plantuml
@startuml UseCase_Diagram
    :Administrator: as Admin
    :Atacator: as Attacker
    
    (Vizualizare Dashboard) as UC1
    (Adăugare/Ștergere Reguli) as UC2
    (Analiză Trafic Real-time) as UC3
    (Declanșare Honeyport) as UC4
    (Declanșare IPS Flood) as UC5
    (Auto-Blocare IP) as UC6
    
    Admin --> UC1
    Admin --> UC2
    Admin --> UC3
    Attacker --> UC4
    Attacker --> UC5
    
    UC4 --> UC6 : declanșează
    UC5 --> UC6 : declanșează
@enduml
```


