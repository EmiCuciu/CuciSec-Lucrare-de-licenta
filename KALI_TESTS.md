# Scenarii de Test — CuciSec cu Kali Linux

> Toate comenzile se rulează de pe **VM Kali** (10.0.2.5).
> CuciSec rulează pe **Ubuntu Server** (10.0.2.10, hook forward).
> **Ținta** traficului este **Ubuntu Client** (10.0.3.5, Apache pe port 80).
>
> Pe Ubuntu Server, în terminal separat: `tail -f logs/cucisec.log`
> Monitorizare kernel drops: `watch -n1 'sudo nft list ruleset | grep -A1 comment'`

---

## T1 — Test conectivitate de bază (baseline)

Înainte de orice atac, verifică că traficul normal trece prin CuciSec.

```bash
# T1.1 — Ping normal (ICMP) la țintă
ping -c 5 10.0.3.5

# Așteptat: ACCEPT în log CuciSec, 5 pachete ajung la Client

# T1.2 — HTTP normal la Apache
curl -v http://10.0.3.5/

# Așteptat: 200 OK, ACCEPT în log

# T1.3 — Verificare log CuciSec
curl "http://10.0.2.10:8000/api/logs/?limit=10&ip_src=10.0.2.5"
```

---

## T2 — Teste FloodEngine (Kernel + Userspace)

### T2.1 — ICMP Flood (kernel rate limit: 5/sec)

```bash
# Flood ICMP rapid — depășește limita kernel de 5 pachete/sec
sudo hping3 --icmp --flood 10.0.3.5

# SAU cu ping flood
sudo ping -f 10.0.3.5

# Rulează 10-15 secunde, apoi Ctrl+C
```

**Așteptat:**
- Kernel: contorul `icmp_flood` crește vizibil în `nft list ruleset`
- Dacă supraviețuiesc pachete suficiente → FloodEngine userspace banează IP-ul
- Log CuciSec: `[FLOOD] 10.0.2.5 is flooding ICMP`
- Kali apare în blacklist: `curl http://10.0.2.10:8000/api/blacklist/`

```bash
# Verificare contor kernel
sudo nft list ruleset | grep -A3 "icmp_flood"

# Verificare blacklist
curl http://10.0.2.10:8000/api/blacklist/
```

---

### T2.2 — TCP SYN Flood (kernel rate limit: 20 SYN/sec per IP)

```bash
# TCP SYN flood pe portul 80 al țintei
sudo hping3 -S --flood -p 80 10.0.3.5

# SAU specificând rata
sudo hping3 -S -p 80 --faster 10.0.3.5

# Rulează 15-20 secunde
```

**Așteptat:**
- Kernel drop la `tcp_syn_flood` după primele 40 pachete burst
- Dacă IP-ul nu e deja banat → FloodEngine userspace detectează > 200 TCP/12s → BAN

```bash
# Verificare contor kernel
sudo nft list ruleset | grep -A3 "tcp_syn_flood"

# Verificare stats dashboard
curl http://10.0.2.10:8000/api/stats/ | python3 -m json.tool
```

---

### T2.3 — UDP Flood

```bash
# UDP flood pe portul 53 (DNS simulat)
sudo hping3 --udp --flood -p 53 10.0.3.5

# SAU generare UDP flood cu hping3 cu date
sudo hping3 --udp -p 1234 --flood 10.0.3.5
```

**Așteptat:**
- Kernel drop la `udp_flood` după 250 pachete burst
- Log: `[FLOOD] 10.0.2.5 is flooding UDP`

---

### T2.4 — Reset după test flood

```bash
# Pe Ubuntu Server — unban Kali pentru testele următoare
curl -X DELETE "http://10.0.2.10:8000/api/blacklist/10.0.2.5"

# Verifică că Kali a dispărut din blacklist
curl http://10.0.2.10:8000/api/blacklist/

# Verifică că Kali poate din nou ping (ATENȚIE: necesită P0-1 implementat)
# ping -c 3 10.0.3.5
```

---

## T3 — Teste HoneyportEngine

Porturi capcană active: `23, 2323, 3389, 4444, 9999`

### T3.1 — Conexiune la Telnet (port 23)

```bash
# Încearcă conexiune TCP la portul capcană 23
nc -zv 10.0.3.5 23

# SAU cu timeout scurt
timeout 3 bash -c 'echo "" | nc 10.0.3.5 23'

# Așteptat: conexiunea pică imediat (DROP), Kali este banat
```

**Verificare:**
```bash
curl http://10.0.2.10:8000/api/logs/?limit=5&ip_src=10.0.2.5
# → details: "HONEYPORT_DROP: Honeyport HIT: suspicious activity - dropped -> TCP:23"

curl http://10.0.2.10:8000/api/blacklist/
# → 10.0.2.5 apare cu reason "Honeyport HIT..."
```

---

### T3.2 — Conexiune la RDP (port 3389)

```bash
# Simulare tentativă RDP
nc -zv 10.0.3.5 3389
# SAU
nmap -sT -p 3389 10.0.3.5 --open
```

---

### T3.3 — Connexiune la port backdoor (4444 — Metasploit default)

```bash
nc -zv 10.0.3.5 4444
```

---

### T3.4 — Scan cu nmap pe toate honeyport-urile

```bash
# Scanare porturi capcană — primul port care răspunde banează IP-ul
nmap -sT -p 23,2323,3389,4444,9999 10.0.3.5

# Așteptat: la primul port atins → BAN, restul scanului eșuează
```

**Important:** După fiecare test T3.x, rulează unban:
```bash
curl -X DELETE "http://10.0.2.10:8000/api/blacklist/10.0.2.5"
```

---

## T4 — Teste DPIEngine (Layer 7)

DPI inspectează payload-ul HTTP (port 80, 8080) pentru semnături malițioase.
Apache rulează pe Ubuntu Client (10.0.3.5:80).

### T4.1 — SQL Injection în request HTTP

```bash
# UNION SELECT
curl "http://10.0.3.5/?id=1%20UNION%20SELECT%20*%20FROM%20users"

# OR 1=1
curl "http://10.0.3.5/?id=1%20OR%201%3D1"

# DROP TABLE
curl "http://10.0.3.5/?q=DROP%20TABLE%20users"
```

**Așteptat:**
- Log CuciSec: `[DPI ALERT] Attack detected: Signature 'union\s+select'`
- Pachetul este DROP-at + IP banat
- Apache Client NU primește request-ul

```bash
# Verificare log DPI
curl "http://10.0.2.10:8000/api/logs/?limit=5&action=DROP&ip_src=10.0.2.5"
```

---

### T4.2 — XSS în payload

```bash
# Script tag în parametru GET
curl "http://10.0.3.5/search?q=<script>alert(1)</script>"

# URL encoded
curl "http://10.0.3.5/?q=%3Cscript%3Ealert%281%29%3C%2Fscript%3E"
```

---

### T4.3 — Path Traversal

```bash
# Accesare /etc/passwd prin traversare
curl "http://10.0.3.5/../../../etc/passwd"

# SAU direct în parametru
curl "http://10.0.3.5/?file=../../../etc/passwd"
```

---

### T4.4 — Nikto web scanner (detectat prin semnătură "nikto" în User-Agent)

```bash
# Rulează nikto — User-Agent-ul conține "Nikto"
nikto -h http://10.0.3.5

# Așteptat: primul request nikto → DPI detectează "nikto" în payload → DROP + BAN
```

---

### T4.5 — Bypass DPI (pentru demonstrarea limitărilor)

```bash
# HTTPS — DPI nu inspectează (payload criptat)
# (necesită HTTPS pe Client)
curl "https://10.0.3.5/?id=1 UNION SELECT * FROM users"
# → trece (DPI nu vede payload-ul criptat)

# Encoding alternativ — dacă DPI nu normalizează URL
curl "http://10.0.3.5/?id=1%20uni%6fn%20sel%65ct%20*"
# → poate trece (regex-ul nu prinde encoding parțial)
```

Acest test arată o limitare reală a sistemului — util pentru secțiunea de concluzii.

---

## T5 — Teste RuleEngine (Reguli statice L3/L4)

### T5.1 — Blocare IP specific

```bash
# Pe Ubuntu Server — adaugă regulă DROP pentru Kali
curl -X POST http://10.0.2.10:8000/api/rules/ \
  -H "Content-Type: application/json" \
  -d '{"ip_src":"10.0.2.5","action":"DROP","description":"Block Kali","zone":"WAN"}'

# Confirmă hot-reload
curl http://10.0.2.10:8000/api/rules/

# Din Kali — testează că traficul e blocat
ping -c 3 10.0.3.5   # trebuie să eșueze cu DROP
curl http://10.0.3.5  # timeout

# Verificare log
curl "http://10.0.2.10:8000/api/logs/?limit=5&ip_src=10.0.2.5&action=DROP"
# → details: "RULE_ENGINE_DROP_WAN"
```

---

### T5.2 — Blocare subnet CIDR

```bash
# Blochează toată rețeaua /24 a atacatorului
curl -X POST http://10.0.2.10:8000/api/rules/ \
  -H "Content-Type: application/json" \
  -d '{"ip_src":"10.0.2.0/24","action":"DROP","description":"Block WAN subnet","zone":"WAN"}'

# Din Kali
ping -c 3 10.0.3.5  # trebuie blocat
```

---

### T5.3 — Blocare protocol specific

```bash
# Blochează tot ICMP
curl -X POST http://10.0.2.10:8000/api/rules/ \
  -H "Content-Type: application/json" \
  -d '{"protocol":"ICMP","action":"DROP","description":"No ping from WAN"}'

# Din Kali
ping -c 3 10.0.3.5   # trebuie blocat
curl http://10.0.3.5  # trebuie să meargă (doar ICMP e blocat)
```

---

### T5.4 — Blocare port specific

```bash
# Blochează portul 80 de pe Kali
curl -X POST http://10.0.2.10:8000/api/rules/ \
  -H "Content-Type: application/json" \
  -d '{"ip_src":"10.0.2.5","port":80,"protocol":"TCP","action":"DROP","description":"Block HTTP from Kali"}'

# Din Kali
curl http://10.0.3.5   # blocat (port 80 DROP)
nc -zv 10.0.3.5 22     # dacă SSH există pe Client — NU e blocat (alt port)
```

---

### T5.5 — Toggle regulă (enable/disable)

```bash
# Dezactivează regula cu id=1
curl -X PATCH "http://10.0.2.10:8000/api/rules/1/toggle?enabled=0"

# Verifică că Kali poate din nou accesa
curl http://10.0.3.5  # trebuie să meargă acum

# Reactivează
curl -X PATCH "http://10.0.2.10:8000/api/rules/1/toggle?enabled=1"
```

---

### T5.6 — Ștergere regulă (hot-reload)

```bash
# Șterge regula cu id=1
curl -X DELETE "http://10.0.2.10:8000/api/rules/1"

# Hot-reload automat — Kali poate din nou accesa imediat
curl http://10.0.3.5  # trebuie să meargă
```

---

## T6 — Teste Blacklist (ban manual)

### T6.1 — Ban manual din API

```bash
# Ban manual IP Kali
curl -X POST http://10.0.2.10:8000/api/blacklist/ \
  -H "Content-Type: application/json" \
  -d '{"ip":"10.0.2.5","reason":"Manual test ban"}'

# Verifică că Kali e în blacklist
curl http://10.0.2.10:8000/api/blacklist/

# Verifică că traficul e blocat
ping -c 3 10.0.3.5    # trebuie blocat (kernel drop instantaneu — O(1))

# Verifică că kernel are IP-ul în set
sudo nft list set inet cucisec blacklist_v4   # pe Ubuntu Server
```

---

### T6.2 — Unban din API

```bash
# Unban (ATENȚIE: necesită P0-1 implementat pentru a funcționa complet)
curl -X DELETE "http://10.0.2.10:8000/api/blacklist/10.0.2.5"

# Verifică că IP-ul a dispărut din kernel
sudo nft list set inet cucisec blacklist_v4   # pe Ubuntu Server

# Verifică că Kali poate din nou accesa
ping -c 3 10.0.3.5  # trebuie să meargă
```

---

## T7 — Test combinat (scenario realist)

Simularea unui atac real în mai mulți pași:

```bash
# Pas 1: Scanare porturi (Kali → Client)
nmap -sT -p 1-1000 10.0.3.5

# Pas 2: Descoperire port 80 open → tentativă SQL Injection
curl "http://10.0.3.5/?id=1 UNION SELECT username,password FROM users"
# → DPI detectează → BAN

# Pas 3: Încearcă alt vector — portul capcană
# (IP-ul e deja banat — kernel drop instantaneu, dar dacă nu era banat:)
# nc -zv 10.0.3.5 4444  → Honeyport BAN

# Verificare finală
curl http://10.0.2.10:8000/api/stats/ | python3 -m json.tool
curl http://10.0.2.10:8000/api/blacklist/
curl "http://10.0.2.10:8000/api/logs/?limit=20&ip_src=10.0.2.5"
```

---

## T8 — Captură de ecran pentru lucrare

Comenzi utile pentru capturi relevante în teză:

```bash
# Dashboard în timp real (deschide în browser pe host)
# http://10.0.2.10:8000

# Stats în JSON formatat
curl http://10.0.2.10:8000/api/stats/ | python3 -m json.tool

# Ruleset kernel complet
sudo nft list ruleset

# Contoare kernel live
watch -n1 'sudo nft list ruleset | grep -E "comment|packets"'

# Log în timp real
tail -f logs/cucisec.log | grep -E "DROP|BAN|FLOOD|DPI|HONEYPORT"

# Blacklist curent
curl http://10.0.2.10:8000/api/blacklist/ | python3 -m json.tool
```

---

## Resetare completă între scenarii

```bash
# Pe Ubuntu Server:

# 1. Oprire CuciSec (Ctrl+C în terminalul principal)
# → cleanup() automat șterge tabela nftables

# 2. Resetare DB (opțional)
source venv/bin/activate
python3 database/mock_db_data.py

# 3. Repornire
sudo venv/bin/python firewall_main.py

# 4. Verificare stare curată
curl http://10.0.2.10:8000/api/blacklist/  # → []
curl http://10.0.2.10:8000/api/rules/       # → []
```
