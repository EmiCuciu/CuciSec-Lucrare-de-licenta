# VM Setup — Testbed CuciSec (3 VM-uri)

## Topologia rețelei

```
┌──────────────────┐       ┌──────────────────────────────┐       ┌──────────────────┐
│   Kali Attacker  │       │   Ubuntu Server — CuciSec    │       │  Ubuntu Client   │
│   10.0.2.5/24    │◄─────►│ eth0: 10.0.2.10/24 (WAN)    │◄─────►│  10.0.3.5/24     │
│                  │       │ eth1: 10.0.3.10/24 (LAN)     │       │                  │
└──────────────────┘       │ (IP Forwarding ENABLED)       │       └──────────────────┘
  Host-Only Net A           │ CuciSec hook forward          │         Host-Only Net B
  (vboxnet0 / vmnet1)      └──────────────────────────────┘         (vboxnet1 / vmnet2)
```

- **Kali** atacatorul — trimite trafic malițios
- **Ubuntu Server** — CuciSec rulează aici, routează traficul între cele două rețele
- **Ubuntu Client** — victima/ținta; traficul Kali → Client trece PRIN CuciSec

---

## Software necesar pe host

- VirtualBox 7.x (gratuit) SAU VMware Workstation Player
- Minim 8GB RAM pe host (3 VM-uri × ~2GB)
- Minim 40GB spațiu disk

---

## Pasul 1 — Creare rețele Host-Only în VirtualBox

Deschide VirtualBox → File → Host Network Manager → Create:

```
vboxnet0:  192.168.56.0/24  (sau 10.0.2.0/24)  — WAN side (Kali ↔ CuciSec)
vboxnet1:  192.168.57.0/24  (sau 10.0.3.0/24)  — LAN side (CuciSec ↔ Client)
```

Dezactivează DHCP pe ambele rețele (vom seta IP-urile manual).

---

## Pasul 2 — Crearea și configurarea VM-urilor

### VM 1 — Ubuntu Server (CuciSec)

**Specificații:**
- OS: Ubuntu Server 22.04 LTS (minimal install)
- RAM: 2GB
- CPU: 2 core-uri
- Disk: 20GB
- **Adaptor 1:** Host-Only → vboxnet0 (eth0 — WAN)
- **Adaptor 2:** Host-Only → vboxnet1 (eth1 — LAN)

**Configurare rețea (după instalare):**

```bash
# Editează /etc/netplan/00-installer-config.yaml
sudo nano /etc/netplan/00-installer-config.yaml
```

```yaml
network:
  version: 2
  ethernets:
    eth0:
      dhcp4: no
      addresses: [10.0.2.10/24]
    eth1:
      dhcp4: no
      addresses: [10.0.3.10/24]
```

```bash
sudo netplan apply

# Activează IP forwarding
sudo sysctl -w net.ipv4.ip_forward=1
sudo sysctl -w net.ipv6.conf.all.forwarding=1

# Persistent (adaugă în /etc/sysctl.conf)
echo "net.ipv4.ip_forward=1" | sudo tee -a /etc/sysctl.conf
echo "net.ipv6.conf.all.forwarding=1" | sudo tee -a /etc/sysctl.conf
sudo sysctl -p

# Verificare
cat /proc/sys/net/ipv4/ip_forward  # → trebuie să afișeze 1
```

---

### VM 2 — Kali Linux (Attacker)

**Specificații:**
- OS: Kali Linux 2024.x (imagine oficială VirtualBox de pe kali.org)
- RAM: 2GB
- CPU: 2 core-uri
- Disk: 20GB
- **Adaptor 1:** Host-Only → vboxnet0 (eth0 — WAN)

**Configurare rețea:**

```bash
sudo nano /etc/network/interfaces
```

```
auto eth0
iface eth0 inet static
    address 10.0.2.5
    netmask 255.255.255.0
    gateway 10.0.2.10      # gateway = interfața WAN a CuciSec
```

```bash
sudo systemctl restart networking

# SAU cu ip command (temporar, pentru test rapid)
sudo ip addr add 10.0.2.5/24 dev eth0
sudo ip route add default via 10.0.2.10

# Verificare conectivitate
ping 10.0.2.10   # ping la CuciSec WAN interface
ping 10.0.3.5    # ping la Ubuntu Client (trece prin CuciSec)
```

---

### VM 3 — Ubuntu Client (Victim)

**Specificații:**
- OS: Ubuntu Desktop 22.04 LTS SAU Ubuntu Server
- RAM: 1.5GB
- CPU: 1 core
- Disk: 15GB
- **Adaptor 1:** Host-Only → vboxnet1 (eth1 — LAN)

**Configurare rețea:**

```bash
sudo nano /etc/netplan/00-installer-config.yaml
```

```yaml
network:
  version: 2
  ethernets:
    eth0:
      dhcp4: no
      addresses: [10.0.3.5/24]
      routes:
        - to: default
          via: 10.0.3.10      # gateway = interfața LAN a CuciSec
      nameservers:
        addresses: [8.8.8.8]
```

```bash
sudo netplan apply

# Instalează un server web simplu pentru testare DPI
sudo apt install apache2 -y
sudo systemctl start apache2

# Verificare: din Kali trebuie să fie accesibil
# curl http://10.0.3.5/  (prin CuciSec)
```

---

## Pasul 3 — Instalare CuciSec pe Ubuntu Server

```bash
# Pe VM Ubuntu Server

# Dependențe OS
sudo apt update
sudo apt install -y libnetfilter-queue-dev nftables iptables python3-venv python3-pip git

# Clonare repo
git clone https://github.com/EmiCuciu/CuciSec-Lucrare-de-licenta.git
cd CuciSec-Lucrare-de-licenta

# Mediu virtual Python
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Build frontend (opțional, pentru UI)
# Necesită Node.js 18+
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt install -y nodejs
npm install -g pnpm
cd frontend-cucisec
pnpm install
pnpm run build
cd ..
```

---

## Pasul 4 — Pornire CuciSec

```bash
# Pe Ubuntu Server, în directorul proiectului
source venv/bin/activate
sudo venv/bin/python firewall_main.py
```

**Verificare pornire corectă — output așteptat:**
```
2026-05-12 10:00:00 | INFO     | [BOOT] CuciSec Firewall started
2026-05-12 10:00:00 | INFO     | [BOOT] Database initialized
2026-05-12 10:00:00 | INFO     | [BOOT] Kernel initialized (nftables flushed & created)
2026-05-12 10:00:00 | INFO     | [BOOT] Blacklist synced: 0 IPS from DB to Kernel
2026-05-12 10:00:00 | INFO     | [BOOT] FastAPI running on http://0.0.0.0:8000
2026-05-12 10:00:00 | INFO     | [INTERCEPTOR]. Listening on NFQUEUE 1 (max 8192 packets)..
```

```bash
# Verificare ruleset kernel (alt terminal)
sudo nft list ruleset

# Verificare API
curl http://10.0.2.10:8000/api/
# → {"system": "CuciSec", "status": "running", "docs": "/docs"}

# Accesează dashboard din browser (pe host sau VM)
# http://10.0.2.10:8000
```

---

## Pasul 5 — Verificare conectivitate end-to-end

```bash
# Din Kali:
ping 10.0.2.10       # ping la interfața WAN CuciSec — trebuie să meargă
ping 10.0.3.5        # ping la Ubuntu Client prin CuciSec — trebuie să meargă
curl http://10.0.3.5 # HTTP la Apache pe Ubuntu Client — trebuie să meargă

# Din Ubuntu Client:
ping 10.0.3.10       # ping la interfața LAN CuciSec
ping 10.0.2.5        # ping la Kali prin CuciSec

# Pe Ubuntu Server (CuciSec) — verifică loguri în timp real
tail -f logs/cucisec.log
```

---

## Troubleshooting frecvent

### NFQUEUE nu primește pachete
```bash
# Verifică că regula queue există în nftables
sudo nft list ruleset | grep queue

# Verifică că procesul Python are permisiuni root
sudo venv/bin/python firewall_main.py  # cu sudo obligatoriu

# Verifică că modulul kernel e disponibil
lsmod | grep nfnetlink_queue
modprobe nfnetlink_queue  # dacă nu e încărcat
```

### IP forwarding nu funcționează
```bash
# Verifică starea
cat /proc/sys/net/ipv4/ip_forward  # trebuie 1

# Verifică că nu există alte reguli iptables care blochează
sudo iptables -L FORWARD -v
# Dacă există reguli DEFAULT DROP: sudo iptables -P FORWARD ACCEPT
```

### Pachetele nu trec prin CuciSec
```bash
# Verifică routele pe Kali
ip route show
# Trebuie să existe: default via 10.0.2.10

# Verifică routele pe Ubuntu Client
ip route show
# Trebuie să existe: default via 10.0.3.10

# Traceroute din Kali la Client — trebuie să treacă prin 10.0.2.10
traceroute 10.0.3.5
```

### Port 8000 nu e accesibil
```bash
# Verifică că FastAPI ascultă
ss -tlnp | grep 8000

# Verifică firewall Ubuntu Server
sudo ufw status
sudo ufw allow 8000/tcp  # dacă ufw e activ
```

### Eroare "Permission denied" la nft
```bash
# Adaugă utilizatorul la sudoers fără parolă pentru nft (pentru scripturi)
sudo visudo
# Adaugă: emicuciu ALL=(ALL) NOPASSWD: /usr/sbin/nft
```

---

## Snapshot-uri recomandate

Odată ce toate cele 3 VM-uri sunt configurate și conectivitatea funcționează:

1. **VirtualBox → VM → Snapshots → Take Snapshot**
2. Numește snapshot-ul: `"CuciSec-Clean-State"` pentru fiecare VM
3. Înainte de fiecare sesiune de teste distructive → restaurează snapshot-ul

Astfel, după un test care ban-ează Kali sau modifică reguli, poți reveni la starea curată în 30 de secunde.
