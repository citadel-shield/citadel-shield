# Citadel Shield

A self-hosted VPN coordination platform built on WireGuard. Add devices from a web panel, scan a QR code, and connect — encrypted, private, on infrastructure you own.

No third-party coordination servers. No telemetry. No vendor lock-in. One-time payment, lifetime access.

---

## How it works

1. You run Citadel Shield on a Linux server
2. Open the admin panel in your browser
3. Click "Add device" — get a WireGuard config and QR code
4. Scan it with the WireGuard app on any device
5. Connected. Encrypted. On your network.

---

## Features

**VPN coordination**
- WireGuard-encrypted tunnels between all devices
- Hub-and-spoke architecture — all traffic routes through your server
- Automatic peer sync — admin panel changes apply within 60 seconds
- Works with the free WireGuard app on iOS, Android, macOS, Windows, Linux

**Web admin panel** (password-protected)
- Device management — add, remove, view connected devices
- QR code generation — scan to connect, no manual config needed
- DNS config editor — MagicDNS, nameservers, base domain
- Pre-auth key generator
- Audit log — every admin action tracked with timestamps and IPs

**User system**
- Signup and login
- Stripe checkout — $29 one-time for managed hosting
- Pro dashboard with device management and setup guide
- Free tier with upgrade prompt

**Master panel** (hidden, separate auth)
- Site analytics — page visits by day
- User management — view signups, toggle subscriptions, delete accounts
- Accessible at a secret URL, not linked from anywhere

**Infrastructure**
- Auto-deploy from GitHub (cron polls every 2 minutes)
- Caddy reverse proxy with Cloudflare HTTPS (Flexible mode)
- UFW firewall — ports 22, 80, 8080, 51820 only
- SSH key-only authentication
- Scrypt-hashed passwords
- API keys via environment variables, never in source

---

## Quick start

### Prerequisites

- Linux server (Ubuntu 24.04+ recommended)
- Domain pointed at the server (Cloudflare recommended)
- Docker installed

### 1. Install WireGuard

```bash
apt update && apt install -y wireguard qrencode
```

### 2. Configure the server

```bash
cd /etc/wireguard
umask 077
wg genkey | tee server_private.key | wg pubkey > server_public.key

cat > wg0.conf << EOF
[Interface]
Address = 10.100.0.1/24
ListenPort = 51820
PrivateKey = $(cat server_private.key)
PostUp = iptables -A FORWARD -i wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
PostDown = iptables -D FORWARD -i wg0 -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE
EOF

echo "net.ipv4.ip_forward = 1" >> /etc/sysctl.conf
sysctl -p
systemctl enable wg-quick@wg0
systemctl start wg-quick@wg0
ufw allow 51820/udp
```

### 3. Deploy Citadel Shield

```bash
git clone https://github.com/citadel-shield/citadel-shield.git
cd citadel-shield
cp .env.example .env
# Edit .env with your values
docker compose up -d
```

### 4. Copy the server public key

```bash
cp /etc/wireguard/server_public.key /data/server_public.key
```

### 5. Set your admin password

```bash
docker exec -it citadel-web python3 -c "from werkzeug.security import generate_password_hash; print(generate_password_hash(input('Password: ')))"
```

Paste the hash into `app.py` as `ADMIN_PASSWORD_HASH`.

### 6. Add your first device

Open `https://your-domain.com/admin/devices/add`, name the device, and scan the QR code with the WireGuard app.

---

## Project structure
---

## Security

- All VPN traffic encrypted with WireGuard (built into the Linux kernel)
- Admin and master passwords are scrypt-hashed — never stored in plaintext
- Stripe keys and API credentials passed via environment variables
- `.env` is gitignored — secrets never committed
- UFW firewall: only ports 22 (SSH), 80 (HTTP), 8080 (coordination), 51820 (WireGuard)
- SSH key-only access — password authentication disabled
- Audit log tracks every admin action with timestamps and source IPs
- `debug=False` in production

---

## Cloudflare setup

1. Add an A record: `@` → your server IP, Proxied (orange cloud)
2. SSL/TLS → Flexible mode
3. Email Routing → create `contact@yourdomain.com` forwarding rule

---

## Stack

| Component | Role |
|-----------|------|
| WireGuard | VPN tunnels (kernel-level encryption) |
| Flask | Web application and admin panel |
| Gunicorn | Production WSGI server |
| Docker | Container runtime |
| Caddy | Reverse proxy |
| Cloudflare | DNS, HTTPS, email routing |
| Stripe | Payment processing |
| SQLite | User database |

---

## License

MIT
