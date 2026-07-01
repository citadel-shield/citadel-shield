import subprocess
import json
import os
import base64
import io
import qrcode

PEERS_FILE = "/data/peers.json"
SERVER_PUBKEY_FILE = "/data/server_public.key"
SERVER_ENDPOINT = "5.161.47.164:51820"
SUBNET = "10.100.0"
DNS = "1.1.1.1, 9.9.9.9"

def _load_peers():
    try:
        with open(PEERS_FILE) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return []

def _save_peers(peers):
    with open(PEERS_FILE, "w") as f:
        json.dump(peers, f, indent=2)

def _get_server_pubkey():
    try:
        with open(SERVER_PUBKEY_FILE) as f:
            return f.read().strip()
    except FileNotFoundError:
        return ""

def _next_ip(peers):
    used = {p["ip"] for p in peers}
    for i in range(2, 255):
        ip = f"{SUBNET}.{i}"
        if ip not in used:
            return ip
    return None

def generate_keypair():
    private = subprocess.run(["wg", "genkey"], capture_output=True, text=True).stdout.strip()
    public = subprocess.run(["wg", "pubkey"], input=private, capture_output=True, text=True).stdout.strip()
    return private, public

def add_peer(name):
    peers = _load_peers()
    ip = _next_ip(peers)
    if not ip:
        return None, "No available IPs"
    private_key, public_key = generate_keypair()
    peer = {
        "name": name,
        "ip": ip,
        "public_key": public_key,
        "private_key": private_key,
        "active": True
    }
    peers.append(peer)
    _save_peers(peers)
    _write_sync_file(peers)
    return peer, None

def remove_peer(public_key):
    peers = _load_peers()
    peers = [p for p in peers if p["public_key"] != public_key]
    _save_peers(peers)
    _write_sync_file(peers)

def list_peers():
    return _load_peers()

def generate_client_config(peer):
    server_pubkey = _get_server_pubkey()
    return f"""[Interface]
PrivateKey = {peer['private_key']}
Address = {peer['ip']}/24
DNS = {DNS}

[Peer]
PublicKey = {server_pubkey}
Endpoint = {SERVER_ENDPOINT}
AllowedIPs = {SUBNET}.0/24
PersistentKeepalive = 25"""

def generate_qr_base64(config_text):
    qr = qrcode.make(config_text, box_size=8, border=2)
    buf = io.BytesIO()
    qr.save(buf, format="PNG")
    return base64.b64encode(buf.getvalue()).decode()

def _write_sync_file(peers):
    active = [p for p in peers if p.get("active", True)]
    sync_data = [{"public_key": p["public_key"], "ip": p["ip"]} for p in active]
    with open("/data/wg_sync.json", "w") as f:
        json.dump(sync_data, f, indent=2)
