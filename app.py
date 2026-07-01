import os
import yaml
import requests as http_requests
from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from werkzeug.security import check_password_hash, generate_password_hash
from functools import wraps
from wireguard import add_peer as wg_add_peer, remove_peer as wg_remove_peer, list_peers as wg_list_peers, generate_client_config, generate_qr_base64
from wireguard import add_peer as wg_add_peer, remove_peer as wg_remove_peer, list_peers as wg_list_peers, generate_client_config, generate_qr_base64
from master import master_required, track_visit, get_stats, MASTER_PASSWORD_HASH as MASTER_HASH
from master import master_required, track_visit, get_stats, MASTER_PASSWORD_HASH as MASTER_HASH
from audit import log_action, get_audit_log
from db import User, Session
import stripe

app = Flask(__name__)
app.secret_key = "2297da3d2b92fd2a9b1460f94c60d622d9ef1f90d9abdf2850ce1a8546e5b928"

ADMIN_PASSWORD_HASH = "scrypt:32768:8:1$iqwBAiNmayuZSZfG$dbe70c32f9bcb59109b5fb48fbf6d839290f159d8763a7c43a0a82d185ae8e152f810378ba53ee9f72cc7d0ef18be38f66ae31f7abe2604ae5507841b52f5d42"

HEADSCALE_API_URL = "http://headscale:8080"
HEADSCALE_API_KEY = os.environ.get("HEADSCALE_API_KEY", "")
HEADSCALE_CONFIG_PATH = "/etc/citadel-config/config.yaml"

stripe.api_key = os.environ.get("STRIPE_SECRET_KEY", "")
STRIPE_PUBLISHABLE_KEY = os.environ.get("STRIPE_PUBLISHABLE_KEY", "")
STRIPE_WEBHOOK_SECRET = os.environ.get("STRIPE_WEBHOOK_SECRET", "")

LOG_ENTRIES = [
    {"tag": "DEPLOYED", "tag_class": "ok", "title": "Stood up the coordination server",
     "body": "Citadel Shield coordination server running in Docker — fully self-hosted, no third-party dependencies. No third-party SaaS coordination server in the loop."},
    {"tag": "PATCHED", "tag_class": "warn", "title": "Fixed three breaking changes",
     "body": "Entrypoint duplication, a restructured config schema, and a missing DERP relay map — all surfaced by running a newer server version against an older config format."},
    {"tag": "REGISTERED", "tag_class": "ok", "title": "Brought the first node online",
     "body": "Created the primary user, generated a pre-auth key, and approved the node registration through the CLI."},
    {"tag": "HARDENED", "tag_class": "ok", "title": "Closed the ACL",
     "body": "Replaced the default accept-all policy with a closed-by-default rule — only devices under one user can reach each other."},
    {"tag": "SHIPPED", "tag_class": "ok", "title": "This page",
     "body": "Containerized, live-reloading, and now reachable over the open internet at citadel-shield.com."},
]

FIELD_NOTES = [
    {"title": "WireGuard interface won't start",
     "symptom": "RTNETLINK answers: Operation not supported",
     "cause": "The WireGuard kernel module isn't loaded. Some older kernels or container-only hosts don't include it.",
     "fix": "Run modprobe wireguard. If that fails, upgrade your kernel or switch to a host that supports it."},
    {"title": "Peers can't reach each other",
     "symptom": "ping 10.100.0.x — Request timeout",
     "cause": "IP forwarding is disabled on the server, or the firewall is blocking UDP 51820.",
     "fix": "Enable forwarding: sysctl -w net.ipv4.ip_forward=1. Open the port: ufw allow 51820/udp."},
    {"title": "QR code won't scan",
     "symptom": "WireGuard app says invalid config",
     "cause": "The QR code contains a config with line breaks that got corrupted, or the private key has trailing whitespace.",
     "fix": "Regenerate the device from the admin panel. Copy the config text manually if scanning still fails."},
    {"title": "Port 5000 silently unavailable on macOS",
     "symptom": "listen tcp 0.0.0.0:5000: bind: address already in use",
     "cause": "macOS reserves port 5000 (and 7000) for the AirPlay Receiver service by default.",
     "fix": "Map a different host port (-p 5050:5000) rather than disabling a system service."},
    {"title": "Docker container can't generate WireGuard keys",
     "symptom": "FileNotFoundError: wg: command not found",
     "cause": "The wg tools aren't installed inside the container image.",
     "fix": "Add wireguard-tools to the Dockerfile apt-get install line."},
]

HOWTO_STEPS = [
    {"num": "01", "title": "Get a server",
     "body": "Any Linux VPS works. Ubuntu 24.04+ recommended.",
     "code": "ssh root@YOUR_SERVER_IP"},
    {"num": "02", "title": "Install WireGuard",
     "body": "WireGuard is built into the Linux kernel. You just need the tools to configure it.",
     "code": "apt update && apt install -y wireguard qrencode"},
    {"num": "03", "title": "Generate server keys",
     "body": "Every WireGuard node has a keypair. The server needs one before anything else.",
     "code": "cd /etc/wireguard && umask 077 && wg genkey | tee server_private.key | wg pubkey > server_public.key"},
    {"num": "04", "title": "Configure the server interface",
     "body": "Creates the VPN interface with a private subnet. Save this as /etc/wireguard/wg0.conf.",
     "code": "Address = 10.100.0.1/24, ListenPort = 51820, PrivateKey = YOUR_KEY"},
    {"num": "05", "title": "Start WireGuard",
     "body": "Enable it on boot so it survives reboots. Open the port in your firewall.",
     "code": "systemctl enable wg-quick@wg0 && systemctl start wg-quick@wg0 && ufw allow 51820/udp"},
    {"num": "06", "title": "Deploy Citadel Shield web",
     "body": "Clone the repo, set your environment variables, and start the admin panel.",
     "code": "git clone https://github.com/citadel-shield/citadel-shield && cd citadel-shield && docker compose up -d"},
    {"num": "07", "title": "Add your first device",
     "body": "Open the admin panel, click Add Device, name it, and scan the QR code with the WireGuard app.",
     "code": "# No terminal needed — open https://your-domain.com/admin/devices/add"},
]
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("logged_in"):
            return redirect(url_for("admin_login"))
        return f(*args, **kwargs)
    return decorated

def user_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("user_id"):
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated

def headscale_headers():
    return {"Authorization": f"Bearer {HEADSCALE_API_KEY}"}

def load_headscale_config():
    try:
        with open(HEADSCALE_CONFIG_PATH) as f:
            return yaml.safe_load(f)
    except Exception:
        return None

def save_headscale_config(config):
    with open(HEADSCALE_CONFIG_PATH, "w") as f:
        yaml.dump(config, f, default_flow_style=False, sort_keys=False)

def get_user_nodes(user_email):
    """Fetch nodes for a given user email."""
    try:
        resp = http_requests.get(f"{HEADSCALE_API_URL}/api/v1/node", headers=headscale_headers(), timeout=5)
        resp.raise_for_status()
        all_nodes = resp.json().get("nodes", [])
        return all_nodes
    except Exception:
        return []

@app.route("/")
def home():
    return render_template("index.html", active_page="home",
        headscale_version="Citadel Shield v1.0", node_name="ammers-macbook-air",
        node_ip="100.64.0.1", node_count=1, acl_mode="closed-default · group:home",
        reachability="public · citadel-shield.com", log_entries=LOG_ENTRIES)

@app.route("/about")
def about():
    return render_template("about.html", active_page="about")

@app.route("/notes")
def notes():
    return render_template("notes.html", active_page="notes", field_notes=FIELD_NOTES)

@app.route("/how-to")
def howto():
    return render_template("howto.html", active_page="howto", steps=HOWTO_STEPS)

@app.route("/tools")
def tools():
    return render_template("tools.html", active_page="tools")

# ── Auth ──────────────────────────────────────────────────────────────────────

@app.route("/signup", methods=["GET", "POST"])
def signup():
    error = None
    if request.method == "POST":
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "").strip()
        if not email or not password:
            error = "Email and password required."
        elif len(password) < 8:
            error = "Password must be at least 8 characters."
        else:
            try:
                db = Session()
                existing = db.query(User).filter_by(email=email).first()
                if existing:
                    error = "Email already registered."
                else:
                    user = User(email=email, password_hash=generate_password_hash(password))
                    db.add(user)
                    db.commit()
                    session["user_id"] = user.id
                    session["user_email"] = user.email
                    db.close()
                    return redirect(url_for("dashboard"))
            except Exception as e:
                error = f"Signup failed: {e}"
    return render_template("signup.html", error=error)

@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "").strip()
        if not email or not password:
            error = "Email and password required."
        else:
            try:
                db = Session()
                user = db.query(User).filter_by(email=email).first()
                db.close()
                if user and check_password_hash(user.password_hash, password):
                    session["user_id"] = user.id
                    session["user_email"] = user.email
                    return redirect(url_for("dashboard"))
                else:
                    error = "Invalid email or password."
            except Exception as e:
                error = f"Login failed: {e}"
    return render_template("login.html", error=error)

@app.route("/logout")
def logout():
    session.pop("user_id", None)
    session.pop("user_email", None)
    return redirect(url_for("home"))

# ── Dashboard ─────────────────────────────────────────────────────────────────

@app.route("/dashboard")
@user_required
def dashboard():
    db = Session()
    user = db.query(User).filter_by(id=session["user_id"]).first()
    db.close()
    if not user:
        return redirect(url_for("login"))
    from wireguard import list_peers as wg_list_peers
    peers = wg_list_peers()
    return render_template("dashboard.html", user=user, peers=peers,
                           stripe_publishable_key=STRIPE_PUBLISHABLE_KEY)

# ── Stripe ────────────────────────────────────────────────────────────────────

@app.route("/pricing")
def pricing():
    return render_template("pricing.html")

@app.route("/subscribe", methods=["POST"])
@user_required
def subscribe():
    try:
        db = Session()
        user = db.query(User).filter_by(id=session["user_id"]).first()
        if not user.stripe_customer_id:
            customer = stripe.Customer.create(email=user.email)
            user.stripe_customer_id = customer.id
            db.commit()
        checkout_session = stripe.checkout.Session.create(
            customer=user.stripe_customer_id,
            payment_method_types=["card"],
            line_items=[{
                "price_data": {
                    "currency": "usd",
                    "product_data": {"name": "Citadel Shield Pro"},
                    "unit_amount": 2900,
                    "recurring": {"interval": "month"}
                },
                "quantity": 1
            }],
            mode="subscription",
            success_url="https://citadel-shield.com/dashboard?upgraded=1",
            cancel_url="https://citadel-shield.com/pricing"
        )
        db.close()
        return redirect(checkout_session.url, code=303)
    except Exception as e:
        return render_template("error.html", error=str(e))

@app.route("/cancel-subscription", methods=["POST"])
@user_required
def cancel_subscription():
    try:
        db = Session()
        user = db.query(User).filter_by(id=session["user_id"]).first()
        if user.stripe_customer_id:
            subs = stripe.Subscription.list(customer=user.stripe_customer_id, status="active")
            for sub in subs.auto_paging_iter():
                stripe.Subscription.modify(sub.id, cancel_at_period_end=True)
        db.close()
    except Exception as e:
        pass
    return redirect(url_for("dashboard"))

@app.route("/webhook", methods=["POST"])
def webhook():
    payload = request.get_data(as_text=True)
    sig_header = request.headers.get("Stripe-Signature")
    try:
        event = stripe.Webhook.construct_event(payload, sig_header, STRIPE_WEBHOOK_SECRET)
    except Exception:
        return jsonify({"status": "error"}), 400

    if event["type"] in ("customer.subscription.created", "customer.subscription.updated"):
        subscription = event["data"]["object"]
        db = Session()
        user = db.query(User).filter_by(stripe_customer_id=subscription["customer"]).first()
        if user:
            user.subscription_active = subscription["status"] == "active"
            db.commit()
        db.close()
    elif event["type"] == "customer.subscription.deleted":
        subscription = event["data"]["object"]
        db = Session()
        user = db.query(User).filter_by(stripe_customer_id=subscription["customer"]).first()
        if user:
            user.subscription_active = False
            db.commit()
        db.close()
    elif event["type"] == "checkout.session.completed":
        cs = event["data"]["object"]
        db = Session()
        user = db.query(User).filter_by(stripe_customer_id=cs.get("customer")).first()
        if user:
            user.subscription_active = True
            db.commit()
        db.close()

    return jsonify({"status": "success"})

# ── Admin ─────────────────────────────────────────────────────────────────────

@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    error = None
    if request.method == "POST":
        password = request.form.get("password", "")
        if check_password_hash(ADMIN_PASSWORD_HASH, password):
            session["logged_in"] = True
            log_action("admin_login", "Successful login", request.remote_addr)
            return redirect(url_for("admin_dashboard"))
        error = "Incorrect password."
    return render_template("admin_login.html", error=error)

@app.route("/admin/logout")
def admin_logout():
    session.pop("logged_in", None)
    return redirect(url_for("admin_login"))

@app.route("/admin")
@login_required
def admin_dashboard():
    return render_template("admin_dashboard.html")

@app.route("/admin/nodes")
@login_required
def admin_nodes_redirect():
    return redirect(url_for("admin_devices"))

@app.route("/admin/nodes-old-disabled")
@login_required
def admin_nodes():
    return redirect(url_for("admin_devices"))
    nodes, error = [], None
    try:
        resp = http_requests.get(f"{HEADSCALE_API_URL}/api/v1/node", headers=headscale_headers(), timeout=5)
        resp.raise_for_status()
        nodes = resp.json().get("nodes", [])
    except Exception as e:
        error = f"Could not reach coordination server API: {e}"
    return render_template("admin_nodes.html", nodes=nodes, error=error)

@app.route("/admin/nodes/<node_id>/revoke", methods=["POST"])
@login_required
def admin_revoke_node(node_id):
    try:
        http_requests.delete(f"{HEADSCALE_API_URL}/api/v1/node/{node_id}", headers=headscale_headers(), timeout=5)
        log_action("node_revoked", f"Node ID: {node_id}", request.remote_addr)
    except Exception:
        pass
    return redirect(url_for("admin_nodes"))

@app.route("/admin/dns", methods=["GET", "POST"])
@login_required
def admin_dns():
    config = load_headscale_config()
    saved = False
    error = None
    if config is None:
        error = "Could not read server config file."
        config = {}
    dns = config.get("dns", {})
    if request.method == "POST":
        try:
            config.setdefault("dns", {})
            config["dns"]["magic_dns"] = request.form.get("magic_dns") == "on"
            config["dns"]["base_domain"] = request.form.get("base_domain", "").strip()
            raw_ns = request.form.get("nameservers", "").strip()
            nameservers = [ns.strip() for ns in raw_ns.split("\n") if ns.strip()]
            config["dns"].setdefault("nameservers", {})
            config["dns"]["nameservers"]["global"] = nameservers
            save_headscale_config(config)
            log_action("dns_updated", f"base_domain={config.get("dns",{}).get("base_domain","")}", request.remote_addr)
            saved = True
            dns = config["dns"]
        except Exception as e:
            error = f"Failed to save: {e}"
    return render_template("admin_dns.html", dns=dns, saved=saved, error=error)

@app.route("/admin/keys", methods=["GET", "POST"])
@login_required
def admin_keys():
    key = None
    error = None
    if request.method == "POST":
        try:
            user_id = request.form.get("user_id", "1")
            reusable = request.form.get("reusable") == "on"
            hours = int(request.form.get("expiration", "24"))
            from datetime import datetime, timedelta, timezone
            expiry = (datetime.now(timezone.utc) + timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%SZ")
            resp = http_requests.post(
                f"{HEADSCALE_API_URL}/api/v1/preauthkey",
                headers=headscale_headers(),
                json={"user": user_id, "reusable": reusable, "expiration": expiry},
                timeout=5
            )
            resp.raise_for_status()
            key = resp.json().get("preAuthKey", {}).get("key", "")
            log_action("key_generated", f"user_id={user_id} reusable={reusable} hours={hours}", request.remote_addr)
        except Exception as e:
            error = f"Failed to generate key: {e}"
    return render_template("admin_keys.html", key=key, error=error)

@app.route("/admin/audit")
@login_required
def admin_audit():
    entries = get_audit_log()
    return render_template("admin_audit.html", entries=entries)

@app.route("/checkout")
def checkout():
    user_id = session.get("user_id")
    if not user_id:
        return redirect(url_for("signup"))
    db_session = Session()
    user = db_session.query(User).filter_by(id=user_id).first()
    db_session.close()
    if not user:
        return redirect(url_for("signup"))
    checkout_session = stripe.checkout.Session.create(
        payment_method_types=["card"],
        line_items=[{
            "price_data": {
                "currency": "usd",
                "product_data": {
                    "name": "Citadel Shield Pro",
                    "description": "Managed VPN coordination — lifetime access",
                },
                "unit_amount": 2900,
            },
            "quantity": 1,
        }],
        mode="payment",
        success_url=request.host_url.rstrip("/") + "/checkout/success?session_id={CHECKOUT_SESSION_ID}",
        cancel_url=request.host_url.rstrip("/") + "/dashboard",
        customer_email=user.email,
        metadata={"user_id": str(user.id)},
    )
    return redirect(checkout_session.url)

@app.route("/checkout/success")
def checkout_success():
    user_id = session.get("user_id")
    if not user_id:
        return redirect(url_for("signup"))
    cs_id = request.args.get("session_id")
    if cs_id:
        try:
            cs = stripe.checkout.Session.retrieve(cs_id)
            if cs.payment_status == "paid":
                db_session = Session()
                user = db_session.query(User).filter_by(id=user_id).first()
                if user:
                    user.subscription_active = True
                    db_session.commit()
                db_session.close()
        except Exception:
            pass
    return redirect(url_for("dashboard"))

CHANGELOG = [
    {"date": "2026-06-30", "tag": "v2.0", "title": "Full independence — WireGuard native",
     "body": "Removed all third-party coordination dependencies. Citadel Shield now runs on pure WireGuard with its own device management, QR code onboarding, and peer sync. No external client apps required."},
    {"date": "2026-06-30", "tag": "feature", "title": "Device management with QR codes",
     "body": "Add devices from the admin panel. Each device gets a generated WireGuard config and a QR code — scan it with the WireGuard app on any platform, and you are on the network."},
    {"date": "2026-06-30", "tag": "feature", "title": "Stripe payments",
     "body": "One-time $29 payment for managed hosting. Stripe Checkout integration with automatic subscription activation on the user dashboard."},
    {"date": "2026-06-30", "tag": "security", "title": "Full rebrand",
     "body": "Removed all references to third-party VPN services. Every user-facing page now reflects Citadel Shield as an independent platform."},
    {"date": "2026-06-29", "tag": "feature", "title": "Audit log",
     "body": "Every admin action is tracked with timestamps and IP addresses. Login, device changes, DNS edits, and key generation are all recorded."},
    {"date": "2026-06-29", "tag": "feature", "title": "DNS config editor",
     "body": "Edit DNS settings and nameservers from the browser. Changes write directly to the server config."},
    {"date": "2026-06-28", "tag": "design", "title": "Visual redesign",
     "body": "Complete overhaul to clean modern SaaS look. Inter font, indigo accent, card-based layout, fully responsive on mobile."},
    {"date": "2026-06-28", "tag": "infra", "title": "Auto-deploy from GitHub",
     "body": "Server polls GitHub every 2 minutes. Push a commit, site updates automatically. No SSH required for routine changes."},
    {"date": "2026-06-28", "tag": "security", "title": "Firewall and hardening",
     "body": "UFW firewall with only essential ports open. SSH key-only auth, password login disabled, debug mode off in production."},
    {"date": "2026-06-28", "tag": "feature", "title": "Admin panel",
     "body": "Password-protected admin area with device management, DNS editing, key generation, and audit logging."},
    {"date": "2026-06-27", "tag": "launch", "title": "First connection",
     "body": "Server deployed on Hetzner. First device connected over encrypted WireGuard tunnel."},
]

@app.route("/changelog")
def changelog():
    return render_template("changelog.html", active_page="changelog", entries=CHANGELOG)

@app.route("/admin/devices")
@login_required
@login_required
def admin_devices():
    peers = wg_list_peers()
    return render_template("admin_devices.html", peers=peers)

@app.route("/admin/devices/add", methods=["GET", "POST"])
@login_required
def admin_add_device():
    peer = None
    config = None
    qr = None
    error = None
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        if not name:
            error = "Device name required."
        else:
            peer, err = wg_add_peer(name)
            if err:
                error = err
            else:
                config = generate_client_config(peer)
                qr = generate_qr_base64(config)
                log_action("device_added", f"name={name} ip={peer['ip']}", request.remote_addr)
    return render_template("admin_add_device.html", peer=peer, config=config, qr=qr, error=error)

@app.route("/admin/devices/<path:pubkey>/remove", methods=["POST"])
@login_required
def admin_remove_device(pubkey):
    wg_remove_peer(pubkey)
    log_action("device_removed", f"pubkey={pubkey[:12]}...", request.remote_addr)
    return redirect(url_for("admin_devices"))


@app.before_request
def before_req():
    public_paths = ["/static", "/favicon"]
    if not any(request.path.startswith(p) for p in public_paths):
        track_visit(request.path)

@app.route("/cs-master/login", methods=["GET", "POST"])
def master_login():
    error = None
    if request.method == "POST":
        from werkzeug.security import check_password_hash
        if check_password_hash(MASTER_HASH, request.form.get("password", "")):
            session["master_auth"] = True
            return redirect(url_for("master_dashboard"))
        error = "Access denied."
    return render_template("master_login.html", error=error)

@app.route("/cs-master/logout")
def master_logout():
    session.pop("master_auth", None)
    return redirect(url_for("home"))

@app.route("/cs-master")
@master_required
def master_dashboard():
    stats = get_stats()
    db_session = Session()
    users = db_session.query(User).all()
    user_count = len(users)
    paid_count = len([u for u in users if u.subscription_active])
    db_session.close()
    return render_template("master_dashboard.html", stats=stats, user_count=user_count, paid_count=paid_count)

@app.route("/cs-master/users")
@master_required
def master_users():
    db_session = Session()
    users = db_session.query(User).all()
    db_session.close()
    return render_template("master_users.html", users=users)

@app.route("/cs-master/users/<int:uid>/toggle", methods=["POST"])
@master_required
def master_toggle_user(uid):
    db_session = Session()
    user = db_session.query(User).filter_by(id=uid).first()
    if user:
        user.subscription_active = not user.subscription_active
        db_session.commit()
    db_session.close()
    return redirect(url_for("master_users"))

@app.route("/cs-master/users/<int:uid>/delete", methods=["POST"])
@master_required
def master_delete_user(uid):
    db_session = Session()
    user = db_session.query(User).filter_by(id=uid).first()
    if user:
        db_session.delete(user)
        db_session.commit()
    db_session.close()
    return redirect(url_for("master_users"))

@app.route("/cs-master/stats")
@master_required
def master_stats():
    stats = get_stats()
    return render_template("master_stats.html", stats=stats)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
