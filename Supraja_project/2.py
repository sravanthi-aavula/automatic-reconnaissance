import threading
import socket
import ssl
import json
import os
import sys
import datetime
from pathlib import Path

# ----------------------------- Optional deps (graceful) -----------------------------
try:
    import whois
except Exception:
    whois = None

try:
    import dns.resolver
except Exception:
    dns = None

try:
    import requests
except Exception:
    requests = None

try:
    from bs4 import BeautifulSoup
except Exception:
    BeautifulSoup = None

try:
    import builtwith
except Exception:
    builtwith = None

try:
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
except Exception:
    x509 = None

try:
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options
except Exception:
    webdriver = None

try:
    from fpdf import FPDF
except Exception:
    FPDF = None

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, filedialog
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
import subprocess
import shutil


# ============================= Utility helpers =====================================

CHECK = "[OK]"
CROSS = "[✗]"


def ensure_output_dirs():
    root = Path.cwd() / "output"
    (root / "screenshots").mkdir(parents=True, exist_ok=True)
    return root


def normalize_url(target: str) -> str:
    return target if target.startswith("http://") or target.startswith("https://") else f"http://{target}"


def to_str_list(val):
    if val is None:
        return []
    if isinstance(val, (list, tuple, set)):
        return [str(x) for x in val]
    return [str(val)]


def safe_join_lines(lines):
    return "\n".join(str(x) for x in lines if x is not None)

# ----------------------------- Settings & Email helpers -----------------------------
SETTINGS_PATH = Path.cwd() / "output" / "settings.json"

DEFAULT_SETTINGS = {
    "smtp": {
        "host": "",
        "port": 587,
        "username": "",
        "password": "",
        "use_tls": True,
        "from_email": "",
        "to_email": ""
    },
    "apis": {
        "shodan_api_key": ""
    }
}


def load_settings():
    ensure_output_dirs()
    try:
        if SETTINGS_PATH.exists():
            with open(SETTINGS_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
            # ensure keys
            for k, v in DEFAULT_SETTINGS.items():
                if k not in data or not isinstance(data[k], dict):
                    data[k] = v
                else:
                    for sk, sv in DEFAULT_SETTINGS[k].items():
                        data[k].setdefault(sk, sv)
            return data
    except Exception:
        pass
    return json.loads(json.dumps(DEFAULT_SETTINGS))


def save_settings(data):
    try:
        SETTINGS_PATH.parent.mkdir(parents=True, exist_ok=True)
        with open(SETTINGS_PATH, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        return True
    except Exception as e:
        return f"Settings save error: {e}"


def send_email_with_attachment(cfg, subject, body, attachment_path=None):
    try:
        msg = MIMEMultipart()
        from_addr = cfg.get("from_email") or cfg.get("username")
        to_emails = [e.strip() for e in (cfg.get("to_email", "")).split(",") if e.strip()]
        if not from_addr or not to_emails:
            return "Missing from/to emails in SMTP settings."

        msg["From"] = from_addr
        msg["To"] = ", ".join(to_emails)
        msg["Subject"] = subject
        msg.attach(MIMEText(body, "plain"))

        if attachment_path and os.path.exists(attachment_path):
            with open(attachment_path, "rb") as f:
                part = MIMEBase("application", "octet-stream")
                part.set_payload(f.read())
            encoders.encode_base64(part)
            part.add_header("Content-Disposition", f'attachment; filename="{os.path.basename(attachment_path)}"')
            msg.attach(part)

        host = cfg.get("host") or ""
        port = int(cfg.get("port") or 587)
        use_tls = bool(cfg.get("use_tls", True))
        if use_tls:
            server = smtplib.SMTP(host, port, timeout=15)
            server.starttls()
        else:
            server = smtplib.SMTP_SSL(host, port, timeout=15)
        user = cfg.get("username") or ""
        pwd = cfg.get("password") or ""
        if user:
            server.login(user, pwd)
        server.sendmail(from_addr, to_emails, msg.as_string())
        server.quit()
        return True
    except Exception as e:
        return f"Email error: {e}"


# ============================= Recon functions =====================================

def fetch_ip(domain):
    try:
        return socket.gethostbyname(domain)
    except Exception as e:
        return f"Error resolving IP: {e}"


def fetch_whois(domain):
    if whois is None:
        return "python-whois not installed. pip install python-whois"
    try:
        w = whois.whois(domain)
        # whois library returns a dict-like object; convert to pure dict safely
        return dict(w)
    except Exception as e:
        return f"WHOIS error: {e}"


def fetch_dns_records(domain):
    if dns is None:
        return "dnspython not installed. pip install dnspython"
    out = {"A": [], "AAAA": [], "MX": [], "NS": [], "TXT": [], "CNAME": [], "SOA": []}
    types = list(out.keys())
    for t in types:
        try:
            answers = dns.resolver.resolve(domain, t, lifetime=5)
            for r in answers:
                out[t].append(r.to_text())
        except Exception:
            # ignore per-type failures
            pass
    return out


def fetch_http_headers(domain):
    if requests is None:
        return {"error": "requests not installed. pip install requests"}
    try:
        url = normalize_url(domain)
        r = requests.get(url, timeout=8, allow_redirects=True)
        return {
            "status": r.status_code,
            "headers": dict(r.headers),
            "final_url": r.url
        }
    except Exception as e:
        return {"error": f"HTTP error: {e}"}


def fetch_ssl_cert(domain):
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=6) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                der = ssock.getpeercert(binary_form=True)
                if x509 is None:
                    return {"error": "cryptography not installed. pip install cryptography"}
                cert = x509.load_der_x509_certificate(der, default_backend())
                subject = cert.subject.rfc4514_string()
                issuer = cert.issuer.rfc4514_string()
                san = []
                try:
                    ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
                    san = ext.value.get_values_for_type(x509.DNSName)
                except Exception:
                    pass
                return {
                    "subject": subject,
                    "issuer": issuer,
                    "valid_from": str(cert.not_valid_before),
                    "valid_to": str(cert.not_valid_after),
                    "sans": san
                }
    except Exception as e:
        return {"error": f"SSL fetch error: {e}"}


def fetch_robots_and_sitemap(domain):
    if requests is None:
        return {"error": "requests not installed. pip install requests"}
    base = normalize_url(domain).rstrip("/")
    result = {"robots": None, "sitemap": None, "sitemap_error": None, "robots_error": None}
    # robots.txt
    try:
        r = requests.get(f"{base}/robots.txt", timeout=6)
        result["robots"] = r.text if r.status_code == 200 else f"robots.txt not found ({r.status_code})"
    except Exception as e:
        result["robots_error"] = f"robots fetch error: {e}"

    # sitemap.xml
    try:
        r = requests.get(f"{base}/sitemap.xml", timeout=6)
        if r.status_code == 200 and r.text.strip():
            if BeautifulSoup is None:
                result["sitemap"] = "sitemap.xml found; install beautifulsoup4 to parse"
            else:
                soup = BeautifulSoup(r.text, "xml")
                urls = [u.text for u in soup.find_all("loc")]
                result["sitemap"] = urls[:50]  # cap for safety
        else:
            result["sitemap_error"] = f"sitemap.xml not found ({r.status_code})"
    except Exception as e:
        result["sitemap_error"] = f"sitemap fetch error: {e}"

    return result


def detect_technologies(domain):
    if builtwith is None:
        return {"error": "builtwith not installed. pip install builtwith"}
    try:
        url = normalize_url(domain)
        parsed = builtwith.parse(url)
        return parsed
    except Exception as e:
        return {"error": f"builtwith error: {e}"}


def geolocate_ip(ip):
    if requests is None:
        return {"error": "requests not installed. pip install requests"}
    try:
        r = requests.get(f"http://ip-api.com/json/{ip}", timeout=6)
        return r.json()
    except Exception as e:
        return {"error": f"Geolocation error: {e}"}


def fetch_shodan_info(ip, api_key):
    if not api_key:
        return {"error": "Shodan API key not configured."}
    if requests is None:
        return {"error": "requests not installed. pip install requests"}
    try:
        r = requests.get(f"https://api.shodan.io/shodan/host/{ip}", params={"key": api_key}, timeout=8)
        if r.status_code != 200:
            txt = r.text.strip().replace("\n", " ")
            return {"error": f"Shodan HTTP {r.status_code}: {txt[:200]}"}
        data = r.json()
        out = {
            "ip": data.get("ip_str") or ip,
            "org": data.get("org"),
            "isp": data.get("isp"),
            "asn": data.get("asn"),
            "ports": data.get("ports", [])[:25],
        }
        vulns = data.get("vulns") or {}
        if isinstance(vulns, dict):
            out["vulns"] = list(vulns.keys())[:30]
        elif isinstance(vulns, list):
            out["vulns"] = vulns[:30]
        else:
            out["vulns"] = []
        return out
    except Exception as e:
        return {"error": f"Shodan error: {e}"}


def generate_simulated_results(target):
    now = datetime.datetime.now()
    parts = []
    parts.append(f"Starting reconnaissance on: {target}\n\nTimestamp: {now}\n")
    parts.append(format_basic("93.184.216.34", {"status": "success", "city": "Los Angeles", "regionName": "California", "country": "United States"}))
    parts.append(format_whois_section({"registrar": "Example Registrar", "org": "Example Org", "emails": ["admin@example.com"], "creation_date": [str(now.date())], "expiration_date": [str(now.date())]}))
    parts.append(format_dns_section({"A": ["93.184.216.34"], "AAAA": [], "MX": ["10 mail.example.com."], "NS": ["ns1.example.com."], "TXT": ["v=spf1 -all"], "CNAME": [], "SOA": ["ns1.example.com. hostmaster.example.com. 1 7200 3600 1209600 3600"]}))
    parts.append(format_http({"status": 200, "headers": {"Server": "nginx", "X-Powered-By": "Simulated/1.0"}, "final_url": normalize_url(target)}))
    parts.append(format_ssl({"subject": "CN=example.com", "issuer": "CN=Example CA", "valid_from": str(now), "valid_to": str(now + datetime.timedelta(days=365)), "sans": ["example.com", "www.example.com"]}))
    parts.append(format_robots_sitemap({"robots": "User-agent: *\nDisallow: /admin", "sitemap": ["http://example.com/", "http://example.com/about"]}))
    parts.append(format_tech({"Web frameworks": ["Django"], "JavaScript Frameworks": ["jQuery"]}))
    parts.append(format_meta({"title": "Example Domain", "description": "This is a simulated result.", "keywords": "example, simulated", "generator": "SimGen", "canonical": normalize_url(target)}))
    parts.append(format_admin([(f"{normalize_url(target)}/admin", 403, 1234)]))
    parts.append("\n=== Screenshot ===\n" + CROSS + " Simulation mode: screenshot not captured.")
    parts.append("\n=== Report Saved ===\n\nRecon complete.\n")
    return "\n".join(parts)


def brute_force_admin_panels(domain):
    if requests is None:
        return {"error": "requests not installed. pip install requests"}
    wordlist = ['admin', 'administrator', 'admin.php', 'admin/login', 'login', 'cpanel', 'manage']
    found = []
    base = normalize_url(domain).rstrip("/")
    checked = 0
    for p in wordlist:
        if checked >= 50:
            break
        url = f"{base}/{p}"
        try:
            r = requests.get(url, timeout=5, allow_redirects=False)
            if r.status_code in (200, 401, 403, 302):
                found.append((url, r.status_code, len(r.text)))
        except Exception:
            pass
        checked += 1
    return found


def fetch_html_meta(domain):
    """Return basic HTML meta fields from homepage."""
    if requests is None:
        return {"error": "requests not installed. pip install requests"}
    url = normalize_url(domain)
    try:
        r = requests.get(url, timeout=10)
        html = r.text
        if BeautifulSoup is None:
            return {"warning": "Install beautifulsoup4 to parse meta", "raw_length": len(html)}
        soup = BeautifulSoup(html, "html.parser")
        title = soup.title.string.strip() if soup.title and soup.title.string else None
        meta = {m.get("name", m.get("property", "")).lower(): m.get("content", "") for m in soup.find_all("meta")}
        canonical = ""
        link_canon = soup.find("link", rel="canonical")
        if link_canon and link_canon.get("href"):
            canonical = link_canon["href"]
        return {
            "title": title,
            "description": meta.get("description") or meta.get("og:description"),
            "keywords": meta.get("keywords"),
            "generator": meta.get("generator"),
            "canonical": canonical
        }
    except Exception as e:
        return {"error": f"Meta fetch error: {e}"}


def take_screenshot(domain, out_dir: Path):
    """Take a screenshot with Selenium (Chrome headless). Returns output path or error."""
    if webdriver is None:
        return {"error": "selenium not installed (or webdriver unavailable)."}
    try:
        options = Options()
        options.add_argument("--headless=new")
        options.add_argument("--no-sandbox")
        options.add_argument("--disable-gpu")
        options.add_argument("--window-size=1366,768")
        driver = webdriver.Chrome(options=options)
        url = normalize_url(domain)
        driver.get(url)
        driver.implicitly_wait(3)
        out_path = out_dir / "screenshots" / (domain.replace("://", "_").replace("/", "_") + ".png")
        driver.save_screenshot(str(out_path))
        driver.quit()
        return {"path": str(out_path)}
    except Exception as e:
        return {"error": f"Selenium screenshot error: {e}"}


def export_to_pdf(text, out_path, screenshot_path=None):
    if FPDF is None:
        return "fpdf not installed. pip install fpdf"
    try:
        pdf = FPDF()
        pdf.set_auto_page_break(auto=True, margin=12)
        pdf.add_page()

        # ✅ Add Unicode font (DejaVuSans.ttf must be in same folder as 2.py)
        pdf.add_font("DejaVu", "", "DejaVuSans.ttf", uni=True)
        pdf.set_font("DejaVu", "", 12)

        pdf.cell(0, 8, "Automatic Reconnaissance Report", ln=True)
        pdf.set_font("DejaVu", "", 10)
        pdf.multi_cell(0, 5, text)

        if screenshot_path and os.path.exists(screenshot_path):
            try:
                pdf.add_page()
                pdf.set_font("DejaVu", "", 12)
                pdf.cell(0, 8, "Homepage Screenshot", ln=True)
                pdf.image(screenshot_path, x=10, y=None, w=190)
            except Exception as e:
                print(f"[!] Screenshot insert failed: {e}")

        pdf.output(out_path)
        return out_path
    except Exception as e:
        return f"PDF export error: {e}"
def format_shodan(sdata):
    if not sdata:
        return "\n=== Shodan Info ===\nNo Shodan data available.\n"

    # If API restriction error
    if isinstance(sdata, dict) and "error" in sdata:
        if "Requires membership" in sdata["error"]:
            return "\n=== Shodan Info ===\n⚠️ Shodan requires a paid membership to access detailed host information.\n"
        return f"\n=== Shodan Info ===\nError: {sdata['error']}\n"

    lines = ["\n=== Shodan Info ==="]
    lines.append(f"IP: {sdata.get('ip_str', 'N/A')}")
    lines.append(f"Organization: {sdata.get('org', 'N/A')}")
    lines.append(f"ISP: {sdata.get('isp', 'N/A')}")
    lines.append(f"ASN: {sdata.get('asn', 'N/A')}")
    lines.append(f"Open Ports: {', '.join(map(str, sdata.get('ports', []))) if sdata.get('ports') else 'None'}")
    vulns = sdata.get('vulns', [])
    if vulns:
        lines.append("Vulnerabilities (first 30): " + ", ".join(list(vulns)[:30]))
    return "\n".join(lines)



# ============================= Formatting helpers ============================

def format_basic(ip, geo):
    lines = ["=== Basic Recon ==="]
    if isinstance(ip, str) and ip.startswith("Error"):
        lines.append(f"{CROSS} IP Address: {ip}")
    else:
        lines.append(f"{CHECK} IP Address: {ip}")
        if isinstance(geo, dict) and geo.get("status") == "success":
            loc = f'{geo.get("city")}, {geo.get("regionName")}, {geo.get("country")}'
            lines.append(f"{CHECK} Location: {loc}")
    return safe_join_lines(lines)
def format_whois_section(w):
    lines = ["\n=== Whois Info ==="]
    if isinstance(w, str):
        # already an error string
        lines.append(w if "error" in w.lower() else "Whois data not found.")
        return safe_join_lines(lines)
    if not isinstance(w, dict) or not w:
        lines.append("Whois data not found.")
        return safe_join_lines(lines)
    registrar = w.get("registrar")
    org = w.get("org")
    emails = ", ".join(to_str_list(w.get("emails")))[:500]
    created = to_str_list(w.get("creation_date"))[:1]
    expires = to_str_list(w.get("expiration_date"))[:1]
    lines.append(f"Registrar: {registrar or 'N/A'}")
    lines.append(f"Org: {org or 'N/A'}")
    lines.append(f"Emails: {emails or 'N/A'}")
    if created:
        lines.append(f"Created: {created[0]}")
    if expires:
        lines.append(f"Expires: {expires[0]}")
    return safe_join_lines(lines)


def format_dns_section(dnsmap):
    lines = ["\n=== DNS Records ==="]
    if isinstance(dnsmap, str):
        lines.append(dnsmap)
        return safe_join_lines(lines)
    for k in ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]:
        vals = dnsmap.get(k, [])
        if vals:
            if k in ("TXT",):
                for t in vals[:30]:
                    t = t.replace("\n", " ")
                    lines.append(f"{k}: {t}")
            else:
                for v in vals:
                    lines.append(f"{k}: {v}")
        else:
            lines.append(f"{k}: None")
    return safe_join_lines(lines)


def format_http(headers_info):
    lines = ["\n=== HTTP Headers ==="]
    if "error" in headers_info:
        lines.append(headers_info["error"])
    else:
        lines.append(f"Status: {headers_info.get('status')}")
        hdrs = headers_info.get("headers", {})
        try:
            lines.append("Headers:\n" + json.dumps(hdrs, indent=2))
        except Exception:
            lines.append("Headers: (unprintable)")
        lines.append(f"Final URL: {headers_info.get('final_url')}")
    return safe_join_lines(lines)


def format_ssl(sslmap):
    lines = ["\n=== SSL Info ==="]
    if "error" in sslmap:
        lines.append(sslmap["error"] or "No SSL info found.")
    else:
        lines.append(f"Subject: {sslmap.get('subject')}")
        lines.append(f"Issuer: {sslmap.get('issuer')}")
        lines.append(f"Valid From: {sslmap.get('valid_from')}")
        lines.append(f"Valid To: {sslmap.get('valid_to')}")
        sans = sslmap.get("sans", [])
        if sans:
            lines.append(f"SANs (first 10): {', '.join(sans[:10])}")
    return safe_join_lines(lines)


def format_robots_sitemap(rs):
    lines = ["\n=== robots.txt & sitemap.xml ==="]
    robots_text = rs.get("robots")
    robots_err = rs.get("robots_error")
    sitemap = rs.get("sitemap")
    sitemap_err = rs.get("sitemap_error")

    if robots_err:
        lines.append(robots_err)
    elif robots_text:
        lines.append("robots.txt:\n" + robots_text[:4000])  # cap length
    else:
        lines.append("robots.txt: Not available")

    if isinstance(sitemap, list) and sitemap:
        lines.append("sitemap URLs (first 20):\n" + "\n".join(sitemap[:20]))
    elif isinstance(sitemap, str):
        lines.append(sitemap)
    elif sitemap_err:
        lines.append(sitemap_err)
    else:
        lines.append("sitemap.xml: Not available")

    return safe_join_lines(lines)


def format_tech(tech):
    lines = ["\n=== Tech Stack ==="]
    if "error" in tech:
        lines.append(tech["error"])
        return safe_join_lines(lines)
    if not tech:
        lines.append("None")
        return safe_join_lines(lines)

    # Show common categories if present
    for cat, vals in tech.items():
        if not vals:
            continue
        lines.append(f"{cat}: {', '.join(vals[:8])}")
    return safe_join_lines(lines)


def format_meta(meta):
    lines = ["\n=== HTML Meta Data ==="]
    if "error" in meta:
        lines.append(meta["error"])
    else:
        lines.append(f"Title: {meta.get('title') or 'N/A'}")
        lines.append(f"Description: {meta.get('description') or 'N/A'}")
        lines.append(f"Keywords: {meta.get('keywords') or 'N/A'}")
        lines.append(f"Generator: {meta.get('generator') or 'N/A'}")
        lines.append(f"Canonical: {meta.get('canonical') or 'N/A'}")
    return safe_join_lines(lines)


def format_admin(found):
    lines = ["\n=== Admin Panel Finder ==="]
    if isinstance(found, dict) and "error" in found:
        lines.append(found["error"])
    elif not found:
        lines.append("No admin endpoints discovered.")
    else:
        for url, code, size in found:
            lines.append(f"[+] {url}  -> {code} ({size} bytes)")
    return safe_join_lines(lines)


# ============================= GUI Class ====================================

class ReconGUI:
    def __init__(self, root):
        self.root = root
        root.title("Automatic Reconnaissance with Python")
        root.geometry("940x700")

        frame = ttk.Frame(root, padding=8)
        frame.pack(fill='both', expand=True)

        row = ttk.Frame(frame)
        row.pack(fill='x', pady=6)
        ttk.Label(row, text="Target (domain or IP):").pack(side='left')
        self.target_entry = ttk.Entry(row, width=50)
        self.target_entry.pack(side='left', padx=6)

        ttk.Button(row, text="Start Recon", command=self.start_recon).pack(side='left', padx=6)
        ttk.Button(row, text="Clear Output", command=self.clear_output).pack(side='left')
        ttk.Button(row, text="Project Info", command=self.show_info).pack(side='left', padx=6)
        self.sim_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(row, text="Simulation Mode", variable=self.sim_var).pack(side='left', padx=6)

        self.out = scrolledtext.ScrolledText(frame, wrap='word', state='normal', font=("Consolas", 10))
        self.out.pack(fill='both', expand=True)

        bottom = ttk.Frame(frame)
        bottom.pack(fill='x', pady=8)
        ttk.Button(bottom, text='Export to PDF', command=self.save_pdf).pack(side='left')
        ttk.Button(bottom, text='Email Report', command=self.email_report).pack(side='left', padx=6)
        ttk.Button(bottom, text='Settings', command=self.open_settings).pack(side='left')
        ttk.Button(bottom, text='Build EXE', command=self.build_exe).pack(side='left', padx=6)

        self.last_results = ''
        self.settings = load_settings()
        self.last_pdf_path = None
        self.last_screenshot_path = None

    # ---- safe append from any thread
    def append(self, text):
        self.out.config(state='normal')
        self.out.insert('end', text)
        self.out.see('end')
        self.out.config(state='disabled')

    def safe_append(self, text):
        self.root.after(0, lambda: self.append(text))

    def clear_output(self):
        self.out.config(state='normal')
        self.out.delete('1.0', 'end')
        self.out.config(state='disabled')

    # ---------------- Project Info -----------------
    def create_table(self, parent, title, data, three_columns=False):
        frame = tk.Frame(parent)
        frame.pack(fill="x", pady=8)

        tk.Label(frame, text=title, font=("Arial", 13, "bold"), anchor="w").pack(anchor="w", pady=4)

        table = tk.Frame(frame)
        table.pack(fill="x")

        row = 0
        for key, value in data.items():
            tk.Label(table, text=key, font=("Arial", 10, "bold"), width=20, anchor="w").grid(row=row, column=0, sticky="w", padx=4, pady=2)
            tk.Label(table, text=value, font=("Arial", 10), anchor="w").grid(row=row, column=1, sticky="w", padx=4, pady=2)
            if three_columns:
                tk.Label(table, text="", width=20).grid(row=row, column=2)
            row += 1

    def show_info(self):
        info_win = tk.Toplevel(self.root)
        info_win.title("Project Information")
        info_win.geometry("850x650")

        main_frame = tk.Frame(info_win, padx=20, pady=20)
        main_frame.pack(fill="both", expand=True)

        header_frame = tk.Frame(main_frame)
        header_frame.pack(fill="x", pady=(0, 10))

        tk.Label(header_frame, text="Project Information", font=("Arial", 20, "bold")).pack(side="left")

        try:
            from PIL import Image, ImageTk
            logo_img = Image.open("company_logo.png")
            logo_img = logo_img.resize((120, 80))
            logo_photo = ImageTk.PhotoImage(logo_img)
            logo_label = tk.Label(header_frame, image=logo_photo)
            logo_label.image = logo_photo
            logo_label.pack(side="right")
        except Exception:
            pass

        intro = (
            "This project was developed by Anonymous as part of a Cyber Security Internship. "
            "It automates reconnaissance steps to help analysts gather baseline security information."
        )
        tk.Label(main_frame, text=intro, wraplength=780, justify="left", font=("Arial", 11)).pack(anchor="w", pady=10)

        project_details = {
            "Project Name": "Automatic Reconnaissance with Python",
            "Description": "Automated Python-based reconnaissance tool for security information gathering.",
            "Start Date": "27-JULY-2025",
            "End Date": "20-AUGUST-2025",
            "Status": "Completed"
        }
        self.create_table(main_frame, "Project Details", project_details)

        # Developer Team Details
        developers = {
            "Samala Rakshith Babu": {"ID": "ST#IS#7371", "Email": "samalarakshithbabu722@gmail.com"},
            "Buyya Vaishnavi Goud": {"ID": "ST#IS#7383", "Email": "buyyavaishnavi73@gmail.com"},
            "Rumnitha Varipally": {"ID": "ST#IS#7381", "Email": "varipally.rumnitha@gmail.com"},
            "Sravanthi Aavula": {"ID": "ST#IS#7390", "Email": "sravanthiaavula30@gmail.com"},
            "Pendyala Jaithree": {"ID": "ST#IS#7391", "Email": "pendyalajaithree@gmail.com"}
        }

        # Create Developer Details Section
        frame = tk.Frame(main_frame)
        frame.pack(fill="x", pady=8)

        tk.Label(frame, text="Developer Details", font=("Arial", 13, "bold"), anchor="w").pack(anchor="w", pady=4)

        table = tk.Frame(frame)
        table.pack(fill="x")

        row = 0
        for name, info in developers.items():
            tk.Label(table, text=name, font=("Arial", 10, "bold"), width=25, anchor="w").grid(row=row, column=0, sticky="w", padx=4, pady=2)
            tk.Label(table, text=info["ID"], font=("Arial", 10), width=15, anchor="w").grid(row=row, column=1, sticky="w", padx=4, pady=2)
            tk.Label(table, text=info["Email"], font=("Arial", 10), anchor="w").grid(row=row, column=2, sticky="w", padx=4, pady=2)
            row += 1


        company_details = {"Name": "Supraja Technologies", "Email": "contact@suprajatechnologies.com"}
        self.create_table(main_frame, "Company Details", company_details)

    # ---------------- Recon Run -----------------
    def start_recon(self):
        target = self.target_entry.get().strip()
        if not target:
            messagebox.showwarning('Input required', 'Please enter a target domain or IP')
            return
        t = threading.Thread(target=self._run_recon, args=(target,), daemon=True)
        t.start()

    def _run_recon(self, target):
        self.clear_output()
        outroot = ensure_output_dirs()

        header = safe_join_lines([
            f"Starting reconnaissance on: {target}",
            "",
            f"Timestamp: {datetime.datetime.now()}",
            ""
        ]) + "\n"
        self.safe_append(header)

        if self.sim_var.get():
            sim = generate_simulated_results(target)
            self.safe_append(sim)
            self.last_results = sim
            self.last_screenshot_path = None
            return

        # Resolve IP
        ip = fetch_ip(target)

        # Geolocate (only if an IP and not error)
        if isinstance(ip, str) and ip.startswith("Error"):
            geo = None
        else:
            geo = geolocate_ip(ip)

        self.safe_append(format_basic(ip, geo) + "\n")

        # Shodan (if API key configured)
        try:
            shodan_key = ((self.settings.get("apis") or {}).get("shodan_api_key") if isinstance(self.settings, dict) else "")
        except Exception:
            shodan_key = ""
        if isinstance(ip, str) and not ip.startswith("Error") and shodan_key:
            sdata = fetch_shodan_info(ip, shodan_key)
            self.safe_append(format_shodan(sdata) + "\n")

        # WHOIS
        w = fetch_whois(target)
        self.safe_append(format_whois_section(w) + "\n")

        # DNS
        dnsmap = fetch_dns_records(target)
        self.safe_append(format_dns_section(dnsmap) + "\n")

        # HTTP headers
        http_info = fetch_http_headers(target)
        self.safe_append(format_http(http_info) + "\n")

        # SSL
        sslmap = fetch_ssl_cert(target if "://" not in target else target.split("://")[-1].split("/")[0])
        self.safe_append(format_ssl(sslmap) + "\n")

        # robots & sitemap
        rs = fetch_robots_and_sitemap(target)
        self.safe_append(format_robots_sitemap(rs) + "\n")

        # Tech detection
        tech = detect_technologies(target)
        self.safe_append(format_tech(tech) + "\n")

        # HTML Meta
        meta = fetch_html_meta(target)
        self.safe_append(format_meta(meta) + "\n")

        # Admin brute
        admin_found = brute_force_admin_panels(target)
        self.safe_append(format_admin(admin_found) + "\n")

        # Screenshot (optional)
        self.safe_append("\n=== Screenshot ===\n")
        shot = take_screenshot(target, outroot)
        if "path" in shot:
            self.last_screenshot_path = shot['path']
            self.safe_append(f"Screenshot saved: {shot['path']}\n")
        else:
            self.last_screenshot_path = None
            self.safe_append(f"{CROSS} {shot.get('error', 'Screenshot not taken')}\n")

        self.safe_append("\n=== Report Saved ===\n")
        self.safe_append("\nRecon complete.\n")
        self.last_results = self.out.get('1.0', 'end')

    def save_pdf(self):
        if not self.last_results.strip():
            messagebox.showwarning('No data', 'No results to export. Run a recon first.')
            return
        path = filedialog.asksaveasfilename(defaultextension='.pdf', filetypes=[('PDF','*.pdf')])
        if not path:
            return
        res = export_to_pdf(self.last_results, path, getattr(self, "last_screenshot_path", None))
        if isinstance(res, str) and os.path.exists(path):
            self.last_pdf_path = path
            messagebox.showinfo('Saved', f'Results exported to {path}')
        elif os.path.exists(path):
            self.last_pdf_path = path
            messagebox.showinfo('Saved', f'Results exported to {path}')
        else:
            messagebox.showerror('Error', str(res))

    def email_report(self):
        if not self.last_results.strip():
            messagebox.showwarning('No data', 'No results to email. Run a recon first.')
            return
        outroot = ensure_output_dirs()
        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        pdf_path = str(outroot / f"report_{ts}.pdf")
        res = export_to_pdf(self.last_results, pdf_path, getattr(self, "last_screenshot_path", None))
        if not (isinstance(res, str) and os.path.exists(pdf_path)):
            messagebox.showerror('Error', f'PDF generation failed: {res}')
            return
        self.last_pdf_path = pdf_path
        smtp_cfg = (self.settings.get("smtp") if isinstance(self.settings, dict) else {}) or {}
        check_fields = ["host", "port", "from_email", "to_email"]
        missing = [k for k in check_fields if not str(smtp_cfg.get(k, "")).strip()]
        if missing:
            messagebox.showerror('Email not configured', f"Missing SMTP settings: {', '.join(missing)}. Please go to Settings to configure.")
            return

        subject = f"Recon Report: {self.target_entry.get().strip()}"
        body = f"Automatic reconnaissance report for {self.target_entry.get().strip()} generated on {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}."
        email_res = send_email_with_attachment(smtp_cfg, subject, body, pdf_path)

        if email_res is True:
            messagebox.showinfo('Success', 'Email sent successfully!')
        else:
            messagebox.showerror('Email Failed', email_res)

    def open_settings(self):
        settings_win = tk.Toplevel(self.root)
        settings_win.title("Settings")
        settings_win.geometry("500x350")
        settings_win.grab_set()

        frame = ttk.Frame(settings_win, padding=10)
        frame.pack(fill='both', expand=True)

        notebook = ttk.Notebook(frame)
        notebook.pack(fill='both', expand=True)

        # SMTP Tab
        smtp_frame = ttk.Frame(notebook)
        notebook.add(smtp_frame, text="SMTP")

        form_frame = ttk.Frame(smtp_frame)
        form_frame.pack(fill='both', expand=True, padx=10, pady=10)
        
        smtp_vars = {k: tk.StringVar(value=v) for k, v in self.settings['smtp'].items()}
        
        ttk.Label(form_frame, text="SMTP Host:").grid(row=0, column=0, sticky='w', pady=2)
        ttk.Entry(form_frame, textvariable=smtp_vars['host']).grid(row=0, column=1, sticky='ew', pady=2)
        
        ttk.Label(form_frame, text="Port:").grid(row=1, column=0, sticky='w', pady=2)
        ttk.Entry(form_frame, textvariable=smtp_vars['port']).grid(row=1, column=1, sticky='ew', pady=2)
        
        ttk.Label(form_frame, text="Username:").grid(row=2, column=0, sticky='w', pady=2)
        ttk.Entry(form_frame, textvariable=smtp_vars['username']).grid(row=2, column=1, sticky='ew', pady=2)
        
        ttk.Label(form_frame, text="Password:").grid(row=3, column=0, sticky='w', pady=2)
        pwd_entry = ttk.Entry(form_frame, textvariable=smtp_vars['password'], show='*')
        pwd_entry.grid(row=3, column=1, sticky='ew', pady=2)

        ttk.Label(form_frame, text="From Email:").grid(row=4, column=0, sticky='w', pady=2)
        ttk.Entry(form_frame, textvariable=smtp_vars['from_email']).grid(row=4, column=1, sticky='ew', pady=2)

        ttk.Label(form_frame, text="To Email(s):").grid(row=5, column=0, sticky='w', pady=2)
        ttk.Entry(form_frame, textvariable=smtp_vars['to_email']).grid(row=5, column=1, sticky='ew', pady=2)

        tls_var = tk.BooleanVar(value=self.settings['smtp']['use_tls'])
        ttk.Checkbutton(form_frame, text="Use TLS", variable=tls_var).grid(row=6, column=1, sticky='w', pady=2)
        
        form_frame.columnconfigure(1, weight=1)

        def save_smtp_settings():
            for k, v in smtp_vars.items():
                self.settings['smtp'][k] = v.get()
            self.settings['smtp']['use_tls'] = tls_var.get()
            res = save_settings(self.settings)
            if res is True:
                messagebox.showinfo('Success', 'SMTP settings saved.')
            else:
                messagebox.showerror('Error', res)
            settings_win.destroy()
            
        ttk.Button(smtp_frame, text="Save SMTP Settings", command=save_smtp_settings).pack(pady=10)

        # APIs Tab
        apis_frame = ttk.Frame(notebook)
        notebook.add(apis_frame, text="API Keys")

        api_vars = {k: tk.StringVar(value=v) for k, v in self.settings['apis'].items()}

        api_form_frame = ttk.Frame(apis_frame, padding=10)
        api_form_frame.pack(fill='both', expand=True)

        ttk.Label(api_form_frame, text="Shodan API Key:").grid(row=0, column=0, sticky='w', pady=2)
        ttk.Entry(api_form_frame, textvariable=api_vars['shodan_api_key']).grid(row=0, column=1, sticky='ew', pady=2)

        def save_api_settings():
            for k, v in api_vars.items():
                self.settings['apis'][k] = v.get()
            res = save_settings(self.settings)
            if res is True:
                messagebox.showinfo('Success', 'API settings saved.')
            else:
                messagebox.showerror('Error', res)
            settings_win.destroy()

        ttk.Button(apis_frame, text="Save API Settings", command=save_api_settings).pack(pady=10)

    def build_exe(self):
        result = messagebox.askyesno(
            "Build Executable",
            "This will use PyInstaller to create a standalone executable. "
            "This requires PyInstaller to be installed (`pip install pyinstaller`). Continue?"
        )
        if not result:
            return

        try:
            # ✅ Check for PyInstaller using python -m
            subprocess.run([sys.executable, "-m", "PyInstaller", "--version"], check=True, capture_output=True)

            # ✅ Fix path: always use forward slashes
            script_path = str(Path(__file__).resolve()).replace("\\", "/")

            # Create spec file
            spec_content = f'''
# -*- mode: python ; coding: utf-8 -*-
block_cipher = None
a = Analysis(
    ['{script_path}'],
    pathex=[],
    binaries=[],
    datas=[ ('output', 'output') ],
    hiddenimports=['whois', 'dns.resolver', 'requests', 'bs4', 'builtwith', 'cryptography', 'selenium', 'fpdf'],
    hookspath=[],
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False
)
pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)
exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='recon_tool',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,
    disable_windowed_traceback=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='recon_tool',
)
'''
            spec_path = Path.cwd() / "recon_tool.spec"
            with open(spec_path, "w") as f:
                f.write(spec_content)

            self.safe_append("\nStarting PyInstaller build...\n")

            # ✅ Run PyInstaller with python -m
            build_thread = threading.Thread(target=self._run_pyinstaller, args=(spec_path,))
            build_thread.daemon = True
            build_thread.start()

        except FileNotFoundError:
            messagebox.showerror("Error", "PyInstaller is not installed. Please run 'pip install pyinstaller'.")
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred during build preparation: {e}")



    def _run_pyinstaller(self, spec_path):
        try:
            proc = subprocess.Popen(
                [sys.executable, "-m", "PyInstaller", str(spec_path)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1
            )

            for line in proc.stdout:
                self.safe_append(line)
            for line in proc.stderr:
                self.safe_append(line)

            proc.wait()

            if proc.returncode == 0:
                dist_path = Path.cwd() / "dist" / "recon_tool"
                exe_path = dist_path / "recon_tool.exe"

                try:
                    shutil.copyfile(Path.cwd() / "output" / "settings.json", dist_path / "output" / "settings.json")
                except Exception:
                    pass

                self.safe_append(f"\nBuild successful! Executable is located at: {exe_path}\n")
                messagebox.showinfo("Success", f"Build successful! Executable is located at: {exe_path}")

                # ✅ Auto-open and highlight exe
                try:
                    if os.name == "nt":  # Windows
                        subprocess.Popen(f'explorer /select,"{exe_path}"')
                    elif sys.platform == "darwin":  # macOS
                        subprocess.Popen(["open", "-R", exe_path])
                    else:  # Linux
                        subprocess.Popen(["xdg-open", dist_path])
                except Exception as e:
                    self.safe_append(f"\nCould not auto-open EXE: {e}\n")

            else:
                self.safe_append("\nBuild failed. Check the logs above for details.\n")
                messagebox.showerror("Build Failed", "PyInstaller build failed. See the output log for details.")
        except Exception as e:
            self.safe_append(f"\nPyInstaller execution error: {e}\n")
            messagebox.showerror("Error", f"PyInstaller execution error: {e}")

def main():
    root = tk.Tk()
    app = ReconGUI(root)
    root.mainloop()

if __name__ == '__main__':
    main()