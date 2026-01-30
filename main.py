import customtkinter as ctk
import requests
import threading
import time
import psutil
import socket
import platform
import os
import hashlib
import webbrowser
from tkinter import filedialog, messagebox

# --- YAPILANDIRMA ---
GITHUB_VERSION_URL = "https://ekdev.vercel.app/version.txt"
# Key URL kaldırıldı (Artık Ücretsiz)
CURRENT_VERSION = "3.0" 
APP_NAME = "EK DEV SEC_OPS (OPEN SOURCE)"
UPDATE_LINK = "https://ekdev.vercel.app/"

# --- TASARIM AYARLARI (ULTRA MINIMAL) ---
COLOR_BG = "#020202"         # Derin Siyah
COLOR_SIDEBAR = "#050505"    # Yan Panel
COLOR_ACCENT = "#00ff41"     # Matrix Yeşil
COLOR_TEXT = "#dddddd"       # Yazı Rengi
COLOR_DANGER = "#ff2a2a"     # Kırmızı (Hata/Ban)
COLOR_WARN = "#ffcc00"       # Sarı (Uyarı)
COLOR_SUCCESS = "#00ff41"    # Onay Yeşili

FONT_CODE = ("Consolas", 10)
FONT_HEAD = ("Consolas", 13, "bold")

ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("green")

# --- DİL PAKETİ ---
LANG = {
    "EN": {
        "dash": "DASHBOARD", "live": "ACTIVE DEFENSE", "ghost": "GHOST PROTOCOL",
        "net": "NET SENTRY", "link": "DEEP TRACE", "tool": "TOOLBOX", "sys": "SYSTEM MON", # Yeni Özellik
        "sys_status": "SYSTEM: ONLINE", "host": "HOST", "os": "OS", "ip": "LOCAL IP",
        "edition": "EDITION", "open": "OPEN SOURCE", # Lisans yerine Edition
        "start_prot": "ENGAGE", "stop_prot": "DISENGAGE", "traffic": "TRAFFIC LOG",
        "banned": "BLACKLIST", "remove": "UNBAN", "scan_start": "INITIALIZE SCAN",
        "analyzing": "[*] Analyzing...", 
        "ext_ip": "EXTERNAL IP", "country": "COUNTRY", "isp": "ISP",
        "vpn_warn": "[WARN] PROXY DETECTED",
        "vpn_danger": "[!] EXPOSED IP", "no_conn": "No active threats.",
        "refresh": "REFRESH", "target_link": "Enter target URL...",
        "deep_scan": "TRACE ROUTE", "wifi": "WIFI", "hash": "HASH",
        "shred": "SHREDDER", "dns": "DNS", "port": "PORTS", "ping": "PING",
        "update": "PATCH SYSTEM", "outdated": "UPDATE REQUIRED",
        "attack_detected": "\n[!] THREAT: {ip} -> BLOCKED.\n",
        "clean": "[OK] Target appears clean.", "sus": "[?] SUSPICIOUS: Redirect loop.",
        "danger": "[!!!] DANGER: MALICIOUS NODE DETECTED!",
        "unbanned": "[i] {ip} unblocked.\n",
        "cpu": "CPU LOAD", "ram": "RAM USAGE", "disk": "DISK SPACE", "swap": "SWAP MEM"
    },
    "TR": {
        "dash": "KONTROL PANELİ", "live": "AKTİF KORUMA", "ghost": "GİZLİLİK",
        "net": "AĞ İZLEME", "link": "LİNK ANALİZ", "tool": "ARAÇLAR", "sys": "SİSTEM İZLEME", # Yeni Özellik
        "sys_status": "SİSTEM: AKTİF", "host": "CİHAZ", "os": "SİSTEM", "ip": "YEREL IP",
        "edition": "SÜRÜM", "open": "AÇIK KAYNAK", # Lisans yerine Sürüm
        "start_prot": "BAŞLAT", "stop_prot": "DURDUR", "traffic": "TRAFİK AKIŞI",
        "banned": "ENGEL LİSTESİ", "remove": "KALDIR", "scan_start": "TARAMA BAŞLAT",
        "analyzing": "[*] Analiz ediliyor...", 
        "ext_ip": "DIŞ IP", "country": "ÜLKE", "isp": "SAĞLAYICI",
        "vpn_warn": "[UYARI] PROXY TESPİTİ",
        "vpn_danger": "[!] IP ADRESİ AÇIKTA", "no_conn": "Tehdit bulunamadı.",
        "refresh": "YENİLE", "target_link": "Hedef linki girin...",
        "deep_scan": "DERİN TARAMA", "wifi": "WIFI", "hash": "HASH",
        "shred": "YOK ET", "dns": "DNS", "port": "PORTLAR", "ping": "PING",
        "update": "GÜNCELLE", "outdated": "GÜNCELLEME GEREKLİ",
        "attack_detected": "\n[!] TEHDİT: {ip} -> ENGELLENDİ.\n",
        "clean": "[OK] Hedef temiz görünüyor.", "sus": "[?] ŞÜPHELİ: Çoklu yönlendirme.",
        "danger": "[!!!] TEHLİKE: IP LOGGER ZİNCİRİ TESPİT EDİLDİ!",
        "unbanned": "[i] {ip} engeli kaldırıldı.\n",
        "cpu": "İŞLEMCİ", "ram": "BELLEK", "disk": "DİSK ALANI", "swap": "TAKAS ALANI"
    }
}

CURRENT_LANG = "EN"

class EkDevApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title(APP_NAME)
        self.geometry("1000x600")
        self.resizable(False, False)
        self.eval('tk::PlaceWindow . center')
        
        # ARTIK HERKES PRO (AÇIK KAYNAK)
        self.is_pro = True 

        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self.init_ui()
        self.check_version()

    def init_ui(self):
        for widget in self.winfo_children(): widget.destroy()
        self.create_sidebar()
        self.create_frames()

    def create_sidebar(self):
        self.sidebar = ctk.CTkFrame(self, width=180, corner_radius=0, fg_color=COLOR_SIDEBAR)
        self.sidebar.grid(row=0, column=0, sticky="nsew")
        
        ctk.CTkLabel(self.sidebar, text=" EK DEV ", font=("Impact", 20), text_color=COLOR_ACCENT).pack(pady=(20, 2))
        ctk.CTkLabel(self.sidebar, text="OPEN SOURCE", font=("Consolas", 9), text_color="#555").pack(pady=(0, 20))
        
        ctk.CTkButton(self.sidebar, text=f"[{CURRENT_LANG}]", width=50, height=20, 
                      fg_color="transparent", hover_color="#222", border_width=1, border_color="#222",
                      font=("Consolas", 9), command=self.switch_language).pack(pady=(0, 20))

        t = LANG[CURRENT_LANG]
        self.menu_btn(t["dash"], self.show_dashboard)
        self.menu_btn(t["live"], self.show_ddos)
        self.menu_btn(t["ghost"], self.show_ghost)
        self.menu_btn(t["net"], self.show_net)
        self.menu_btn(t["link"], self.show_link)
        self.menu_btn(t["tool"], self.show_toolbox)
        self.menu_btn(t["sys"], self.show_sysmon) # YENİ BUTON
        
        ctk.CTkLabel(self.sidebar, text=f"v{CURRENT_VERSION}", text_color="#333", font=("Arial", 8)).pack(side="bottom", pady=5)

    def switch_language(self):
        global CURRENT_LANG
        CURRENT_LANG = "TR" if CURRENT_LANG == "EN" else "EN"
        self.init_ui()

    def menu_btn(self, text, cmd):
        btn = ctk.CTkButton(self.sidebar, text=f"> {text}", command=cmd, fg_color="transparent", hover_color="#111", 
                            text_color="#aaa", anchor="w", height=35, font=("Consolas", 11), corner_radius=0)
        btn.pack(fill="x", padx=10, pady=1)

    def create_frames(self):
        self.frames = {}
        # LicensePage KALDIRILDI -> SystemMonitor EKLENDİ
        for F in (Dashboard, GhostCheck, NetSentry, LinkScanner, DdosGuard, Toolbox, SystemMonitor, UpdateLock):
            frame = F(parent=self, controller=self)
            self.frames[F.__name__] = frame
            frame.grid(row=0, column=1, sticky="nsew")
        self.show_dashboard()

    def show_frame(self, name): self.frames[name].tkraise()
    def show_dashboard(self): self.show_frame("Dashboard")
    def show_ghost(self): self.show_frame("GhostCheck")
    def show_net(self): self.show_frame("NetSentry")
    def show_link(self): self.show_frame("LinkScanner")
    def show_toolbox(self): self.show_frame("Toolbox")
    def show_sysmon(self): self.show_frame("SystemMonitor") # YENİ SAYFA
    def show_ddos(self): self.show_frame("DdosGuard") # ARTIK HERKESE AÇIK

    def check_version(self):
        def _c():
            try:
                url = f"{GITHUB_VERSION_URL}?t={time.time()}" 
                r = requests.get(url, timeout=3)
                if r.status_code == 200:
                    remote = r.text.strip().split('\n')[0].replace("version=", "").strip()
                    if remote != CURRENT_VERSION:
                        self.frames["UpdateLock"].set_ver(remote)
                        self.show_frame("UpdateLock")
            except: pass
        threading.Thread(target=_c, daemon=True).start()

# --- SAYFALAR ---

class Dashboard(ctk.CTkFrame):
    def __init__(self, parent, controller):
        super().__init__(parent, fg_color=COLOR_BG)
        self.controller = controller
        self.setup_ui()

    def setup_ui(self):
        for widget in self.winfo_children(): widget.destroy()
        
        t = LANG[CURRENT_LANG]
        ctk.CTkLabel(self, text=t["sys_status"], font=("Impact", 30), text_color=COLOR_ACCENT).pack(pady=50)
        
        grid = ctk.CTkFrame(self, fg_color="transparent")
        grid.pack(pady=20)
        
        self.card(grid, t["host"], socket.gethostname()).grid(row=0, column=0, padx=5, pady=5)
        self.card(grid, t["os"], platform.system()).grid(row=0, column=1, padx=5, pady=5)
        self.card(grid, t["ip"], socket.gethostbyname(socket.gethostname())).grid(row=1, column=0, padx=5, pady=5)
        
        # Lisans Kartı -> Sürüm Kartına Dönüştü
        self.card(grid, t["edition"], t["open"], val_color=COLOR_ACCENT).grid(row=1, column=1, padx=5, pady=5)

    def card(self, p, title, val, val_color="white"):
        f = ctk.CTkFrame(p, fg_color="#080808", border_color="#1a1a1a", border_width=1, width=200, height=80, corner_radius=0)
        ctk.CTkLabel(f, text=title, font=("Consolas", 9), text_color="gray").place(x=10, y=10)
        ctk.CTkLabel(f, text=val, font=("Consolas", 12, "bold"), text_color=val_color).place(x=10, y=35)
        return f

# --- YENİ ÖZELLİK: SİSTEM İZLEYİCİ (LİSANS YERİNE GELDİ) ---
class SystemMonitor(ctk.CTkFrame):
    def __init__(self, parent, controller):
        super().__init__(parent, fg_color=COLOR_BG)
        self.setup_ui()
        self.update_stats()

    def setup_ui(self):
        for widget in self.winfo_children(): widget.destroy()
        t = LANG[CURRENT_LANG]
        
        ctk.CTkLabel(self, text=":: " + t["sys"], font=FONT_HEAD, text_color="white").pack(pady=40)
        
        self.bars = {}
        
        # Progress barları oluştur
        self.create_monitor(t["cpu"], "cpu")
        self.create_monitor(t["ram"], "ram")
        self.create_monitor(t["disk"], "disk")
        self.create_monitor(t["swap"], "swap")

    def create_monitor(self, title, key):
        frame = ctk.CTkFrame(self, fg_color="transparent")
        frame.pack(fill="x", padx=100, pady=10)
        
        lbl_frame = ctk.CTkFrame(frame, fg_color="transparent")
        lbl_frame.pack(fill="x")
        ctk.CTkLabel(lbl_frame, text=title, font=("Consolas", 11), text_color="gray").pack(side="left")
        self.bars[f"{key}_lbl"] = ctk.CTkLabel(lbl_frame, text="0%", font=("Consolas", 11), text_color=COLOR_ACCENT)
        self.bars[f"{key}_lbl"].pack(side="right")
        
        self.bars[key] = ctk.CTkProgressBar(frame, height=10, corner_radius=0, progress_color=COLOR_ACCENT, fg_color="#111")
        self.bars[key].pack(fill="x", pady=5)
        self.bars[key].set(0)

    def update_stats(self):
        try:
            # CPU
            cpu = psutil.cpu_percent()
            self.bars["cpu"].set(cpu / 100)
            self.bars["cpu_lbl"].configure(text=f"%{cpu}")
            
            # RAM
            ram = psutil.virtual_memory().percent
            self.bars["ram"].set(ram / 100)
            self.bars["ram_lbl"].configure(text=f"%{ram}")
            
            # DISK
            disk = psutil.disk_usage('/').percent
            self.bars["disk"].set(disk / 100)
            self.bars["disk_lbl"].configure(text=f"%{disk}")
            
            # SWAP
            swap = psutil.swap_memory().percent
            self.bars["swap"].set(swap / 100)
            self.bars["swap_lbl"].configure(text=f"%{swap}")
            
        except: pass
        self.after(2000, self.update_stats) # 2 saniyede bir güncelle

class DdosGuard(ctk.CTkFrame):
    def __init__(self, parent, controller):
        super().__init__(parent, fg_color=COLOR_BG)
        t = LANG[CURRENT_LANG]
        
        top = ctk.CTkFrame(self, fg_color="transparent")
        top.pack(fill="x", padx=20, pady=20)
        ctk.CTkLabel(top, text=":: " + t["live"], font=FONT_HEAD, text_color=COLOR_DANGER).pack(side="left")
        self.btn_toggle = ctk.CTkButton(top, text=t["start_prot"], command=self.toggle_server, 
                                        fg_color="#111", border_color=COLOR_ACCENT, border_width=1, corner_radius=0, width=100)
        self.btn_toggle.pack(side="right")
        
        mid = ctk.CTkFrame(self, fg_color="transparent")
        mid.pack(fill="both", expand=True, padx=20, pady=0)
        
        log_frame = ctk.CTkFrame(mid, fg_color="#080808", corner_radius=0)
        log_frame.pack(side="left", fill="both", expand=True, padx=(0, 10))
        self.console = ctk.CTkTextbox(log_frame, font=FONT_CODE, text_color=COLOR_ACCENT, fg_color="#080808", corner_radius=0)
        self.console.pack(fill="both", expand=True, padx=1, pady=1)
        
        ban_area = ctk.CTkFrame(mid, width=250, fg_color="#080808", corner_radius=0)
        ban_area.pack(side="right", fill="y")
        ctk.CTkLabel(ban_area, text=t["banned"], text_color=COLOR_DANGER, font=("Consolas", 10)).pack(pady=5)
        self.ban_scroll = ctk.CTkScrollableFrame(ban_area, fg_color="transparent")
        self.ban_scroll.pack(fill="both", expand=True)
        
        self.server_running = False
        self.blocked_ips = set()
        self.ip_counters = {}
        self.server_socket = None
        self.ban_widgets = {}

    def toggle_server(self):
        t = LANG[CURRENT_LANG]
        if not self.server_running:
            self.server_running = True
            self.btn_toggle.configure(text=t["stop_prot"], fg_color=COLOR_DANGER, border_color=COLOR_DANGER)
            self.log("[*] Defense Protocol Initiated (Port 9999)...\n")
            threading.Thread(target=self.start_honeypot, daemon=True).start()
        else:
            self.server_running = False
            self.btn_toggle.configure(text=t["start_prot"], fg_color="#111", border_color=COLOR_ACCENT)
            self.log("[!] Defense Disengaged.\n")
            if self.server_socket:
                try: self.server_socket.close()
                except: pass

    def start_honeypot(self):
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.bind(("0.0.0.0", 9999))
            self.server_socket.listen(5)
            self.server_socket.settimeout(1)
            while self.server_running:
                try:
                    conn, addr = self.server_socket.accept()
                    ip = addr[0]
                    if ip in self.blocked_ips:
                        conn.close()
                        continue
                    now = time.time()
                    if ip not in self.ip_counters: self.ip_counters[ip] = []
                    self.ip_counters[ip].append(now)
                    self.ip_counters[ip] = [t for t in self.ip_counters[ip] if now - t < 1.0]
                    if len(self.ip_counters[ip]) > 10: self.block_ip(ip)
                    else: self.log(f"[+] Traffic: {ip}\n")
                    conn.close()
                except socket.timeout: pass
                except Exception as e: 
                    if self.server_running: self.log(f"Err: {e}\n")
        except Exception as e:
            self.log(f"Server Error: {e}\n")
            self.server_running = False

    def block_ip(self, ip):
        t = LANG[CURRENT_LANG]
        if ip not in self.blocked_ips:
            self.blocked_ips.add(ip)
            self.log(t["attack_detected"].format(ip=ip), "alert")
            self.add_ban_ui(ip)

    def add_ban_ui(self, ip):
        row = ctk.CTkFrame(self.ban_scroll, fg_color="#111", height=30, corner_radius=0)
        row.pack(fill="x", pady=1)
        ctk.CTkLabel(row, text=ip, text_color="#ddd", font=("Consolas", 10)).pack(side="left", padx=5)
        ctk.CTkButton(row, text="X", width=25, height=20, fg_color="#222", hover_color=COLOR_SUCCESS,
                      command=lambda i=ip, r=row: self.unban_ip(i, r)).pack(side="right", padx=2)
        self.ban_widgets[ip] = row

    def unban_ip(self, ip, row_widget):
        if ip in self.blocked_ips:
            self.blocked_ips.remove(ip)
            row_widget.destroy()
            del self.ban_widgets[ip]
            self.log(LANG[CURRENT_LANG]["unbanned"].format(ip=ip), "info")

    def log(self, msg, tag=None):
        self.console.insert("end", msg, tag)
        self.console.see("end")
        self.console.tag_config("alert", foreground=COLOR_DANGER)
        self.console.tag_config("info", foreground=COLOR_WARN)

class GhostCheck(ctk.CTkFrame):
    def __init__(self, parent, controller):
        super().__init__(parent, fg_color=COLOR_BG)
        t = LANG[CURRENT_LANG]
        ctk.CTkLabel(self, text=":: " + t["ghost"], font=FONT_HEAD, text_color=COLOR_ACCENT).pack(pady=30)
        ctk.CTkButton(self, text=t["scan_start"], command=self.scan, fg_color="#111", border_color=COLOR_ACCENT, border_width=1, corner_radius=0).pack(pady=10)
        self.log = ctk.CTkTextbox(self, width=600, height=300, fg_color="#080808", text_color="#0f0", font=FONT_CODE, corner_radius=0)
        self.log.pack(pady=20)
    def scan(self):
        t = LANG[CURRENT_LANG]
        self.log.delete("1.0", "end")
        self.log.insert("end", t["analyzing"] + "\n")
        def _req():
            try:
                r = requests.get("http://ip-api.com/json/", timeout=5)
                data = r.json()
                self.log.insert("end", f"\n[+] {t['ext_ip']}: {data.get('query')}\n")
                self.log.insert("end", f"[+] {t['country']}: {data.get('country')}\n")
                self.log.insert("end", f"[+] {t['isp']}: {data.get('isp')}\n")
                if data.get('proxy') or data.get('hosting'):
                     self.log.insert("end", f"\n{t['vpn_warn']}\n", "warn")
                else:
                     self.log.insert("end", f"\n{t['vpn_danger']}\n", "danger")
                     self.log.tag_config("danger", foreground=COLOR_DANGER)
            except Exception as e: self.log.insert("end", f"\nError: {e}")
        threading.Thread(target=_req).start()

class LinkScanner(ctk.CTkFrame):
    def __init__(self, parent, controller):
        super().__init__(parent, fg_color=COLOR_BG)
        t = LANG[CURRENT_LANG]
        ctk.CTkLabel(self, text=":: " + t["link"], font=FONT_HEAD, text_color=COLOR_ACCENT).pack(pady=30)
        self.entry = ctk.CTkEntry(self, placeholder_text=t["target_link"], width=500, fg_color="#111", border_color="#333", text_color="white", corner_radius=0)
        self.entry.pack(pady=10)
        ctk.CTkButton(self, text=t["deep_scan"], command=self.scan, fg_color=COLOR_ACCENT, text_color="black", corner_radius=0).pack(pady=10)
        self.log = ctk.CTkTextbox(self, width=650, height=300, fg_color="#080808", font=FONT_CODE, corner_radius=0)
        self.log.pack(pady=10)

    def scan(self):
        t = LANG[CURRENT_LANG]
        url = self.entry.get().strip()
        if not url: return
        if not url.startswith("http"): url = "https://" + url
        self.log.delete("1.0", "end")
        self.log.insert("end", f"[*] Target: {url}\n[*] Trace initiated...\n\n")
        def _trace():
            try:
                session = requests.Session()
                session.headers.update({'User-Agent': 'Mozilla/5.0'})
                resp = session.head(url, allow_redirects=True, timeout=8)
                chain_urls = []
                if resp.history:
                    for i, r in enumerate(resp.history):
                        chain_urls.append(r.url)
                        self.log.insert("end", f"   > Hop {i+1}: {r.url} [{r.status_code}]\n", "warn")
                final_url = resp.url
                chain_urls.append(final_url)
                self.log.insert("end", f"\n[=] FINAL: {final_url}\n", "info")
                
                sus_domains = ["grabify", "iplogger", "blasze", "ps3cfw", "yourls", "bit.ly", "cutt.ly", "account.beauty", "crypto-o.click"]
                detected = False
                for chain_link in chain_urls:
                    if any(d in chain_link.lower() for d in sus_domains):
                        detected = True
                        break
                path = final_url.split('/')[-1]
                potential_code = (len(path) == 6 and path.isalnum())

                if detected: self.log.insert("end", "\n" + t["danger"], "danger")
                elif potential_code: self.log.insert("end", "\n" + t["sus"], "warn")
                elif len(resp.history) > 3: self.log.insert("end", "\n" + t["sus"], "warn")
                else: self.log.insert("end", "\n" + t["clean"], "success")
                
                self.log.tag_config("warn", foreground="orange")
                self.log.tag_config("info", foreground="cyan")
                self.log.tag_config("danger", foreground=COLOR_DANGER)
                self.log.tag_config("success", foreground=COLOR_SUCCESS)
            except Exception as e: self.log.insert("end", f"\nErr: {e}")
        threading.Thread(target=_trace).start()

class NetSentry(ctk.CTkFrame):
    def __init__(self, parent, controller):
        super().__init__(parent, fg_color=COLOR_BG)
        t = LANG[CURRENT_LANG]
        ctk.CTkLabel(self, text=":: " + t["net"], font=FONT_HEAD, text_color=COLOR_ACCENT).pack(pady=30)
        self.scroll = ctk.CTkScrollableFrame(self, width=700, height=350, fg_color="#080808", corner_radius=0)
        self.scroll.pack(pady=20)
        ctk.CTkButton(self, text=t["refresh"], command=self.refresh, width=100, fg_color="#222", corner_radius=0).pack()
        self.refresh()
    def refresh(self):
        t = LANG[CURRENT_LANG]
        for w in self.scroll.winfo_children(): w.destroy()
        try:
            conns = psutil.net_connections(kind='inet')
            found = False
            for c in conns:
                if c.status == 'ESTABLISHED' and c.raddr:
                    ip, port = c.raddr.ip, c.raddr.port
                    if ip != "127.0.0.1":
                        row = ctk.CTkFrame(self.scroll, fg_color="#111", height=25, corner_radius=0)
                        row.pack(fill="x", pady=1)
                        ctk.CTkLabel(row, text=f"{ip}:{port}", font=FONT_CODE, text_color="#ff5555").pack(side="left", padx=10)
                        found = True
            if not found: ctk.CTkLabel(self.scroll, text=t["no_conn"], text_color=COLOR_SUCCESS).pack(pady=20)
        except: pass

class Toolbox(ctk.CTkFrame):
    def __init__(self, parent, controller):
        super().__init__(parent, fg_color=COLOR_BG)
        t = LANG[CURRENT_LANG]
        ctk.CTkLabel(self, text=":: " + t["tool"], font=FONT_HEAD, text_color=COLOR_ACCENT).pack(pady=30)
        grid = ctk.CTkFrame(self, fg_color="transparent")
        grid.pack(pady=20)
        self.tool_btn(grid, t["wifi"], self.wifi_scan, 0, 0)
        self.tool_btn(grid, t["hash"], self.hash_check, 0, 1)
        self.tool_btn(grid, t["shred"], self.shredder, 1, 0)
        self.tool_btn(grid, t["dns"], self.dns_check, 1, 1)
        self.tool_btn(grid, t["port"], self.port_scan, 2, 0)
        self.tool_btn(grid, t["ping"], self.ping_test, 2, 1)
        self.console = ctk.CTkTextbox(self, width=700, height=200, fg_color="#080808", font=FONT_CODE, corner_radius=0)
        self.console.pack(pady=20)
    def tool_btn(self, parent, text, cmd, r, c):
        ctk.CTkButton(parent, text=text, command=cmd, width=200, height=40, fg_color="#111", 
                      hover_color=COLOR_ACCENT, border_width=1, border_color="#333", corner_radius=0).grid(row=r, column=c, padx=10, pady=10)
    def log(self, msg):
        self.console.delete("1.0", "end")
        self.console.insert("end", msg)
    def wifi_scan(self): threading.Thread(target=lambda: self.log(os.popen('nmcli dev wifi' if os.name != 'nt' else 'netsh wlan show networks').read())).start()
    def hash_check(self):
        path = filedialog.askopenfilename()
        if path:
            sha256 = hashlib.sha256()
            with open(path, "rb") as f:
                while chunk := f.read(4096): sha256.update(chunk)
            self.log(f"SHA256: {sha256.hexdigest()}")
    def shredder(self):
        path = filedialog.askopenfilename()
        if path and messagebox.askyesno("CONFIRM", "Delete?"):
            with open(path, "wb") as f: f.write(os.urandom(os.path.getsize(path)))
            os.remove(path)
            self.log("Deleted.")
    def dns_check(self): self.log(f"DNS: {socket.gethostbyname(socket.gethostname())}")
    def port_scan(self):
        self.log("Scanning Ports (Localhost)...")
        def _s():
            o = []
            for p in [21,22,53,80,443,3000,3306,8080,9999]:
                s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.5)
                if s.connect_ex(('127.0.0.1',p))==0: o.append(p)
                s.close()
            self.log(f"Open Ports: {o}" if o else "No critical ports open.")
        threading.Thread(target=_s).start()
    def ping_test(self): threading.Thread(target=lambda: self.log(os.popen(f"ping {'-n' if os.name=='nt' else '-c'} 1 8.8.8.8").read())).start()

class UpdateLock(ctk.CTkFrame):
    def __init__(self, parent, controller):
        super().__init__(parent, fg_color="#000")
        t = LANG[CURRENT_LANG]
        ctk.CTkLabel(self, text=t["outdated"], font=("Impact", 40), text_color="red").pack(pady=100)
        self.lbl = ctk.CTkLabel(self, text="", text_color="white")
        self.lbl.pack()
        ctk.CTkButton(self, text=t["update"], command=lambda: webbrowser.open(UPDATE_LINK), fg_color="red", corner_radius=0).pack(pady=20)
    def set_ver(self, v): self.lbl.configure(text=f"New Patch: {v}")

if __name__ == "__main__":
    app = EkDevApp()
    app.mainloop()