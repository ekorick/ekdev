<div align="center">

# 🛡️ EK DEV SEC_OPS
### Advanced Cybersecurity Operations Center (v3.0)

![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-0078D6?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-Stable-success?style=for-the-badge)

<br>

**Ultra-Minimalist. Powerful. Open Source.** *A Python-based security tool for monitoring, analyzing, and defending your system.*

[🇹🇷 Türkçe Oku](#-türkçe) | [Features](#-features) | [Installation](#-installation) | [Build](#-build-executable)

</div>

---

## 📸 Screenshots

*(Buraya programın ekran görüntülerini ekleyebilirsin. Örnek: `![Dashboard](screenshots/dash.png)`)*

---

## ⚡ Features

### 🔴 ACTIVE DEFENSE (Honeypot System)
- **Trap Port (9999):** Deploys a fake service to attract attackers.
- **Auto-Ban:** Automatically detects and blocks IPs sending excessive requests (10+ req/s).
- **Live Traffic:** Real-time monitoring of incoming packets.
- **Management:** View and unban blocked IP addresses manually.

### 🔗 DEEP TRACE (Link Analyzer)
- **Chain Analysis:** Traces the full path of a URL, not just the final destination.
- **Logger Detection:** Identifies hidden IP Loggers (Grabify, IPLogger, etc.) in the redirect chain.
- **Loop Detection:** Warns about suspicious redirect loops.

### 👁️ NET SENTRY (Network Monitor)
- **Live Connections:** Scans all established external connections.
- **Process Mapping:** Shows which IP and Port your system is connected to.
- **Filter:** Automatically filters out localhost traffic to focus on threats.

### 👻 GHOST PROTOCOL (Privacy Check)
- **Identity Check:** Displays your external IP, Country, and ISP.
- **Leak Detection:** Checks for VPN/Proxy usage and warns if you are exposed.

### 💻 SYSTEM MONITOR
- **Real-time Stats:** Monitors CPU, RAM, Disk, and Swap usage with visual progress bars.

### 🛠️ TOOLBOX
- **File Shredder:** Permanently destroys files (DoD standard overwrite).
- **Hash Checker:** Verifies file integrity (SHA-256).
- **Port Patrol:** Scans critical system ports (21, 22, 80, 443, 3306, 8080, 9999).
- **WiFi Scanner:** Lists available wireless networks.
- **DNS & Ping:** Diagnostics for network latency and DNS config.

---

## 🚀 Installation

### Prerequisites
- Python 3.10 or higher
- Git

### 1. Clone the Repository
```bash
git clone [https://github.com/ekorick/ekdev.git](https://github.com/ekorick/ekdev.git)
cd ekdev

```

### 2. Install Dependencies

```bash
pip install -r requirements.txt

```

*(Dependencies: `customtkinter`, `requests`, `psutil`, `pillow`, `pyinstaller`)*

### 3. Run the Application

```bash
python main.py

```

---

## 📦 Build (Executable)

You can convert this python script into a standalone executable (`.exe` or Linux binary).

### For Windows (.exe)

```bash
pyinstaller --noconsole --onefile --collect-all customtkinter --name "EkDev_SecOps_v3.0" main.py

```

### For Linux

```bash
pyinstaller --noconsole --onefile --collect-all customtkinter --clean --name "EkDev_SecOps_v3.0_Linux" main.py

```

---

## 🇹🇷 Türkçe

**EK DEV SEC_OPS**, sisteminizi izleyen, ağ trafiğini analiz eden ve aktif saldırılara karşı koruma sağlayan, ultra minimalist bir arayüze sahip Python tabanlı bir siber güvenlik aracıdır.

### Temel Özellikler

* **Aktif Koruma (Honeypot):** 9999 portunda sahte bir servis açarak saldırganları tuzağa düşürür ve IP adreslerini otomatik engeller.
* **Derin Link Analizi:** Linklerin sadece gittiği yeri değil, geçtiği tüm yolları tarar. Grabify gibi IP Logger'ları tespit eder.
* **Ağ Gözcüsü:** Bilgisayarınızdaki şüpheli dış bağlantıları anlık olarak gösterir.
* **Gizlilik Kontrolü:** IP adresinizin ve konumunuzun ifşa olup olmadığını kontrol eder.
* **Sistem İzleme:** CPU, RAM ve Disk kullanımını canlı takip eder.
* **Araç Kutusu:** Dosya öğütücü, Hash kontrolü, Port tarama, WiFi tarama gibi ek araçlar içerir.

---

## ⚠️ Disclaimer

This tool is for **educational purposes and self-defense only**. The developer is not responsible for any misuse or damage caused by this program. Use responsibly.

---

<div align="center">

**Developed by Ek Dev** *Open Source for the Community*

</div>

```
