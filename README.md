# 🔍 WordPress Vulnerability Scanner CLI

A simple, powerful Python-based CLI tool that uses WPScan and its API to scan WordPress websites for core, plugin, theme, and user vulnerabilities. Designed for developers, security testers, and DevSecOps teams who want a clean, categorized, and readable scan output.

---

## 🎥 Demo Video

Check out this demonstration of WpFortress in action:

[![WpFortress Demo Video](https://img.youtube.com/vi/iyy-U2rI8hk/0.jpg)](https://youtu.be/iyy-U2rI8hk?si=nSNo1YkG3z1SXSsb)

## 🚀 Features

- 🧠 **Smart CLI** – Prompts for URL, no flags needed
- 🔍 **Deep Enumeration** – Scans for:
  - Core vulnerabilities
  - Plugins & themes (incl. vulnerable versions)
  - Publicly exposed files (`xmlrpc.php`, `readme.html`, etc.)
  - WordPress users
- 📋 **Structured, human-readable output**
- 🔐 **WPScan API integration**
- ☁️ Ideal for terminal use or scripting

---

## 📦 Requirements

- Python 3.6+
- [WPScan](https://github.com/wpscanteam/wpscan) installed and in your `PATH`
- A free [WPScan API token](https://wpscan.com/profile)

---

## 🛠 Installation

```bash
git clone https://github.com/ademto/WpFortress.git
cd WpFortress
chmod +x scanwp.py
```

---

## 🔑 Setup API Token

```bash
export WPSCAN_API_TOKEN=your_token_here
```

To make it permanent, add it to your shell config (`~/.bashrc`, `~/.zshrc`, etc.):

```bash
echo 'export WPSCAN_API_TOKEN=your_token_here' >> ~/.bashrc
source ~/.bashrc
```

---

## 🧪 Usage

```bash
./scanwp.py
```

Then enter a WordPress URL when prompted.

---

## 💡 Example Output

```
📄 Site Information
  - URL: https://example.com
  - IP: x.x.x.x
  - WordPress: 5.1.1
  - Outdated: True
  - Server: nginx
  - PHP: 7.2.18

🎨 Theme
  - Twenty Nineteen v1.3 (latest: 3.1) ⚠️ Outdated

👥 Users Found
  - admin
  - editor

🗂️ Public Files
  - https://example.com/xmlrpc.php
  - https://example.com/readme.html
  - https://example.com//wp-cron.php

🚨 Core Vulnerabilities
  🔸 WordPress 5.0-5.2.2 - Authenticated Stored XSS in Shortcode Previews
     - Severity : High
     - Type     : XSS
     - Fixed In : 5.1.2
     - CVE(s)   : 2019-16219
     - References(s)   : https://wordpress.org/news/2019/09/wordpress-5-2-3-security-and-maintenance-release/

  🔸 WordPress <= 5.2.2 - Cross-Site Scripting (XSS) in URL Sanitisation
     - Severity : Medium
     - Type     : XSS
     - Fixed In : 5.1.2
     - CVE(s)   : 2019-16222
     - References(s)   : https://wordpress.org/news/2019/09/wordpress-5-2-3-security-and-maintenance-release/

🔌 Plugin Vulnerabilities
  - Contact Form 7: XSS in Upload Handler
     - Severity: Medium
     - Fixed In: 5.1.1
🎨 Theme Vulnerabilities
  - Astra: Unauthenticated Reflected XSS in Customizer Preview
     - Severity: Critical
     - Fixed In: 2.5.4

  - Twenty Nineteen: Authenticated Stored XSS in Block Editor
     - Severity: High
     - Fixed In: 1.4
✅ Scan completed at 2025-04-29 21:15:51
```

---

## 📁 Project Structure

```
wordpress-scanner-cli/
├── scanwp.py         # Main executable CLI script
├── README.md         # You are here
└── LICENSE           # MIT
```

---

## 👨‍💻 Author

**Emmanuel Adetoro**  
[LinkedIn](https://www.linkedin.com/in/emmanuel-adetoro/)  
[GitHub](https://github.com/ademto)

---

## ✨ Upcoming Features

- Testing website safety against "RockYou" password lists
- Integrating AI to provide tailored security recommendations
- A web version for easier accessibility

## 🙌 Contribute

Pull requests welcome! Add features like:

- JSON export (`--json`)
- Color output with `rich`
- Optional web frontend
