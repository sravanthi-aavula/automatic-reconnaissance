# 🔎 Automatic Reconnaissance Tool

## Overview
This project is an **Automatic Reconnaissance Tool** built in Python as part of my internship at *Supraja Technologies*.  
It automates information gathering (First phase of Ethical Hacking) by collecting details about a target **Domain or IP**.

The tool comes with a **Tkinter-based GUI** and supports exporting results, emailing reports, and even building a standalone **.exe** using PyInstaller.  

---

## Features  
- **Basic Reconnaissance**  - Fetch IP address of domain
- Geolocation lookup  
- **WHOIS Lookup** – Domain registration details (registrar, org, creation/expiry dates, emails)  
- **DNS Records Extraction** – A, MX, NS, TXT, CNAME, SOA  
- **HTTP Headers / Banner Grabbing** – Server type, security headers  
- **SSL Certificate Information** – Issuer, validity, Subject Alternative Names  
- **robots.txt & sitemap.xml** parsing  
- **Technology Detection** (via BuiltWith API)  
- **HTML Metadata Extraction** – Title, Description, Canonical, Keywords  
- **Admin Panel Finder** – Brute force common admin endpoints  
- **Website Screenshot** using Selenium (headless Chrome)  
- **Shodan Integration** (requires API key)  
- **Report Generation** – Export to PDF with optional screenshot  
- **Email Report** – Send report directly via SMTP  
- **EXE Build** – Convert Python script into executable with one click  

---

## Technologies Used  
- **Programming Language**: Python (3.x)  
- **GUI**: Tkinter  
- **Libraries**:  
  - `whois` → WHOIS Lookup  
  - `dnspython` → DNS Records  
  - `requests` → HTTP, API calls  
  - `bs4` (BeautifulSoup) → Parsing sitemap/meta  
  - `builtwith` → Technology detection  
  - `cryptography` → SSL Certificate parsing  
  - `selenium` → Website screenshots (headless Chrome)  
  - `fpdf` → PDF report generation  
  - `smtplib` → Email report sending  
  - `PyInstaller` → EXE build support  

---

## Project Workflow / System Architecture  
**Input:** Domain or IP  
**Process:**  
- WHOIS Lookup  
- DNS Records Extraction  
- HTTP Headers & SSL Info  
- Tech Detection  
- robots.txt & sitemap.xml  
- Admin Panel Finder  
- Shodan API (optional)  
- Website Screenshot  
- Report Generation (PDF + Email)  

**Output:**  
- Reconnaissance Report (PDF)  
- Report can also be sent via Email  

---

## How to Run
1. Clone the repository:
   ```bash
   git clone https://github.com/your-username/Automatic_Reconnaissance.git
   cd Automatic_Reconnaissance
