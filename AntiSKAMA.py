#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Author: Dickson Massawe
# Tool: AntiSKAMA Pro Max Ultra
# Description: All-in-one scam destruction toolkit - NOW WITH 200% MORE SKAMA CRUSHING!

import urllib.request
import time
import os
import re
import random
import ssl
import socket
import whois
from datetime import datetime
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from PIL import Image
import io

# Configuration
KEYWORD_FILE = "skama_words.txt"
SCAN_LOG = "antiskama_log.txt"
SCREENSHOT_DIR = "skama_evidence"
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "AntiSKAMA-Ninja/2.0",
    "Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0",
    "SkamaTerminator/9000"
]

class SkamaHunter:
    def __init__(self):
        self.user_agent = random.choice(USER_AGENTS)
        self.scan_id = datetime.now().strftime("%Y%m%d-%H%M%S")
        self.setup_dirs()
        
    def setup_dirs(self):
        """Create evidence directories"""
        if not os.path.exists(SCREENSHOT_DIR):
            os.makedirs(SCREENSHOT_DIR)
    
    def load_keywords(self):
        """Load scam keywords with validation"""
        try:
            with open(KEYWORD_FILE, 'r', encoding='utf-8') as f:
                return {line.strip().lower() for line in f if line.strip()}
        except FileNotFoundError:
            print("\n[!] MISSING WEAPON: skama_words.txt not found!")
            print("[!] Create this file with scam keywords to activate detection")
            return set()

    def capture_screenshot(self, url):
        """Take visual evidence of the skama"""
        try:
            options = Options()
            options.add_argument(f"user-agent={self.user_agent}")
            options.add_argument("--headless")
            options.add_argument("--disable-gpu")
            options.add_argument("--window-size=1920,1080")
            
            driver = webdriver.Chrome(options=options)
            driver.get(url)
            time.sleep(3)  # Allow page to load
            
            screenshot_path = os.path.join(SCREENSHOT_DIR, f"skama_{self.scan_id}.png")
            driver.save_screenshot(screenshot_path)
            driver.quit()
            
            # Optimize image
            with Image.open(screenshot_path) as img:
                img.save(screenshot_path, optimize=True, quality=85)
            
            return screenshot_path
        except Exception as e:
            print(f"\n[!] SCREENSHOT FAILED: {str(e)}")
            return None

    def check_ssl(self, domain):
        """Analyze SSL certificate for skama signs"""
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
            
            issuer = dict(x[0] for x in cert['issuer'])
            valid_from = datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z')
            valid_to = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
            
            return {
                'issuer': issuer.get('organizationName', 'Unknown'),
                'valid_from': valid_from,
                'valid_to': valid_to,
                'valid_days': (valid_to - datetime.now()).days,
                'subject': dict(x[0] for x in cert['subject']),
                'is_valid': valid_to > datetime.now()
            }
        except Exception as e:
            print(f"\n[!] SSL ANALYSIS FAILED: {str(e)}")
            return None

    def whois_lookup(self, domain):
        """Investigate domain registration"""
        try:
            domain_info = whois.whois(domain)
            return {
                'registrar': domain_info.registrar,
                'creation_date': domain_info.creation_date,
                'expiration_date': domain_info.expiration_date,
                'name_servers': domain_info.name_servers,
                'status': domain_info.status
            }
        except Exception as e:
            print(f"\n[!] WHOIS LOOKUP FAILED: {str(e)}")
            return None

    def scan_content(self, content, keywords):
        """Ultra skama detection algorithm"""
        content = content.lower()
        results = {
            'keywords': set(),
            'patterns': {
                'phishing_forms': len(re.findall(r'<form.*?(password|login|signin).*?>', content, re.I)),
                'fake_alerts': len(re.findall(r'alert\(|confirm\(|your\s+account\s+is', content, re.I)),
                'urgent_actions': len(re.findall(r'act\s+now|limited\s+time|click\s+below|immediately', content, re.I)),
                'obfuscation': len(re.findall(r'\\x[0-9a-f]{2}|eval\(|unescape\(|fromCharCode', content))
            }
        }
        
        for kw in keywords:
            if kw in content:
                results['keywords'].add(kw)
                
        return results if (results['keywords'] or any(results['patterns'].values())) else None

    def analyze_dom(self, html):
        """DOM forensic analysis"""
        return {
            'hidden_elements': len(re.findall(r'style=[\'"].*display:\s*none', html, re.I)),
            'suspicious_iframes': len(re.findall(r'<iframe.*src=[\'"].*[\'"]', html, re.I)),
            'redirects': len(re.findall(r'window\.location|meta\s+http-equiv=["\']refresh', html, re.I))
        }

    def log_results(self, url, result, details):
        """Comprehensive evidence logging"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = (
            f"\n[SKAMA SCAN REPORT - {timestamp}]\n"
            f"Scan ID: {self.scan_id}\n"
            f"Target URL: {url}\n"
            f"Verdict: {'SKAMA DETECTED!' if result else 'No obvious threats'}\n"
            f"\n[EVIDENCE]\n{details or 'No indicators found'}\n"
            f"{'='*60}\n"
        )
        with open(SCAN_LOG, 'a', encoding='utf-8') as log:
            log.write(log_entry)

    def fetch_page(self, url):
        """Stealthy content retrieval"""
        req = urllib.request.Request(url, headers={
            'User-Agent': self.user_agent,
            'Accept': 'text/html,application/xhtml+xml',
            'Accept-Language': 'en-US,en;q=0.9'
        })
        try:
            with urllib.request.urlopen(req, timeout=20) as response:
                return response.read().decode('utf-8', errors='replace')
        except Exception as e:
            print(f"\n[!] CONNECTION FAILED: {str(e)}")
            return None

def show_banner():
    """Display ultimate skama hunting interface"""
    os.system('cls' if os.name == 'nt' else 'clear')
    print(r"""
    █████╗ ███╗   ██╗████████╗██╗███████╗██╗  ██╗ █████╗ ███╗   ███╗ █████╗ 
   ██╔══██╗████╗  ██║╚══██╔══╝██║██╔════╝██║ ██╔╝██╔══██╗████╗ ████║██╔══██╗
   ███████║██╔██╗ ██║   ██║   ██║███████╗█████╔╝ ███████║██╔████╔██║███████║
   ██╔══██║██║╚██╗██║   ██║   ██║╚════██║██╔═██╗ ██╔══██║██║╚██╔╝██║██╔══██║
   ██║  ██║██║ ╚████║   ██║   ██║███████║██║  ██╗██║  ██║██║ ╚═╝ ██║██║  ██║
   ╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝
   ██████╗ ██████╗  ██████╗      ██████╗██╗  ██╗███████╗██████╗ ███████╗██████╗ 
   ██╔══██╗██╔══██╗██╔═══██╗    ██╔════╝██║  ██║██╔════╝██╔══██╗██╔════╝██╔══██╗
   ██████╔╝██████╔╝██║   ██║    ██║     ███████║█████╗  ██████╔╝█████╗  ██████╔╝
   ██╔═══╝ ██╔══██╗██║   ██║    ██║     ██╔══██║██╔══╝  ██╔═══╝ ██╔══╝  ██╔══██╗
   ██║     ██║  ██║╚██████╔╝    ╚██████╗██║  ██║███████╗██║     ███████╗██║  ██║
   ╚═╝     ╚═╝  ╚═╝ ╚═════╝      ╚═════╝╚═╝  ╚═╝╚══════╝╚═╝     ╚══════╝╚═╝  ╚═╝
    """)
    print("=== SKAMAAAA TERMINATION PROTOCOL ACTIVATED ===")
    print("=== MODE: FULL SPECTRUM ANALYSIS ===\n")

def main():
    show_banner()
    hunter = SkamaHunter()
    
    # User input
    print("ENTER TARGET URL BELOW (OR PRESS CTRL+C TO ABORT)")
    scan_url = input("\n[?] TARGET URL: ").strip()
    if not scan_url.startswith(('http://', 'https://')):
        scan_url = 'http://' + scan_url

    print(f"\n[!] INITIATING SKAMA ANNIHILATION SEQUENCE ON: {scan_url}")
    start_time = time.time()

    try:
        # Extract domain for WHOIS/SSL
        domain = re.sub(r'^https?://(?:www\.)?([^/]+).*$', r'\1', scan_url)
        
        # Parallel execution
        print("\n[+] LOADING SKAMA DETECTION MODULES...")
        keyword_set = hunter.load_keywords()
        print("[+] CAPTURING VISUAL EVIDENCE...")
        screenshot_path = hunter.capture_screenshot(scan_url)
        print("[+] ANALYZING SSL CERTIFICATE...")
        ssl_info = hunter.check_ssl(domain)
        print("[+] PERFORMING WHOIS INVESTIGATION...")
        whois_info = hunter.whois_lookup(domain)
        print("[+] SCANNING FOR MALICIOUS PATTERNS...")
        page_content = hunter.fetch_page(scan_url)
        
        if not page_content:
            return

        # Save raw content
        with open(f'skama_scan_{hunter.scan_id}.html', 'w', encoding='utf-8') as f:
            f.write(page_content)

        # Execute scans
        content_scan = hunter.scan_content(page_content, keyword_set)
        dom_analysis = hunter.analyze_dom(page_content)
        
        # Process results
        is_skama = bool(content_scan or any(dom_analysis.values()))
        details = []
        
        if content_scan:
            if content_scan['keywords']:
                details.append(f"SKAMA KEYWORDS: {', '.join(content_scan['keywords'])}")
            for pattern, count in content_scan['patterns'].items():
                if count > 0:
                    details.append(f"{pattern.upper()}: {count} detected")
        
        if any(dom_analysis.values()):
            details.append(f"DOM ANOMALIES: {dom_analysis}")
        
        if ssl_info:
            details.append(f"SSL ISSUER: {ssl_info['issuer']}")
            details.append(f"SSL VALID: {'Yes' if ssl_info['is_valid'] else 'NO! EXPIRED!'}")
            details.append(f"SSL EXPIRES IN: {ssl_info['valid_days']} days")
        
        if whois_info:
            details.append(f"REGISTRAR: {whois_info.get('registrar', 'Unknown')}")
            if whois_info.get('creation_date'):
                if isinstance(whois_info['creation_date'], list):
                    created = whois_info['creation_date'][0]
                else:
                    created = whois_info['creation_date']
                details.append(f"CREATED: {created.strftime('%Y-%m-%d') if hasattr(created, 'strftime') else created}")

        # Display report
        os.system('cls')
        show_banner()
        print("\n[SKAMA TERMINATION REPORT]")
        print(f"TARGET: {scan_url}")
        print(f"SCAN ID: {hunter.scan_id}")
        print(f"ELAPSED TIME: {time.time() - start_time:.2f} seconds")
        
        if screenshot_path:
            print(f"\n[+] VISUAL EVIDENCE SAVED TO: {screenshot_path}")

        if is_skama:
            print("\n[!] !!! SKAMA NUKED SUCCESSFULLY !!!")
            print("[!] THE FOLLOWING THREATS WERE ELIMINATED:")
            print('\n'.join(f"> {item}" for item in details))
            print("\n[!] WARNING: THIS SITE IS HOSTILE TERRITORY!")
        else:
            print("\n[✓] NO SKAMA SIGNATURES DETECTED")
            print("[✓] SITE APPEARS CLEAN (BUT STAY PARANOID!)")

        # Log results
        hunter.log_results(scan_url, is_skama, '\n'.join(details) if details else None)

    except KeyboardInterrupt:
        print("\n[!] SCAN ABORTED - SKAMA TARGET ESCAPED THIS TIME!")
    except Exception as e:
        print(f"\n[!] CRITICAL FAILURE: {str(e)}")
        print("[!] THE SKAMA FIGHTS BACK! RETRY WITH MORE FIREPOWER!")

if __name__ == "__main__":
    print("\n[!] WARNING: THIS TOOL REQUIRES ADDITIONAL WEAPONS:")
    print("[!] Install required packages with:")
    print("pip install selenium pillow python-whois")
    print("[!] Also download ChromeDriver for screenshot functionality")
    main()