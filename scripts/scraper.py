#!/usr/bin/env python3
"""
Proxy Scraper - Scrapes proxies from multiple free sources
Supports: HTTP, HTTPS, SOCKS4, SOCKS5
"""

import requests
import re
import time
import random
import os
import json
from datetime import datetime

HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.5',
}

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_DIR = os.path.dirname(SCRIPT_DIR)
META_DIR = os.path.join(REPO_DIR, 'meta')

PROXY_FILES = {
    'http': os.path.join(REPO_DIR, 'http.txt'),
    'https': os.path.join(REPO_DIR, 'https.txt'),
    'socks4': os.path.join(REPO_DIR, 'socks4.txt'),
    'socks5': os.path.join(REPO_DIR, 'socks5.txt'),
}

IP_PORT_REGEX = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s*[:\t]\s*(\d{2,5})')


def load_existing_proxies(proxy_type):
    """Load existing proxies from file to avoid duplicates"""
    filepath = PROXY_FILES.get(proxy_type)
    if not filepath or not os.path.exists(filepath):
        return set()
    with open(filepath, 'r') as f:
        return set(line.strip() for line in f if line.strip())


def save_proxies(proxy_type, proxies):
    """Save proxies to file, merged with existing ones"""
    filepath = PROXY_FILES.get(proxy_type)
    if not filepath:
        return
    existing = load_existing_proxies(proxy_type)
    all_proxies = existing.union(proxies)
    sorted_proxies = sorted(all_proxies)
    with open(filepath, 'w') as f:
        f.write('\n'.join(sorted_proxies) + '\n' if sorted_proxies else '')
    return len(sorted_proxies) - len(existing)


def extract_proxies(text):
    """Extract IP:PORT pairs from text"""
    found = set()
    for match in IP_PORT_REGEX.finditer(text):
        ip = match.group(1)
        port = match.group(2)
        # Basic validation
        parts = ip.split('.')
        if all(0 <= int(p) <= 255 for p in parts) and 1 <= int(port) <= 65535:
            found.add(f"{ip}:{port}")
    return found


def scrape_proxyscrape():
    """Scrape from proxyscrape.com API"""
    proxies = {'http': set(), 'https': set(), 'socks4': set(), 'socks5': set()}
    base_url = "https://api.proxyscrape.com/v3/free-proxy-list/get?request=displayproxies&proxy_format=protocolipport&format=text"
    
    for ptype in ['http', 'socks4', 'socks5']:
        try:
            url = f"{base_url}&protocol={ptype}&timeout=10000"
            resp = requests.get(url, headers=HEADERS, timeout=15)
            if resp.status_code == 200:
                lines = resp.text.strip().split('\n')
                for line in lines:
                    line = line.strip()
                    if not line:
                        continue
                    # Format: protocol://ip:port
                    if '://' in line:
                        line = line.split('://', 1)[1]
                    clean = line.strip()
                    if re.match(r'\d+\.\d+\.\d+\.\d+:\d+', clean):
                        if ptype == 'http':
                            proxies['http'].add(clean)
                            proxies['https'].add(clean)
                        else:
                            proxies[ptype].add(clean)
            time.sleep(0.5)
        except Exception as e:
            print(f"  [!] proxyscrape {ptype} error: {e}")
    return proxies


def scrape_geonode():
    """Scrape from geonode.com free proxy API"""
    proxies = {'http': set(), 'https': set(), 'socks4': set(), 'socks5': set()}
    try:
        url = "https://proxylist.geonode.com/api/proxy-list?protocols=http,https,socks4,socks5&limit=500&page=1&sort_by=lastChecked&sort_type=desc"
        resp = requests.get(url, headers=HEADERS, timeout=15)
        if resp.status_code == 200:
            data = resp.json()
            for item in data.get('data', []):
                ip = item.get('ip')
                port = item.get('port')
                protocols = item.get('protocols', [])
                if ip and port:
                    proxy_str = f"{ip}:{port}"
                    for proto in protocols:
                        proto_lower = proto.lower()
                        if proto_lower in proxies:
                            proxies[proto_lower].add(proxy_str)
    except Exception as e:
        print(f"  [!] geonode error: {e}")
    return proxies


def scrape_free_proxy_list():
    """Scrape from free-proxy-list.net"""
    proxies = {'http': set(), 'https': set(), 'socks4': set(), 'socks5': set()}
    urls = [
        'https://free-proxy-list.net/',
        'https://www.sslproxies.org/',
        'https://www.socks-proxy.net/',
        'https://free-proxy-list.net/uk-proxy.html',
        'https://free-proxy-list.net/us-proxy.html',
    ]
    for url in urls:
        try:
            resp = requests.get(url, headers=HEADERS, timeout=15)
            if resp.status_code == 200:
                found = extract_proxies(resp.text)
                if 'socks-proxy' in url or 'socks' in url:
                    proxies['socks4'].update(found)
                    proxies['socks5'].update(found)
                elif 'ssl' in url:
                    proxies['https'].update(found)
                    proxies['http'].update(found)
                else:
                    proxies['http'].update(found)
                    proxies['https'].update(found)
            time.sleep(0.5)
        except Exception as e:
            print(f"  [!] free-proxy-list {url} error: {e}")
    return proxies


def scrape_proxy_list_download():
    """Scrape from proxy-list.download"""
    proxies = {'http': set(), 'https': set(), 'socks4': set(), 'socks5': set()}
    base = "https://www.proxy-list.download/api/v2/get"
    for ptype in ['http', 'https', 'socks4', 'socks5']:
        try:
            url = f"{base}?l=en&t={ptype}"
            resp = requests.get(url, headers=HEADERS, timeout=15)
            if resp.status_code == 200:
                try:
                    data = resp.json()
                    for item in data.get('LISTA', []):
                        proxy = item.get('PROXY', '').strip() or item.get('IP', '').strip()
                        if proxy and ':' in proxy:
                            if ptype == 'https':
                                proxies['https'].add(proxy)
                                proxies['http'].add(proxy)
                            else:
                                proxies[ptype].add(proxy)
                except json.JSONDecodeError:
                    found = extract_proxies(resp.text)
                    proxies[ptype].update(found)
            time.sleep(0.5)
        except Exception as e:
            print(f"  [!] proxy-list.download {ptype} error: {e}")
    return proxies


def scrape_raw_github_sources():
    """Scrape from raw GitHub proxy lists"""
    proxies = {'http': set(), 'https': set(), 'socks4': set(), 'socks5': set()}
    sources = [
        ('https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt', 'http'),
        ('https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks4.txt', 'socks4'),
        ('https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt', 'socks5'),
        ('https://raw.githubusercontent.com/clarketm/proxy-list/master/proxy-list-raw.txt', 'http'),
        ('https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/http.txt', 'http'),
        ('https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/https.txt', 'https'),
        ('https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/socks4.txt', 'socks4'),
        ('https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/socks5.txt', 'socks5'),
        ('https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt', 'http'),
        ('https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks4.txt', 'socks4'),
        ('https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt', 'socks5'),
        ('https://raw.githubusercontent.com/hookzof/socks5_list/master/proxy.txt', 'socks5'),
        ('https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-http.txt', 'http'),
        ('https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-socks4.txt', 'socks4'),
        ('https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-socks5.txt', 'socks5'),
        ('https://raw.githubusercontent.com/roosterkid/openproxylist/main/HTTPS_RAW.txt', 'https'),
        ('https://raw.githubusercontent.com/roosterkid/openproxylist/main/SOCKS4_RAW.txt', 'socks4'),
        ('https://raw.githubusercontent.com/roosterkid/openproxylist/main/SOCKS5_RAW.txt', 'socks5'),
    ]
    for url, ptype in sources:
        try:
            resp = requests.get(url, headers=HEADERS, timeout=15)
            if resp.status_code == 200:
                found = extract_proxies(resp.text)
                if ptype == 'http':
                    proxies['http'].update(found)
                    proxies['https'].update(found)
                elif ptype == 'https':
                    proxies['https'].update(found)
                    proxies['http'].update(found)
                else:
                    proxies[ptype].update(found)
            time.sleep(0.3)
        except Exception as e:
            print(f"  [!] github source {url} error: {e}")
    return proxies


def scrape_spys_one():
    """Scrape from spys.one"""
    proxies = {'http': set(), 'https': set(), 'socks4': set(), 'socks5': set()}
    urls = [
        ('https://spys.one/en/http-proxy-list/', 'http'),
        ('https://spys.one/en/ssl-proxy-list/', 'https'),
        ('https://spys.one/en/socks-proxy-list/', 'socks5'),
    ]
    for url, ptype in urls:
        try:
            resp = requests.get(url, headers=HEADERS, timeout=15)
            if resp.status_code == 200:
                found = extract_proxies(resp.text)
                proxies[ptype].update(found)
            time.sleep(0.5)
        except Exception as e:
            print(f"  [!] spys.one {ptype} error: {e}")
    return proxies


def scrape_hide_my_name():
    """Scrape from hide.my.name proxy list"""
    proxies = {'http': set(), 'https': set(), 'socks4': set(), 'socks5': set()}
    for ptype, codes in [('http', [1, 2]), ('socks4', [4]), ('socks5', [5])]:
        for code in codes:
            try:
                url = f"https://hidemy.name/en/proxy-list/?type={code}"
                resp = requests.get(url, headers=HEADERS, timeout=15)
                if resp.status_code == 200:
                    found = extract_proxies(resp.text)
                    proxies[ptype].update(found)
                time.sleep(0.5)
            except Exception as e:
                print(f"  [!] hide.my.name {ptype} error: {e}")
    return proxies


def merge_all(sources):
    """Merge all scraped proxies"""
    merged = {'http': set(), 'https': set(), 'socks4': set(), 'socks5': set()}
    for source in sources:
        for ptype in merged:
            merged[ptype].update(source.get(ptype, set()))
    return merged


def main():
    print(f"{'='*60}")
    print(f"[SCRAPER] Starting proxy scraping - {datetime.now().isoformat()}")
    print(f"{'='*60}")
    
    os.makedirs(META_DIR, exist_ok=True)
    
    # Run all scrapers
    scrapers = [
        ("ProxyScrape API", scrape_proxyscrape),
        ("GeoNode API", scrape_geonode),
        ("Free-Proxy-List", scrape_free_proxy_list),
        ("Proxy-List-Download", scrape_proxy_list_download),
        ("GitHub Sources", scrape_raw_github_sources),
        ("Spys.one", scrape_spys_one),
        ("Hide.my.name", scrape_hide_my_name),
    ]
    
    all_sources = []
    for name, func in scrapers:
        print(f"\n[*] Scraping from {name}...")
        try:
            result = func()
            total = sum(len(v) for v in result.values())
            print(f"  [+] Got {total} proxies from {name}")
            for ptype, proxy_set in result.items():
                print(f"      {ptype}: {len(proxy_set)}")
            all_sources.append(result)
        except Exception as e:
            print(f"  [!] Failed to scrape {name}: {e}")
    
    # Merge all sources
    merged = merge_all(all_sources)
    
    # Save to files
    print(f"\n{'='*60}")
    print("[SCRAPER] Saving proxies...")
    total_saved = 0
    for ptype, proxy_set in merged.items():
        new_count = save_proxies(ptype, proxy_set)
        total = len(load_existing_proxies(ptype))
        print(f"  {ptype}.txt: {total} total ({new_count} new)")
        total_saved += total
    
    # Save metadata
    meta = {
        'last_scrape': datetime.now().isoformat(),
        'total_proxies': {ptype: len(load_existing_proxies(ptype)) for ptype in merged},
        'sources_used': [s[0] for s in scrapers],
    }
    with open(os.path.join(META_DIR, 'scrape_info.json'), 'w') as f:
        json.dump(meta, f, indent=2)
    
    print(f"\n[SCRAPER] Done! Total proxies across all files: {total_saved}")
    print(f"{'='*60}")


if __name__ == '__main__':
    main()
