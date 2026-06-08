#!/usr/bin/env python3
"""
Proxy Validator - Validates proxies like proxyscrape.com online-proxy-checker
Checks: connectivity, response time, anonymity level, protocol support
Removes dead proxies, keeps only working ones
Optimized for GitHub Actions: fast validation with time limits
"""

import requests
import socks
import socket
import time
import os
import json
import concurrent.futures
from datetime import datetime

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_DIR = os.path.dirname(SCRIPT_DIR)
META_DIR = os.path.join(REPO_DIR, 'meta')

PROXY_FILES = {
    'http': os.path.join(REPO_DIR, 'http.txt'),
    'https': os.path.join(REPO_DIR, 'https.txt'),
    'socks4': os.path.join(REPO_DIR, 'socks4.txt'),
    'socks5': os.path.join(REPO_DIR, 'socks5.txt'),
}

# Validation test endpoints (like proxyscrape checker uses)
TEST_URLS = {
    'http': 'http://httpbin.org/ip',
    'https': 'https://httpbin.org/ip',
    'judge': 'http://azenv.net/',
}

# Multiple fallback test URLs for reliability
FALLBACK_TEST_URLS = [
    'http://httpbin.org/ip',
    'http://ip-api.com/json/',
    'http://ifconfig.me/ip',
]

# Validation thresholds (similar to proxyscrape)
MAX_TIMEOUT = 5          # seconds per proxy check
CONNECT_TIMEOUT = 3      # seconds for connection
MAX_WORKERS = 100        # concurrent threads for speed
MAX_PROXIES_PER_TYPE = 2000  # limit to avoid timeout in CI
TIME_LIMIT_MINUTES = 6   # hard time limit for validation


def get_real_ip():
    """Get the real IP of the current machine for anonymity detection"""
    try:
        resp = requests.get('https://httpbin.org/ip', timeout=10)
        return resp.json().get('origin', '').split(',')[0].strip()
    except:
        try:
            resp = requests.get('https://api.ipify.org', timeout=10)
            return resp.text.strip()
        except:
            return None


def quick_check_http(proxy_str, proxy_type='http'):
    """
    Quick connectivity check for HTTP/HTTPS proxy
    Similar to proxyscrape checker - just test if proxy can reach a target
    Returns response time if working, None if dead
    """
    proxy_url = f"{proxy_type}://{proxy_str}"
    proxies = {'http': proxy_url, 'https': proxy_url}

    try:
        start = time.time()
        resp = requests.get(
            TEST_URLS['http'],
            proxies=proxies,
            timeout=(CONNECT_TIMEOUT, MAX_TIMEOUT),
            headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'},
            allow_redirects=True
        )
        elapsed = time.time() - start

        if resp.status_code == 200:
            return round(elapsed, 3)
        return None
    except:
        return None


def check_anonymity(proxy_str, proxy_type, real_ip):
    """
    Check proxy anonymity level via proxy judge (like proxyscrape)
    Returns: 'elite', 'anonymous', 'transparent', or 'unknown'
    """
    proxy_url = f"{proxy_type}://{proxy_str}"
    proxies = {'http': proxy_url, 'https': proxy_url}

    try:
        resp = requests.get(
            TEST_URLS['judge'],
            proxies=proxies,
            timeout=(CONNECT_TIMEOUT, MAX_TIMEOUT),
            headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
        )
        if resp.status_code == 200:
            judge_text = resp.text.lower()
            if real_ip and real_ip in judge_text:
                return 'transparent'
            elif any(h in judge_text for h in ['via', 'x-forwarded-for', 'forwarded-for', 'forwarded', 'x-proxy-id']):
                return 'anonymous'
            else:
                return 'elite'
    except:
        pass
    return 'unknown'


def validate_http_proxy(proxy_str, proxy_type='http', real_ip=None):
    """
    Full validation of an HTTP/HTTPS proxy
    Returns: dict with results or None if dead
    """
    # Step 1: Quick connectivity check
    response_time = quick_check_http(proxy_str, proxy_type)
    if response_time is None:
        return None

    result = {
        'proxy': proxy_str,
        'type': proxy_type,
        'working': True,
        'response_time': response_time,
        'anonymity': 'unknown',
    }

    # Step 2: HTTPS support check (for https type)
    if proxy_type == 'https':
        try:
            resp_https = requests.get(
                TEST_URLS['https'],
                proxies={'http': f'https://{proxy_str}', 'https': f'https://{proxy_str}'},
                timeout=(CONNECT_TIMEOUT, MAX_TIMEOUT),
                headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
            )
            if resp_https.status_code != 200:
                result['type'] = 'http'
        except:
            result['type'] = 'http'

    # Step 3: Anonymity check (skip for speed if too many proxies)
    result['anonymity'] = check_anonymity(proxy_str, proxy_type, real_ip)

    return result


def validate_socks_proxy(proxy_str, socks_type='socks5', real_ip=None):
    """
    Validate a SOCKS4/SOCKS5 proxy
    Returns: dict with results or None if dead
    """
    try:
        ip, port = proxy_str.split(':')
        port = int(port)
    except:
        return None

    sock_type = socks.SOCKS5 if socks_type == 'socks5' else socks.SOCKS4

    try:
        s = socks.socksocket()
        s.set_proxy(sock_type, ip, port)
        s.settimeout(MAX_TIMEOUT)

        start = time.time()
        s.connect(('httpbin.org', 80))
        elapsed = time.time() - start

        s.sendall(b'GET /ip HTTP/1.1\r\nHost: httpbin.org\r\nConnection: close\r\n\r\n')
        response = b''
        s.settimeout(3)
        while True:
            try:
                chunk = s.recv(4096)
                if not chunk:
                    break
                response += chunk
            except socket.timeout:
                break
        s.close()

        if b'200 OK' in response or b'origin' in response:
            result = {
                'proxy': proxy_str,
                'type': socks_type,
                'working': True,
                'response_time': round(elapsed, 3),
                'anonymity': 'unknown',
            }
            # Quick anonymity check
            try:
                s2 = socks.socksocket()
                s2.set_proxy(sock_type, ip, port)
                s2.settimeout(MAX_TIMEOUT)
                s2.connect(('azenv.net', 80))
                s2.sendall(b'GET / HTTP/1.1\r\nHost: azenv.net\r\nConnection: close\r\n\r\n')
                judge_resp = b''
                s2.settimeout(3)
                while True:
                    try:
                        chunk = s2.recv(4096)
                        if not chunk:
                            break
                        judge_resp += chunk
                    except socket.timeout:
                        break
                s2.close()

                judge_text = judge_resp.decode('utf-8', errors='ignore').lower()
                if real_ip and real_ip in judge_text:
                    result['anonymity'] = 'transparent'
                else:
                    result['anonymity'] = 'elite'
            except:
                pass

            return result
        return None

    except:
        return None


def validate_proxy(proxy_str, proxy_type, real_ip=None):
    """Validate a single proxy based on its type"""
    if proxy_type in ('http', 'https'):
        return validate_http_proxy(proxy_str, proxy_type, real_ip)
    elif proxy_type in ('socks4', 'socks5'):
        return validate_socks_proxy(proxy_str, proxy_type, real_ip)
    return None


def load_proxies(proxy_type):
    """Load proxies from file"""
    filepath = PROXY_FILES.get(proxy_type)
    if not filepath or not os.path.exists(filepath):
        return []
    with open(filepath, 'r') as f:
        return [line.strip() for line in f if line.strip()]


def save_validated_proxies(proxy_type, working_proxies):
    """Save only working proxies back to file, sorted by response time (fastest first)"""
    filepath = PROXY_FILES.get(proxy_type)
    if not filepath:
        return 0

    sorted_proxies = sorted(working_proxies, key=lambda x: x.get('response_time', 999))

    with open(filepath, 'w') as f:
        for p in sorted_proxies:
            f.write(f"{p['proxy']}\n")

    return len(sorted_proxies)


def validate_all_proxies(proxy_type, real_ip, max_workers=MAX_WORKERS):
    """Validate all proxies of a given type using thread pool with time limit"""
    proxies = load_proxies(proxy_type)
    if not proxies:
        print(f"  No {proxy_type} proxies to validate")
        return 0, 0, []

    # Limit to avoid CI timeout
    if len(proxies) > MAX_PROXIES_PER_TYPE:
        print(f"  Limiting {proxy_type} from {len(proxies)} to {MAX_PROXIES_PER_TYPE} (random sample)")
        import random
        proxies = random.sample(proxies, MAX_PROXIES_PER_TYPE)

    print(f"  Validating {len(proxies)} {proxy_type} proxies with {max_workers} threads...")

    working = []
    dead = 0
    checked = 0

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_proxy = {
            executor.submit(validate_proxy, proxy, proxy_type, real_ip): proxy
            for proxy in proxies
        }

        for future in concurrent.futures.as_completed(future_to_proxy):
            checked += 1
            if checked % 200 == 0:
                print(f"    Progress: {checked}/{len(proxies)} checked, {len(working)} working so far")
            try:
                result = future.result()
                if result and result.get('working'):
                    working.append(result)
                else:
                    dead += 1
            except Exception:
                dead += 1

    saved = save_validated_proxies(proxy_type, working)
    return len(proxies), dead, working


def main():
    start_time = time.time()
    print(f"{'='*60}")
    print(f"[VALIDATOR] Starting proxy validation - {datetime.now().isoformat()}")
    print(f"{'='*60}")

    os.makedirs(META_DIR, exist_ok=True)

    real_ip = get_real_ip()
    print(f"[*] Real IP for anonymity check: {real_ip or 'unknown'}")

    total_before = 0
    total_after = 0
    total_dead = 0
    all_working = {}

    for ptype in ['http', 'https', 'socks4', 'socks5']:
        elapsed = (time.time() - start_time) / 60
        if elapsed >= TIME_LIMIT_MINUTES:
            print(f"\n[!] Time limit reached ({elapsed:.1f}min), skipping remaining types")
            break

        print(f"\n[*] Validating {ptype} proxies... ({elapsed:.1f}min elapsed)")
        before_count, dead_count, working = validate_all_proxies(ptype, real_ip)
        total_before += before_count
        total_dead += dead_count
        total_after += len(working)
        all_working[ptype] = working

        anonymity_counts = {}
        for p in working:
            anon = p.get('anonymity', 'unknown')
            anonymity_counts[anon] = anonymity_counts.get(anon, 0) + 1

        avg_time = sum(p.get('response_time', 0) for p in working) / max(len(working), 1)

        print(f"  Results: {before_count} checked -> {len(working)} working, {dead_count} dead")
        print(f"  Average response time: {avg_time:.2f}s")
        print(f"  Anonymity: {anonymity_counts}")

    # Save validation metadata
    meta = {
        'last_validation': datetime.now().isoformat(),
        'validation_time_seconds': round(time.time() - start_time, 1),
        'total_before': total_before,
        'total_after': total_after,
        'total_dead': total_dead,
        'real_ip': real_ip,
        'by_type': {
            ptype: {
                'working': len(all_working.get(ptype, [])),
                'avg_response_time': round(
                    sum(p.get('response_time', 0) for p in all_working.get(ptype, [])) /
                    max(len(all_working.get(ptype, [])), 1), 3
                ),
                'anonymity': {
                    anon: sum(1 for p in all_working.get(ptype, []) if p.get('anonymity') == anon)
                    for anon in ['transparent', 'anonymous', 'elite', 'unknown']
                }
            }
            for ptype in ['http', 'https', 'socks4', 'socks5']
        }
    }

    with open(os.path.join(META_DIR, 'validation_info.json'), 'w') as f:
        json.dump(meta, f, indent=2)

    elapsed = (time.time() - start_time) / 60
    print(f"\n{'='*60}")
    print(f"[VALIDATOR] Summary (took {elapsed:.1f} minutes):")
    print(f"  Before: {total_before} proxies")
    print(f"  After:  {total_after} working")
    print(f"  Dead:   {total_dead} removed")
    print(f"{'='*60}")


if __name__ == '__main__':
    main()
