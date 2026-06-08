#!/usr/bin/env python3
"""
Proxy Validator - Validates proxies like proxyscrape.com online-proxy-checker
Checks: connectivity, response time, anonymity level, protocol support
Removes dead proxies, keeps only working ones
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

# Test URLs for validation (like proxyscrape checker)
TEST_URLS = {
    'http': 'http://httpbin.org/ip',
    'https': 'https://httpbin.org/ip',
    'judge': 'http://azenv.net/',  # Proxy judge for anonymity check
}

# Validation thresholds (similar to proxyscrape)
MAX_TIMEOUT = 10  # seconds - max time to wait for proxy response
WORKING_TIMEOUT = 15  # seconds - max for "working" classification
MAX_WORKERS = 50  # concurrent validation threads


def get_real_ip():
    """Get the real IP of the current machine for anonymity detection"""
    try:
        resp = requests.get('https://httpbin.org/ip', timeout=10)
        return resp.json().get('origin', '').split(',')[0].strip()
    except:
        return None


def validate_http_proxy(proxy_str, proxy_type='http'):
    """
    Validate an HTTP/HTTPS proxy similar to proxyscrape checker
    Returns: dict with validation results or None if dead
    """
    proxy_url = f"{proxy_type}://{proxy_str}"
    proxies = {
        'http': proxy_url,
        'https': proxy_url,
    }
    
    result = {
        'proxy': proxy_str,
        'type': proxy_type,
        'working': False,
        'response_time': None,
        'anonymity': None,
        'country': None,
    }
    
    # Test 1: Basic connectivity check via httpbin
    try:
        start = time.time()
        resp = requests.get(
            TEST_URLS['http'],
            proxies=proxies,
            timeout=MAX_TIMEOUT,
            headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
        )
        elapsed = time.time() - start
        
        if resp.status_code != 200:
            return None
        
        result['response_time'] = round(elapsed, 3)
        result['working'] = True
        
        # Parse returned IP
        try:
            proxy_ip = resp.json().get('origin', '').split(',')[0].strip()
        except:
            proxy_ip = None
            
    except requests.exceptions.ProxyError:
        return None
    except requests.exceptions.ConnectTimeout:
        return None
    except requests.exceptions.ReadTimeout:
        return None
    except requests.exceptions.ConnectionError:
        return None
    except Exception as e:
        return None
    
    # Test 2: HTTPS support check (for https proxies)
    if proxy_type == 'https':
        try:
            start = time.time()
            resp_https = requests.get(
                TEST_URLS['https'],
                proxies=proxies,
                timeout=MAX_TIMEOUT,
                headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
            )
            if resp_https.status_code != 200:
                # Proxy works for HTTP but not HTTPS - downgrade
                result['type'] = 'http'
        except:
            result['type'] = 'http'
    
    # Test 3: Anonymity check via proxy judge
    try:
        resp_judge = requests.get(
            TEST_URLS['judge'],
            proxies=proxies,
            timeout=MAX_TIMEOUT,
            headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
        )
        if resp_judge.status_code == 200:
            judge_text = resp_judge.text.lower()
            real_ip = get_real_ip_cached()
            
            # Check for anonymity
            if real_ip and real_ip in judge_text:
                result['anonymity'] = 'transparent'
            elif any(h in judge_text for h in ['via', 'x-forwarded', 'forwarded']):
                result['anonymity'] = 'anonymous'
            else:
                result['anonymity'] = 'elite'
    except:
        result['anonymity'] = 'unknown'
    
    # Only keep if response time is acceptable
    if result['response_time'] and result['response_time'] > WORKING_TIMEOUT:
        return None
    
    return result


def validate_socks_proxy(proxy_str, socks_type='socks5'):
    """
    Validate a SOCKS4/SOCKS5 proxy
    Returns: dict with validation results or None if dead
    """
    result = {
        'proxy': proxy_str,
        'type': socks_type,
        'working': False,
        'response_time': None,
        'anonymity': None,
    }
    
    try:
        ip, port = proxy_str.split(':')
        port = int(port)
    except:
        return None
    
    sock_type = socks.SOCKS5 if socks_type == 'socks5' else socks.SOCKS4
    
    original_socket = socket.socket
    try:
        s = socks.socksocket()
        s.set_proxy(sock_type, ip, port)
        s.settimeout(MAX_TIMEOUT)
        
        start = time.time()
        s.connect(('httpbin.org', 80))
        elapsed = time.time() - start
        
        # Send HTTP request through the SOCKS proxy
        s.sendall(b'GET /ip HTTP/1.1\r\nHost: httpbin.org\r\nConnection: close\r\n\r\n')
        response = b''
        while True:
            try:
                chunk = s.recv(4096)
                if not chunk:
                    break
                response += chunk
            except socket.timeout:
                break
        s.close()
        
        result['response_time'] = round(elapsed, 3)
        
        # Check if we got a valid response
        if b'200 OK' in response or b'origin' in response:
            result['working'] = True
        else:
            return None
            
    except socks.ProxyError:
        return None
    except socket.timeout:
        return None
    except socket.error:
        return None
    except Exception:
        return None
    
    # Anonymity check for SOCKS
    try:
        s2 = socks.socksocket()
        s2.set_proxy(sock_type, ip, port)
        s2.settimeout(MAX_TIMEOUT)
        s2.connect(('azenv.net', 80))
        s2.sendall(b'GET / HTTP/1.1\r\nHost: azenv.net\r\nConnection: close\r\n\r\n')
        judge_resp = b''
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
        real_ip = get_real_ip_cached()
        if real_ip and real_ip in judge_text:
            result['anonymity'] = 'transparent'
        else:
            result['anonymity'] = 'elite'
    except:
        result['anonymity'] = 'unknown'
    
    return result


# Cache for real IP
_real_ip_cache = None

def get_real_ip_cached():
    global _real_ip_cache
    if _real_ip_cache is None:
        _real_ip_cache = get_real_ip()
    return _real_ip_cache


def validate_proxy(proxy_str, proxy_type):
    """Validate a single proxy based on its type"""
    if proxy_type in ('http', 'https'):
        return validate_http_proxy(proxy_str, proxy_type)
    elif proxy_type in ('socks4', 'socks5'):
        return validate_socks_proxy(proxy_str, proxy_type)
    return None


def load_proxies(proxy_type):
    """Load proxies from file"""
    filepath = PROXY_FILES.get(proxy_type)
    if not filepath or not os.path.exists(filepath):
        return []
    with open(filepath, 'r') as f:
        return [line.strip() for line in f if line.strip()]


def save_validated_proxies(proxy_type, working_proxies):
    """Save only working proxies back to file"""
    filepath = PROXY_FILES.get(proxy_type)
    if not filepath:
        return
    
    # Sort by response time (fastest first)
    sorted_proxies = sorted(working_proxies, key=lambda x: x.get('response_time', 999))
    
    with open(filepath, 'w') as f:
        for p in sorted_proxies:
            f.write(f"{p['proxy']}\n")
    
    return len(sorted_proxies)


def validate_all_proxies(proxy_type, max_workers=MAX_WORKERS):
    """Validate all proxies of a given type using thread pool"""
    proxies = load_proxies(proxy_type)
    if not proxies:
        print(f"  No {proxy_type} proxies to validate")
        return 0, 0, []
    
    print(f"  Validating {len(proxies)} {proxy_type} proxies...")
    
    working = []
    dead = 0
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_proxy = {
            executor.submit(validate_proxy, proxy, proxy_type): proxy
            for proxy in proxies
        }
        
        for future in concurrent.futures.as_completed(future_to_proxy):
            proxy_str = future_to_proxy[future]
            try:
                result = future.result()
                if result and result.get('working'):
                    working.append(result)
                else:
                    dead += 1
            except Exception:
                dead += 1
    
    # Save only working proxies
    saved = save_validated_proxies(proxy_type, working)
    
    return len(proxies), dead, working


def filter_by_anonymity(working_proxies, min_anonymity='transparent'):
    """Filter proxies by anonymity level"""
    levels = {'transparent': 0, 'anonymous': 1, 'elite': 2, 'unknown': -1}
    min_level = levels.get(min_anonymity, 0)
    return [p for p in working_proxies if levels.get(p.get('anonymity', 'unknown'), -1) >= min_level]


def main():
    print(f"{'='*60}")
    print(f"[VALIDATOR] Starting proxy validation - {datetime.now().isoformat()}")
    print(f"{'='*60}")
    
    os.makedirs(META_DIR, exist_ok=True)
    
    # Reset IP cache
    global _real_ip_cache
    _real_ip_cache = None
    
    real_ip = get_real_ip_cached()
    print(f"[*] Real IP for anonymity check: {real_ip or 'unknown'}")
    
    total_before = 0
    total_after = 0
    total_dead = 0
    all_working = {}
    
    for ptype in ['http', 'https', 'socks4', 'socks5']:
        print(f"\n[*] Validating {ptype} proxies...")
        before_count, dead_count, working = validate_all_proxies(ptype)
        total_before += before_count
        total_dead += dead_count
        total_after += len(working)
        all_working[ptype] = working
        
        # Print stats
        anonymity_counts = {}
        for p in working:
            anon = p.get('anonymity', 'unknown')
            anonymity_counts[anon] = anonymity_counts.get(anon, 0) + 1
        
        avg_time = sum(p.get('response_time', 0) for p in working) / len(working) if working else 0
        
        print(f"  Results: {before_count} total -> {len(working)} working, {dead_count} dead")
        print(f"  Average response time: {avg_time:.2f}s")
        print(f"  Anonymity: {anonymity_counts}")
    
    # Save validation metadata
    meta = {
        'last_validation': datetime.now().isoformat(),
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
    
    print(f"\n{'='*60}")
    print(f"[VALIDATOR] Summary:")
    print(f"  Before: {total_before} proxies")
    print(f"  After:  {total_after} working")
    print(f"  Dead:   {total_dead} removed")
    print(f"{'='*60}")


if __name__ == '__main__':
    main()
