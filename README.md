# 🌐 Auto-Updated Proxy List

![Scrape](https://img.shields.io/github/actions/workflow/status/proxy-list-bot/auto-proxies/scrape.yml?label=Scrape&style=flat-square)
![Validate](https://img.shields.io/github/actions/workflow/status/proxy-list-bot/auto-proxies/validate.yml?label=Validate&style=flat-square)
![Last Update](https://img.shields.io/github/last-commit/proxy-list-bot/auto-proxies?label=Last%20Update&style=flat-square)

Automatically scraped and validated proxy lists, updated every 5 minutes.

## 📁 Proxy Lists

| File | Protocol | Raw URL |
|------|----------|---------|
| `http.txt` | HTTP | [Download](https://raw.githubusercontent.com/proxy-list-bot/auto-proxies/main/http.txt) |
| `https.txt` | HTTPS | [Download](https://raw.githubusercontent.com/proxy-list-bot/auto-proxies/main/https.txt) |
| `socks4.txt` | SOCKS4 | [Download](https://raw.githubusercontent.com/proxy-list-bot/auto-proxies/main/socks4.txt) |
| `socks5.txt` | SOCKS5 | [Download](https://raw.githubusercontent.com/proxy-list-bot/auto-proxies/main/socks5.txt) |

## ⏱ Update Schedule

| Action | Interval | Description |
|--------|----------|-------------|
| 🔄 Scrape | Every 5 minutes | Scrapes new proxies from 7+ sources |
| ✅ Validate | Every 10 minutes | Checks all proxies, removes dead ones |

## ✅ Validation Method

Each proxy is validated similar to [proxyscrape.com/proxy-checker](https://proxyscrape.com/online-proxy-checker):

1. **Connectivity** — HTTP request through proxy to httpbin.org/ip
2. **HTTPS Support** — Verifies SSL/TLS capability for HTTPS proxies
3. **Response Time** — Measured in seconds, proxies with >15s timeout are rejected
4. **Anonymity Level** — Checked via proxy judge (azenv.net):
   - 🟢 **Elite** — No headers revealing proxy usage
   - 🟡 **Anonymous** — Proxy headers present but real IP hidden
   - 🔴 **Transparent** — Real IP is visible
5. **SOCKS Validation** — Direct SOCKS4/SOCKS5 connection test

Dead proxies are automatically removed and replaced with working ones on the next cycle.

## 📊 Metadata

- `meta/scrape_info.json` — Last scrape timestamp and source stats
- `meta/validation_info.json` — Validation results with anonymity breakdown

## 📜 Format

Each file contains one proxy per line in `IP:PORT` format:
```
103.152.112.166:8080
45.77.56.114:443
192.168.1.1:1080
```

## ⚠️ Disclaimer

These proxies are scraped from public sources for educational purposes. Use responsibly and in compliance with applicable laws.
