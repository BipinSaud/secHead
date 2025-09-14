# secHead — Security Headers Checker

**Author:** okBoss  
**License:** GPLv3

secHead is a compact command‑line utility that inspects HTTP(S) responses for widely recommended **security headers** and reports which are **present**, which are **missing**, and where values appear **risky**. It is well‑suited for quick audits, CI steps, inventories, or troubleshooting.

---

## Features

- Checks a curated set of security headers:
  - **Strict-Transport-Security (HSTS)** — enforces HTTPS for subsequent requests.
  - **Content-Security-Policy (CSP)** — mitigates XSS and content injection.
  - **X-Frame-Options** — reduces clickjacking risk.
  - **X-Content-Type-Options** — prevents MIME sniffing.
  - **Referrer-Policy** — controls referrer information leakage.
  - **Permissions-Policy** — limits powerful browser features.
  - **Cross-Origin-Embedder-Policy / Cross-Origin-Opener-Policy / Cross-Origin-Resource-Policy** — modern cross‑origin isolation headers.
- Flags **information disclosure** headers (e.g., `Server`, `X-Powered-By`) to help reduce fingerprinting.
- Lists **caching** headers (`Cache-Control`, `ETag`, etc.) for situational awareness.
- **Concurrency** with a thread pool for scanning multiple targets quickly.
- **JSON output** for pipelines and tooling.
- Choice of **HEAD** (default) or **GET** methods.
- Optional **TLS verification disable** for troubleshooting only.

---

## Installation

```bash
git clone https://github.com/BipinSaud/secHead.git
cd secHead
python3 -m venv venv        # recommended
source venv/bin/activate    # on Windows: venv\Scripts\activate
pip install -r requirements.txt
chmod +x secHead.py
```

> If your OS blocks global installs (e.g., macOS with “externally-managed-environment”), prefer the **virtual environment** shown above or use --break-system-packages (quick & dirty).

```
pip3 install requests colorama --break-system-packages
```

---

## Usage

### Quick check

```bash
./secHead.py https://example.com
```

### Multiple targets

```bash
./secHead.py https://a.com https://b.com
```

### Use GET instead of HEAD

```bash
./secHead.py https://example.com -m GET
```

### JSON output (machine-readable)

```bash
./secHead.py https://example.com -j
```

### Ignore TLS certificate errors

```bash
./secHead.py https://example.com -d
```

### Increase concurrency and timeouts

```bash
./secHead.py https://a.com https://b.com -t 20 --timeout 20
```

---

## Output Guide

- `[*] Analyzing headers of …` — target being evaluated (with final effective URL if redirects occur).
- `[+] <Header>: <Value>` — security header present.
- `[!] Missing security header: <Header>` — security header absent.
- `[!] Information disclosure header: <Header> (Value: <v>)` — server/framework exposure to consider removing or obfuscating.
- `[!] Caching header: <Header> (Value: <v>)` — present; review in your threat model.
- `[*] Note: …` — advisory for risky values (e.g., `HSTS max-age=0`, `Referrer-Policy: unsafe-url`).
- The final summary shows **present vs missing** and a visual **coverage bar**.

---

## What secHead Checks (quick reference)

| Category               | Headers                                                                                                                                                                                                                  |
| ---------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Security               | Strict-Transport-Security, Content-Security-Policy, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, Cross-Origin-Embedder-Policy, Cross-Origin-Opener-Policy, Cross-Origin-Resource-Policy |
| Information Disclosure | Server, X-Powered-By, X-AspNet-Version, X-AspNetMvc-Version                                                                                                                                                              |
| Caching                | Cache-Control, Pragma, Expires, ETag, Last-Modified                                                                                                                                                                      |

> **Note:** secHead reports presence/absence and risky patterns but does not replace a full security assessment.

---

## Troubleshooting

- **`ModuleNotFoundError: No module named 'requests'`**  
  Install dependencies: `pip install -r requirements.txt` (preferably in a virtualenv).

- **`externally-managed-environment` on macOS or new Linux distros**  
  Use a virtual environment (preferred) or `pip install --user ...`.

- **Blocked by proxies or WAF**  
  Some targets may block HEAD or unfamiliar User‑Agents. Use `-m GET` if necessary.

---

## License

GPLv3 — see `LICENSE` for details.
