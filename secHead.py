#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
secHead - Security Headers Checker
Author: okBoss
License: GPLv3
"""
from __future__ import annotations
import argparse
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Tuple, Union
import requests
from colorama import Fore, Style, init

init(autoreset=True)

DEFAULT_HEADERS: Dict[str, str] = {
    "User-Agent": "secHead/1.0 (+https://github.com/okBoss/secHead)",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Upgrade-Insecure-Requests": "1",
}

SECURITY_HEADERS: Dict[str, str] = {
    "Strict-Transport-Security": "error",
    "Content-Security-Policy": "warning",
    "X-Frame-Options": "warning",
    "X-Content-Type-Options": "warning",
    "Referrer-Policy": "warning",
    "Permissions-Policy": "warning",
    "Cross-Origin-Embedder-Policy": "warning",
    "Cross-Origin-Opener-Policy": "warning",
    "Cross-Origin-Resource-Policy": "warning",
}

INFO_HEADERS: List[str] = [
    "Server",
    "X-Powered-By",
    "X-AspNet-Version",
    "X-AspNetMvc-Version",
]

CACHE_HEADERS: List[str] = [
    "Cache-Control",
    "Pragma",
    "Expires",
    "ETag",
    "Last-Modified",
]

def banner() -> None:
    print("")
    print(Fore.CYAN + "┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓" + Style.RESET_ALL)
    print(Fore.CYAN + "┃Security Headers Checker - secHead by okBoss          ┃" + Style.RESET_ALL)
    print(Fore.MAGENTA + "┃⚡ Hunting down weak/missing security headers ⚡      ┃" + Style.RESET_ALL)
    print(Fore.CYAN + "┃Bonus: Detects info disclosure & caching risks        ┃" + Style.RESET_ALL)
    print(Fore.CYAN + "┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛" + Style.RESET_ALL)
    print("")

def normalize_url(url: str) -> str:
    if not url.lower().startswith(("http://", "https://")):
        return "https://" + url
    return url

def build_session(verify_ssl: bool, headers: Dict[str, str]) -> requests.Session:
    session = requests.Session()
    session.headers.update(headers)
    session.verify = verify_ssl
    adapter = requests.adapters.HTTPAdapter(pool_connections=50, pool_maxsize=50)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    return session

def fetch_headers(session: requests.Session, url: str, method: str, timeout: int = 10) -> Tuple[Dict[str, str], str]:
    try:
        response = session.request(method, url, allow_redirects=True, timeout=timeout)
        return response.headers, response.url
    except Exception as exc:
        return {"error": str(exc)}, url

def analyze_headers(headers: Dict[str, str]) -> Dict[str, Union[Dict[str, str], List[str], str]]:
    results: Dict[str, Union[Dict[str, str], List[str], str]] = {"present": {}, "missing": [], "info_disclosure": {}, "caching": {}}
    if "error" in headers:
        results["error"] = headers["error"]
        return results
    for header in SECURITY_HEADERS:
        if header in headers:
            results["present"][header] = headers[header]
        else:
            results["missing"].append(header)
    for header in INFO_HEADERS:
        if header in headers:
            results["info_disclosure"][header] = headers[header]
    for header in CACHE_HEADERS:
        if header in headers:
            results["caching"][header] = headers[header]
    notes: List[str] = []
    hsts = results["present"].get("Strict-Transport-Security")  # type: ignore[union-attr]
    if isinstance(hsts, str) and "max-age=0" in hsts:
        notes.append("Strict-Transport-Security specifies 'max-age=0', which disables HSTS. Consider removing this header or setting a positive max-age.")
    refpol = results["present"].get("Referrer-Policy")  # type: ignore[union-attr]
    if isinstance(refpol, str) and refpol.strip().lower() == "unsafe-url":
        notes.append("Referrer-Policy is 'unsafe-url', which may leak sensitive path/query data. Consider 'no-referrer' or 'strict-origin-when-cross-origin'.")
    if notes:
        results["notes"] = notes
    return results

def _stylize(text: str, level: str) -> str:
    mapping = {"info": Fore.CYAN, "ok": Fore.GREEN, "warn": Fore.YELLOW, "bad": Fore.RED, "note": Fore.MAGENTA}
    return mapping.get(level, "") + text + Style.RESET_ALL

def _progress_bar(safe: int, missing: int) -> str:
    total = max(1, safe + missing)
    units = 20
    filled = int(units * safe / total)
    return "[" + "█" * filled + "░" * (units - filled) + f"] {safe}/{total}"

def print_report(url: str, final_url: str, results: Dict[str, Union[Dict[str, str], List[str], str]], json_output: bool = False) -> Optional[Dict[str, Union[Dict[str, str], List[str], str]]]:
    if json_output:
        return {final_url: results}
    print(_stylize("[*] Analyzing headers of " + url, "info"))
    if final_url and final_url != url:
        print(_stylize("[*] Effective URL: " + final_url, "info"))
    if "error" in results:
        print(_stylize("[!] Error: " + str(results["error"]), "bad"))
        return None
    present: Dict[str, str] = results.get("present", {})  # type: ignore[assignment]
    missing: List[str] = results.get("missing", [])        # type: ignore[assignment]
    for header, value in present.items():
        print(_stylize(f"[+] {header}: {value}", "ok"))
    for header in missing:
        print(_stylize(f"[!] Missing security header: {header}", "bad"))
    info: Dict[str, str] = results.get("info_disclosure", {})  # type: ignore[assignment]
    for header, value in info.items():
        print(_stylize(f"[!] Information disclosure header: {header} (Value: {value})", "warn"))
    caching: Dict[str, str] = results.get("caching", {})  # type: ignore[assignment]
    for header, value in caching.items():
        print(_stylize(f"[!] Caching header: {header} (Value: {value})", "warn"))
    notes: List[str] = results.get("notes", [])  # type: ignore[assignment]
    for note in notes:
        print(_stylize(f"[*] Note: {note}", "note"))
    print("")
    print("┄" * 55)
    print(_stylize(f"[!] Headers analyzed for {final_url}", "info"))
    print(_stylize(f"[+] There are {len(present)} security headers present", "ok"))
    print(_stylize(f"[-] There are {len(missing)} security headers missing", "bad"))
    print(_stylize("    " + _progress_bar(len(present), len(missing)), "note"))
    print("")
    return None

def main() -> None:
    parser = argparse.ArgumentParser(description="secHead - Security Headers Checker by okBoss")
    parser.add_argument("targets", nargs="+", help="One or more target URLs or hostnames (scheme optional; defaults to HTTPS).")
    parser.add_argument("-m", "--method", default="HEAD", choices=["HEAD", "GET"], help="HTTP method to use (default: HEAD).")
    parser.add_argument("-j", "--json", action="store_true", help="Emit machine-readable JSON instead of human-readable output.")
    parser.add_argument("-d", "--disable-ssl", action="store_true", help="Disable TLS certificate verification.")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Number of concurrent worker threads (default: 10).")
    parser.add_argument("--timeout", type=int, default=10, help="Per-request timeout in seconds (default: 10).")
    args = parser.parse_args()
    banner()
    targets: List[str] = [normalize_url(t) for t in args.targets]
    session = build_session(not args.disable_ssl, dict(DEFAULT_HEADERS))
    json_out: Dict[str, Dict[str, Union[Dict[str, str], List[str], str]]] = {}
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = {executor.submit(fetch_headers, session, url, args.method, args.timeout): url for url in targets}
        for fut in as_completed(futures):
            url = futures[fut]
            headers, final_url = fut.result()
            results = analyze_headers(headers)
            out = print_report(url, final_url, results, args.json)
            if args.json:
                json_out.update({final_url: results})
    if args.json:
        print(json.dumps(json_out, indent=2))

if __name__ == "__main__":
    main()
