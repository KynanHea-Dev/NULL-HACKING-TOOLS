#!/usr/bin/env python3
"""
Run:
    null.py

Network boundaries:
- Port checks are restricted to this computer (loopback).
- HTTP header inspection is restricted to localhost.
- DNS and TLS certificate inspection perform ordinary lookups/connections
  to a hostname the user enters; only use domains you own or are authorized to test.
"""

import base64
import hashlib
import ipaddress
import os
import secrets
import socket
import ssl
import string
import urllib.error
import urllib.request
from datetime import datetime
from urllib.parse import urlparse

RED = "\033[91m"
WHITE = "\033[97m"
GREY = "\033[90m"
RESET = "\033[0m"
BOLD = "\033[1m"

def clear():
    os.system("cls" if os.name == "nt" else "clear")

def banner():
    print(f"""{RED}{BOLD}
 _   _ _   _ _     _        SECURITY LAB
| \\ | | | | | |   | |
|  \\| | | | | |   | |       LOCAL TRAINING MODE
| |\\  | |_| | |___| |___    v2.0
|_| \\_|\\___/|_____|_____|
{RESET}{GREY}Practical tools • Standard library • Authorized testing only{RESET}
""")

def pause():
    input(f"\n{GREY}Press Enter to return to the console...{RESET}")

def safe_hostname(raw):
    raw = raw.strip()
    if "://" in raw:
        raw = urlparse(raw).hostname or ""
    raw = raw.rstrip(".")
    if not raw or any(ch.isspace() for ch in raw) or "/" in raw or "\\" in raw:
        raise ValueError("Enter a hostname only, e.g. example.com")
    return raw

def dns_lookup():
    print(f"\n{RED}DNS LOOKUP{RESET}")
    print("Performs a normal DNS/system resolver lookup. Use a domain you're allowed to assess.")
    try:
        host = safe_hostname(input("Hostname: "))
        results = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
        unique = sorted({item[4][0] for item in results})
        if not unique:
            print("No addresses returned.")
        else:
            for address in unique:
                try:
                    kind = "IPv6" if ipaddress.ip_address(address).version == 6 else "IPv4"
                except ValueError:
                    kind = "Address"
                print(f"  {kind:<5} {address}")
    except (ValueError, socket.gaierror, OSError) as exc:
        print(f"Lookup failed: {exc}")
    pause()

def localhost_port_check():
    print(f"\n{RED}LOCALHOST PORT CHECK{RESET}")
    print("Checks selected TCP ports on THIS computer only (127.0.0.1).")
    print("Enter comma-separated ports, or press Enter for common development ports.")
    raw = input("Ports: ").strip()
    if not raw:
        ports = [22, 80, 443, 3000, 5000, 8000, 8080, 8443]
    else:
        try:
            ports = sorted(set(int(x.strip()) for x in raw.split(",")))
            if not ports or any(p < 1 or p > 65535 for p in ports):
                raise ValueError
        except ValueError:
            print("Use comma-separated port numbers from 1 to 65535.")
            pause()
            return
    print("\nChecking loopback only...")
    for port in ports[:50]:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.25)
        try:
            status = "OPEN" if sock.connect_ex(("127.0.0.1", port)) == 0 else "closed"
            print(f"  127.0.0.1:{port:<5} {status}")
        finally:
            sock.close()
    if len(ports) > 50:
        print("Only the first 50 ports were checked.")
    print("An open port is not automatically a vulnerability; identify its service and purpose.")
    pause()

def local_header_inspector():
    print(f"\n{RED}LOCAL HTTP SECURITY HEADER INSPECTOR{RESET}")
    print("Restricted to localhost / loopback addresses.")
    url = input("Local URL (example: http://127.0.0.1:8000): ").strip()
    parsed = urlparse(url)
    allowed_hosts = {"localhost", "127.0.0.1", "::1"}
    if parsed.scheme not in {"http", "https"} or parsed.hostname not in allowed_hosts:
        print("Blocked: use a local URL such as http://localhost:8000.")
        pause()
        return
    try:
        request = urllib.request.Request(url, headers={"User-Agent": "NULL-Security-Lab/2.0"})
        with urllib.request.urlopen(request, timeout=3) as response:
            headers = {k.lower(): v for k, v in response.headers.items()}
            print(f"\nHTTP status: {response.status}")
            checks = [
                ("content-security-policy", "Restricts where page resources can load from"),
                ("x-content-type-options", "Helps prevent MIME-type sniffing"),
                ("x-frame-options", "Can help reduce clickjacking risk"),
                ("strict-transport-security", "Enforces HTTPS in supporting browsers; relevant on HTTPS"),
                ("referrer-policy", "Controls referrer information sent by the browser"),
                ("permissions-policy", "Controls access to selected browser features"),
            ]
            for key, note in checks:
                value = headers.get(key)
                print(f"\n{'[FOUND]' if value else '[MISSING]'} {key}")
                if value:
                    print(f"  {value}")
                print(f"  {note}")
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        print(f"Could not reach local service: {exc}")
        print("For a basic local test page, open a folder in Terminal and run:")
        print("  python3 -m http.server 8000")
        print("Then inspect http://127.0.0.1:8000")
    pause()

def tls_certificate_inspector():
    print(f"\n{RED}TLS CERTIFICATE INSPECTOR{RESET}")
    print("Opens a standard TLS connection to the hostname you enter.")
    print("Only inspect systems you own or are authorized to test.")
    try:
        host = safe_hostname(input("Hostname (e.g. example.com): "))
        context = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=5) as raw:
            with context.wrap_socket(raw, server_hostname=host) as conn:
                cert = conn.getpeercert()
                print(f"\nTLS version: {conn.version()}")
                print(f"Cipher: {conn.cipher()[0] if conn.cipher() else 'unknown'}")
                print(f"Certificate subject: {cert.get('subject', 'not supplied')}")
                print(f"Issuer: {cert.get('issuer', 'not supplied')}")
                print(f"Valid from: {cert.get('notBefore', 'unknown')}")
                print(f"Expires: {cert.get('notAfter', 'unknown')}")
                print(f"Subject alternative names: {len(cert.get('subjectAltName', []))} listed")
                print("Certificate validation: passed for this connection.")
    except (ValueError, socket.gaierror, OSError, ssl.SSLError) as exc:
        print(f"Connection or certificate check failed: {exc}")
    pause()

def hash_text():
    print(f"\n{RED}TEXT HASH CALCULATOR{RESET}")
    text = input("Text to hash (don't enter secrets): ")
    raw = text.encode("utf-8")
    print(f"SHA-256: {hashlib.sha256(raw).hexdigest()}")
    print(f"SHA-1:   {hashlib.sha1(raw).hexdigest()}  (legacy; avoid for security use)")
    print(f"MD5:     {hashlib.md5(raw).hexdigest()}  (legacy; not collision-resistant)")
    pause()

def file_integrity():
    print(f"\n{RED}FILE INTEGRITY CHECKER{RESET}")
    print("Calculates SHA-256 for a file on your computer.")
    path = input("File path: ").strip()
    if path.startswith("~"):
        path = os.path.expanduser(path)
    try:
        digest = hashlib.sha256()
        with open(path, "rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        print(f"File:   {os.path.abspath(path)}")
        print(f"SHA-256: {digest.hexdigest()}")
        print("Compare this digest with one from a trusted source to check file integrity.")
    except (OSError, ValueError) as exc:
        print(f"Could not read file: {exc}")
    pause()

def password_generator():
    print(f"\n{RED}SECURE PASSWORD GENERATOR{RESET}")
    try:
        length = int(input("Length (12-64): "))
        if not 12 <= length <= 64:
            raise ValueError
    except ValueError:
        print("Choose a whole number from 12 to 64.")
        pause()
        return
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*()-_=+"
    password = "".join(secrets.choice(alphabet) for _ in range(length))
    print("\nGenerated password (store it in a password manager):")
    print(f"{WHITE}{BOLD}{password}{RESET}")
    print("This tool does not save or transmit the generated password.")
    pause()

def password_auditor():
    print(f"\n{RED}SAMPLE PASSWORD STRENGTH AUDITOR{RESET}")
    print("Use a made-up practice password only. Never enter a real password.")
    password = input("Sample password: ")
    if not password:
        print("No sample supplied.")
        pause()
        return
    checks = [
        (len(password) >= 12, "At least 12 characters"),
        (any(c.islower() for c in password), "Contains lowercase letters"),
        (any(c.isupper() for c in password), "Contains uppercase letters"),
        (any(c.isdigit() for c in password), "Contains numbers"),
        (any(not c.isalnum() for c in password), "Contains symbols"),
        (len(set(password)) >= min(8, len(password)), "Uses varied characters"),
    ]
    score = 0
    for passed, label in checks:
        print(f"  [{'OK' if passed else 'NO'}] {label}")
        score += int(passed)
    rating = "WEAK" if score <= 2 else "FAIR" if score <= 4 else "STRONGER"
    print(f"\nResult: {rating} ({score}/6 checks)")
    print("This is a basic educational heuristic, not a security guarantee.")
    pause()

def base64_lab():
    print(f"\n{RED}BASE64 ENCODER / DECODER{RESET}")
    mode = input("[E]ncode or [D]ecode? ").strip().lower()
    value = input("Text or Base64: ")
    try:
        if mode.startswith("d"):
            output = base64.b64decode(value, validate=True).decode("utf-8")
        elif mode.startswith("e"):
            output = base64.b64encode(value.encode("utf-8")).decode("ascii")
        else:
            print("Choose E or D.")
            pause()
            return
        print(f"\nOutput: {output}")
        print("Base64 is encoding, not encryption. It does not protect secrets.")
    except (ValueError, UnicodeDecodeError) as exc:
        print(f"Could not decode valid UTF-8 Base64: {exc}")
    pause()

def caesar_cipher():
    print(f"\n{RED}CIPHER LAB — CAESAR SHIFT{RESET}")
    mode = input("[E]ncode or [D]ecode? ").strip().lower()
    text = input("Text: ")
    try:
        shift = int(input("Shift (0-25): ")) % 26
    except ValueError:
        print("Shift must be a number.")
        pause()
        return
    if mode.startswith("d"):
        shift = -shift
    elif not mode.startswith("e"):
        print("Choose E or D.")
        pause()
        return
    result = ""
    for char in text:
        if "a" <= char <= "z":
            result += chr((ord(char) - 97 + shift) % 26 + 97)
        elif "A" <= char <= "Z":
            result += chr((ord(char) - 65 + shift) % 26 + 65)
        else:
            result += char
    print(f"\nOutput: {result}")
    print("Caesar ciphers are educational, not secure encryption.")
    pause()

def challenge():
    print(f"\n{RED}CHALLENGE: HASH BASICS{RESET}")
    sample = "null-lab"
    expected = hashlib.sha256(sample.encode()).hexdigest()
    print(f"Sample text: {sample}")
    guess = input("SHA-256 digest for that exact text: ").strip().lower()
    if secrets.compare_digest(guess, expected):
        print("ACCESS GRANTED — challenge complete.")
    else:
        print("Not quite. SHA-256 produces 64 hexadecimal characters.")
    pause()

def main():
    actions = {
        "1": dns_lookup,
        "2": localhost_port_check,
        "3": local_header_inspector,
        "4": tls_certificate_inspector,
        "5": hash_text,
        "6": file_integrity,
        "7": password_generator,
        "8": password_auditor,
        "9": base64_lab,
        "10": caesar_cipher,
        "11": challenge,
    }
    while True:
        clear()
        banner()
        print(f"""{WHITE}
 [1]  DNS lookup
 [2]  Real TCP port check (localhost only)
 [3]  HTTP security headers (localhost only)
 [4]  TLS certificate inspector
 [5]  Text hash calculator (SHA-256 / legacy hashes)
 [6]  File integrity checker (SHA-256)
 [7]  Secure password generator
 [8]  Sample password strength auditor
 [9]  Base64 encoder / decoder
 [10] Caesar cipher lab
 [11] Hash basics challenge
 [0]  Exit
{RESET}""")
        choice = input(f"{RED}NULL@LAB {RESET}> ").strip()
        if choice == "0":
            print("Session closed.")
            break
        action = actions.get(choice)
        if action:
            action()
        else:
            print("Unknown command.")
            pause()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nSession interrupted.")
