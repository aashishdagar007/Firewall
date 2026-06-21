#!/usr/bin/env python3
import socket
import ssl
import sys
import argparse

def test_protocol(host, port, protocol_name, min_version, max_version):
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.minimum_version = min_version
        ctx.maximum_version = max_version
        
        with socket.create_connection((host, port), timeout=3) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                print(f"[+] {protocol_name} is SUPPORTED (VULNERABLE!)")
                return True
    except ssl.SSLError as e:
        print(f"[-] {protocol_name} is NOT supported")
        return False
    except socket.timeout:
        print(f"[!] Connection timeout while testing {protocol_name}")
        return False
    except ConnectionRefusedError:
        print(f"[!] Connection refused. Is the port open?")
        sys.exit(1)
    except Exception as e:
        print(f"[!] Error testing {protocol_name}: {e}")
        return False

def test_secure_protocol(host, port, protocol_name, min_version, max_version):
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.minimum_version = min_version
        ctx.maximum_version = max_version
        
        with socket.create_connection((host, port), timeout=3) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                print(f"[+] {protocol_name} is SUPPORTED (SECURE)")
                return True
    except ssl.SSLError as e:
        print(f"[-] {protocol_name} is NOT supported")
        return False
    except Exception as e:
        print(f"[!] Error testing {protocol_name}: {e}")
        return False

def main():
    parser = argparse.ArgumentParser(description="Scan target for vulnerable TLS/SSL protocols")
    parser.add_argument("host", help="Target host")
    parser.add_argument("-p", "--port", type=int, default=443, help="Target port (default: 443)")
    args = parser.parse_args()

    print(f"Scanning {args.host}:{args.port} for TLS/SSL versions...\n")
    
    print("--- Vulnerable Protocols ---")
    test_protocol(args.host, args.port, "TLS 1.0", ssl.TLSVersion.TLSv1, ssl.TLSVersion.TLSv1)
    test_protocol(args.host, args.port, "TLS 1.1", ssl.TLSVersion.TLSv1_1, ssl.TLSVersion.TLSv1_1)
    
    print("\n--- Secure Protocols ---")
    test_secure_protocol(args.host, args.port, "TLS 1.2", ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_2)
    test_secure_protocol(args.host, args.port, "TLS 1.3", ssl.TLSVersion.TLSv1_3, ssl.TLSVersion.TLSv1_3)
    
    print("\nRecommendation: Disable TLS 1.0 and TLS 1.1 on your server to prevent vulnerability exploitation.")

if __name__ == "__main__":
    main()
