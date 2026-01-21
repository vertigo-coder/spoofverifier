import csv
import dns.resolver
import re
import sys
import dns.exception
import time

resolver = dns.resolver.Resolver()
resolver.timeout = 2.0
resolver.lifetime = 2.0

def is_vulnerable(domain):
    dmarc_policy = None
    has_spf = False
    has_dkim = False
    
    try:
        dmarc_records = resolver.resolve(f"_dmarc.{domain}", 'TXT')
        for r in dmarc_records:
            record_text = str(r).strip('"')
            if 'v=DMARC1' in record_text:
                p = re.search(r'p=(none|quarantine|reject)', record_text)
                if p:
                    dmarc_policy = p.group(1)
                    break
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.DNSException):
        pass
    
    if dmarc_policy in ('quarantine', 'reject'):
        return False
    
    try:
        spf_records = resolver.resolve(domain, 'TXT')
        for r in spf_records:
            record_text = str(r).strip('"')
            if record_text.startswith('v=spf1'):
                has_spf = True
                break
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.DNSException):
        pass
    
    if has_spf:
        return False
    
    selectors = ['k1', 's1', 'mail', 'selector', 'google', 'microsoft', 'amazonses']
    for selector in selectors:
        try:
            dkim_records = resolver.resolve(f"{selector}._domainkey.{domain}", 'TXT')
            for r in dkim_records:
                record_text = str(r).strip('"')
                if record_text.startswith('v=DKIM1'):
                    has_dkim = True
                    raise StopIteration
        except StopIteration:
            break
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.DNSException):
            continue
    
    if has_dkim:
        return False
    
    return True

def process_domain(domain):
    if is_vulnerable(domain):
        print(f"{domain} - VULNERABLE TO EMAIL SPOOFING")

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python spoofverifier.py <input_csv>", file=sys.stderr)
        sys.exit(1)
    
    try:
        with open(sys.argv[1], 'r') as f:
            reader = csv.reader(f)
            domains = [row[1] if len(row) > 1 else row[0] for row in reader]
            for domain in domains:
                process_domain(domain)
                time.sleep(1)  # Wait 1 second between domain checks
    except KeyboardInterrupt:
        print("\nScan interrupted by user.", file=sys.stderr)
        sys.exit(0)