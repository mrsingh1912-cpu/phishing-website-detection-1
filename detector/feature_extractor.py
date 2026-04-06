
import re
from urllib.parse import urlparse
import ipaddress
import tldextract

SUSPICIOUS_WORDS = [
    'login', 'verify', 'update', 'secure', 'account', 'banking',
    'confirm', 'signin', 'password', 'wallet', 'payment', 'alert',
    'suspended', 'unlock', 'recover', 'invoice', 'crypto', 'bonus',
    'gift', 'free', 'claim', 'otp', 'kyc'
]

SHORTENERS = {
    'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'is.gd', 'buff.ly',
    'ow.ly', 'rb.gy', 'cutt.ly', 'shorturl.at'
}

SUSPICIOUS_TLDS = {
    'zip', 'review', 'country', 'kim', 'cricket', 'link', 'work', 'party', 'gq', 'tk', 'xyz'
}

TRUSTED_BRANDS = [
    'paypal', 'google', 'microsoft', 'apple', 'amazon', 'facebook',
    'instagram', 'netflix', 'bank', 'whatsapp', 'telegram', 'coinbase'
]

def safe_url(url: str) -> str:
    url = url.strip()
    if not re.match(r'^[a-zA-Z]+://', url):
        url = 'http://' + url
    return url

def is_ip(hostname: str) -> int:
    try:
        ipaddress.ip_address(hostname)
        return 1
    except Exception:
        return 0

def count_digits(text: str) -> int:
    return sum(ch.isdigit() for ch in text)

def extract_features(url: str) -> dict:
    original_url = url
    url = safe_url(url)
    parsed = urlparse(url)
    hostname = parsed.netloc.split('@')[-1].split(':')[0].lower()
    path = parsed.path or ''
    query = parsed.query or ''
    full = url.lower()

    ext = tldextract.extract(url)
    domain = ext.domain or ''
    suffix = ext.suffix or ''

    try:
        has_port = int(parsed.port is not None) if parsed.netloc else 0
    except ValueError:
        has_port = 1

    matched_brand = ''
    brand_mismatch = 0
    for brand in TRUSTED_BRANDS:
        if brand in full and brand not in domain:
            brand_mismatch = 1
            matched_brand = brand
            break

    return {
        'url': original_url,
        'normalized_url': url,
        'hostname': hostname,
        'domain': domain,
        'suffix': suffix,
        'url_length': len(full),
        'dot_count': full.count('.'),
        'hyphen_count': full.count('-'),
        'slash_count': full.count('/'),
        'digit_count': count_digits(full),
        'subdomain_count': len([x for x in ext.subdomain.split('.') if x]) if ext.subdomain else 0,
        'has_ip': is_ip(hostname),
        'has_at_symbol': int('@' in full),
        'https_token_in_domain': int('https' in hostname.replace('https://', '')),
        'has_port': has_port,
        'suspicious_word_hits': sum(1 for word in SUSPICIOUS_WORDS if word in full),
        'shortener_used': int(hostname in SHORTENERS),
        'tld_suspicious': int(suffix in SUSPICIOUS_TLDS),
        'brand_mismatch': brand_mismatch,
        'matched_brand': matched_brand,
        'path_length': len(path),
        'query_length': len(query),
    }
