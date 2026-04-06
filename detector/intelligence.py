
import socket
import ssl
from datetime import datetime, timezone
import whois

def get_domain_age_info(hostname: str):
    if not hostname:
        return {'whois_available': False, 'domain_age_days': None, 'domain_age_note': 'No hostname found.'}
    try:
        data = whois.whois(hostname)
        creation_date = data.creation_date
        if isinstance(creation_date, list) and creation_date:
            creation_date = creation_date[0]
        if creation_date:
            if creation_date.tzinfo is None:
                creation_date = creation_date.replace(tzinfo=timezone.utc)
            age_days = (datetime.now(timezone.utc) - creation_date).days
            return {'whois_available': True, 'domain_age_days': age_days, 'domain_age_note': 'WHOIS lookup successful.'}
        return {'whois_available': True, 'domain_age_days': None, 'domain_age_note': 'Creation date not available from WHOIS.'}
    except Exception as e:
        return {'whois_available': False, 'domain_age_days': None, 'domain_age_note': f'WHOIS lookup failed: {e}'}

def get_ssl_info(hostname: str):
    if not hostname:
        return {'ssl_present': False, 'ssl_note': 'No hostname found.'}
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=4) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as secure_sock:
                cert = secure_sock.getpeercert()
                subject = dict(x[0] for x in cert.get('subject', [])) if cert.get('subject') else {}
                return {'ssl_present': True, 'ssl_note': 'Valid SSL/TLS handshake completed.', 'ssl_subject': subject}
    except Exception as e:
        return {'ssl_present': False, 'ssl_note': f'SSL check failed: {e}'}
