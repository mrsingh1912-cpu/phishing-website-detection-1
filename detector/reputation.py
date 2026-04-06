
import requests

API_KEY = ""
SAFE_BROWSING_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

def safe_browsing_check(url: str):
    if not API_KEY:
        return {'safe_browsing_enabled': False, 'safe_browsing_status': 'Skipped (no API key configured).'}
    payload = {
        "client": {"clientId": "phishing-detector", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }
    try:
        response = requests.post(f"{SAFE_BROWSING_URL}?key={API_KEY}", json=payload, timeout=6)
        data = response.json() if response.content else {}
        matches = data.get("matches", [])
        return {
            'safe_browsing_enabled': True,
            'safe_browsing_flagged': bool(matches),
            'safe_browsing_status': 'Flagged by Google Safe Browsing.' if matches else 'No match found.'
        }
    except Exception as e:
        return {'safe_browsing_enabled': True, 'safe_browsing_flagged': False, 'safe_browsing_status': f'API check failed: {e}'}
