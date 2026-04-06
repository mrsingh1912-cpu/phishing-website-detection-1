
from detector.feature_extractor import extract_features
from detector.intelligence import get_domain_age_info, get_ssl_info
from detector.reputation import safe_browsing_check

def score_rule_based(features: dict, intel: dict):
    score = 0
    reasons = []

    if features['has_ip']:
        score += 25
        reasons.append('URL uses an IP address instead of a normal domain.')
    if features['shortener_used']:
        score += 20
        reasons.append('URL shortener detected, which can hide the final destination.')
    if features['has_at_symbol']:
        score += 15
        reasons.append('The @ symbol is present, which can be used to mislead users.')
    if features['https_token_in_domain']:
        score += 10
        reasons.append('The word "https" appears inside the domain, which may be deceptive.')
    if features['tld_suspicious']:
        score += 10
        reasons.append('Suspicious top-level domain detected.')
    if features['brand_mismatch']:
        score += 18
        reasons.append('A trusted brand-like keyword appears in the URL, but not in the real domain.')
    if features['url_length'] > 75:
        score += 10
        reasons.append('URL is unusually long.')
    if features['subdomain_count'] >= 3:
        score += 12
        reasons.append('Too many subdomains found.')
    if features['hyphen_count'] >= 3:
        score += 8
        reasons.append('Too many hyphens found in the URL.')
    if features['digit_count'] >= 8:
        score += 5
        reasons.append('Many digits are present in the URL.')
    if features['suspicious_word_hits'] >= 2:
        score += 15
        reasons.append('Multiple suspicious words were found in the URL.')
    if features['has_port']:
        score += 5
        reasons.append('A custom or unusual port is used in the URL.')

    age_days = intel.get('domain_age_days')
    if age_days is not None and age_days < 180:
        score += 12
        reasons.append('Domain appears relatively new, which can be suspicious.')
    if intel.get('whois_available') is False:
        score += 4
        reasons.append('WHOIS information could not be reliably retrieved.')
    if intel.get('ssl_present') is False:
        score += 10
        reasons.append('SSL/TLS validation failed or HTTPS certificate is not available.')
    if intel.get('safe_browsing_flagged'):
        score += 35
        reasons.append('URL was flagged by the reputation check.')

    score = min(score, 100)
    if score >= 65:
        level = 'High Risk'
        prediction = 'Phishing/Suspicious'
    elif score >= 35:
        level = 'Medium Risk'
        prediction = 'Possibly Suspicious'
    else:
        level = 'Low Risk'
        prediction = 'Likely Safe'

    return {
        'prediction': prediction,
        'risk_level': level,
        'risk_score': score,
        'reasons': reasons if reasons else ['No strong phishing indicators were detected.']
    }

def try_ml_prediction(features: dict):
    return None

def analyze_url(url: str):
    features = extract_features(url)
    hostname = features.get('hostname', '')
    intel = {}
    intel.update(get_domain_age_info(hostname))
    intel.update(get_ssl_info(hostname))
    intel.update(safe_browsing_check(features.get('normalized_url', url)))

    result = score_rule_based(features, intel)
    ml_result = try_ml_prediction(features)
    if ml_result:
        result.update(ml_result)

    result['features'] = features
    result['intelligence'] = intel
    return result
