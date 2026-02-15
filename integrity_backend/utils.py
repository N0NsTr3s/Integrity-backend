import json, base64, hashlib, re
from datetime import datetime


def parse_user_agent(user_agent: str) -> dict:
    ua_lower = (user_agent or '').lower()
    if 'chrome/' in ua_lower:
        m = re.search(r'chrome/([0-9.]+)', ua_lower)
        version = m.group(1) if m else 'unknown'
        if 'edg/' in ua_lower:
            m2 = re.search(r'edg/([0-9.]+)', ua_lower)
            return {'browser': 'Edge', 'version': m2.group(1) if m2 else version, 'platform': get_platform(user_agent)}
        return {'browser': 'Chrome', 'version': version, 'platform': get_platform(user_agent)}
    if 'firefox/' in ua_lower:
        m = re.search(r'firefox/([0-9.]+)', ua_lower)
        return {'browser': 'Firefox', 'version': m.group(1) if m else 'unknown', 'platform': get_platform(user_agent)}
    if 'safari/' in ua_lower and 'chrome' not in ua_lower:
        m = re.search(r'version/([0-9.]+)', ua_lower)
        return {'browser': 'Safari', 'version': m.group(1) if m else 'unknown', 'platform': get_platform(user_agent)}
    if 'trident/' in ua_lower or 'msie' in ua_lower:
        m = re.search(r'(?:msie |rv:)([0-9.]+)', ua_lower)
        return {'browser': 'Internet Explorer', 'version': m.group(1) if m else 'unknown', 'platform': get_platform(user_agent)}
    return {'browser': 'Unknown', 'version': 'unknown', 'platform': get_platform(user_agent)}


def get_platform(user_agent: str) -> str:
    ua_lower = (user_agent or '').lower()
    if 'windows nt 10' in ua_lower:
        return 'Windows 10'
    if 'mac os x' in ua_lower:
        m = re.search(r'mac os x ([0-9_]+)', ua_lower)
        if m: return f"macOS {m.group(1).replace('_','.') }"
        return 'macOS'
    if 'linux' in ua_lower:
        return 'Linux'
    if 'android' in ua_lower:
        m = re.search(r'android ([0-9.]+)', ua_lower)
        if m: return f"Android {m.group(1)}"
        return 'Android'
    if 'iphone' in ua_lower or 'ipad' in ua_lower:
        m = re.search(r'os ([0-9_]+)', ua_lower)
        if m: return f"iOS {m.group(1).replace('_','.') }"
        return 'iOS'
    return 'Unknown'


def analyze_injection_risk(injection: dict) -> dict:
    tag = (injection.get('tag') or '').lower()
    attrs = injection.get('attributes') or {}
    risk = []
    if tag in ['script','iframe','object','embed']: risk.append('dangerous_tag')
    for h in ['onclick','onload','onerror']:
        if h in attrs: risk.append(f'inline_{h}')
    src = attrs.get('src') or attrs.get('href') or ''
    if src.startswith('data:'): risk.append('data_url')
    if re.search(r'\d{1,3}(?:\.\d{1,3}){3}', src or ''): risk.append('ip_address')
    final = 'low'
    if len(risk) >= 3: final = 'critical'
    elif len(risk) >= 2: final = 'high'
    elif len(risk) >= 1: final = 'medium'
    return {'risk_factors': risk, 'risk_score': len(risk), 'final_risk': final}
