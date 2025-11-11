# feature_extraction.py
# Extracts 30 features from a given URL for phishing website detection.

import re
import socket
import whois
import pandas as pd
import requests
import tldextract
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from datetime import datetime

REQUEST_TIMEOUT = 4


def safe_bool(x, default=False):
    try:
        return bool(x)
    except Exception:
        return default


def try_get_whois(domain_name):
    try:
        return whois.whois(domain_name)
    except Exception:
        return None


def first_or_same(value):
    if isinstance(value, (list, tuple)) and value:
        return value[0]
    return value


def extract_features(url: str) -> dict:
    """
    Extracts features from a given URL to be used for phishing website detection.
    Returns a dictionary aligned with the model's expected feature columns.
    """
    features = {}
    try:
        parsed = urlparse(url)
        domain = parsed.netloc or parsed.path
        ext = tldextract.extract(url)
        domain_name = (ext.domain + '.' + ext.suffix) if ext.suffix else ext.domain

        soup = None
        response = None
        try:
            response = requests.get(url, timeout=REQUEST_TIMEOUT, allow_redirects=True)
            soup = BeautifulSoup(response.text, 'html.parser')
        except Exception:
            pass

        try:
            socket.inet_aton(domain)
            features['having_IP_Address'] = 1
        except Exception:
            features['having_IP_Address'] = -1

        length = len(url)
        features['URL_Length'] = 1 if length < 54 else (0 if length <= 75 else -1)

        shortening_services = r"(bit\.ly|goo\.gl|tinyurl\.com|ow\.ly|t\.co)"
        features['Shortining_Service'] = -1 if re.search(shortening_services, url, re.I) else 1

        features['having_At_Symbol'] = -1 if "@" in url else 1

        features['double_slash_redirecting'] = -1 if url.count('//') > 1 else 1

        features['Prefix_Suffix'] = -1 if '-' in domain else 1

        dots = ext.subdomain.count('.') if ext.subdomain else 0
        features['having_Sub_Domain'] = 1 if dots == 0 else (0 if dots == 1 else -1)

        features['SSLfinal_State'] = 1 if url.lower().startswith("https") else -1

        w = try_get_whois(domain_name)

        try:
            exp = first_or_same(getattr(w, "expiration_date", None))
            if exp:
                days_left = (exp - datetime.now()).days
                features['Domain_registeration_length'] = 1 if (days_left / 365.0) >= 1 else -1
            else:
                features['Domain_registeration_length'] = -1
        except Exception:
            features['Domain_registeration_length'] = -1

        try:
            if soup:
                icon = soup.find("link", rel=lambda v: v and 'icon' in v.lower())
                href = icon.get('href', '') if icon else ''
                features['Favicon'] = 1 if href and (domain in href or href.startswith('/')) else -1
            else:
                features['Favicon'] = -1
        except Exception:
            features['Favicon'] = -1

        features['port'] = -1 if (":443" not in url and ":80" not in url) else 1

        features['HTTPS_token'] = -1 if "https" in domain.lower() else 1

        try:
            if soup:
                imgs = soup.find_all('img', src=True)
                total = len(imgs)
                if total == 0:
                    features['Request_URL'] = 1
                else:
                    same = sum(1 for img in imgs if domain in img['src'] or img['src'].startswith('/'))
                    features['Request_URL'] = 1 if (same / total) >= 0.5 else -1
            else:
                features['Request_URL'] = 0
        except Exception:
            features['Request_URL'] = 0

        try:
            if soup:
                anchors = soup.find_all('a', href=True)
                total = len(anchors)
                if total == 0:
                    features['URL_of_Anchor'] = 1
                else:
                    unsafe = sum(1 for a in anchors if ("#" in a['href']) or ("javascript" in a['href'].lower()))
                    features['URL_of_Anchor'] = -1 if (unsafe / total) > 0.6 else 1
            else:
                features['URL_of_Anchor'] = 0
        except Exception:
            features['URL_of_Anchor'] = 0

        try:
            if soup:
                links = soup.find_all('link', href=True)
                scripts = soup.find_all('script', src=True)
                total = len(links) + len(scripts)
                if total == 0:
                    features['Links_in_tags'] = 1
                else:
                    safe = sum(1 for l in links if domain in l.get('href', '') or l.get('href', '').startswith('/'))
                    features['Links_in_tags'] = 1 if (safe / total) >= 0.5 else -1
            else:
                features['Links_in_tags'] = 0
        except Exception:
            features['Links_in_tags'] = 0

        try:
            if soup:
                forms = soup.find_all('form', action=True)
                empty = [f for f in forms if f.get('action', '') in ("", "about:blank")]
                features['SFH'] = -1 if len(empty) > 0 else 1
            else:
                features['SFH'] = 0
        except Exception:
            features['SFH'] = 0

        try:
            if soup:
                forms = soup.find_all('form', action=True)
                features['Submitting_to_email'] = -1 if any("mailto:" in f.get('action', '') for f in forms) else 1
            else:
                features['Submitting_to_email'] = 1
        except Exception:
            features['Submitting_to_email'] = 1

        features['Abnormal_URL'] = -1 if domain and (domain not in url) else 1

        try:
            features['Redirect'] = -1 if (response is not None and len(response.history) > 2) else 1
        except Exception:
            features['Redirect'] = 1

        try:
            features['on_mouseover'] = -1 if (
                        response is not None and re.search(r"onmouseover", response.text, re.I)) else 1
        except Exception:
            features['on_mouseover'] = 1

        try:
            features['RightClick'] = -1 if (
                        response is not None and re.search(r"event\\.button\\s*==\\s*2", response.text)) else 1
        except Exception:
            features['RightClick'] = 1

        try:
            features['popUpWidnow'] = -1 if (response is not None and re.search(r"alert\\", response.text)) else 1
        except Exception:
            features['popUpWidnow'] = 1

        try:
            features['Iframe'] = -1 if (response is not None and "<iframe" in response.text.lower()) else 1
        except Exception:
            features['Iframe'] = 1

        try:
            creation = first_or_same(getattr(w, "creation_date", None))
            if creation:
                age_months = max(0.0, (datetime.now() - creation).days / 30.0)
                features['age_of_domain'] = 1 if age_months >= 6 else -1
            else:
                features['age_of_domain'] = -1
        except Exception:
            features['age_of_domain'] = -1

        features['DNSRecord'] = 1 if domain_name else -1

        features['web_traffic'] = 0
        features['Page_Rank'] = 0

        features['Google_Index'] = 1 if "google" in url.lower() else -1

        try:
            features['Links_pointing_to_page'] = 1 if (soup and len(soup.find_all('a')) > 5) else -1
        except Exception:
            features['Links_pointing_to_page'] = -1

        features['Statistical_report'] = -1 if re.search(r"(login|bank|free|verify|update)", url, re.I) else 1

    except Exception as e:
        print("Error extracting features:", e)

    try:
        feature_order = pd.read_csv("X_train.csv").columns.tolist()
    except Exception:
        feature_order = [
            'having_IP_Address', 'URL_Length', 'Shortining_Service', 'having_At_Symbol',
            'double_slash_redirecting', 'Prefix_Suffix', 'having_Sub_Domain', 'SSLfinal_State',
            'Domain_registeration_length', 'Favicon', 'port', 'HTTPS_token', 'Request_URL',
            'URL_of_Anchor', 'Links_in_tags', 'SFH', 'Submitting_to_email', 'Abnormal_URL',
            'Redirect', 'on_mouseover', 'RightClick', 'popUpWidnow', 'Iframe', 'age_of_domain',
            'DNSRecord', 'web_traffic', 'Page_Rank', 'Google_Index', 'Links_pointing_to_page',
            'Statistical_report'
        ]

    final_features = {col: features.get(col, 0) for col in feature_order}
    return final_features
