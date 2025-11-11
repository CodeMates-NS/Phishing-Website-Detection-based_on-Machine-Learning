from flask import Flask, render_template, request
import joblib
import pandas as pd
import random
import re
from urllib.parse import urlparse
from feature_extraction import extract_features

app = Flask(__name__)
app.secret_key = "replace-me"

model = joblib.load("rf_model.pkl")

DOMAIN_LIKE_RE = re.compile(
    r"^(?:https?://)?(?:www\.)?(?:[A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,63}(?:[/:?#].*)?$"
)


def normalize_url(user_input: str) -> tuple[str, str]:
    s = user_input.strip()

    if not DOMAIN_LIKE_RE.match(s):
        return "", s

    parsed = urlparse(s)
    if not parsed.scheme:
        s = "https://" + s.lstrip("/")

    return s, s


@app.route('/')
def home():
    return render_template('index.html')


@app.route('/predict', methods=['POST'])
def predict():
    raw = request.form.get('url', '').strip()
    norm_url, display_url = normalize_url(raw)

    if not norm_url:
        return render_template(
            'index.html',
            prediction_text="Please enter a valid URL (e.g., https://example.com).",
            url=display_url,
            extra_reasons=[],
            confidence=None
        )

    features = extract_features(norm_url)
    df = pd.DataFrame([features])

    prediction = model.predict(df)[0]

    try:
        proba = model.predict_proba(df)[0]
        raw = proba[prediction] * 100

        confidence = (raw * 0.6) + 35
        confidence = round(min(99.0, max(1.0, confidence)), 2)

    except:
        confidence = None

    if prediction == 1:
        result = "Legitimate Website! ✅"
        extra_reasons = []
    else:
        result = "Phishing Website Detected ⚠️"

        try:
            feature_order = list(features.keys())
            importances = getattr(model, "feature_importances_", [0] * len(feature_order))
            feat_imp = dict(zip(feature_order, importances))

            expected_safe_values = {
                'having_IP_Address': -1, 'URL_Length': 1, 'Shortining_Service': 1,
                'having_At_Symbol': 1, 'double_slash_redirecting': 1, 'Prefix_Suffix': 1,
                'having_Sub_Domain': 1, 'SSLfinal_State': 1, 'Domain_registeration_length': 1,
                'Favicon': 1, 'port': 1, 'HTTPS_token': 1, 'Request_URL': 1, 'URL_of_Anchor': 1,
                'Links_in_tags': 1, 'SFH': 1, 'Submitting_to_email': 1, 'Abnormal_URL': 1,
                'Redirect': 1, 'on_mouseover': 1, 'RightClick': 1, 'popUpWidnow': 1,
                'Iframe': 1, 'age_of_domain': 1, 'DNSRecord': 1, 'web_traffic': 1,
                'Page_Rank': 1, 'Google_Index': 1, 'Links_pointing_to_page': 1,
                'Statistical_report': 1
            }

            truly_abnormal = [
                f for f, v in features.items()
                if isinstance(v, (int, float)) and str(v) != str(expected_safe_values.get(f, v))
            ]

            abnormal_sorted = sorted(
                truly_abnormal, key=lambda x: feat_imp.get(x, 0), reverse=True
            )

            top_abnormal = random.sample(abnormal_sorted[:8], min(4, len(abnormal_sorted[:8])))

            reason_texts = {
                'having_IP_Address': "The URL uses an IP address instead of a domain name.",
                'URL_Length': "The URL is unusually long, a common phishing tactic.",
                'Shortining_Service': "The URL uses a shortening service, hiding its real destination.",
                'having_At_Symbol': "The '@' symbol is used in URLs to trick users.",
                'double_slash_redirecting': "Multiple slashes suggest a redirect pattern.",
                'Prefix_Suffix': "The domain contains a hyphen, common in fake domains.",
                'having_Sub_Domain': "Too many subdomains detected, often used to hide phishing.",
                'SSLfinal_State': "Website lacks secure HTTPS/SSL certification.",
                'Domain_registeration_length': "The domain was registered for a short period, suspicious.",
                'Favicon': "The favicon may be loaded from an external domain.",
                'port': "The website uses a non-standard port.",
                'HTTPS_token': "The domain name contains 'https', which can be misleading.",
                'Request_URL': "Too many resources are loaded from external domains.",
                'URL_of_Anchor': "Anchor links redirect to different domains or unsafe targets.",
                'Links_in_tags': "Tags contain links pointing to suspicious domains.",
                'SFH': "Form handler sends data to a suspicious or blank destination.",
                'Submitting_to_email': "Form submits data directly to an email address.",
                'Abnormal_URL': "URL structure is inconsistent with domain.",
                'Redirect': "Website performs multiple redirects.",
                'on_mouseover': "Suspicious mouseover scripts found.",
                'RightClick': "Right-click is disabled, often hides malicious intent.",
                'popUpWidnow': "Popups detected, may capture sensitive info.",
                'Iframe': "Page uses iframes, which can mask real content.",
                'age_of_domain': "Domain is newly created, potentially untrustworthy.",
                'DNSRecord': "Domain has missing or invalid DNS records.",
                'web_traffic': "Website has low or no traffic, not trustworthy.",
                'Page_Rank': "Low page rank, not reputable.",
                'Google_Index': "Website not indexed by Google.",
                'Links_pointing_to_page': "Few inbound links, not a legitimate site.",
                'Statistical_report': "Contains phishing-related keywords."
            }

            extra_reasons = [
                reason_texts.get(f, f"Suspicious behavior detected in {f.replace('_', ' ')}.")
                for f in top_abnormal
            ]

        except Exception:
            extra_reasons = ["Anomaly detected — possible phishing behavior."]

    return render_template(
        'index.html',
        prediction_text=result,
        url=display_url,
        extra_reasons=extra_reasons,
        confidence=confidence
    )


if __name__ == "__main__":
    app.run(debug=True)
