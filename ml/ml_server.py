"""
PhishShield ML microservice.
Loads text_model.pkl and url_model.pkl and exposes two HTTP endpoints:
    POST /predict_text   { "text": "..." }  -> verdict
    POST /predict_url    { "url":  "..." }  -> verdict
Run:  python ml_server.py   (listens on http://127.0.0.1:5001)
"""
from flask import Flask, request, jsonify
import joblib, os, re
from urllib.parse import urlparse

BASE = os.path.dirname(os.path.abspath(__file__))
app = Flask(__name__)

TEXT_MODEL_PATH = os.path.join(BASE, 'text_model.pkl')
URL_MODEL_PATH  = os.path.join(BASE, 'url_model.pkl')

text_model = joblib.load(TEXT_MODEL_PATH) if os.path.exists(TEXT_MODEL_PATH) else None
url_model  = joblib.load(URL_MODEL_PATH)  if os.path.exists(URL_MODEL_PATH)  else None


def extract_url_features(url: str) -> str:
    url = str(url).strip().lower()
    try:
        p    = urlparse(url)
        host = p.netloc or ''
        path = p.path or ''
    except Exception:
        host, path = '', ''

    f = []
    f.append('https' if url.startswith('https') else 'http')
    f.append(f'len_{min(len(url)//20, 10)}')
    f.append(f'dots_{host.count(".")}')
    f.append(f'hyphens_{host.count("-")}')
    f.append(f'digits_{sum(c.isdigit() for c in host)}')
    if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', host):
        f.append('ip_host')
    tld = host.split('.')[-1] if '.' in host else ''
    f.append(f'tld_{tld}')
    for brand in ['paypal','google','facebook','amazon','apple','microsoft',
                  'netflix','bank','sbi','hdfc','icici']:
        if brand in host and not host.endswith(brand + '.com'):
            f.append(f'fake_{brand}')
    if any(s in url for s in ['bit.ly','tinyurl','t.co','goo.gl','ow.ly','cutt.ly']):
        f.append('shortener')
    if '@' in url:
        f.append('at_symbol')
    if any(kw in path for kw in ['login','verify','account','update',
                                 'secure','signin','confirm']):
        f.append('suspicious_path')
    if 'xn--' in host:
        f.append('punycode')
    return ' '.join(f)


@app.route('/health', methods=['GET'])
def health():
    return jsonify({
        'ok': True,
        'text_model_loaded': text_model is not None,
        'url_model_loaded':  url_model  is not None,
    })


@app.route('/predict_text', methods=['POST'])
def predict_text():
    if text_model is None:
        return jsonify({'error': 'text_model.pkl not found. Train the model first.'}), 500

    data = request.get_json(force=True, silent=True) or {}
    text = (data.get('text') or '').strip()
    if not text:
        return jsonify({'error': 'No text provided'}), 400

    probabilities = text_model.predict_proba([text])[0]
    class_probabilities = {
        str(label): float(probability)
        for label, probability in zip(text_model.classes_, probabilities)
    }
    predicted_label = str(text_model.predict([text])[0])
    confidence = max(class_probabilities.values())
    if predicted_label in {'safe', 'suspicious', 'phishing'}:
        label = predicted_label
    else:
        binary_label = int(predicted_label)
        label = 'phishing' if binary_label == 1 else 'safe'
        if confidence < 0.65:
            label = 'suspicious'

    return jsonify({
        'label': label,
        'phishing_probability': round(class_probabilities.get('phishing', class_probabilities.get('1', 0.0)), 4),
        'suspicious_probability': round(class_probabilities.get('suspicious', 0.0), 4),
        'safe_probability': round(class_probabilities.get('safe', class_probabilities.get('0', 0.0)), 4),
        'confidence': round(confidence, 4),
    })


@app.route('/predict_url', methods=['POST'])
def predict_url():
    if url_model is None:
        return jsonify({'error': 'url_model.pkl not found. Train the model first.'}), 500

    data = request.get_json(force=True, silent=True) or {}
    url  = (data.get('url') or '').strip()
    if not url:
        return jsonify({'error': 'No URL provided'}), 400

    feats          = extract_url_features(url)
    probabilities = url_model.predict_proba([feats])[0]
    class_probabilities = {
        str(label): float(probability)
        for label, probability in zip(url_model.classes_, probabilities)
    }
    predicted_label = str(url_model.predict([feats])[0])
    confidence = max(class_probabilities.values())
    if predicted_label in {'safe', 'suspicious', 'phishing'}:
        label = predicted_label
    else:
        binary_label = int(predicted_label)
        label = 'phishing' if binary_label == 1 else 'safe'
        if confidence < 0.65:
            label = 'suspicious'

    return jsonify({
        'label': label,
        'phishing_probability': round(class_probabilities.get('phishing', class_probabilities.get('1', 0.0)), 4),
        'suspicious_probability': round(class_probabilities.get('suspicious', 0.0), 4),
        'safe_probability': round(class_probabilities.get('safe', class_probabilities.get('0', 0.0)), 4),
        'confidence': round(confidence, 4),
    })


if __name__ == '__main__':
    print("PhishShield ML service starting on http://127.0.0.1:5001")
    print("text_model loaded:", text_model is not None)
    print("url_model  loaded:", url_model  is not None)
    app.run(host='127.0.0.1', port=5001, debug=False)