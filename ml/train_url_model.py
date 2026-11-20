"""
Trains the URL risk classifier.
Input :  url_dataset.csv (0 = safe, 1 = phishing)
         public_url_samples.csv (safe, suspicious, and phishing)
Output:  url_model.pkl
Run   :  python train_url_model.py
"""
import os
import re
import pandas as pd
import joblib
from urllib.parse import urlparse
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.pipeline import Pipeline
from sklearn.metrics import accuracy_score, classification_report

BASE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(BASE, 'url_dataset.csv')
OUT  = os.path.join(BASE, 'url_model.pkl')

LABEL_ORDER = ['safe', 'suspicious', 'phishing']


def extract_features(url: str) -> str:
    """Same feature string as in ml_server.py — do not diverge!"""
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


def normalize_labels(labels):
    values = labels.astype(str).str.strip().str.lower()
    numeric = set(values.unique())
    if '2' in numeric:
        mapping = {'0': 'safe', '1': 'suspicious', '2': 'phishing'}
    else:
        mapping = {'0': 'safe', '1': 'phishing'}
    mapping.update({
        'safe': 'safe',
        'suspicious': 'suspicious',
        'phish': 'phishing',
        'phishing': 'phishing',
        'fake': 'phishing',
    })
    normalized = values.map(mapping)
    if normalized.isna().any():
        invalid = sorted(values[normalized.isna()].unique())
        raise ValueError(f'Unsupported URL label(s): {invalid}')
    return normalized


public_data = os.path.join(BASE, 'public_url_samples.csv')
datasets = []
for path in (DATA, public_data):
    source = pd.read_csv(path).dropna(subset=['url', 'label']).copy()
    source['url'] = source['url'].astype(str).str.strip()
    source['label'] = normalize_labels(source['label'])
    datasets.append(source[['url', 'label']])

df = pd.concat(datasets, ignore_index=True)
df = df[df['url'] != ''].drop_duplicates(subset=['url', 'label'])
priority = {'safe': 0, 'suspicious': 1, 'phishing': 2}
df['_priority'] = df['label'].map(priority)
df = (df.sort_values('_priority')
        .drop_duplicates(subset=['url'], keep='last')
        .drop(columns='_priority')
        .reset_index(drop=True))
class_counts = df['label'].value_counts()
missing_labels = set(LABEL_ORDER) - set(class_counts.index)
if missing_labels:
    raise ValueError(f'Training data is missing required classes: {sorted(missing_labels)}')
if (class_counts < 2).any():
    raise ValueError('At least two URLs per class are required for a stratified split.')

print("Rows:", len(df), "| class counts:", class_counts.to_dict())

df['features'] = df['url'].apply(extract_features)

X_train, X_test, y_train, y_test = train_test_split(
    df['features'], df['label'],
    test_size=0.2, random_state=42, stratify=df['label']
)

pipeline = Pipeline([
    ('tfidf', TfidfVectorizer(ngram_range=(1, 2), max_features=5000)),
    ('clf', RandomForestClassifier(
        n_estimators=200, random_state=42, n_jobs=-1,
        class_weight='balanced'
    )),
])

print("Training…")
pipeline.fit(X_train, y_train)

preds = pipeline.predict(X_test)
print("Accuracy:", round(accuracy_score(y_test, preds), 4))
print(classification_report(
    y_test, preds, labels=LABEL_ORDER, digits=4, zero_division=0
))

pipeline.fit(df['features'], df['label'])
joblib.dump(pipeline, OUT)
print("Saved:", OUT)