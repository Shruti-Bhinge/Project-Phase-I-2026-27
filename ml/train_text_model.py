"""
Trains the email/message phishing classifier.
Input :  email_dataset.csv (0 = safe, 1 = phishing; text labels also accepted)
         sms_spam_collection.csv (safe and suspicious examples)
         smishing_dataset.csv (public labeled phishing examples)
Output:  text_model.pkl
Run   :  python train_text_model.py
"""
import os
import pandas as pd
import joblib
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.metrics import accuracy_score, classification_report

BASE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(BASE, 'email_dataset.csv')
OUT  = os.path.join(BASE, 'text_model.pkl')


def normalize_labels(labels):
    values = labels.astype(str).str.strip().str.lower()
    numeric = set(values.unique())

    if '2' in numeric:
        mapping = {'0': 'safe', '1': 'suspicious', '2': 'phishing'}
    else:
        mapping = {'0': 'safe', '1': 'phishing'}
    mapping.update({
        'ham': 'safe',
        'safe': 'safe',
        'spam': 'suspicious',
        'suspicious': 'suspicious',
        'phish': 'phishing',
        'phishing': 'phishing',
        'fake': 'phishing',
    })

    normalized = values.map(mapping)
    if normalized.isna().any():
        invalid = sorted(values[normalized.isna()].unique())
        raise ValueError(f'Unsupported label(s) in training data: {invalid}')
    return normalized


print("Loading", DATA)
sms_data = os.path.join(BASE, 'sms_spam_collection.csv')
smishing_data = os.path.join(BASE, 'smishing_dataset.csv')
datasets = []
for path in (DATA, sms_data, smishing_data):
    source = pd.read_csv(path)
    source = source.dropna(subset=['text', 'label']).copy()
    source['text'] = source['text'].astype(str).str.strip()
    source['label'] = normalize_labels(source['label'])
    datasets.append(source[['text', 'label']])

df = pd.concat(datasets, ignore_index=True)
df = df[df['text'] != '']
priority = {'safe': 0, 'suspicious': 1, 'phishing': 2}
df['_priority'] = df['label'].map(priority)
df = (df.sort_values('_priority')
        .drop_duplicates(subset=['text'], keep='last')
        .drop(columns='_priority')
        .reset_index(drop=True))
class_counts = df['label'].value_counts()
required_labels = {'safe', 'suspicious', 'phishing'}
missing_labels = required_labels - set(class_counts.index)
if missing_labels:
    raise ValueError(f'Training data is missing required classes: {sorted(missing_labels)}')
if (class_counts < 2).any():
    raise ValueError('At least two examples per class are required for a stratified split.')

print("Rows:", len(df), "| class counts:", class_counts.to_dict())

X_train, X_test, y_train, y_test = train_test_split(
    df['text'], df['label'],
    test_size=0.2, random_state=42, stratify=df['label']
)

pipeline = Pipeline([
    ('tfidf', TfidfVectorizer(
        lowercase=True,
        stop_words='english',
        ngram_range=(1, 2),
        max_features=10000,
        min_df=2,
    )),
    ('clf', LogisticRegression(max_iter=1000, class_weight='balanced')),
])

print("Training…")
pipeline.fit(X_train, y_train)

preds = pipeline.predict(X_test)
print("Accuracy:", round(accuracy_score(y_test, preds), 4))
print(classification_report(
    y_test, preds, labels=['safe', 'suspicious', 'phishing'],
    digits=4, zero_division=0
))

cv = cross_val_score(
    pipeline, df['text'], df['label'], cv=5, scoring='f1_macro'
)
print("Cross-val F1:", round(cv.mean(), 4), "±", round(cv.std(), 4))

pipeline.fit(df['text'], df['label'])
joblib.dump(pipeline, OUT)
print("Saved:", OUT)