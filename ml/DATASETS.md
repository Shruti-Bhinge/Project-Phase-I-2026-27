# Training data

The text classifier is trained with two local CSV files:

- `email_dataset.csv` contains the project's examples. Numeric labels `0` and `1` mean `safe` and `phishing`; text labels may be `safe`, `suspicious`, or `phishing` (`fake` is accepted as `phishing`).
- `sms_spam_collection.csv` is a sanitized copy of the SMS Spam Collection v.1, containing 5,574 messages. Its `ham` messages are labeled `safe`; its `spam` messages are labeled `suspicious`, since spam is not always phishing. Phone numbers, email addresses, and URLs are masked before training.
- `smishing_dataset.csv` contains 34,716 unique sanitized texts from a public, labeled smishing corpus. Original texts and available translations are used; phone numbers, email addresses, and URLs are masked before training.
- `public_url_samples.csv` contains validated URLs extracted from those two public text corpora. UCI ham links are labeled `safe`, UCI spam links `suspicious`, and smishing-corpus links `phishing`.

The SMS Spam Collection was created by Tiago A. Almeida and José M. Gómez Hidalgo with contributions from the NUS SMS Corpus. The original dataset is available from the [UCI Machine Learning Repository](https://archive.ics.uci.edu/dataset/228/sms+spam+collection). Its included readme requests citation of:

> Almeida, T.A., Gómez Hidalgo, J.M., and Yamakami, A. “Contributions to the Study of SMS Spam Filtering: New Collection and Results.” Proceedings of the 2011 ACM Symposium on Document Engineering, 2011.

The original corpus is provided for free subject to its authors' copyright and use-at-your-own-risk terms. The sanitized copy in this project is derived from that corpus.

The smishing texts come from the [Smishing Dataset IMC 2025](https://github.com/reportsmishing/Smishing-Dataset-IMC25), released under CC BY 4.0. The project uses its `text` and `translation` columns, and removes phone numbers, email addresses, and URLs. Cite:

> Agarwal, S., Papasavva, A., Suarez-Tangil, G., and Vasek, M. “Fishing for Smishing: Understanding SMS Phishing Infrastructure and Strategies by Mining Public User Reports.” Proceedings of the 2025 ACM Internet Measurement Conference, 2025.

Both classifiers use the three labels `safe`, `suspicious`, and `phishing`. Here, `suspicious` means unsolicited spam or a link reported in spam messages; it is not proof of fraud. The project's original binary examples retain their existing label meanings (`0` safe, `1` phishing).

Train both models from this directory with:

```powershell
.\venv\Scripts\python.exe .\train_text_model.py
.\venv\Scripts\python.exe .\train_url_model.py
```

After training, restart `ml_server.py` so it loads the new models. The URL classifier's dataset remains much smaller than the text corpus, so treat its verdicts as a risk estimate rather than a guarantee.
