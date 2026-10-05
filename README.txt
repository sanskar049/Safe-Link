SafeLink retrained AI package

Replace the existing model with:
models/phishing_model_compressed.joblib

Replace ai_model.py with this package's version.

The model was retrained from the recovered malicious_phish.csv using the exact 25
features and the same 90,000-per-class balanced sampling used in the original notebook.
The model was reduced from 300 trees to 100 trees to reduce deployment memory.

The AI layer also has exact-host evidence handling for legitimate domains. This is
intentional because the 25 structural URL features alone cannot distinguish a real
brand domain such as www.google.com from a phishing hostname that merely contains
the word google.

Do not describe the exact-host layer as proof of safety. It is an additional evidence
signal that is combined with the rest of the SafeLink analysis.
