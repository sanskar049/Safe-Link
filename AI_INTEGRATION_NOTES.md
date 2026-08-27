# SafeLink AI integration

The trained Random Forest model is in `models/phishing_model_compressed.joblib`.

Training/test facts:
- 270,000 balanced URLs
- 25 URL features
- 3 classes: Legitimate, Suspicious, Phishing
- 54,000 unseen test URLs
- Accuracy: 94.65%
- Compressed model: 87.57 MB

`ai_model.py` reproduces the exact 25-feature order used during training.

Important:
- Existing invalid-URL and DNS/domain-not-found logic is not replaced.
- For unresolved domains, AI should remain `Not assessable` and the existing score should remain `N/A`.
- For resolved domains, the intended final-score blend is 55% existing SafeLink score + 45% AI risk.
- The helper `apply_ai_layer(...)` was added to `app.py`; call it at the point where the existing result dictionary and numeric score are finalized, after domain resolution.
- Add `{% include "ai_result_card.html" %}` to `templates/index.html` where the result section is rendered.
- Add `<link rel="stylesheet" href="{{ url_for('static', filename='ai_card.css') }}">` in the page head.
