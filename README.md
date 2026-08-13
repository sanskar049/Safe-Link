# SafeLink - Advanced Website & URL Risk Analyzer

Two-layer detection:
- URL/DNS/heuristic analysis
- Public HTML content analysis for gambling/betting, fantasy sports and paid contests, e-commerce, payment signals, aggressive discounts, basic policy/contact signals, and brand impersonation.

Fantasy sports is intentionally separated from gambling so the scanner can report categories more accurately instead of labeling every fantasy-sports website as malicious.

Important:
- Category detection is not proof that a website is illegal, fraudulent, or malicious.
- A valid HTTPS domain is not automatically safe.
- Content signals are heuristics, not proof of fraud.
- A site that accepts orders and never delivers cannot be reliably proven fraudulent from URL/page content alone; reputation, reports and domain history improve that assessment.
- Modern JavaScript-only content may not be visible to this basic HTTP/HTML analyzer.

Run:
pip install -r requirements.txt
python app.py
Open http://127.0.0.1:5000
