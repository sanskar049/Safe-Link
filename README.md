# SafeLink - Advanced Website & URL Risk Analyzer

Two-layer detection:
- URL/DNS/heuristic analysis
- Public HTML content analysis for gambling/betting, e-commerce, payment signals, aggressive discounts, basic policy/contact signals, and brand impersonation.

A valid HTTPS domain is not automatically safe. Content signals are heuristics, not proof of fraud. A site that accepts orders and never delivers cannot be reliably proven fraudulent from URL/page content alone; reputation, reports and domain history improve that assessment.

Run:
pip install -r requirements.txt
python app.py
Open http://127.0.0.1:5000
