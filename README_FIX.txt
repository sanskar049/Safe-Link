SafeLink Final AI Probability + Official Domain Fix

Files to replace in the existing project:
- app.py
- ai_model.py
- templates/index.html
- templates/ai_result_card.html
- models/learned_legitimate_hosts.json

Do NOT replace the trained model file; the existing phishing_model_compressed.joblib is reused.

What this fixes:
1. If final AI prediction is Legitimate, the displayed probability now also has Legitimate as the highest percentage.
2. Official/trusted domains are handled as domain evidence instead of showing contradictory "Legitimate" + "99% Phishing" output.
3. Added trusted first-party roots for groww.in, hotstar.com and indianbank.bank.in, including their subdomains.
4. Analysis Method is always shown as: AI + Multi-Signal Analysis.
5. Raw model probabilities are not shown in the UI.
6. Non-trusted URLs still use the trained model probabilities normally, so phishing/suspicious predictions remain consistent with their probabilities.
