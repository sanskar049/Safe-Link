SafeLink Final AI/Result Fix

Replace these files in the existing project:
- app.py -> project root
- ai_model.py -> project root
- templates/index.html -> templates/index.html
- templates/ai_result_card.html -> templates/ai_result_card.html

Fixes:
1. Official domains use a separate final assessment from raw ML output.
2. Raw model probabilities are explicitly labeled as raw model probabilities.
3. If raw ML says Phishing but the verified official domain is legitimate, the UI explains the difference instead of showing contradictory values.
4. Analysis Method is populated even when the webpage returns 5xx/403.
5. Unresolved domains are shown as Domain Does Not Exist with Risk N/A and AI Not Assessable (unless Google Safe Browsing confirms a known threat).
6. Overall confidence is clearly labeled as confidence in the security assessment, not the raw ML probability.

Important: after replacing files, push to GitHub and confirm Render deploys the new commit. Hard-refresh the browser (Ctrl+F5).
