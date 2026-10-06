SafeLink Final Fix v2

Fixes:
1. Restores the blank ANALYSIS METHOD box with: AI + Multi-Signal Analysis.
2. Keeps the AI Risk Analysis card visible.
3. Updates scikit-learn to 1.8.0 to match the trained model and remove the InconsistentVersionWarning.

Replace:
- app.py
- templates/index.html
- templates/ai_result_card.html
- static/ai_card.css
- requirements.txt

Then:
git add .
git commit -m "Fix analysis method and sklearn version"
git push origin main
