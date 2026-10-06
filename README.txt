SafeLink AI Final Consistency Fix

Purpose:
- The AI prediction and the three displayed percentages now always describe the SAME final assessment.
- If final AI prediction is Legitimate, Legitimate will be the highest displayed percentage.
- No raw model probability/confidence is shown in the normal UI.
- Official domains such as Flipkart and Indian Bank use verified-domain evidence to adjust the final assessment.
- The trained model itself is not retrained or modified.

Example:
Final AI Prediction: Legitimate
Legitimate: 82.1%
Suspicious: 10.1%
Phishing: 7.8%

The exact percentages depend on the model output and verified security evidence.

Files:
- app.py
- ai_model.py
- ai_result_card.html
- index.html
