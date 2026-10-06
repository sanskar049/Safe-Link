SafeLink – Groww + Analysis Method Fix

Changes:
1. Adds groww.in and www.groww.in to verified official domains.
2. Official Groww domains are treated as verified official identity, so normal
   payment/login content does not unnecessarily push the risk score high.
3. Adds analysis_method to the scan result so the UI no longer shows a blank
   ANALYSIS METHOD field.
   - Resolved domains: AI + Multi-Signal Analysis
   - Unresolved domains: Domain Resolution Only
4. No model retraining is required.

Copy these files into the project and deploy normally.
