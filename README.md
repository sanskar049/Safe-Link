# SafeLink - Advanced Website & URL Risk Analyzer

SafeLink combines URL/DNS heuristics, webpage analysis, category detection, brand checks and Google Safe Browsing API v5.

## Google Safe Browsing setup
The app reads the API key from the environment variable:
`GOOGLE_SAFE_BROWSING_API_KEY`

Never commit the key to GitHub.

For Render:
1. Open Safe-Link → Environment.
2. Add `GOOGLE_SAFE_BROWSING_API_KEY`.
3. Paste your Google API key as the value.
4. Save and redeploy.

Google's v5 `urls:search` endpoint checks submitted URLs against known unsafe-resource lists. An empty `threats` result means Google returned no known threat for that URL; it is not a guarantee that the website is safe.

Safe Browsing is for non-commercial use. This is an educational, non-commercial prototype.


## Brand impersonation false-positive fix
SafeLink no longer flags a brand just because its name appears somewhere on a page. It now requires stronger context such as a suspicious brand-containing domain, login/account/payment/verification language, or a suspicious title/context combination. Official brand domains are excluded.
