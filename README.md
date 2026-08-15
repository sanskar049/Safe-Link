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


## Final UI update
The homepage feature section now reflects the current SafeLink architecture:
URL/domain analysis, webpage/category analysis, brand impersonation detection, Google Safe Browsing, multi-layer risk scoring, and scan history/reports.

Result labels are user-friendly: Website Address, Server Response, and Webpage. Technical HTTP/DNS values remain available under Technical details. The Why this result explanations are emphasized for visibility.


## Browser-rendered content analysis
SafeLink now uses a multi-step content acquisition strategy:
1. Direct HTTP analysis.
2. Chromium/Playwright rendering for JavaScript-heavy or 403/blocked pages.
3. URL/domain/reputation fallback when a site blocks both methods.

This improves coverage of modern SPA/JavaScript websites, but no scanner can guarantee access to every website because some sites intentionally block automated traffic, require login, use CAPTCHAs, or restrict regions.
