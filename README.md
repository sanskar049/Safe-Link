# SafeLink — Final Render Version

SafeLink is a BTech project for explainable website and URL risk analysis.

## Included fixes
- Invalid input is shown as a small inline error below the scanner instead of a separate result page.
- User-friendly labels: DOMAIN STATUS, SERVER RESPONSE and WEBPAGE.
- Human-readable content-analysis messages; internal terms such as `URL/domain fallback` are hidden.
- HTTP 404 deep links can fall back to the site's homepage for content analysis when the homepage is publicly accessible.
- HTTP 403/429 and server errors are reported as access/server limitations, not automatically treated as proof of a scam.
- Brand impersonation detection is context-aware to reduce false positives from ordinary social-media links/mentions.
- Google Safe Browsing is displayed in a dedicated result card.
- Why this result? explanations are emphasized in bold.
- History and CSV export routes are included.
- Render deployment does not require Playwright/Chromium installation, so browser-package installation cannot break deployment. The analyzer uses robust HTTP/DNS analysis and clearly reports when a site blocks automated access.

## Render
Use the included `render.yaml`. Add `GOOGLE_SAFE_BROWSING_API_KEY` in Render Environment if Google Safe Browsing verification is desired.
