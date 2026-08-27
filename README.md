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
- Risk scoring is based on security signals—not website category alone.
- JavaScript-heavy pages use a short Chromium fallback when the initial HTML has no readable content.
- Domain Status, Server Response and Webpage appear once each in the result interface.
- Local, private and reserved network addresses are blocked so the public scanner cannot be used to probe internal services.
- Every HTTP redirect is validated before SafeLink follows it.

## Render
Use the included `render.yaml`. It installs Chromium for the JavaScript-page fallback. Add `GOOGLE_SAFE_BROWSING_API_KEY` in Render Environment if Google Safe Browsing verification is desired.
