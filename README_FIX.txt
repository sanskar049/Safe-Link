SafeLink AI Card Fix

Purpose: restore the AI Risk Analysis card on the result page.

Files: app.py, templates/index.html, templates/ai_result_card.html, static/ai_card.css.

Main fix: app.py now guarantees an explicit result["ai"] before rendering a valid scan, with a fallback prediction only if the model layer itself is unavailable. The template also no longer silently hides the card when result.ai is missing.

After replacing these files in the repository, commit and push to main. Render should auto-deploy the new commit.
