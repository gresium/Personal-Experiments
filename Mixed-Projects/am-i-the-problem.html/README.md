
# Am I the Problem? (HTML)

A single-file, interactive **self-audit quiz** that helps you sanity-check whether your conflicts are mostly caused by other people, by you, or by messy context (because reality loves being inconvenient).

## What it does
- Presents an **8-question** multiple-choice quiz
- Tracks completion with a **live progress bar** (answered / total)
- Color-codes selections by category:
  - **It’s them** (external issue)
  - **It’s me** (self pattern)
  - **It’s both / context** (mixed)
- Unlocks the **“See my results”** button only when all questions are answered
- Generates results with:
  - A clear verdict card (3 outcomes)
  - Category breakdown bars + percentages
  - “What to actually do with this” insights
- Includes **Start Over** reset flow

## Result categories
Your answers are tallied into:
- **Mostly them** → environment/people likely the main source  
- **Mostly me** → you might be the repeating pattern  
- **Mixed** → both sides and context matter

## Tech
- Pure **HTML + CSS + JavaScript** (no frameworks)
- Styled UI (dark theme, animations, custom fonts)
- Runs fully client-side (no backend)

## How to run
1. Download or clone the repo  
2. Open the file in your browser:

- macOS Finder: double-click it  
- Or terminal:
  ```bash
  open am-i-the-problem.html

Notes
It’s fully client-side: nothing gets sent anywhere.
If you want to add storage later (localStorage), it’s a straightforward upgrade.

*** Developed by Gresa Hisa (@gresium)
*** GitHub: https://github.com/gresium
