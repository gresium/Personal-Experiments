# Forms Export Bot

Downloads the responses of **your own** Microsoft Forms form as an Excel file (`.xlsx`).

## What it does

1. Opens your form in a browser (Chromium via Playwright).
2. Waits for you to sign in to Microsoft (only needed the first time).
3. Goes to the **Responses** tab and clicks **Open in Excel**.
4. Saves the file to `exports/forms_antworten_<date>_<time>.xlsx`.

## Requirements

- Python 3.9 or newer
- A Microsoft Forms form that **you created** (it appears under "My forms" at https://forms.cloud.microsoft)

## Setup (once)

```
python -m pip install playwright
python -m playwright install chromium
```

Type `playwright` with a "w". A similarly named package, `playright`, is not the same thing.

## Usage

```
python forms_export.py "<form link>"
```

Use the link from the address bar when you have your form open on the **Responses** tab (or the edit view).

Do **not** use a link containing `ResponsePage.aspx`. That is the page people use to fill in the form, and it has no Responses tab or export button, so the script fails there.

The first run opens a browser window. Sign in to Microsoft yourself. The login is kept in the `browser_profile/` folder, so later runs need no login. Your password is never stored in the script.

## Files

| Path | Purpose |
| --- | --- |
| `forms_export.py` | The script |
| `browser_profile/` | Saved browser login (keep private, do not share or upload) |
| `exports/` | Downloaded Excel files |

## Limits

- Works only for forms you own or can open on the Responses tab. It cannot read responses or data that are not yours, and it is not meant to.
- Microsoft has no official API for this, so the script clicks buttons by their label (German and English). If Microsoft renames or moves them, the script may stop working and needs a small update.
- Run it at a normal pace. Repeated automated logins can get a Microsoft account flagged.

## Troubleshooting

| Problem | Fix |
| --- | --- |
| `playwright` command not found | Use `python -m playwright ...` |
| Timeout at "Responses" or "Open in Excel" | Wrong link (fill-in page) or you are not the owner of the form |
| Login window never finishes | Sign in within 3 minutes, then run the script again |
| `pip install install ...` error | Typo: write `python -m pip install --upgrade pip` |
