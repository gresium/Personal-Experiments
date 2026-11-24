"""
Microsoft Forms Export-Bot
Laedt die Antworten deines eigenen Formulars als Excel-Datei herunter.

Setup (einmalig):
    pip install playwright
    playwright install chromium

Benutzung:
    python forms_export.py "<URL deines Formulars (Antworten-Seite)>"

Beim ersten Start oeffnet sich ein Browser. Logge dich dort selbst bei Microsoft ein.
Die Anmeldung wird im Ordner ./browser_profile gespeichert, danach laeuft der Bot
ohne erneutes Login. Dein Passwort steht nirgends im Code.
"""
import re
import sys
from datetime import datetime
from pathlib import Path

from playwright.sync_api import sync_playwright, TimeoutError as PWTimeout

PROFILE_DIR = Path(__file__).parent / "browser_profile"
OUT_DIR = Path(__file__).parent / "exports"

# Button-Texte (Deutsch und Englisch)
RESPONSES_TAB = re.compile(r"^(Antworten|Responses)", re.I)
OPEN_IN_EXCEL = re.compile(r"(In Excel [oö]ffnen|Open in Excel)", re.I)


def main(form_url: str) -> None:
    OUT_DIR.mkdir(exist_ok=True)
    with sync_playwright() as p:
        ctx = p.chromium.launch_persistent_context(
            str(PROFILE_DIR), headless=False, accept_downloads=True
        )
        page = ctx.pages[0] if ctx.pages else ctx.new_page()
        page.goto(form_url)

        # Auf Login warten, falls noetig (bis zu 3 Minuten)
        print("Falls ein Login erscheint: bitte im Browser anmelden ...")
        try:
            page.wait_for_url(re.compile(r"forms\.(cloud\.)?(microsoft|office)"), timeout=180_000)
        except PWTimeout:
            sys.exit("Login nicht abgeschlossen.")

        # Zum Tab "Antworten"
        try:
            page.get_by_role("tab", name=RESPONSES_TAB).click(timeout=15_000)
        except PWTimeout:
            pass  # evtl. schon auf der Antworten-Seite

        # Excel-Download ausloesen
        with page.expect_download(timeout=60_000) as dl:
            page.get_by_role("button", name=OPEN_IN_EXCEL).click()
        download = dl.value

        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        target = OUT_DIR / f"forms_antworten_{stamp}.xlsx"
        download.save_as(str(target))
        print(f"Gespeichert: {target}")
        ctx.close()


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit('Benutzung: python forms_export.py "<Formular-URL>"')
    main(sys.argv[1])
