import os
import sys

from streamlit.web import cli as stcli


def _bundle_root():
    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        return sys._MEIPASS
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def main():
    app_path = os.path.join(_bundle_root(), "app.py")
    sys.argv = [
        "streamlit",
        "run",
        app_path,
        "--server.headless=false",
        "--browser.gatherUsageStats=false",
    ]
    raise SystemExit(stcli.main())


if __name__ == "__main__":
    main()
