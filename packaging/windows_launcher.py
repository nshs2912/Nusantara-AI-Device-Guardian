import os
import sys

from streamlit.web import bootstrap


def _bundle_root():
    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        return sys._MEIPASS
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def main():
    app_path = os.path.abspath(os.path.join(_bundle_root(), "app.py"))
    if not os.path.isfile(app_path):
        raise FileNotFoundError(f"Bundled Streamlit app not found: {app_path}")

    flag_options = {
        "server.headless": False,
        "server.address": "127.0.0.1",
        "server.port": 8501,
        "browser.gatherUsageStats": False,
        "server.fileWatcherType": "none",
        "global.developmentMode": False,
    }

    bootstrap.run(
        app_path,
        command_line="Nusantara-AI-Device-Guardian",
        args=[],
        flag_options=flag_options,
    )


if __name__ == "__main__":
    main()
