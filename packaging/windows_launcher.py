import os
import sys
import traceback
from pathlib import Path

from streamlit.web import cli


def _bundle_root() -> str:
    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        return sys._MEIPASS
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _log_path() -> Path:
    root = Path(os.environ.get("LOCALAPPDATA", Path.home()))
    path = root / "Nusantara AI Device Guardian"
    path.mkdir(parents=True, exist_ok=True)
    return path / "launcher.log"


def _write_error(exc: BaseException) -> None:
    try:
        with _log_path().open("a", encoding="utf-8") as handle:
            handle.write("\n=== Launcher failure ===\n")
            traceback.print_exception(exc, file=handle)
    except Exception:
        pass


def main() -> None:
    app_path = os.path.abspath(os.path.join(_bundle_root(), "app.py"))
    if not os.path.isfile(app_path):
        error = FileNotFoundError(f"Bundled Streamlit app not found: {app_path}")
        _write_error(error)
        raise error

    flag_options = {
        "server.headless": False,
        "server.address": "127.0.0.1",
        "server.port": 8501,
        "browser.serverAddress": "127.0.0.1",
        "browser.gatherUsageStats": False,
        "server.fileWatcherType": "none",
        "global.developmentMode": False,
    }

    try:
        # Follow Streamlit's own streamlit run path for version compatibility.
        cli._main_run(
            app_path,
            args=[],
            flag_options=flag_options,
        )
    except BaseException as exc:
        _write_error(exc)
        raise


if __name__ == "__main__":
    main()
