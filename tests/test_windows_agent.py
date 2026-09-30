import os
import pytest

from src.security.windows_agent import collect_windows_telemetry

def test_windows_agent_is_guarded_on_non_windows():
    if os.name != "nt":
        with pytest.raises(RuntimeError):
            collect_windows_telemetry()
