# main.py - Data Sentinel Vantage V2 scan worker: start-up report, settings, serve, exit
# (worker core standard 2026-48-11 §4, §15; architect note 2026-48-20)
import os
import sys

from ds_scan import SECRET_FILES, SETTINGS_SPEC, VERSION, Settings, lib_version, startup_report, serve


def main():
    # what the container was given, written before the settings are checked; then settings_ok or settings_invalid
    title = {"worker": "scan", "version": VERSION, "connect": lib_version(), "python": sys.version.split()[0]}
    settings = startup_report(title, SETTINGS_SPEC, SECRET_FILES, Settings)
    if settings is None:
        sys.stdout.flush()
        os._exit(2)
    code = serve(settings)
    sys.stdout.flush()
    sys.stderr.flush()
    os._exit(code)


if __name__ == "__main__":
    main()
