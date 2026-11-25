# main.py - Data Sentinel Vantage V2 scan worker: the worker's report, settings, serve, exit
# (worker core standard 2026-48-37 §4, §15, §18)
import os
import sys

from ds_scan import (REQUIRED_SETTINGS, SECRET_FILES, SETTINGS_SPEC, STANDARD_EDITION, VERSION, Settings, lib_version, scan_loaded,
                     scan_reads_from_env, serve, startup_report)


def main():
    # what the container was given and what the worker can do, written before the settings are checked
    title = {"worker": "scan", "version": VERSION, "connect": lib_version(), "python": sys.version.split()[0]}
    settings = startup_report(title, SETTINGS_SPEC, SECRET_FILES, Settings, required=REQUIRED_SETTINGS, reads_fn=scan_reads_from_env,
                              loaded_fn=scan_loaded, standard=STANDARD_EDITION)
    if settings is None:
        sys.stdout.flush()
        os._exit(2)
    code = serve(settings)
    sys.stdout.flush()
    sys.stderr.flush()
    os._exit(code)


if __name__ == "__main__":
    main()
