# main.py - Data Sentinel Vantage V2 scan worker: settings, serve, exit (worker core standard 2026-48-11 §4, §15)
import os
import sys
import time

from ds_scan import Settings, SettingsError, serve


def main():
    try:
        settings = Settings()
    except SettingsError as e:
        # one line that names the variable, in the log's format; exit code 2 before anything is served
        stamp = time.strftime("%Y-%m-%d %H:%M:%S")
        sys.stdout.write("%s|ERROR|settings_invalid variable=%s problem=%s\n" % (stamp, e.variable, e.problem.replace(" ", "_")))
        sys.stdout.flush()
        os._exit(2)
    code = serve(settings)
    sys.stdout.flush()
    sys.stderr.flush()
    os._exit(code)


if __name__ == "__main__":
    main()
