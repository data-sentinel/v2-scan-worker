# ds_scan.py - Data Sentinel Vantage V2 scan worker
#
# Reads the objects discovery found as byte streams. For each file it takes the SHA-256 of the raw
# bytes, skips what the installation already knows, reads the rest into working files for classify,
# and hands in what it found through sentinel.sys_post_scan_batch. Tables are read whole on every run.
#
# Built to: the worker core standard 2026-48-11, architect note 2026-48-10 (rulings and the first
# build), architect directive 2026-48-09 (what scan hands the database), ds_connect_lib 2026.47.4.
#
# Layout of this file
#    1  versions, settings, logging, catalogs of reasons and health codes
#    2  text rules
#    3  limits, the temporary-disk budget, spooling and hashing, the source of an object
#    4  what a file is: sniffing from the bytes
#    5  working files for classify
#    6  readers: text, csv, json, xml, html, pdf, docx, pptx, xlsx, xls, zip
#    7  the pass for one object: a file, an archive's entry, a table
#    8  the database
#    9  the worker: check-in, heartbeat, claiming, the queue, renewals, hand-ins, stopping
#   10  the endpoints and serve()
#
#__version__ = '2026.48.5'    # labels from docMetadata/LabelInfo.xml; a PDF's XMP and MSIP labels, and meta.pdf (version,
#                              encryption, permissions, form, signatures); an HTML page's title and meta tags (note 2026-48-48)
#__version__ = '2026.48.4'    # the worker's report as a document, sent at check-in (v_report) and again when it changes; reads
#                              with why, loaded readers (standard 2026-48-37); a known container with parts_unread opened again
#                              in a run with classify (note 2026-48-39); document properties in meta.doc, meta.labels and
#                              meta.custom; customer files opened with O_NOATIME (note 2026-48-45); US spelling (note 2026-48-44)
#__version__ = '2026.48.3'    # against db 2026-48-02 as built (note 2026-48-17): the {held, known} lookup, became_skipped_parts,
#                              10,000 objects and 50,000 parts a call, part and meta limits; folders checked again until usable
#                              (note 2026-48-22); the shared health sentences (note 2026-48-23); deploy/ds_scan_worker.example.yml
#__version__ = '2026.48.2'    # the start-up report (architect note 2026-48-20): what the container was given, before the
#                              settings are checked; settings_invalid names the path it looked at
#__version__ = '2026.48.1'    # first V2 build: directory and postgres through ds_connect_lib; txt, csv, json, xml, html,
#                              pdf (behind one function), docx, pptx, xlsx, xls, zip at any depth; fingerprints and the
#                              known-content skip; parts; working files; the standard's driver

import asyncio
import base64
import codecs
import collections
import csv
import datetime as dt
import hashlib
import io
import json
import logging
import math
import mmap
import os
import random
import re
import shutil
import stat
import sys
import threading
import time
import unicodedata
import uuid
import zipfile
import zlib
from concurrent.futures import ThreadPoolExecutor
from functools import lru_cache

import ds_connect_lib

# ===========================================================================
# 1. VERSIONS, SETTINGS, LOGGING, CATALOGS
# ===========================================================================
VERSION = "2026.48.5"
WORKER_TYPE = "scan"
STAGE = "scan"
STANDARD = "worker-core-standard 2026-48-37"
STANDARD_EDITION = "2026-48-37"

# what this worker can read, by data source type; the capabilities are these, less any whose driver
# the image lacks (ds_connect_lib.types()) or, for directory, when no file roots are set
SCAN_SOURCE_TYPES = ("directory", "postgres")

# timers (seconds). The standard's numbers; the tests shorten them by setting these attributes
HEARTBEAT_SEC = 30.0
RENEW_SEC = 30.0
BATCH_OBJECTS = 10000              # a hand-in at 10,000 objects (or 50,000 parts) or ...
BATCH_SEC = 300.0                  # ... every five minutes, whichever comes first
STOP_LIMIT_SEC = 10.0              # scan's stop limit (architect note 2026-48-10 §3)
SIGTERM_LIMIT_SEC = 30.0           # the standard's SIGTERM allowance
RECONNECT_MAX_SEC = 30.0
CONTRACT_RECHECK_SEC = 60.0
PAGE_LIMIT = 500                   # objects read from the queue per call
PARTS_PER_CALL = 50000             # parts in all in one call (db 2026-48-02); an object's parts beyond go over several calls (parts_final)
INNER_PATH_MAX = 1000              # a part's inner_path, characters (db 2026-48-02)
PART_NAME_MAX = 400                # a part's name, characters (db 2026-48-02)
META_DB_TYPES_MAX = 8000           # bytes of a table's meta.db_types before the list is cut
TABLE_PART_ROWS = 50000            # rows per working-file part
TEXT_PART_CHARS = 64 * 1024 * 1024 # a text part is also cut at this many characters
TABLE_FETCH_ROWS = 5000            # rows per fetch on a server-side cursor
CHECKPOINT_TOUCH_BYTES = 64 * 1024 * 1024   # an object this large is named in a checkpoint at once
WORK_SPACE_RECHECK_SEC = 15.0
STALE_RUN_FOLDER_DAYS = 7
CHUNK = 4 * 1024 * 1024
HEAD = 8192

_MB = 1024 * 1024

# the functions this worker calls, with the parameters it sends; optional ones are used when present
CONTRACT = {
    "sys_post_worker_checkin": ("v_worker_type", "v_worker_name", "v_worker_version", "v_address", "v_port", "v_capabilities", "v_report"),
    "sys_post_worker_report": ("v_worker_id", "v_report"),
    "sys_post_worker_heartbeat": ("v_worker_id", "v_status", "v_health"),
    "sys_get_partitions_held": ("v_worker_id",),
    "sys_post_partition_claim_next": ("v_worker_id",),
    "sys_post_partition_renew": ("v_run_id", "v_stage", "v_partition_id", "v_worker_id", "v_attempt", "v_progress", "v_checkpoint"),
    "sys_post_partition_complete": ("v_run_id", "v_stage", "v_partition_id", "v_worker_id", "v_attempt", "v_summary"),
    "sys_post_partition_release": ("v_run_id", "v_stage", "v_partition_id", "v_worker_id", "v_attempt", "v_outcome", "v_code",
                                   "v_params", "v_text"),
    "sys_get_partition_objects": ("v_run_id", "v_stage", "v_partition_id", "v_worker_id", "v_attempt", "v_after", "v_limit"),
    "sys_get_data_source_connection": ("v_data_source_id",),
    "sys_post_scan_batch": ("v_run_id", "v_partition_id", "v_worker_id", "v_attempt", "v_objects"),
    "sys_get_known_content": ("v_run_id", "v_partition_id", "v_worker_id", "v_attempt", "v_sha256"),
}
CONTRACT_OPTIONAL = ("sys_get_known_content", "sys_post_worker_report")
# parameters looked for at the contract check and sent only when the function takes them (standard 2026-48-37 §5, §6)
CONTRACT_OPTIONAL_PARAMS = {"sys_post_worker_checkin": ("v_report",)}

# the SQL type of every parameter sent, so each call is unambiguous
PARAM_TYPES = {
    "v_worker_type": "text", "v_worker_name": "text", "v_worker_version": "text", "v_address": "text", "v_port": "integer",
    "v_capabilities": "jsonb", "v_worker_id": "bigint", "v_status": "text", "v_health": "jsonb", "v_run_id": "bigint",
    "v_stage": "text", "v_partition_id": "integer", "v_attempt": "integer", "v_progress": "jsonb", "v_checkpoint": "jsonb",
    "v_summary": "jsonb", "v_outcome": "text", "v_code": "text", "v_params": "jsonb", "v_text": "text", "v_after": "bigint",
    "v_limit": "integer", "v_data_source_id": "bigint", "v_objects": "jsonb", "v_sha256": "text[]", "v_report": "jsonb",
}


class SettingsError(Exception):
    """A setting that can't be used: the process stops before it serves anything (exit code 2)."""

    def __init__(self, variable, problem, path=None):
        super().__init__(variable + ": " + problem)
        self.variable = variable
        self.problem = problem
        self.path = path            # the file or folder looked at, when the problem is one


def _read_secret_file(path):
    """A secret file's value: a JSON object keyed by the secret's own name (the platform's convention),
    or the file's text as it is."""
    with open(path, "r", encoding="utf-8") as fh:
        text = fh.read()
    name = os.path.basename(path)
    try:
        parsed = json.loads(text)
        if isinstance(parsed, dict) and name in parsed:
            return str(parsed[name])
    except (ValueError, TypeError):
        pass
    return text.rstrip("\r\n")


class Settings(object):
    """Every setting, read once at start from the environment. A value that can't be used raises
    SettingsError naming the variable."""

    def __init__(self, env=None):
        env = os.environ if env is None else env
        self._env = env

        self.service = (env.get("DS_SERVICE") or "").strip()
        if not self.service:
            raise SettingsError("DS_SERVICE", "is required")
        if not re.match(r"^[A-Za-z0-9_.-]{1,60}$", self.service):
            raise SettingsError("DS_SERVICE", "must be 1 to 60 letters, digits, dots, dashes or underscores")
        self.port = self._int("DS_SERVICE_PORT", 5540, 1, 65535)
        self.external_host = (env.get("DS_SERVICE_EXTERNAL_HOST") or self.service).strip()
        self.external_port = self._int("DS_SERVICE_EXTERNAL_PORT", self.port, 1, 65535)

        self.secrets_dir = (env.get("DS_SECRETS_DIR") or "/run/secrets").rstrip("/") or "/"
        self.db_host = self._db_value("DS_DB_HOST", "repository_host", None)
        if not self.db_host:
            raise SettingsError("DS_DB_HOST", "is required when the secret repository_host isn't mounted")
        self.db_port = self._int_value(self._db_value("DS_DB_PORT", "repository_port", "5432"), "DS_DB_PORT", 1, 65535)
        self.db_name = self._db_value("DS_DB_NAME", "repository_name", "data_sentinel")
        self.db_user = self._db_value("DS_DB_USER", "repository_username", "sentinel_worker")
        self.db_password_file = (env.get("DS_DB_PASSWORD_FILE") or self.secrets_dir + "/sentinel_worker_password").strip()
        state = file_state(self.db_password_file)
        if state == "cannot_tell":
            raise SettingsError("DS_DB_PASSWORD_FILE", "its folder can't be looked into by this user", self.db_password_file)
        if state == "not_found":
            raise SettingsError("DS_DB_PASSWORD_FILE", "no file at that path", self.db_password_file)
        if state == "found_unreadable":
            raise SettingsError("DS_DB_PASSWORD_FILE", "the file can't be read by this user", self.db_password_file)

        self.poll_sec = self._int("DS_POLL_SEC", 5, 1, 20)
        self.log_dir = (env.get("DS_LOG_DIR") or "/mnt/logs").strip()
        self.log_level = (env.get("DS_LOG_LEVEL") or "info").strip().lower()
        if self.log_level not in ("debug", "info", "warning", "error"):
            raise SettingsError("DS_LOG_LEVEL", "must be debug, info, warning or error")

        # the settings passed to the connection library (standard 2026-48-11 §4)
        roots = [r.strip() for r in (env.get("DS_FILE_ROOTS") or "").split(":") if r.strip()]
        for r in roots:
            if not os.path.isabs(r):
                raise SettingsError("DS_FILE_ROOTS", "every root must be an absolute path", r)
        self.file_roots = roots
        self.ca_bundle = (env.get("DS_CA_BUNDLE") or "").strip() or None
        if self.ca_bundle and file_state(self.ca_bundle) != "found":
            raise SettingsError("DS_CA_BUNDLE", "no readable file at that path", self.ca_bundle)
        self.https_proxy = (env.get("HTTPS_PROXY") or env.get("https_proxy") or "").strip() or None
        self.no_proxy = (env.get("NO_PROXY") or env.get("no_proxy") or "").strip() or None

        self.work_dir = self._abs("DS_WORK_DIR", "/mnt/datasets")
        self.scan_tmp = self._abs("DS_SCAN_TMP", "/mnt/scan_tmp")
        self.threads = self._int("DS_SCAN_THREADS", 4, 1, 16)
        self.memory_mb = self._int("DS_SCAN_MEMORY_MB", 8, 1, 1024)

        # the limits (architect note 2026-48-10, ruling 13)
        self.archive_max_depth = self._int("DS_ARCHIVE_MAX_DEPTH", 8, 1, 64)
        self.archive_max_mb = self._int("DS_ARCHIVE_MAX_MB", 20480, 1, 10 ** 8)
        self.archive_entry_max_mb = self._int("DS_ARCHIVE_ENTRY_MAX_MB", 4096, 1, 10 ** 8)
        self.archive_max_entries = self._int("DS_ARCHIVE_MAX_ENTRIES", 200000, 1, 10 ** 8)
        self.archive_max_ratio = self._int("DS_ARCHIVE_MAX_RATIO", 200, 2, 10 ** 6)
        self.archive_ratio_min_mb = self._int("DS_ARCHIVE_RATIO_MIN_MB", 1, 0, 10 ** 6)
        self.scan_tmp_max_mb = self._int("DS_SCAN_TMP_MAX_MB", 51200, 1, 10 ** 9)
        self.object_max_mb = self._int("DS_OBJECT_MAX_MB", 51200, 1, 10 ** 9)
        self.work_min_free_mb = self._int("DS_WORK_MIN_FREE_MB", 2048, 0, 10 ** 9)

    # -- helpers
    def _int(self, name, default, lo, hi):
        raw = self._env.get(name)
        if raw is None or str(raw).strip() == "":
            return default
        return self._int_value(raw, name, lo, hi)

    @staticmethod
    def _int_value(raw, name, lo, hi):
        try:
            value = int(str(raw).strip())
        except (TypeError, ValueError):
            raise SettingsError(name, "must be a whole number")
        if value < lo or value > hi:
            raise SettingsError(name, "must be from %d to %d" % (lo, hi))
        return value

    def _abs(self, name, default):
        value = (self._env.get(name) or default).strip()
        if not os.path.isabs(value):
            raise SettingsError(name, "must be an absolute path", value)
        return value.rstrip("/") or "/"

    def _db_value(self, env_name, secret_name, default):
        value = (self._env.get(env_name) or "").strip()
        if value:
            return value
        path = self.secrets_dir + "/" + secret_name
        state = file_state(path)
        if state == "cannot_tell":
            raise SettingsError(env_name, "the secrets folder can't be looked into by this user", self.secrets_dir)
        if state == "found_unreadable":
            raise SettingsError(env_name, "the secret file " + secret_name + " can't be read by this user", path)
        if state == "found":
            try:
                value = _read_secret_file(path).strip()
            except (OSError, UnicodeError):
                raise SettingsError(env_name, "the secret file " + secret_name + " can't be read", path)
            if value:
                return value
        return default

    def read_password(self):
        """The database password, read at every connect so a rotated secret is picked up."""
        return _read_secret_file(self.db_password_file)

    def proxy(self):
        if not self.https_proxy:
            return None
        out = {"https": self.https_proxy}
        if self.no_proxy:
            out["no_proxy"] = self.no_proxy
        return out

    def summary(self):
        """The start line's settings: no secret and no connection value beyond the host."""
        return {"service": self.service, "port": self.port, "poll_sec": self.poll_sec, "file_roots": len(self.file_roots),
                "ca_bundle": bool(self.ca_bundle), "proxy": bool(self.https_proxy), "work_dir": self.work_dir,
                "scan_tmp": self.scan_tmp, "threads": self.threads, "memory_mb": self.memory_mb,
                "archive_max_depth": self.archive_max_depth, "archive_max_mb": self.archive_max_mb,
                "archive_entry_max_mb": self.archive_entry_max_mb, "archive_max_entries": self.archive_max_entries,
                "archive_max_ratio": self.archive_max_ratio, "archive_ratio_min_mb": self.archive_ratio_min_mb,
                "scan_tmp_max_mb": self.scan_tmp_max_mb, "object_max_mb": self.object_max_mb,
                "work_min_free_mb": self.work_min_free_mb, "log_level": self.log_level}


def file_state(path):
    """found, not_found, found_unreadable, or cannot_tell (its folder can't be looked into). Opens the
    file to know whether it can be read; never reads it."""
    try:
        st = os.stat(path)
    except FileNotFoundError:
        return "not_found"
    except NotADirectoryError:
        return "not_found"
    except PermissionError:
        return "cannot_tell"
    except OSError:
        return "not_found"
    if not stat.S_ISREG(st.st_mode):
        return "not_found"
    try:
        with open(path, "rb"):
            pass
    except PermissionError:
        return "found_unreadable"
    except OSError:
        return "found_unreadable"
    return "found"


# ---------------------------------------------------------------------------
# 1.1 the start-up report (architect note 2026-48-20): what the container was given, and what it wasn't
#   SETTINGS_SPEC is this worker's; startup_report() has nothing of scan in it, for the standard's next edition.
#   Kinds: value (shown), connection (set or not set, never the value), path (a file, shown), dir_write (a folder
#   the worker writes, shown and checked), dirs_read (folders separated by colons, shown, each checked for reading).
#   The default is what is shown when the variable isn't set: a text, a function of the environment, or None.
# ---------------------------------------------------------------------------
SECRET_FILES = ("repository_host", "repository_port", "repository_name", "repository_username", "sentinel_worker_password")
REQUIRED_SETTINGS = ("DS_SERVICE",)
SETTINGS_SPEC = (
    ("DS_SERVICE", "value", None),
    ("DS_SERVICE_PORT", "value", "5540"),
    ("DS_SERVICE_EXTERNAL_HOST", "connection", "the service's name"),
    ("DS_SERVICE_EXTERNAL_PORT", "value", lambda env: (env.get("DS_SERVICE_PORT") or "").strip() or "5540"),
    ("DS_SECRETS_DIR", "path", "/run/secrets"),
    ("DS_DB_HOST", "connection", "the secret file repository_host"),
    ("DS_DB_PORT", "connection", "the secret file repository_port, else the standard's"),
    ("DS_DB_NAME", "connection", "the secret file repository_name, else the standard's"),
    ("DS_DB_USER", "connection", "the secret file repository_username, else the standard's"),
    ("DS_DB_PASSWORD_FILE", "path", lambda env: ((env.get("DS_SECRETS_DIR") or "/run/secrets").rstrip("/") or "") + "/sentinel_worker_password"),
    ("DS_POLL_SEC", "value", "5"),
    ("DS_LOG_DIR", "dir_write", "/mnt/logs"),
    ("DS_LOG_LEVEL", "value", "info"),
    ("DS_FILE_ROOTS", "dirs_read", None),
    ("DS_CA_BUNDLE", "path", None),
    ("HTTPS_PROXY", "connection", None, ("https_proxy",)),
    ("NO_PROXY", "connection", None, ("no_proxy",)),
    ("DS_WORK_DIR", "dir_write", "/mnt/datasets"),
    ("DS_SCAN_TMP", "dir_write", "/mnt/scan_tmp"),
    ("DS_SCAN_THREADS", "value", "4"),
    ("DS_SCAN_MEMORY_MB", "value", "8"),
    ("DS_ARCHIVE_MAX_DEPTH", "value", "8"),
    ("DS_ARCHIVE_MAX_MB", "value", "20480"),
    ("DS_ARCHIVE_ENTRY_MAX_MB", "value", "4096"),
    ("DS_ARCHIVE_MAX_ENTRIES", "value", "200000"),
    ("DS_ARCHIVE_MAX_RATIO", "value", "200"),
    ("DS_ARCHIVE_RATIO_MIN_MB", "value", "1"),
    ("DS_SCAN_TMP_MAX_MB", "value", "51200"),
    ("DS_OBJECT_MAX_MB", "value", "51200"),
    ("DS_WORK_MIN_FREE_MB", "value", "2048"),
)


def worker_report(title, settings_spec, secret_files, env=None, required=(), reads=None, loaded=None, standard=None, mode=None):
    """The worker's report (standard 2026-48-37 §18): what the container was given and what the worker can do,
    as (document, lines). The document is what the check-in's v_report carries; the lines are the log's, from
    the same facts, so the two never disagree. Nothing in it is a password, a key, a connection value or
    anything read from a customer's data. Standard names it relies on: DS_SERVICE, DS_LOG_DIR,
    DS_SECRETS_DIR, DS_DB_PASSWORD_FILE. reads and loaded are the worker's own lists, given as data."""
    import json as _json
    import os as _os
    import platform as _platform
    import stat as _stat

    env = _os.environ if env is None else env

    def q(value):
        text = str(value)
        if len(text) > 500:
            text = text[:500] + "..."
        if text == "" or any(ch in text for ch in ' \t|="\\') or not text.isprintable():
            return _json.dumps(text, ensure_ascii=False)
        return text

    def line(level, event, **fields):
        lines.append((level, event + "".join(" %s=%s" % (k, q(v)) for k, v in fields.items())))

    def state_of(path):
        try:
            st = _os.stat(path)
        except PermissionError:
            return "cannot_tell"
        except OSError:
            return "not_found"
        if not _stat.S_ISREG(st.st_mode):
            return "not_found"
        try:
            with open(path, "rb"):
                pass
        except OSError:
            return "found_unreadable"
        return "found"

    def folder(path, mode_):
        try:
            st = _os.stat(path)
        except PermissionError:
            return "cannot_tell", "no"
        except OSError:
            return "no", "no"
        if not _stat.S_ISDIR(st.st_mode):
            return "not_a_folder", "no"
        ok = _os.access(path, (_os.W_OK | _os.X_OK) if mode_ == "write" else (_os.R_OK | _os.X_OK))
        return "yes", "yes" if ok else "no"

    def raw(name, aliases=()):
        for n in (name,) + tuple(aliases):
            v = env.get(n)
            if v is not None and str(v).strip() != "":
                return str(v).strip()
        return None

    doc_state = {"found": "found", "not_found": "not_found", "found_unreadable": "unreadable", "cannot_tell": "unreadable"}
    machine = _platform.machine().lower()
    lines = []
    doc = {"standard": standard, "build": {"worker": title.get("version"), "connect": title.get("connect"), "python": title.get("python"),
                                           "platform": "linux/" + {"x86_64": "amd64", "aarch64": "arm64"}.get(machine, machine),
                                           "uid": _os.getuid(), "gid": _os.getgid()},
           "mode": mode, "settings": [], "secrets": [], "folders": [], "reads": list(reads or []), "loaded": list(loaded or []),
           "unknown_settings": []}
    line("INFO", "startup_report", **title)
    # 1. who it runs as
    line("INFO", "startup_user", uid=_os.getuid(), gid=_os.getgid())
    # 2. every setting the worker knows, in a fixed order
    folders = []
    known = set()
    for item in settings_spec:
        name, kind, default = item[0], item[1], item[2]
        aliases = tuple(item[3]) if len(item) > 3 else ()
        known.add(name)
        known.update(a for a in aliases if a.startswith("DS_"))
        value = raw(name, aliases)
        is_set = value is not None
        if not is_set:
            default = default(env) if callable(default) else default
        source = "set" if is_set else ("missing" if name in required else "default")
        if kind == "connection":
            doc["settings"].append({"name": name, "value": None, "from": source, "hidden": True})
            if is_set:
                line("INFO", "startup_setting", name=name, state="set")
            elif default is None:
                line("INFO", "startup_setting", name=name, state="not_set")
            else:
                line("INFO", "startup_setting", name=name, state="not_set", default=default)
            continue
        shown = value if is_set else (default if default is not None else "none")
        doc["settings"].append({"name": name, "value": value if is_set else default, "from": source})
        line("INFO", "startup_setting", name=name, state="set" if is_set else "not_set", value=shown)
        if kind == "dir_write":
            folders.append((name, value or default, "write"))
        elif kind == "dirs_read" and (value or default):
            for path in [x.strip() for x in str(value or default).split(":") if x.strip()]:
                folders.append((name, path, "read"))
    # 3. the secrets folder
    secrets_dir = (raw("DS_SECRETS_DIR") or "/run/secrets").rstrip("/") or "/"
    exists, _w = folder(secrets_dir, "read")
    can_look = "no"
    if exists == "yes":
        try:
            _os.listdir(secrets_dir)
            can_look = "yes"
        except OSError:
            can_look = "no"
    doc["secrets_folder"] = {"path": secrets_dir, "exists": exists == "yes", "can_look_in": can_look == "yes"}
    line("INFO", "startup_secrets_folder", path=secrets_dir, exists=exists, can_look_in=can_look)
    # 4. each secret file the worker looks for: the state only
    for name in secret_files:
        st = state_of(_os.path.join(secrets_dir, name))
        doc["secrets"].append({"name": name, "state": doc_state[st]})
        line("INFO" if st == "found" else "WARNING", "startup_secret_file", name=name, state=st)
    # 5. the password file in use
    pw = raw("DS_DB_PASSWORD_FILE") or (secrets_dir.rstrip("/") + "/sentinel_worker_password")
    st = state_of(pw)
    doc["password_file"] = {"path": pw, "state": doc_state[st]}
    line("INFO" if st == "found" else "WARNING", "startup_password_file", path=pw, state=st)
    # 6. each folder it needs
    for name, path, mode_ in folders:
        exists, ok = folder(path, mode_)
        doc["folders"].append({"setting": name, "path": path, "needs": mode_, "exists": exists == "yes", "usable": exists == "yes" and ok == "yes"})
        fields = {"setting": name, "path": path, "exists": exists}
        fields["writable" if mode_ == "write" else "readable"] = ok
        line("INFO" if (exists == "yes" and ok == "yes") else "WARNING", "startup_folder", **fields)
    # what it can read, and what it loaded (the worker's own lists)
    for r in doc["reads"]:
        fields = {"type": r.get("type"), "offered": "yes" if r.get("offered") else "no"}
        if r.get("why"):
            fields["why"] = r["why"]
        line("INFO" if r.get("offered") else "WARNING", "startup_reads", **fields)
    for item in doc["loaded"]:
        fields = {"kind": item.get("kind"), "name": item.get("name")}
        if item.get("version"):
            fields["version"] = item["version"]
        fields["ok"] = "yes" if item.get("ok") else "no"
        if item.get("why"):
            fields["why"] = item["why"]
        line("INFO", "startup_loaded", **fields)
    # 7. DS_ variables this worker doesn't know: names only
    for name in sorted(k for k in env if k.startswith("DS_") and k not in known):
        doc["unknown_settings"].append(name)
        line("WARNING", "startup_unknown_variable", name=name)
    return doc, lines


def startup_report(title, settings_spec, secret_files, check, env=None, required=(), reads_fn=None, loaded_fn=None, standard=None):
    """Writes the worker's report before the settings are checked, then runs check(): settings_ok, or
    settings_invalid with the variable, the problem and the path looked at. One line per item, in the log's
    format, to stdout and to <DS_LOG_DIR>/<DS_SERVICE>.log when that folder can be used. Returns check()'s
    result, or None when the settings can't be used (the caller exits 2)."""
    import logging as _logging
    import os as _os
    import re as _re
    import sys as _sys

    env = _os.environ if env is None else env
    try:
        reads = reads_fn(env) if reads_fn else None
    except Exception:
        reads = None
    try:
        loaded = loaded_fn() if loaded_fn else None
    except Exception:
        loaded = None
    _doc, lines = worker_report(title, settings_spec, secret_files, env=env, required=required, reads=reads, loaded=loaded, standard=standard)

    logger = _logging.getLogger("startup_report")
    logger.propagate = False
    logger.setLevel(_logging.INFO)
    for h in list(logger.handlers):
        logger.removeHandler(h)
    fmt = _logging.Formatter("%(asctime)s|%(levelname)s|%(message)s")
    handlers = [_logging.StreamHandler(_sys.stdout)]
    service = (env.get("DS_SERVICE") or "").strip()
    log_dir = (env.get("DS_LOG_DIR") or "").strip() or "/mnt/logs"
    log_file = None
    if _re.match(r"^[A-Za-z0-9_.-]{1,60}$", service) and _os.path.isdir(log_dir) and _os.access(log_dir, _os.W_OK | _os.X_OK):
        try:
            log_file = _logging.FileHandler(_os.path.join(log_dir, service + ".log"), mode="a", encoding="utf-8")
            handlers.append(log_file)
        except OSError:
            log_file = None
    for h in handlers:
        h.setFormatter(fmt)
        logger.addHandler(h)
    levels = {"INFO": _logging.INFO, "WARNING": _logging.WARNING, "ERROR": _logging.ERROR}
    try:
        for level, message in lines:
            logger.log(levels[level], message)
        try:
            result = check()
        except Exception as e:
            fields = {"variable": getattr(e, "variable", "-"), "problem": str(getattr(e, "problem", type(e).__name__)).replace(" ", "_")}
            text = "settings_invalid" + "".join(" %s=%s" % (k, v) for k, v in fields.items())
            if getattr(e, "path", None):
                text += " path=" + (e.path if (e.path and " " not in e.path and "|" not in e.path) else '"%s"' % e.path)
            logger.error(text)
            return None
        logger.info("settings_ok")
        return result
    finally:
        for h in handlers:
            try:
                h.flush()
            except Exception:
                pass
            logger.removeHandler(h)
        if log_file is not None:
            log_file.close()


log = logging.getLogger("ds_scan")
LOG_FORMAT = "%(asctime)s|%(levelname)s|%(message)s"


def setup_logging(settings):
    """One format, to stdout always and to <log dir>/<service>.log when the folder is there."""
    level = getattr(logging, settings.log_level.upper(), logging.INFO)
    fmt = logging.Formatter(LOG_FORMAT)
    for h in list(log.handlers):
        log.removeHandler(h)
        try:
            h.close()
        except Exception:
            pass
    out = logging.StreamHandler(sys.stdout)
    out.setFormatter(fmt)
    log.addHandler(out)
    if settings.log_dir and os.path.isdir(settings.log_dir):
        try:
            fh = logging.FileHandler(os.path.join(settings.log_dir, settings.service + ".log"), mode="a", encoding="utf-8")
            fh.setFormatter(fmt)
            log.addHandler(fh)
        except OSError:
            pass
    log.setLevel(level)
    log.propagate = False
    # the libraries' own loggers: warnings only, through the same handlers, never a request line
    for name in ("uvicorn", "uvicorn.error", "uvicorn.access", "quart", "quart.app", "quart.serving", "asyncio", "ds_connect_lib"):
        lg = logging.getLogger(name)
        lg.handlers = list(log.handlers)
        lg.setLevel(logging.WARNING if name != "uvicorn.access" else logging.CRITICAL)
        lg.propagate = False


def _kv_value(v):
    if v is None:
        return "-"
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, float):
        return ("%.3f" % v).rstrip("0").rstrip(".")
    s = str(v)
    return re.sub(r"[\s|=]+", "_", s)[:120]


def kv(event, **fields):
    """A key=value log line. Only ids, counts, sizes, codes and the worker's own words go in."""
    return event + " " + " ".join(k + "=" + _kv_value(v) for k, v in fields.items())


def where(exc):
    """The exception's class and the function it happened in: never a traceback, never a path."""
    tb = exc.__traceback__
    fn = "?"
    while tb is not None:
        fn = tb.tb_frame.f_code.co_name
        tb = tb.tb_next
    return type(exc).__name__, fn


# ---------------------------------------------------------------------------
# Reasons: a code, its parameters and one sentence (standard §13). The library's codes come from
# ds_connect_lib.message(). Each text: one sentence, no full stop, at most 200 characters.
# ---------------------------------------------------------------------------
REASONS = collections.OrderedDict([
    ("object_unreadable", ("The object couldn't be read: {reason}", ("reason",))),
    ("object_gone", ("The object was no longer there", ())),
    ("unexpected", ("The worker failed unexpectedly: {reason}", ("reason",))),
    ("worker_stopped", ("The worker stopped while reading this object on an earlier try", ())),
    ("archive_too_deep", ("The archive is nested more than {limit} levels deep", ("limit",))),
    ("archive_too_large", ("The archive expands to more than {limit_mb} MB", ("limit_mb",))),
    ("archive_too_many_entries", ("The archive holds more than {limit} entries", ("limit",))),
    ("archive_ratio_exceeded", ("An entry expands to more than {limit} times its compressed size", ("limit",))),
    ("object_too_large", ("The object is larger than the limit of {limit_mb} MB", ("limit_mb",))),
    ("path_outside_root", ("The object's path leads outside the data source's root", ())),
    ("object_encrypted", ("The object is encrypted", ())),
    ("object_changed", ("The object changed while it was being read", ())),
    ("scan_tmp_full", ("The worker's temporary folder has no room for this object", ())),
    ("handin_refused", ("The database refused what the worker found for this object: {problem}", ("problem",))),
    ("data_source_unusable", ("The data source can't be used: {problem}", ("problem",))),
])

# health codes (standard §7): one code for one sentence; problems and work alike
HEALTH = collections.OrderedDict([
    # the five every worker has, word for word as every worker sends them (architect note 2026-48-23)
    ("idle", "Idle"),
    ("starting", "The worker is still starting"),
    ("reconnecting", "The worker is reconnecting to the database"),
    ("stopping", "The worker is stopping"),
    ("contract_missing", "The database is missing functions this worker needs"),
    # a queue worker's work codes, as the standard has them (§7)
    ("working", "Working on the {stage} stage of run {run_id}"),
    ("waiting_for_work", "Waiting for objects on run {run_id}"),
    ("winding_down", "Finishing up on run {run_id}"),
    # scan's own
    ("waiting_for_space", "Waiting for free space in the working folder on run {run_id}"),
    ("work_dir_unusable", "The worker can't use the folder set by {setting}: the {step} step failed"),
    ("queue_set_aside", "A queue was set aside after the database refused it three times"),
])
HEALTH_STANDARD = ("idle", "starting", "reconnecting", "stopping", "contract_missing", "working", "waiting_for_work", "winding_down")


def _sentence(text):
    text = re.sub(r"[\r\n\t]+", " ", str(text)).strip()
    while text.endswith("."):
        text = text[:-1].rstrip()
    return text[:200]


def reason(code, **params):
    """{code, params, text} for a reason of this worker or of the connection library."""
    if code in REASONS:
        template, keys = REASONS[code]
        clean = {}
        for k in keys:
            v = params.get(k, "")
            v = re.sub(r"[\x00-\x1f\x7f]+", " ", str(v)).strip()
            if k in ("reason", "problem"):
                v = v.splitlines()[0][:120] if v else ""
            clean[k] = v
        out_params = {k: params[k] for k in keys if k in params}
        for k in ("reason", "problem"):
            if k in out_params:
                out_params[k] = clean[k]
        return {"code": code, "params": out_params, "text": _sentence(template.format(**clean))}
    try:
        text = ds_connect_lib.message(code, params)
    except Exception:
        text = code
    return {"code": code, "params": dict(params), "text": _sentence(text)}


def health_item(code, **params):
    return {"code": code, "params": params, "text": _sentence(HEALTH[code].format(**params))}


# ---------------------------------------------------------------------------
# What goes wrong
# ---------------------------------------------------------------------------
class ScanFail(Exception):
    """One object, or one part, can't be read: it is marked failed with this reason."""

    def __init__(self, code, whole_archive=False, **params):
        super().__init__(code)
        self.code = code
        self.params = params
        self.whole_archive = whole_archive      # an archive-wide limit: the archive being read fails, not just the entry


class Stopped(Exception):
    """A stop reached the reader: the object is left waiting, unread."""


class QueueAbort(Exception):
    """The data source can't be reached: the queue is released as retry with the library's code."""

    def __init__(self, code, params):
        super().__init__(code)
        self.code = code
        self.params = params or {}


class DbAway(Exception):
    """The database is out of reach."""


class ContractBroken(Exception):
    """A function is gone or changed (42883, 3F000, 42501, 42P01)."""


class NotService(Exception):
    """The login isn't the workers' (PT403 not_service): the process stops with exit code 1."""


class Refused(Exception):
    """A function refused the call: matched on its HINT, never on its message."""

    def __init__(self, sqlstate, hint, detail):
        super().__init__(hint or sqlstate)
        self.sqlstate = sqlstate
        self.hint = hint
        self.detail = detail


# ===========================================================================
# 2. TEXT RULES (from V1 2025.41.2-.4, unchanged in spirit)
#   A character is never silently deleted: what is removed becomes a space. Real characters are kept.
#   Content is NFC-normalized; identifiers are not.
# ===========================================================================
_SURROGATE_RE = re.compile(r"[\ud800-\udfff]")
_PG_UNSAFE_RE = re.compile(r"[\x00-\x1f\x7f-\x9f\ud800-\udfff]")
_unwanted = {i: 32 for i in range(32)}
_unwanted.update({i: 32 for i in range(127, 160)})
_unwanted[10] = 10
_unwanted[13] = 10
_unwanted[9] = 32
_CLEAN_TBL = str.maketrans(_unwanted)
MAX_UNIT_CHARS = 20000


def clean_text(text):
    """Content: controls become spaces (LF kept, CRLF and CR become LF, TAB a space), lone surrogates
    become spaces, NFC."""
    if not isinstance(text, str):
        return text
    if "\r" in text:
        text = text.replace("\r\n", "\n")
    if not text.isascii():
        text = _SURROGATE_RE.sub(" ", text)
        text = unicodedata.normalize("NFC", text)
    return text.translate(_CLEAN_TBL)


def pg_safe_str(s):
    """Identifiers and JSON values: every control character and lone surrogate becomes a space."""
    if not isinstance(s, str):
        return s
    return _PG_UNSAFE_RE.sub(" ", s)


def split_unit(text, max_length=MAX_UNIT_CHARS):
    """One unit (a line, a paragraph, a slide, a page) as rows of at most max_length characters,
    cut at the last line feed, then sentence punctuation, then a space. Line feeds inside are kept."""
    text = clean_text(text).strip()
    if not text:
        return []
    n = len(text)
    if n <= max_length:
        return [text]
    rows = []
    start = 0
    while start < n:
        end = min(start + max_length, n)
        if end == n:
            boundary = n
        else:
            boundary = text.rfind("\n", start, end)
            if boundary <= start:
                best = max(text.rfind(ch, start, end) for ch in (".", "!", "?"))
                boundary = best + 1 if best > start else -1
            if boundary <= start:
                sp = text.rfind(" ", start, end)
                boundary = sp if sp > start else end
        chunk = text[start:boundary].strip()
        if chunk:
            rows.append(chunk)
        start = boundary if boundary > start else start + max_length
    return rows


def decode_bytes(b):
    """Bytes as text without losing a byte: strict UTF-8, else cp1252 with replacement."""
    if b is None:
        return ""
    if isinstance(b, str):
        return b
    try:
        return bytes(b).decode("utf-8")
    except UnicodeDecodeError:
        return bytes(b).decode("cp1252", errors="replace")


def json_safe(obj, depth=0):
    """A value fit for JSONB: controls and surrogates become spaces, NaN and infinities null, anything
    else its text."""
    if depth > 20:
        return None
    if isinstance(obj, dict):
        return {pg_safe_str(str(k)): json_safe(v, depth + 1) for k, v in obj.items()}
    if isinstance(obj, (list, tuple, set)):
        return [json_safe(v, depth + 1) for v in obj]
    if isinstance(obj, str):
        return pg_safe_str(obj)
    if obj is None or isinstance(obj, bool) or isinstance(obj, int):
        return obj
    if isinstance(obj, float):
        return obj if math.isfinite(obj) else None
    if isinstance(obj, (bytes, bytearray)):
        return pg_safe_str(decode_bytes(obj))
    if isinstance(obj, (dt.datetime, dt.date)):
        return obj.isoformat()
    return pg_safe_str(str(obj))


META_MAX = 16384           # the database's limit, in bytes of the JSON text (db 2026-48-02)
META_TARGET = 15360        # what scan keeps meta under: the database's text and Python's can differ by a little


def _meta_bytes(meta):
    return len(json.dumps(meta, ensure_ascii=False).encode("utf-8"))


def cap_meta(meta):
    """meta held under META_TARGET (note 2026-48-45): the custom properties go first, then long values, and
    the short fields of doc and labels last. Whenever anything was cut, meta_cut is true."""
    meta = json_safe(meta or {})
    if _meta_bytes(meta) <= META_TARGET:
        return meta

    def cut(v, n):
        if isinstance(v, str):
            return v[:n]
        if isinstance(v, list):
            return [cut(x, n) for x in v[:50]]
        if isinstance(v, dict):
            return {k: cut(x, n) for k, x in v.items()}
        return v

    meta["meta_cut"] = True
    meta.pop("custom", None)
    if _meta_bytes(meta) <= META_TARGET:
        return meta
    protected = ("doc", "labels", "meta_cut")
    for n in (1000, 200, 60):
        for k in list(meta):
            if k not in protected:
                meta[k] = cut(meta[k], n)
        if _meta_bytes(meta) <= META_TARGET:
            return meta
    others = sorted((k for k in meta if k not in protected), key=lambda k: len(json.dumps(meta[k], ensure_ascii=False)), reverse=True)
    for k in others:
        meta.pop(k, None)
        if _meta_bytes(meta) <= META_TARGET:
            return meta
    for n in (200, 60):
        for k in ("doc", "labels"):
            if k in meta:
                meta[k] = cut(meta[k], n)
        if _meta_bytes(meta) <= META_TARGET:
            return meta
    meta.pop("labels", None)
    if _meta_bytes(meta) > META_TARGET:
        meta.pop("doc", None)
    return meta


# ===========================================================================
# 3. LIMITS, THE TEMPORARY-DISK BUDGET, SPOOLING AND HASHING, THE SOURCE OF AN OBJECT
# ===========================================================================
class Budget(object):
    """The temporary disk this worker may hold at once (DS_SCAN_TMP_MAX_MB)."""

    def __init__(self, limit_bytes):
        self.limit = limit_bytes
        self.used = 0
        self.lock = threading.Lock()

    def take(self, n):
        with self.lock:
            if self.used + n > self.limit:
                raise ScanFail("scan_tmp_full")
            self.used += n

    def give(self, n):
        with self.lock:
            self.used = max(0, self.used - n)


O_NOATIME = getattr(os, "O_NOATIME", 0)
NOATIME_REFUSED = [0]           # opens of a customer's file the system refused O_NOATIME for (the worker doesn't own the file)


def open_customer_fd(path, follow=False, noatime=True):
    """Opens a customer's file for reading without moving its access time (note 2026-48-45): O_NOATIME where
    the system has it. The system refuses that flag to a process that doesn't own the file; then the file
    is opened again without it. Returns (fd, noatime_held). follow=True for /proc/self/fd links."""
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    if not follow:
        flags |= getattr(os, "O_NOFOLLOW", 0)
    if O_NOATIME and noatime:
        try:
            return os.open(path, flags | O_NOATIME), True
        except PermissionError as e:
            if getattr(e, "errno", None) != 1:      # EPERM: O_NOATIME refused. Anything else is the file's own refusal
                raise
            NOATIME_REFUSED[0] += 1
    return os.open(path, flags), False


class Source(object):
    """The bytes of one object or part, in memory, spooled to the worker's temporary folder, or read in
    place on a mounted share. Knows its size, its SHA-256 and its first bytes. noatime is None for bytes of
    our own (memory, spool), and for a customer's file read in place says whether O_NOATIME was allowed."""

    def __init__(self, name, path=None, data=None, size=0, sha256=None, head=b"", owned=False, budget=None, budgeted=0, noatime=None):
        self.name = name or ""
        self.path = path
        self.data = data
        self.size = size
        self.sha256 = sha256
        self.head = head
        self.noatime = noatime
        self._owned = owned         # a spool file of ours, removed by cleanup()
        self._budget = budget
        self._budgeted = budgeted
        self._copies = []           # copies made for a library that opens files itself

    @property
    def ext(self):
        base = self.name.rsplit("/", 1)[-1]
        return base.rsplit(".", 1)[-1].lower() if "." in base else ""

    def open(self):
        if self.data is not None:
            return io.BytesIO(self.data)
        if self.noatime is not None:
            fd, _held = open_customer_fd(self.path, follow=True, noatime=self.noatime)
            return os.fdopen(fd, "rb")
        return open(self.path, "rb")

    def bytes(self):
        """The whole object in memory: only for objects under the memory threshold."""
        if self.data is not None:
            return self.data
        with self.open() as fh:
            return fh.read()

    def for_library(self, ctx):
        """What to give a library that opens files by itself (PyMuPDF, xlrd): (path, data). A customer's file
        held with O_NOATIME is never given by its path, because the library's own open would move its access
        time: one under DS_SCAN_MEMORY_MB goes in memory, a larger one is copied to the temporary folder
        first, through our own open."""
        if self.data is not None:
            return None, self.data
        if not self.noatime:
            return self.path, None
        if self.size <= ctx.settings.memory_mb * _MB:
            return None, self.bytes()
        self._budget = self._budget or ctx.budget
        self._budget.take(self.size)
        self._budgeted += self.size
        out, path = ctx.new_spool_file()
        self._copies.append(path)
        with out, self.open() as fh:
            while True:
                ctx.check()
                chunk = fh.read(CHUNK)
                if not chunk:
                    break
                out.write(chunk)
        return path, None

    def cleanup(self):
        for path in self._copies:
            try:
                os.remove(path)
            except OSError:
                pass
        self._copies = []
        if self._owned and self.path:
            try:
                os.remove(self.path)
            except OSError:
                pass
            self.path = None
        if self._budget is not None and self._budgeted:
            self._budget.give(self._budgeted)
            self._budgeted = 0
        self.data = None


_ARCHIVE_MAGIC = (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08", b"\x1f\x8b", b"BZh", b"\xfd7zXZ\x00", b"7z\xbc\xaf\x27\x1c",
                  b"Rar!\x1a\x07")


def looks_like_archive(head):
    return any(head.startswith(m) for m in _ARCHIVE_MAGIC) or (len(head) > 262 and head[257:262] == b"ustar")


def spool_stream(read_chunk, name, ctx, declared=None, compressed=None, archive_entry=False):
    """Copies a stream to memory or to disk while taking its SHA-256: the fingerprint and the spool are
    one pass. An archive goes to disk whatever its size; anything else stays in memory under
    DS_SCAN_MEMORY_MB. For an archive's entry the limits are enforced as the bytes come: the entry's
    size, its expansion ratio and the archive's expanded total."""
    s = ctx.settings
    mem_limit = s.memory_mb * _MB
    entry_max = s.archive_entry_max_mb * _MB
    object_max = s.object_max_mb * _MB
    ratio = s.archive_max_ratio
    ratio_min = s.archive_ratio_min_mb * _MB
    h = hashlib.sha256()
    n = 0
    head = b""
    buf = None
    fh = None
    path = None
    budgeted = 0
    to_disk = False
    try:
        while True:
            ctx.check()
            chunk = read_chunk(CHUNK)
            if not chunk:
                break
            if not head:
                head = bytes(chunk[:HEAD])
                to_disk = looks_like_archive(head) or (declared is not None and declared >= mem_limit)
                if not to_disk:
                    buf = io.BytesIO()
            n += len(chunk)
            if archive_entry:
                if n > entry_max:
                    raise ScanFail("object_too_large", limit_mb=s.archive_entry_max_mb)
                if compressed is not None and n > ratio_min and n > ratio * max(1, compressed):
                    raise ScanFail("archive_ratio_exceeded", limit=ratio)
                ctx.add_expanded(len(chunk))
            elif n > object_max:
                raise ScanFail("object_too_large", limit_mb=s.object_max_mb)
            h.update(chunk)
            if not to_disk and buf is not None and buf.tell() + len(chunk) >= mem_limit:
                to_disk = True
                held = buf.getvalue()
                buf = None
                fh, path = ctx.new_spool_file()
                ctx.budget.take(len(held))
                budgeted += len(held)
                fh.write(held)
            if to_disk:
                if fh is None:
                    fh, path = ctx.new_spool_file()
                ctx.budget.take(len(chunk))
                budgeted += len(chunk)
                fh.write(chunk)
            else:
                buf.write(chunk)
        if fh is not None:
            fh.close()
            fh = None
            return Source(name, path=path, size=n, sha256=h.hexdigest(), head=head, owned=True, budget=ctx.budget, budgeted=budgeted)
        return Source(name, data=(buf.getvalue() if buf is not None else b""), size=n, sha256=h.hexdigest(), head=head)
    except BaseException:
        if fh is not None:
            try:
                fh.close()
            except Exception:
                pass
        if path:
            try:
                os.remove(path)
            except OSError:
                pass
        if budgeted:
            ctx.budget.give(budgeted)
        raise


def hash_in_place(fobj, ctx, touch=None):
    """A file on a mounted share is already on disk: it is read in place, in chunks, for its SHA-256 and
    its first bytes. Returns (sha256, size, head)."""
    h = hashlib.sha256()
    n = 0
    head = b""
    while True:
        ctx.check()
        chunk = fobj.read(CHUNK)
        if not chunk:
            break
        if not head:
            head = bytes(chunk[:HEAD])
        n += len(chunk)
        h.update(chunk)
        ctx.add_bytes_read(len(chunk))
    return h.hexdigest(), n, head


# ===========================================================================
# 4. WHAT A FILE IS: SNIFFING FROM THE BYTES
#   The type comes from the bytes. The name's extension only decides among text formats, which bytes
#   can't tell apart. Readers exist for the types in READ_TYPES; the rest are done with read.why.
# ===========================================================================
TYPE_GROUPS = {
    "docx": "docx", "docm": "docx", "dotx": "docx", "dotm": "docx",
    "xlsx": "xlsx", "xlsm": "xlsx", "xltx": "xlsx", "xltm": "xlsx",
    "pptx": "pptx", "pptm": "pptx", "potx": "pptx", "potm": "pptx", "ppsx": "pptx", "ppsm": "pptx",
}
UNSUPPORTED_TYPES = {"doc", "ppt", "msg", "ole", "xlsb", "odt", "ods", "odp", "odg", "odf", "epub", "mobi", "fb2", "xps", "rtf",
                     "gz", "bz2", "xz", "7z", "rar", "tar"}
IMAGE_TYPES = {"jpg", "png", "gif", "bmp", "tiff", "webp", "heic", "avif", "ico", "svg"}
TEXT_EXT = {
    "csv": "csv", "tsv": "csv", "tab": "csv",
    "json": "json", "jsonl": "txt", "ndjson": "txt",
    "xml": "xml", "xsd": "xml", "xsl": "xml", "xslt": "xml", "rss": "xml", "atom": "xml", "kml": "xml", "gpx": "xml",
    "htm": "html", "html": "html", "xhtml": "html", "shtml": "html",
}


class TypeInfo(object):
    def __init__(self, type_, encrypted=False):
        self.type = type_
        self.encrypted = encrypted

    @property
    def reader(self):
        return READERS.get(TYPE_GROUPS.get(self.type, self.type))

    @property
    def why(self):
        if self.reader is not None:
            return None
        if self.type in IMAGE_TYPES:
            return "image"
        if self.type in UNSUPPORTED_TYPES:
            return "unsupported_type"
        return "unknown_type"


def _looks_like_text(head):
    if not head:
        return True
    if head.startswith((codecs.BOM_UTF8, codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE)):
        return True
    if b"\x00" in head:
        return False
    sample = head[:4096]
    try:
        sample.decode("utf-8")
        return True
    except UnicodeDecodeError as e:
        if e.start >= len(sample) - 4:          # a character cut by the sample's end
            return True
    printable = sum(1 for b in sample if b in (9, 10, 12, 13) or 32 <= b < 127 or b >= 160)
    return printable >= 0.95 * len(sample)


def _zip_type(src):
    """Which zip-based format: OOXML, ODF, EPUB, XPS, or a plain archive."""
    try:
        with src.open() as fh:
            zf = zipfile.ZipFile(fh)
            names = set(zf.namelist())
            if "word/document.xml" in names:
                return "docx"
            if "xl/workbook.xml" in names:
                return "xlsx"
            if "xl/workbook.bin" in names:
                return "xlsb"
            if "ppt/presentation.xml" in names:
                return "pptx"
            if "mimetype" in names:
                try:
                    mt = zf.read("mimetype")[:100].decode("ascii", "replace").strip()
                except Exception:
                    mt = ""
                odf = {"application/vnd.oasis.opendocument.text": "odt",
                       "application/vnd.oasis.opendocument.spreadsheet": "ods",
                       "application/vnd.oasis.opendocument.presentation": "odp",
                       "application/vnd.oasis.opendocument.graphics": "odg",
                       "application/epub+zip": "epub"}
                if mt in odf:
                    return odf[mt]
                if mt.startswith("application/vnd.oasis.opendocument"):
                    return "odf"
            if "FixedDocumentSequence.fdseq" in names or any(n.endswith(".fdseq") for n in names):
                return "xps"
    except (zipfile.BadZipFile, OSError, ValueError, EOFError):
        return "zip"
    return "zip"


def _ole_type(src):
    """Which OLE compound file: xls, doc, ppt, msg, an encrypted Office file, or unknown."""
    try:
        from xlrd import compdoc
    except ImportError:
        return TypeInfo("ole")
    mm = None
    fh = None
    try:
        if src.data is not None:
            mem = src.data
        else:
            fh = src.open()
            mm = mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ)
            mem = mm
        cd = compdoc.CompDoc(mem, logfile=io.StringIO(), ignore_workbook_corruption=True)
        names = set(d.name for d in cd.dirlist if getattr(d, "name", None))
    except Exception:
        return TypeInfo("ole")
    finally:
        if mm is not None:
            try:
                mm.close()
            except Exception:
                pass
        if fh is not None:
            fh.close()
    if "EncryptedPackage" in names and "EncryptionInfo" in names:
        return TypeInfo("ole", encrypted=True)
    if "Workbook" in names or "Book" in names:
        return TypeInfo("xls")
    if "WordDocument" in names:
        return TypeInfo("doc")
    if "PowerPoint Document" in names:
        return TypeInfo("ppt")
    if any(n.startswith("__substg1.0_") or n.startswith("__properties_version1.0") for n in names):
        return TypeInfo("msg")
    return TypeInfo("ole")


def identify(src):
    """The type of an object from its bytes."""
    head = src.head or b""
    if head.startswith((b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")):
        return TypeInfo(_zip_type(src))
    if head.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
        return _ole_type(src)
    if b"%PDF-" in head[:1024]:
        return TypeInfo("pdf")
    if head.startswith(b"\xff\xd8\xff"):
        return TypeInfo("jpg")
    if head.startswith(b"\x89PNG\r\n\x1a\n"):
        return TypeInfo("png")
    if head.startswith((b"GIF87a", b"GIF89a")):
        return TypeInfo("gif")
    if head.startswith(b"BM") and len(head) > 14 and src.ext in ("bmp", "dib"):
        return TypeInfo("bmp")
    if head.startswith((b"II*\x00", b"MM\x00*")):
        return TypeInfo("tiff")
    if head.startswith(b"RIFF") and head[8:12] == b"WEBP":
        return TypeInfo("webp")
    if head[4:8] == b"ftyp" and head[8:12] in (b"avif", b"avis"):
        return TypeInfo("avif")
    if head[4:8] == b"ftyp" and head[8:12] in (b"heic", b"heix", b"hevc", b"heim", b"heis", b"mif1", b"msf1"):
        return TypeInfo("heic")
    if head.startswith(b"\x00\x00\x01\x00") and src.ext == "ico":
        return TypeInfo("ico")
    if head.startswith(b"\x1f\x8b"):
        return TypeInfo("gz")
    if head.startswith(b"BZh"):
        return TypeInfo("bz2")
    if head.startswith(b"\xfd7zXZ\x00"):
        return TypeInfo("xz")
    if head.startswith(b"7z\xbc\xaf\x27\x1c"):
        return TypeInfo("7z")
    if head.startswith(b"Rar!\x1a\x07"):
        return TypeInfo("rar")
    if len(head) > 262 and head[257:262] == b"ustar":
        return TypeInfo("tar")
    if len(head) >= 68 and head[60:68] == b"BOOKMOBI":
        return TypeInfo("mobi")
    if head.startswith(b"{\\rtf"):
        return TypeInfo("rtf")
    if not _looks_like_text(head):
        return TypeInfo("binary")
    # text: the bytes say it is text; the extension and the first characters say which
    lower = head[:2048].lstrip(b"\xef\xbb\xbf \t\r\n").lower()
    if b"<svg" in lower[:1024] and (lower.startswith(b"<?xml") or lower.startswith(b"<svg") or lower.startswith(b"<!doctype svg")):
        return TypeInfo("svg")
    if b"<fictionbook" in lower[:1024]:
        return TypeInfo("fb2")
    by_ext = TEXT_EXT.get(src.ext)
    if by_ext:
        return TypeInfo(by_ext)
    if lower.startswith(b"<!doctype html") or lower.startswith(b"<html"):
        return TypeInfo("html")
    if lower.startswith(b"<?xml"):
        return TypeInfo("xml")
    return TypeInfo("txt")


# ===========================================================================
# 5. WORKING FILES FOR CLASSIFY, AND THE CONTEXT OF ONE READ
# ===========================================================================
class Scope(object):
    """What every object of one queue shares: the settings, the run, whether to write working files,
    the stop, the fingerprint lookup, the temporary-disk budget. Safe to use from the reading threads."""

    def __init__(self, settings, run_id, write, full, stop_event, lookup=None, budget=None, on_bytes=None, touch=None):
        self.settings = settings
        self.run_id = run_id
        self.write = write                  # the run has a classify stage: working files are written
        self.full = full                    # a force run: no lookup, everything is read
        self.stop = stop_event
        self.lookup = lookup                # sha256 -> {extracted, why, ...} or None; None when the function is absent
        self.budget = budget or Budget(settings.scan_tmp_max_mb * _MB)
        self.on_bytes = on_bytes
        self.touch = touch
        self.spool_dir = os.path.join(settings.scan_tmp, settings.service)

    def run_dir(self):
        return os.path.join(self.settings.work_dir, str(self.run_id))


class ReadCtx(object):
    """One object being read, at one level of nesting. Children share the object's parts, its refs,
    its working files and its archive total."""

    def __init__(self, scope, location_id, depth=1, parent_ref=None, shared=None):
        self.scope = scope
        self.settings = scope.settings
        self.budget = scope.budget
        self.location_id = location_id
        self.depth = depth
        self.parent_ref = parent_ref
        self.shared = shared if shared is not None else {"parts": [], "next_ref": 0, "written": [], "expanded": 0}

    @property
    def parts(self):
        return self.shared["parts"]

    def child(self, ref):
        return ReadCtx(self.scope, self.location_id, self.depth + 1, ref, self.shared)

    def next_ref(self):
        self.shared["next_ref"] += 1
        return str(self.shared["next_ref"])

    def check(self):
        if self.scope.stop.is_set():
            raise Stopped()

    def add_expanded(self, n):
        self.shared["expanded"] += n
        if self.shared["expanded"] > self.settings.archive_max_mb * _MB:
            raise ScanFail("archive_too_large", whole_archive=True, limit_mb=self.settings.archive_max_mb)

    def add_bytes_read(self, n):
        if self.scope.on_bytes is not None:
            self.scope.on_bytes(n)

    def new_spool_file(self):
        os.makedirs(self.scope.spool_dir, exist_ok=True)
        path = os.path.join(self.scope.spool_dir, uuid.uuid4().hex + ".spool")
        fh = open(path, "wb")
        return fh, path

    def sink(self, ref, shape, obj_type, columns=None):
        if not self.scope.write:
            return NullSink(shape)
        return Sink(self, ref, shape, obj_type, columns)

    def forget_written(self, refs):
        """Removes the working files of the parts named (a failed archive's descendants)."""
        keep = []
        for ref, path in self.shared["written"]:
            if ref in refs:
                remove_tree(path)
            else:
                keep.append((ref, path))
        self.shared["written"] = keep

    def discard_from(self, index):
        """Drops parts from index on (the descendants of a part that failed), and their working files."""
        gone = self.parts[index:]
        del self.parts[index:]
        refs = set(p["ref"] for p in gone)
        if refs:
            self.forget_written(refs)


def remove_tree(path):
    try:
        if os.path.isdir(path):
            shutil.rmtree(path, ignore_errors=True)
        elif os.path.exists(path):
            os.remove(path)
    except OSError:
        pass


def tree_bytes(path):
    total = 0
    try:
        for name in os.listdir(path):
            p = os.path.join(path, name)
            if os.path.isfile(p):
                total += os.path.getsize(p)
    except OSError:
        pass
    return total


class NullSink(object):
    """No classify stage: nothing is written; rows are counted and dropped."""

    def __init__(self, shape):
        self.shape = shape
        self.rows = 0
        self.chars = 0
        self.bytes_out = 0

    def add_text(self, text, row_id=None, other=None):
        self.rows += 1
        self.chars += len(text)

    def add_row(self, values, row_id=None, other=None):
        self.rows += 1

    def finish(self):
        return None

    def abort(self):
        pass


class Sink(object):
    """The working files of one object or part: part-NNNNN.parquet, shape text (data, ds_key) or rows
    (one column per source column, then ds_key), written under a temporary name in the run's folder and
    renamed into place when complete, so classify never meets half a file."""

    def __init__(self, ctx, ref, shape, obj_type, columns=None):
        import pyarrow  # noqa: F401  (fail early, inside the object's own error handling)
        scope = ctx.scope
        self.ctx = ctx
        self.ref = ref
        self.shape = shape
        self.obj_type = obj_type
        self.run_id = scope.run_id
        self.location_id = ctx.location_id
        self.rel = "%s/%s%s" % (scope.run_id, ctx.location_id, ("-" + ref) if ref else "")
        self.final = os.path.join(scope.settings.work_dir, self.rel)
        self.tmp = os.path.join(scope.run_dir(), ".tmp-%s-%s" % (scope.settings.service, uuid.uuid4().hex))
        self.columns = list(columns or [])
        self.rows = 0
        self.chars = 0
        self.parts = 0
        self.bytes_out = 0
        self._data = [] if shape == "text" else [[] for _ in self.columns]
        self._keys = []
        self._buf_chars = 0
        self._opened = False

    def _key(self, row_id, other):
        d = {"location_id": self.location_id, "ref": self.ref, "row_id": row_id, "run_id": self.run_id, "obj_type": self.obj_type}
        if other:
            d["other"] = other
        return json.dumps(d, ensure_ascii=False, separators=(",", ":"))

    def add_text(self, text, row_id=None, other=None):
        self.rows += 1
        self.chars += len(text)
        self._buf_chars += len(text)
        self._data.append(text)
        self._keys.append(self._key(row_id if row_id is not None else self.rows, other))
        if len(self._keys) >= TABLE_PART_ROWS or self._buf_chars >= TEXT_PART_CHARS:
            self._flush()

    def add_row(self, values, row_id=None, other=None):
        self.rows += 1
        width = len(self.columns)
        for i in range(width):
            v = values[i] if i < len(values) else None
            if v is not None:
                self.chars += len(v)
                self._buf_chars += len(v)
            self._data[i].append(v)
        self._keys.append(self._key(row_id if row_id is not None else self.rows, other))
        if len(self._keys) >= TABLE_PART_ROWS or self._buf_chars >= TEXT_PART_CHARS:
            self._flush()

    def _flush(self):
        if not self._keys:
            return
        import pyarrow as pa
        import pyarrow.parquet as pq
        if not self._opened:
            os.makedirs(self.tmp, exist_ok=True)
            self._opened = True
        if self.shape == "text":
            arrays = [pa.array(self._data, type=pa.string()), pa.array(self._keys, type=pa.string())]
            names = ["data", "ds_key"]
            self._data = []
        else:
            arrays = [pa.array(col, type=pa.string()) for col in self._data] + [pa.array(self._keys, type=pa.string())]
            names = list(self.columns) + ["ds_key"]
            self._data = [[] for _ in self.columns]
        path = os.path.join(self.tmp, "part-%05d.parquet" % self.parts)
        pq.write_table(pa.Table.from_arrays(arrays, names=names), path, compression="snappy")
        self.parts += 1
        self._keys = []
        self._buf_chars = 0

    def finish(self):
        """Renames the files into place: the extract, or None when nothing was extracted."""
        self._flush()
        if not self._opened or self.rows == 0:
            self.abort()
            return None
        remove_tree(self.final)
        os.rename(self.tmp, self.final)
        self.bytes_out = tree_bytes(self.final)
        self.ctx.shared["written"].append((self.ref, self.final))
        return {"path": self.rel, "shape": self.shape, "parts": self.parts, "rows": self.rows}

    def abort(self):
        if self._opened:
            remove_tree(self.tmp)
            self._opened = False


def read_result(extracted=True, why=None, meta=None, sink=None, columns=None, extract=None):
    """What a reader found, in the hand-in's terms."""
    out = {"read": {"extracted": bool(extracted), "why": why, "scan_version": VERSION},
           "meta": meta or {}, "rows": None, "chars": None, "columns": columns, "extract": extract, "bytes_out": 0}
    if sink is not None and extracted:
        out["extract"] = sink.finish()
        out["bytes_out"] = sink.bytes_out
        out["rows"] = sink.rows
        out["chars"] = sink.chars
    return out


def no_classify_result(meta=None, columns=None):
    """The run has no classify stage: nothing is extracted, and a later run with one reads it again."""
    return read_result(False, "no_classify_stage", meta=meta, columns=columns)


# ===========================================================================
# 6. READERS
#   Each takes (src, ctx, ti) and returns read_result(...). A reader that finds parts (an archive's
#   entries, a document's embedded files, a workbook's sheets) appends them to ctx.parts.
#   Every long loop calls ctx.check() between rows, pages, entries or chunks: a stop is honoured there.
# ===========================================================================

# ---------------------------------------------------------------------------
# 6.1 text lines (txt, and the fall-back for JSON and CSV that can't be read as such)
# ---------------------------------------------------------------------------
LINE_PIECE = 1 << 20


def _bom_encoding(head):
    if head.startswith(codecs.BOM_UTF8):
        return "utf-8-sig"
    if head.startswith(codecs.BOM_UTF32_LE) or head.startswith(codecs.BOM_UTF32_BE):
        return "utf-32"
    if head.startswith(codecs.BOM_UTF16_LE) or head.startswith(codecs.BOM_UTF16_BE):
        return "utf-16"
    return None


def iter_text_pieces(fobj, head, ctx):
    """The text of a file as lines (or pieces of at most 1 MiB of a longer line): a BOM's encoding when
    there is one, otherwise UTF-8 line by line, falling back to cp1252 for a line that isn't UTF-8."""
    enc = _bom_encoding(head or b"")
    if enc:
        reader = io.TextIOWrapper(fobj, encoding=enc, errors="replace", newline=None)
        while True:
            ctx.check()
            piece = reader.readline(LINE_PIECE)
            if not piece:
                return
            yield piece
    carry = b""
    while True:
        ctx.check()
        raw = fobj.readline(LINE_PIECE)
        if not raw:
            if carry:
                yield carry.decode("cp1252", errors="replace")
            return
        raw = carry + raw
        carry = b""
        try:
            yield raw.decode("utf-8")
        except UnicodeDecodeError as e:
            if not raw.endswith(b"\n") and e.start >= len(raw) - 3 and e.reason.startswith("unexpected end"):
                good = raw[:e.start]
                carry = raw[e.start:]
                if good:
                    yield good.decode("utf-8", errors="replace")
            else:
                yield raw.decode("cp1252", errors="replace")


def _sink_ref(ctx):
    """The ref a reader's working files belong to: None for the object itself, else the part being read."""
    return ctx.parent_ref


def read_text(src, ctx, ti, obj_type="text"):
    if not ctx.scope.write:
        return no_classify_result()
    sink = ctx.sink(_sink_ref(ctx), "text", obj_type)
    try:
        n = 0
        with src.open() as fh:
            for piece in iter_text_pieces(fh, src.head, ctx):
                for row in split_unit(piece):
                    n += 1
                    sink.add_text(row, n)
        meta = {"encoding": _bom_encoding(src.head or b"") or "utf-8/cp1252"}
        return read_result(True, meta=meta, sink=sink)
    except BaseException:
        sink.abort()
        raise


# ---------------------------------------------------------------------------
# 6.2 typed rows: the spreadsheet header rules, shared by xlsx, xls and csv (V1 2025.41.1, unchanged)
#   Header detection is a confidence call: all four conditions must pass; otherwise col_N and row 1 stays
#   a data row. Losing a real record is the only failure worse than no headers.
# ---------------------------------------------------------------------------
_XLSX_LOOKAHEAD = 100
_XLSX_HEADER_MAX_LEN = 64
_XLSX_DTYPE_MAJORITY = 0.90
_XLSX_COLUMN_CAP = 1000
_XLSX_SHARED_MAX_ENTRIES = 5_000_000
_XLSX_SHARED_MAX_BYTES = 1_500_000_000
_XLSX_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_XLSX_BUILTIN_DATE_FMTS = {14, 15, 16, 17, 18, 19, 20, 21, 22, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 45, 46, 47, 50, 51, 52, 53,
                           54, 55, 56, 57, 58}
_XLSX_FMT_STRIP_RE = re.compile(r'(\[[^\]]*\])|("[^"]*")|(\\.)')
_XLSX_FMT_DATE_RE = re.compile(r"[dmhysDMHYS]")
_T_STR, _T_NUM, _T_DATE, _T_BOOL, _T_ERR = "s", "n", "d", "b", "e"


class SheetLimit(Exception):
    """A sheet breaks a configured spreadsheet limit (the column cap, the shared strings)."""


def _header_verdict(buffer_rows, width):
    verdict = {"is_header": False,
               "conditions": {"textual_short": False, "typologically_distinct": False, "no_verbatim_repeat": False, "not_sparser": False},
               "failed": [], "header_candidate": []}
    if not buffer_rows:
        verdict["failed"] = list(verdict["conditions"].keys())
        return verdict
    row1 = list(buffer_rows[0]) + [None] * (width - len(buffer_rows[0]))
    body = buffer_rows[1:]
    verdict["header_candidate"] = [(c[0] if c is not None else None) for c in row1]
    nonempty = [c for c in row1 if c is not None]
    c1 = bool(nonempty) and all(c[1] == _T_STR and len(c[0]) <= _XLSX_HEADER_MAX_LEN and "\n" not in c[0] for c in nonempty)
    verdict["conditions"]["textual_short"] = c1
    col_cells = []
    for ci in range(width):
        col_cells.append([r[ci] for r in body if ci < len(r) and r[ci] is not None])
    c2 = False
    for ci in range(width):
        h = row1[ci]
        cells = col_cells[ci]
        if h is None or h[1] != _T_STR or len(cells) < 3:
            continue
        n = len(cells)
        num_share = sum(1 for v in cells if v[1] in (_T_NUM, _T_BOOL)) / n
        date_share = sum(1 for v in cells if v[1] == _T_DATE) / n
        email_share = sum(1 for v in cells if v[1] == _T_STR and _XLSX_EMAIL_RE.match(v[0] or "")) / n
        if num_share >= _XLSX_DTYPE_MAJORITY or date_share >= _XLSX_DTYPE_MAJORITY:
            c2 = True
            break
        if email_share >= _XLSX_DTYPE_MAJORITY and not _XLSX_EMAIL_RE.match(h[0] or ""):
            c2 = True
            break
    verdict["conditions"]["typologically_distinct"] = c2
    c3 = True
    for ci in range(width):
        h = row1[ci]
        if h is not None and any(v[0] == h[0] for v in col_cells[ci]):
            c3 = False
            break
    verdict["conditions"]["no_verbatim_repeat"] = c3
    if body:
        empties = sorted(sum(1 for ci in range(width) if ci >= len(r) or r[ci] is None) for r in body)
        median_empty = empties[len(empties) // 2]
    else:
        median_empty = 0
    c4 = sum(1 for c in row1 if c is None) <= median_empty
    verdict["conditions"]["not_sparser"] = c4
    verdict["is_header"] = c1 and c2 and c3 and c4
    verdict["failed"] = [k for k, ok in verdict["conditions"].items() if not ok]
    return verdict


def _normalize_header(text):
    return re.sub(r"\s+", " ", pg_safe_str(text)).strip()


def _column_names(verdict, width):
    if verdict["is_header"]:
        names = []
        for ci in range(width):
            cand = verdict["header_candidate"][ci] if ci < len(verdict["header_candidate"]) else None
            names.append(_normalize_header(cand) if cand else "col_%d" % (ci + 1))
    else:
        names = ["col_%d" % (ci + 1) for ci in range(width)]
    seen = {"ds_key": 1}
    out = []
    for name in names:
        base = name if name else "col"
        if base not in seen:
            seen[base] = 1
            out.append(base)
        else:
            seen[base] += 1
            out.append("%s_%d" % (base, seen[base]))
    return out


def emit_rowshape(make_rows, sheet_name, ctx, ref, max_width, obj_type="spreadsheet", region=True):
    """Streams typed rows into a sink: one row per source row, one column per source column, the header
    decided on a look-ahead. Returns (sink, columns, verdict, dtypes)."""
    if max_width > _XLSX_COLUMN_CAP:
        raise SheetLimit("more than %d columns" % _XLSX_COLUMN_CAP)
    source = iter(make_rows())
    buffer = []
    for numbered in source:
        buffer.append(numbered)
        if len(buffer) >= _XLSX_LOOKAHEAD:
            break
    verdict = _header_verdict([r for _n, r in buffer], max_width)
    columns = _column_names(verdict, max_width)
    data_buffer = buffer[1:] if verdict["is_header"] else buffer
    sink = ctx.sink(ref, "rows", obj_type, columns)
    other = {"data_region": pg_safe_str(str(sheet_name))} if (region and sheet_name is not None) else None
    type_counts = [dict(s=0, n=0, d=0, b=0, e=0) for _ in range(max_width)]
    try:
        def take(row_num, typed):
            values = []
            for ci in range(max_width):
                cell = typed[ci] if ci < len(typed) else None
                if cell is None:
                    values.append(None)
                else:
                    values.append(clean_text(cell[0]))
                    type_counts[ci][cell[1]] += 1
            sink.add_row(values, row_num, other)

        for i, (row_num, typed) in enumerate(data_buffer):
            take(row_num, typed)
        k = 0
        for row_num, typed in source:
            k += 1
            if k % 256 == 0:
                ctx.check()
            take(row_num, typed)
    except BaseException:
        sink.abort()
        raise
    dtypes = []
    for c in type_counts:
        filled = c["s"] + c["n"] + c["d"] + c["b"] + c["e"]
        if filled and (c["n"] + c["b"]) / filled >= _XLSX_DTYPE_MAJORITY:
            dtypes.append("number")
        elif filled and c["d"] / filled >= _XLSX_DTYPE_MAJORITY:
            dtypes.append("date")
        else:
            dtypes.append("string")
    return sink, columns, verdict, dtypes


def _columns_json(columns, dtypes):
    return [{"name": columns[i], "pos": i, "dtype": dtypes[i]} for i in range(len(columns))]


def sheet_part(ctx, name, position, prescan, emit):
    """One sheet of a workbook as a part: is_asset false, part_type sheet, no bytes of its own. A sheet
    without data isn't a part; it is listed in the workbook's meta."""
    safe = (pg_safe_str(str(name)) or ("Sheet %d" % position))[:PART_NAME_MAX]
    entry = {"name": safe, "position": position}
    try:
        data_rows, max_width = prescan()
    except SheetLimit as e:
        data_rows, max_width = None, 0
        entry["error"] = str(e)
    except Stopped:
        raise
    except Exception as e:
        data_rows, max_width = None, 0
        entry["error"] = type(e).__name__
    if data_rows == 0:
        entry.update(status="empty", rows=0)
        return entry
    ref = ctx.next_ref()
    part = {"ref": ref, "parent_ref": ctx.parent_ref, "inner_path": safe, "name": safe, "is_asset": False, "part_type": "sheet",
            "content": None}
    ctx.parts.append(part)
    entry["ref"] = ref
    if data_rows is None:
        part.update(outcome="failed", bytes_out=0, **_reason_fields(reason("object_unreadable", reason=entry["error"])))
        entry["status"] = "error"
        return entry
    try:
        sink, columns, verdict, dtypes = emit(ref, max_width)
        cols = _columns_json(columns, dtypes)
        if ctx.scope.write:
            res = read_result(True, meta={"header": verdict["is_header"], "header_failed": verdict["failed"]}, sink=sink, columns=cols)
        else:
            res = no_classify_result(meta={"header": verdict["is_header"], "header_failed": verdict["failed"]}, columns=cols)
        part.update(outcome="done", **_done_fields(res))
        entry.update(status="scanned", rows=data_rows, columns=len(columns))
    except Stopped:
        raise
    except SheetLimit as e:
        part.update(outcome="failed", bytes_out=0, **_reason_fields(reason("object_unreadable", reason=str(e))))
        entry["status"] = "error"
    except Exception as e:
        part.update(outcome="failed", bytes_out=0, **_reason_fields(reason("object_unreadable", reason=type(e).__name__)))
        entry["status"] = "error"
    return entry


def _reason_fields(r):
    return {"code": r["code"], "params": r["params"], "text": r["text"]}


def _done_fields(res):
    return {"bytes_out": res["bytes_out"], "read": res["read"], "meta": cap_meta(res["meta"]), "rows": res["rows"],
            "chars": res["chars"], "columns": res["columns"], "extract": res["extract"]}


# ---------------------------------------------------------------------------
# 6.3 xlsx (V1 2025.41.1 streaming reader: the workbook is a container, each sheet with data a part)
# ---------------------------------------------------------------------------
def _xl_local(tag):
    return tag.rsplit("}", 1)[-1] if isinstance(tag, str) else tag


def _xl_attr(elem, name):
    val = elem.get(name)
    if val is not None:
        return val
    for k, v in elem.attrib.items():
        if _xl_local(k) == name:
            return v
    return None


def _xl_iterparse(fobj, end_tags):
    from lxml import etree
    for _event, elem in etree.iterparse(fobj, events=("end",), huge_tree=True, resolve_entities=False, no_network=True):
        name = _xl_local(elem.tag)
        if name in end_tags:
            yield name, elem
            elem.clear()


def _xl_is_date_format(fmt_code):
    if not fmt_code:
        return False
    return bool(_XLSX_FMT_DATE_RE.search(_XLSX_FMT_STRIP_RE.sub("", fmt_code)))


def _xl_date_styles(zf):
    date_xf = set()
    try:
        if "xl/styles.xml" not in zf.namelist():
            return date_xf
        custom = set()
        xf_numfmt = []
        with zf.open("xl/styles.xml") as fh:
            for name, elem in _xl_iterparse(fh, {"numFmt", "cellXfs"}):
                if name == "numFmt":
                    fid = _xl_attr(elem, "numFmtId")
                    if fid is not None and _xl_is_date_format(_xl_attr(elem, "formatCode")):
                        custom.add(int(fid))
                else:
                    for xf in elem:
                        if _xl_local(xf.tag) == "xf":
                            fid = _xl_attr(xf, "numFmtId")
                            xf_numfmt.append(int(fid) if fid is not None else 0)
        for idx, fid in enumerate(xf_numfmt):
            if fid in _XLSX_BUILTIN_DATE_FMTS or fid in custom:
                date_xf.add(idx)
    except Exception:
        pass
    return date_xf


def _xl_shared_strings(zf, ctx):
    shared = []
    if "xl/sharedStrings.xml" not in zf.namelist():
        return shared
    total = 0
    with zf.open("xl/sharedStrings.xml") as fh:
        for _name, si in _xl_iterparse(fh, {"si"}):
            parts = []
            for child in si.iter():
                cname = _xl_local(child.tag)
                if cname == "rPh":
                    for t in child.iter():
                        t.text = None
                elif cname == "t" and child.text:
                    parts.append(child.text)
            text = "".join(parts)
            shared.append(text)
            total += len(text)
            if len(shared) % 10000 == 0:
                ctx.check()
            if len(shared) > _XLSX_SHARED_MAX_ENTRIES or total > _XLSX_SHARED_MAX_BYTES:
                raise SheetLimit("shared strings exceed the limit")
    return shared


def _xl_sheets(zf):
    rels = {}
    rels_path = "xl/_rels/workbook.xml.rels"
    if rels_path in zf.namelist():
        with zf.open(rels_path) as fh:
            for _n, rel in _xl_iterparse(fh, {"Relationship"}):
                rid = _xl_attr(rel, "Id")
                target = _xl_attr(rel, "Target") or ""
                if target.startswith("/"):
                    target = target.lstrip("/")
                elif not target.startswith("xl/"):
                    target = "xl/" + target
                rels[rid] = target
    sheets = []
    date1904 = False
    names = set(zf.namelist())
    with zf.open("xl/workbook.xml") as fh:
        for name, elem in _xl_iterparse(fh, {"sheet", "workbookPr"}):
            if name == "workbookPr":
                date1904 = str(_xl_attr(elem, "date1904")).lower() in ("1", "true")
                continue
            target = rels.get(_xl_attr(elem, "id"))
            if target is None:
                target = "xl/worksheets/sheet%s.xml" % _xl_attr(elem, "sheetId")
            if target in names:
                sheets.append({"name": _xl_attr(elem, "name"), "target": target})
    return sheets, date1904


def _xl_render_date(serial, date1904):
    if 0 <= serial < 1:
        total = round(serial * 86400)
        h, rem = divmod(total, 3600)
        m, s = divmod(rem, 60)
        return "%02d:%02d:%02d" % (h, m, s)
    epoch = dt.datetime(1904, 1, 1) if date1904 else dt.datetime(1899, 12, 30)
    d = epoch + dt.timedelta(days=serial)
    if abs(serial - int(serial)) < 1e-9:
        return d.strftime("%Y-%m-%d")
    return d.strftime("%Y-%m-%d %H:%M:%S")


def _xl_split_ref(cell_ref):
    for i, ch in enumerate(cell_ref):
        if "0" <= ch <= "9":
            return cell_ref[:i], cell_ref[i:]
    return cell_ref, ""


@lru_cache(maxsize=None)
def _xl_col2idx(letters):
    idx = 0
    for ch in letters:
        idx = idx * 26 + (ord(ch) - ord("A")) + 1
    return idx


def _xl_render_cell(cell, shared, date_xf, date1904):
    ctype = _xl_attr(cell, "t") or ""
    style = _xl_attr(cell, "s")
    raw = None
    inline = None
    for child in cell:
        cname = _xl_local(child.tag)
        if cname == "v":
            raw = child.text
        elif cname == "is":
            inline = "".join(t.text for t in child.iter() if _xl_local(t.tag) == "t" and t.text)
    if ctype == "inlineStr":
        return (inline if inline else None), _T_STR
    if raw is None or raw == "":
        return None, _T_STR
    if ctype == "s":
        try:
            text = shared[int(raw)]
        except (ValueError, IndexError):
            text = raw
        return (text if text != "" else None), _T_STR
    if ctype == "str":
        return raw, _T_STR
    if ctype == "b":
        return ("TRUE" if raw.strip() == "1" else "FALSE"), _T_BOOL
    if ctype == "e":
        return raw, _T_ERR
    try:
        if style is not None and int(style) in date_xf:
            return _xl_render_date(float(raw), date1904), _T_DATE
    except (ValueError, OverflowError):
        return raw, _T_NUM
    return raw, _T_NUM


def _xl_typed_rows(zf, target, shared, date_xf, date1904):
    seq_row = 0
    with zf.open(target) as fh:
        for _name, row in _xl_iterparse(fh, {"row"}):
            r_attr = _xl_attr(row, "r")
            seq_row = int(r_attr) if r_attr else seq_row + 1
            out = []
            seq_col = -1
            for cell in row:
                if _xl_local(cell.tag) != "c":
                    continue
                ref = _xl_attr(cell, "r")
                if ref:
                    ci = _xl_col2idx(_xl_split_ref(ref)[0]) - 1
                else:
                    ci = seq_col + 1
                seq_col = ci
                val, ntype = _xl_render_cell(cell, shared, date_xf, date1904)
                while len(out) < ci:
                    out.append(None)
                out.append((val, ntype) if val is not None else None)
            while out and out[-1] is None:
                out.pop()
            if out:
                yield seq_row, out


def _prescan(make_rows, ctx):
    data_rows = 0
    max_width = 0
    for _num, typed in make_rows():
        data_rows += 1
        if data_rows % 1024 == 0:
            ctx.check()
        if len(typed) > max_width:
            max_width = len(typed)
    return data_rows, max_width


def _workbook_result(ctx, sheet_list, meta_extra=None):
    meta = {"is_container": True, "shape": "workbook", "sheets": sheet_list}
    if meta_extra:
        meta.update(meta_extra)
    return read_result(False, "container", meta=meta)


def read_xlsx(src, ctx, ti):
    with src.open() as fh:
        zf = zipfile.ZipFile(fh)
        sheets, date1904 = _xl_sheets(zf)
        date_xf = _xl_date_styles(zf)
        try:
            shared = _xl_shared_strings(zf, ctx)
        except SheetLimit as e:
            raise ScanFail("object_unreadable", reason=str(e))
        sheet_list = []
        for i, sh in enumerate(sheets):
            ctx.check()

            def make_rows(sh=sh):
                return _xl_typed_rows(zf, sh["target"], shared, date_xf, date1904)

            entry = sheet_part(ctx, sh["name"], i + 1, lambda mk=make_rows: _prescan(mk, ctx),
                               lambda ref, w, mk=make_rows, nm=sh["name"]: emit_rowshape(mk, nm, ctx, ref, w))
            sheet_list.append(entry)
        try:
            props = office_properties(zf)
        except Exception:
            props = {}
        return _workbook_result(ctx, sheet_list, props)


# ---------------------------------------------------------------------------
# 6.4 xls (xlrd, the same model as xlsx)
# ---------------------------------------------------------------------------
def _xls_typed_rows(sheet, datemode):
    import xlrd
    for r in range(sheet.nrows):
        out = []
        for cell in sheet.row(r):
            ct, v = cell.ctype, cell.value
            if ct in (xlrd.XL_CELL_EMPTY, xlrd.XL_CELL_BLANK):
                out.append(None)
                continue
            if ct == xlrd.XL_CELL_TEXT:
                item = (v, _T_STR) if v != "" else None
            elif ct == xlrd.XL_CELL_NUMBER:
                item = (str(int(v)) if float(v).is_integer() and abs(v) < 1e15 else repr(float(v)), _T_NUM)
            elif ct == xlrd.XL_CELL_DATE:
                try:
                    item = (_xl_render_date(float(v), datemode == 1), _T_DATE)
                except Exception:
                    item = (repr(v), _T_NUM)
            elif ct == xlrd.XL_CELL_BOOLEAN:
                item = ("TRUE" if v else "FALSE", _T_BOOL)
            elif ct == xlrd.XL_CELL_ERROR:
                item = (xlrd.error_text_from_code.get(v, "#ERR"), _T_ERR)
            else:
                item = (str(v), _T_STR)
            out.append(item)
        while out and out[-1] is None:
            out.pop()
        if out:
            yield r + 1, out


def read_xls(src, ctx, ti):
    import xlrd
    try:
        path, data = src.for_library(ctx)
        if path is not None:
            book = xlrd.open_workbook(path, on_demand=True, logfile=io.StringIO(), ignore_workbook_corruption=True)
        else:
            book = xlrd.open_workbook(file_contents=data, on_demand=True, logfile=io.StringIO(), ignore_workbook_corruption=True)
    except xlrd.biffh.XLRDError as e:
        if "encrypt" in str(e).lower():
            raise ScanFail("object_encrypted")
        raise ScanFail("object_unreadable", reason="not a readable Excel 97-2003 workbook")
    try:
        names = book.sheet_names()
        sheet_list = []
        for i, nm in enumerate(names):
            ctx.check()

            def make_rows(i=i):
                return _xls_typed_rows(book.sheet_by_index(i), book.datemode)

            entry = sheet_part(ctx, nm, i + 1, lambda mk=make_rows: _prescan(mk, ctx),
                               lambda ref, w, mk=make_rows, n=nm: emit_rowshape(mk, n, ctx, ref, w))
            try:
                book.unload_sheet(i)
            except Exception:
                pass
            sheet_list.append(entry)
        return _workbook_result(ctx, sheet_list)
    finally:
        try:
            book.release_resources()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# 6.5 csv: streamed with the csv module, typed by pattern, header by the same confidence rules
# ---------------------------------------------------------------------------
_NUM_RE = re.compile(r"^[-+]?(\d{1,3}(,\d{3})+|\d+)?(\.\d+)?([eE][-+]?\d+)?%?$")
_DATE_RE = re.compile(r"^(\d{4}-\d{1,2}-\d{1,2}([ T]\d{1,2}:\d{2}(:\d{2}(\.\d+)?)?(Z|[+-]\d{2}:?\d{2})?)?"
                      r"|\d{1,2}[/.-]\d{1,2}[/.-]\d{2,4}|\d{1,2}[ -][A-Za-z]{3,9}[ -]\d{2,4})$")
_BOOL_VALUES = {"true", "false", "yes", "no"}
CSV_FIELD_LIMIT = 16 * _MB
_DELIMS = {",": "comma", ";": "semicolon", "\t": "tab", "|": "pipe"}


def _type_of(value):
    v = value.strip()
    if not v:
        return None
    if any(ch.isdigit() for ch in v) and _NUM_RE.match(v):
        return (value, _T_NUM)
    if _DATE_RE.match(v):
        return (value, _T_DATE)
    if v.lower() in _BOOL_VALUES:
        return (value, _T_BOOL)
    return (value, _T_STR)


def _fix_cell(s):
    """A cell read with surrogateescape: bytes that weren't UTF-8 are read again as cp1252."""
    if any("\udc80" <= ch <= "\udcff" for ch in s):
        return s.encode("utf-8", "surrogateescape").decode("cp1252", errors="replace")
    return s


def _csv_delimiter(src):
    if src.ext in ("tsv", "tab"):
        return "\t"
    head = decode_bytes(src.head[:8192])
    try:
        return csv.Sniffer().sniff(head, delimiters=",;\t|").delimiter
    except csv.Error:
        return ","


def _csv_rows(src, delim):
    def gen():
        csv.field_size_limit(CSV_FIELD_LIMIT)
        with src.open() as raw:
            enc = _bom_encoding(src.head or b"")
            text = io.TextIOWrapper(raw, encoding=enc or "utf-8", errors="replace" if enc else "surrogateescape", newline="")
            n = 0
            for rec in csv.reader(text, delimiter=delim):
                n += 1
                out = [(_type_of(_fix_cell(v)) if v != "" else None) for v in rec]
                while out and out[-1] is None:
                    out.pop()
                if out:
                    yield n, out
    return gen


def read_csv(src, ctx, ti):
    delim = _csv_delimiter(src)
    make_rows = _csv_rows(src, delim)
    try:
        data_rows, width = _prescan(make_rows, ctx)
    except csv.Error:
        # a field past the limit, or a file the csv module can't follow: read as text lines
        return read_text(src, ctx, ti, obj_type="text")
    if width > _XLSX_COLUMN_CAP:
        return read_text(src, ctx, ti, obj_type="text")
    if not ctx.scope.write:
        buffer = []
        for numbered in make_rows():
            buffer.append(numbered)
            if len(buffer) >= _XLSX_LOOKAHEAD:
                break
        verdict = _header_verdict([r for _n, r in buffer], width)
        columns = _column_names(verdict, width)
        return no_classify_result(meta={"delimiter": _DELIMS.get(delim, "other"), "header": verdict["is_header"]},
                                  columns=[{"name": c, "pos": i, "dtype": "string"} for i, c in enumerate(columns)])
    sink, columns, verdict, dtypes = emit_rowshape(make_rows, None, ctx, _sink_ref(ctx), width, obj_type="table", region=False)
    meta = {"delimiter": _DELIMS.get(delim, "other"), "header": verdict["is_header"], "header_failed": verdict["failed"]}
    return read_result(True, meta=meta, sink=sink, columns=_columns_json(columns, dtypes))


# ---------------------------------------------------------------------------
# 6.6 json: one row per top-level key of each record; a large or invalid file is read as text lines
# ---------------------------------------------------------------------------
JSON_MAX_BYTES = 64 * _MB


def read_json(src, ctx, ti):
    if not ctx.scope.write:
        return no_classify_result()
    if src.size > JSON_MAX_BYTES:
        return read_text(src, ctx, ti, obj_type="json")
    try:
        data = json.loads(decode_bytes(src.bytes()).lstrip("﻿"))
    except (ValueError, RecursionError):
        res = read_text(src, ctx, ti, obj_type="json")
        res["meta"]["json"] = "invalid"
        return res
    records = data if isinstance(data, list) else [data]
    sink = ctx.sink(_sink_ref(ctx), "text", "json")
    try:
        n = 0
        for ri, rec in enumerate(records):
            if ri % 256 == 0:
                ctx.check()
            if isinstance(rec, dict):
                items = rec.items()
            else:
                items = [(None, rec)]
            for key, value in items:
                if isinstance(value, (dict, list)):
                    value = json.dumps(value, ensure_ascii=False)
                text = "" if value is None else str(value)
                other = {"record_index": ri}
                if key is not None:
                    other["json_key"] = pg_safe_str(str(key))
                for row in split_unit(text):
                    n += 1
                    sink.add_text(row, n, other)
        return read_result(True, meta={"records": len(records)}, sink=sink)
    except BaseException:
        sink.abort()
        raise


# ---------------------------------------------------------------------------
# 6.7 xml and html: streamed through lxml's parser target (no tree is built). Text and tails both
#     come through data(), in document order, so nothing after an inline tag is lost.
# ---------------------------------------------------------------------------
class _XmlTarget(object):
    def __init__(self, emit):
        self.emit = emit
        self.buf = []

    def _flush(self):
        if self.buf:
            text = "".join(self.buf)
            self.buf = []
            if text.strip():
                self.emit(text)

    def start(self, tag, attrib, nsmap=None):
        self._flush()

    def end(self, tag):
        self._flush()

    def data(self, text):
        self.buf.append(text)

    def comment(self, text):
        pass

    def pi(self, target, data=None):
        pass

    def close(self):
        self._flush()
        return None


_HTML_SKIP = {"script", "style", "head", "title", "noscript", "template", "xml", "svg", "math"}
_HTML_BLOCK = {"p", "div", "li", "ul", "ol", "tr", "table", "tbody", "thead", "tfoot", "h1", "h2", "h3", "h4", "h5", "h6",
               "blockquote", "pre", "section", "article", "header", "footer", "address", "hr", "dl", "dt", "dd", "form", "fieldset",
               "figure", "figcaption", "caption", "center", "body", "html", "nav", "aside", "main", "details", "summary", "option"}
_HTML_CELL = {"td", "th"}
_WS_RE = re.compile(r"[ \t\r\n\f\v]+")


class _HtmlTarget(object):
    """Visible text by block: a block element ends a row, <br> is a line feed inside it, table cells are
    separated by a space, script and style are dropped, whitespace collapsed as a browser does except
    inside <pre>."""

    def __init__(self, emit):
        self.emit = emit
        self.buf = []
        self.skip = 0
        self.pre = 0

    def _flush(self):
        if self.buf:
            text = "".join(self.buf)
            self.buf = []
            lines = [ln.strip(" ") for ln in text.split("\n")]
            text = "\n".join(ln for ln in lines if ln)
            if text.strip():
                self.emit(text)

    @staticmethod
    def _name(tag):
        return tag.rsplit("}", 1)[-1].lower() if isinstance(tag, str) else ""

    def start(self, tag, attrib, nsmap=None):
        name = self._name(tag)
        if name in _HTML_SKIP:
            self.skip += 1
            return
        if self.skip:
            return
        if name == "pre":
            self.pre += 1
        if name == "br":
            self.buf.append("\n")
        elif name in _HTML_BLOCK:
            self._flush()
        elif name in _HTML_CELL:
            self.buf.append(" ")

    def end(self, tag):
        name = self._name(tag)
        if name in _HTML_SKIP:
            self.skip = max(0, self.skip - 1)
            return
        if self.skip:
            return
        if name in _HTML_BLOCK:
            self._flush()
        if name == "pre":
            self.pre = max(0, self.pre - 1)

    def data(self, text):
        if self.skip:
            return
        self.buf.append(text if self.pre else _WS_RE.sub(" ", text))

    def comment(self, text):
        pass

    def close(self):
        self._flush()
        return None


_META_CHARSET_RE = re.compile(rb"""<meta[^>]+charset\s*=\s*["']?\s*([A-Za-z0-9_.:-]+)""", re.I)


def _html_encoding(head):
    enc = _bom_encoding(head or b"")
    if enc:
        return enc
    m = _META_CHARSET_RE.search(head or b"")
    if m:
        try:
            return codecs.lookup(m.group(1).decode("ascii")).name
        except LookupError:
            pass
    return "utf-8"


def _read_markup(src, ctx, html_mode):
    from lxml import etree
    if not ctx.scope.write:
        return no_classify_result()
    sink = ctx.sink(_sink_ref(ctx), "text", "html" if html_mode else "xml")
    n = [0]

    def emit(text):
        for row in split_unit(text):
            n[0] += 1
            sink.add_text(row, n[0])

    target = _HtmlTarget(emit) if html_mode else _XmlTarget(emit)
    if html_mode:
        parser = etree.HTMLParser(target=target, recover=True, no_network=True, remove_comments=True, remove_pis=True)
    else:
        parser = etree.XMLParser(target=target, recover=True, huge_tree=True, resolve_entities=False, no_network=True, load_dtd=False)
    enc = _html_encoding(src.head) if html_mode else (_bom_encoding(src.head or b"") or None)
    decoder = codecs.getincrementaldecoder(enc)(errors="replace") if (html_mode or enc) else None
    try:
        with src.open() as fh:
            while True:
                ctx.check()
                chunk = fh.read(_MB)
                if not chunk:
                    break
                parser.feed(decoder.decode(chunk) if decoder else chunk)
            if decoder:
                tail = decoder.decode(b"", final=True)
                if tail:
                    parser.feed(tail)
            try:
                parser.close()
            except etree.XMLSyntaxError:
                target.close()
        return read_result(True, sink=sink)
    except etree.XMLSyntaxError:
        target.close()
        return read_result(True, sink=sink)
    except BaseException:
        sink.abort()
        raise


_HTML_META_NAMES = {"author": "author", "description": "comments", "keywords": "keywords", "generator": "application"}
HTML_HEAD_MAX = 256 * 1024


class _HtmlProps(object):
    """The page's <title> and the author, description, keywords and generator of its <meta> tags, up to <body>
    (architect note 2026-48-48 §3.4). Customer text: never logged."""

    def __init__(self):
        self.doc = {}
        self.title = None
        self.done = False

    def start(self, tag, attrib, nsmap=None):
        if self.done:
            return
        name = _HtmlTarget._name(tag)
        if name == "body":
            self.done = True
        elif name == "title" and "title" not in self.doc and self.title is None:
            self.title = []
        elif name == "meta":
            key = _HTML_META_NAMES.get((attrib.get("name") or "").strip().lower())
            content = (attrib.get("content") or "").strip()
            if key and content and key not in self.doc:
                self.doc[key] = _prop_text(_WS_RE.sub(" ", content))

    def end(self, tag):
        name = _HtmlTarget._name(tag)
        if name == "title" and self.title is not None:
            text = _WS_RE.sub(" ", "".join(self.title)).strip()
            if text:
                self.doc["title"] = _prop_text(text)
            self.title = None
        elif name == "head":
            self.done = True

    def data(self, text):
        if self.title is not None and not self.done:
            self.title.append(text)

    def comment(self, text):
        pass

    def close(self):
        return None


def html_properties(src, ctx):
    """meta.doc of a page, from at most its first HTML_HEAD_MAX bytes, with or without a classify stage.
    A page that can't be read for them gives nothing; the object doesn't fail."""
    from lxml import etree
    props = _HtmlProps()
    try:
        parser = etree.HTMLParser(target=props, recover=True, no_network=True, remove_comments=True, remove_pis=True)
        decoder = codecs.getincrementaldecoder(_html_encoding(src.head))(errors="replace")
        with src.open() as fh:
            left = HTML_HEAD_MAX
            while left > 0 and not props.done:
                ctx.check()
                chunk = fh.read(min(64 * 1024, left))
                if not chunk:
                    break
                left -= len(chunk)
                parser.feed(decoder.decode(chunk))
        try:
            parser.close()
        except etree.XMLSyntaxError:
            pass
    except (ScanFail, QueueAbort, Stopped):
        raise
    except Exception:
        return {}
    return {"doc": props.doc} if props.doc else {}


def read_xml(src, ctx, ti):
    return _read_markup(src, ctx, False)


def read_html(src, ctx, ti):
    meta = html_properties(src, ctx)
    out = _read_markup(src, ctx, True)
    if meta:
        out["meta"] = dict(out.get("meta") or {}, **meta)
    return out


# ---------------------------------------------------------------------------
# 6.8 pdf, behind one function (architect note 2026-48-10, ruling 9: the library may change)
# ---------------------------------------------------------------------------
class PdfDocument(object):
    """THE ONE PLACE A PDF LIBRARY IS USED. Today PyMuPDF; replacing it means rewriting this class only.
    .meta (document properties and the page count), .pages() yields (page number from 1, text with its
    line feeds), .close(). An encrypted PDF raises ScanFail(object_encrypted)."""

    LIBRARY = ("PyMuPDF", "pymupdf")     # the distribution and the module, named in the worker's report

    def __init__(self, src, ctx):
        import pymupdf
        try:
            pymupdf.TOOLS.mupdf_display_errors(False)
            pymupdf.TOOLS.mupdf_display_warnings(False)
        except Exception:
            pass
        try:
            path, data = src.for_library(ctx)
            if path is not None:
                self._doc = pymupdf.open(path, filetype="pdf")
            else:
                self._doc = pymupdf.open(stream=data, filetype="pdf")
        except Exception:
            raise ScanFail("object_unreadable", reason="not a readable PDF")
        if self._doc.needs_pass:
            self.close()
            raise ScanFail("object_encrypted")
        md = {"pages": self._doc.page_count}
        try:
            md.update(pdf_properties(self._doc.metadata))
        except Exception:
            pass
        labels = collections.OrderedDict()
        try:
            for (label_id, field), value in self._info_labels().items():
                _add_label_prop(labels, label_id, field, value)
        except Exception:
            pass
        try:
            xmp_doc, xmp_labels = pdf_xmp(self._doc.get_xml_metadata())
            for name, value in xmp_doc.items():          # the info dictionary first; XMP fills what it lacks
                md.setdefault("doc", {}).setdefault(name, value)
            for (label_id, field), value in xmp_labels.items():
                if _LABEL_FIELDS.get(field) not in labels.get(_guid(label_id), {}):
                    _add_label_prop(labels, label_id, field, value)
        except Exception:
            pass
        if labels:
            md["labels"] = _label_list(labels)
        try:
            md["pdf"] = self._security()
        except Exception:
            pass
        self.meta = md

    def _info_labels(self):
        """The MSIP_Label_* keys of the info dictionary, where a labeled Office file saved as PDF can keep them."""
        out = collections.OrderedDict()
        kind, ref = self._doc.xref_get_key(-1, "Info")
        if kind != "xref":
            return out
        info = int(ref.split()[0])
        for key in self._doc.xref_get_keys(info):
            m = _LABEL_RE.match(key)
            if m:
                vkind, value = self._doc.xref_get_key(info, key)
                if vkind in ("string", "name", "bool", "int"):
                    out[(m.group(1), m.group(2))] = value.lstrip("/")
        return out

    def _security(self):
        """meta.pdf (note 2026-48-48 §3.3): the PDF version, whether it is encrypted, what its permissions allow,
        whether it has a form, and how many signature fields are signed. A signature is counted, never verified."""
        md = self._doc.metadata or {}
        fmt = (md.get("format") or "").strip()
        perms = self._doc.permissions
        fields, signed, xfa = self._form_fields()
        return {"version": fmt[4:] if fmt.upper().startswith("PDF ") else (fmt or None),
                "encrypted": bool(md.get("encryption")),
                "permissions": {name: bool(perms & bit) for name, bit in _PDF_PERMS},
                "form": bool(fields or xfa),
                "signatures": signed}

    def _form_fields(self):
        """The form's fields, walked from the catalog's AcroForm without loading a page: (fields, signed signature
        fields, has XFA). A field's type is inherited from its parent. At most PDF_FIELDS_MAX nodes."""
        doc = self._doc
        cat = doc.pdf_catalog()
        kind, _v = doc.xref_get_key(cat, "AcroForm/XFA")
        xfa = kind not in ("null", "")
        kind, value = doc.xref_get_key(cat, "AcroForm/Fields")
        if kind != "array":
            return 0, 0, xfa
        refs = re.compile(r"(\d+)\s+\d+\s+R")
        todo = [(int(x), None) for x in refs.findall(value)]
        seen, fields, signed = set(), 0, 0
        while todo and len(seen) < PDF_FIELDS_MAX:
            xref, parent_type = todo.pop()
            if xref in seen:
                continue
            seen.add(xref)
            ft_kind, ft = doc.xref_get_key(xref, "FT")
            ftype = ft if ft_kind == "name" else parent_type
            kids_kind, kids = doc.xref_get_key(xref, "Kids")
            kid_refs = refs.findall(kids) if kids_kind == "array" else []
            named_kids = [int(k) for k in kid_refs if doc.xref_get_key(int(k), "T")[0] != "null"]
            if named_kids:
                todo.extend((k, ftype) for k in named_kids)
                continue
            fields += 1
            if ftype == "/Sig" and doc.xref_get_key(xref, "V")[0] in ("xref", "dict"):
                signed += 1
        return fields, signed, xfa

    def pages(self):
        for i in range(self._doc.page_count):
            yield i + 1, self._doc.load_page(i).get_text("text")

    def close(self):
        try:
            self._doc.close()
        except Exception:
            pass


def read_pdf(src, ctx, ti):
    doc = PdfDocument(src, ctx)
    try:
        if not ctx.scope.write:
            return no_classify_result(meta=doc.meta)
        sink = ctx.sink(_sink_ref(ctx), "text", "pdf")
        try:
            for number, text in doc.pages():
                ctx.check()
                text = clean_text(text).strip()
                if text:
                    sink.add_text(text, number, {"data_region": "page %d" % number})
            return read_result(True, meta=doc.meta, sink=sink)
        except BaseException:
            sink.abort()
            raise
    finally:
        doc.close()


# ---------------------------------------------------------------------------
# 6.9 docx and pptx: paragraphs and slides; embedded files are parts
# ---------------------------------------------------------------------------
_W_NS = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}"
_A_NS = "{http://schemas.openxmlformats.org/drawingml/2006/main}"
_W_T, _W_P = _W_NS + "t", _W_NS + "p"
_W_SPACE = {_W_NS + "tab", _W_NS + "cr", _W_NS + "ptab"}
_W_LF = {_W_NS + "br"}
_W_HYPHEN = _W_NS + "noBreakHyphen"
_A_T, _A_P = _A_NS + "t", _A_NS + "p"
_A_LF = {_A_NS + "br"}
_EMBED_EXT = {"docx", "docm", "xlsx", "xlsm", "pptx", "pptm", "txt", "pdf", "csv", "xls", "zip"}
_IMAGE_EXT = {"png", "jpg", "jpeg", "gif", "bmp", "emf", "wmf", "tif", "tiff", "svg", "webp"}


def _para_text(para, t_tag, space_tags, hyphen_tag, lf_tags):
    out = []
    for el in para.iter():
        tag = el.tag
        if tag == t_tag:
            if el.text:
                out.append(el.text)
        elif tag in lf_tags:
            out.append("\n")
        elif tag in space_tags:
            out.append(" ")
        elif hyphen_tag is not None and tag == hyphen_tag:
            out.append("-")
    return "".join(out)


def _iter_paragraphs(zf, name, p_tag, t_tag, space_tags, hyphen_tag, lf_tags, ctx):
    from lxml import etree
    with zf.open(name) as fh:
        k = 0
        for _ev, el in etree.iterparse(fh, events=("end",), tag=p_tag, huge_tree=True, resolve_entities=False, no_network=True):
            k += 1
            if k % 256 == 0:
                ctx.check()
            # a paragraph inside another (a text box) ends first and is cleared, so the outer one doesn't repeat it
            yield _para_text(el, t_tag, space_tags, hyphen_tag, lf_tags)
            el.clear()


# ---------------------------------------------------------------------------
# 6.9a document properties (architect note 2026-48-45): one vocabulary in meta.doc, sensitivity labels in
#      meta.labels, every other custom property in meta.custom. Customer text: never logged, never in a reason.
# ---------------------------------------------------------------------------
_CORE_NAMES = {"title": "title", "subject": "subject", "keywords": "keywords", "creator": "author", "lastModifiedBy": "last_modified_by",
               "created": "created", "modified": "modified", "lastPrinted": "last_printed", "revision": "revision",
               "category": "category", "language": "language", "description": "comments", "contentStatus": "status"}
_APP_TEXT = {"Company": "company", "Manager": "manager", "Template": "template", "Application": "application", "AppVersion": "app_version"}
_APP_COUNTS = {"Pages": "pages", "Words": "words", "Characters": "characters", "Paragraphs": "paragraphs", "Lines": "lines",
               "Slides": "slides", "Notes": "notes", "HiddenSlides": "hidden_slides", "TotalTime": "editing_minutes"}
_DATE_NAMES = {"created", "modified", "last_printed"}
_LABEL_RE = re.compile(r"^MSIP_Label_([0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12})_([A-Za-z]+)$")
_LABEL_FIELDS = {"Name": "name", "Enabled": "enabled", "SetDate": "set_at", "Method": "method", "SiteId": "site_id"}
_PDF_DATE_RE = re.compile(r"^D:(\d{4})(\d{2})?(\d{2})?(\d{2})?(\d{2})?(\d{2})?(?:([Zz])|([+-])(\d{2})'?(\d{2})?'?)?")
CUSTOM_MAX = 50
CUSTOM_VALUE_MAX = 200
PROP_VALUE_MAX = 1000


def iso_date(text):
    """A date as ISO 8601, with its offset when the file gives one; text that isn't a date stays as it is."""
    t = (text or "").strip()
    m = _PDF_DATE_RE.match(t)
    if m:
        y, mo, d, h, mi, s, z, sign, oh, om = m.groups()
        out = "%s-%s-%sT%s:%s:%s" % (y, mo or "01", d or "01", h or "00", mi or "00", s or "00")
        if z:
            return out + "+00:00"
        if sign:
            return out + "%s%s:%s" % (sign, oh, om or "00")
        return out
    try:
        return dt.datetime.fromisoformat(t.replace("Z", "+00:00")).isoformat()
    except ValueError:
        return t


def _prop_text(v, limit=PROP_VALUE_MAX):
    return pg_safe_str(str(v)).strip()[:limit]


def _xml_root(zf, name):
    from lxml import etree
    try:
        info = zf.getinfo(name)
    except KeyError:
        return None
    if info.file_size > 8 * _MB:
        return None
    try:
        return etree.fromstring(zf.read(info), parser=etree.XMLParser(resolve_entities=False, no_network=True, huge_tree=False))
    except Exception:
        return None


def _props_parts(zf):
    """Where the package keeps its three property parts: by its relationships, else the usual names."""
    found = {"core": "docProps/core.xml", "app": "docProps/app.xml", "custom": "docProps/custom.xml",
             "labelinfo": "docMetadata/LabelInfo.xml"}
    root = _xml_root(zf, "_rels/.rels")
    if root is not None:
        for rel in root:
            rtype = rel.get("Type") or ""
            target = (rel.get("Target") or "").lstrip("/")
            for key, tail in (("core", "/core-properties"), ("app", "/extended-properties"), ("custom", "/custom-properties"),
                              ("labelinfo", "/classificationlabels")):
                if rtype.endswith(tail) and target:
                    found[key] = target
    return found


def _custom_value(prop):
    for child in prop:
        kind = _xl_local(child.tag)
        text = child.text or ""
        if kind == "bool":
            return text.strip().lower() in ("true", "1")
        if kind in ("i1", "i2", "i4", "i8", "int", "ui1", "ui2", "ui4", "ui8", "uint"):
            try:
                return int(text)
            except ValueError:
                return _prop_text(text, CUSTOM_VALUE_MAX)
        if kind in ("r4", "r8", "decimal"):
            try:
                return float(text)
            except ValueError:
                return _prop_text(text, CUSTOM_VALUE_MAX)
        if kind in ("filetime", "date"):
            return iso_date(text)
        return _prop_text(text, CUSTOM_VALUE_MAX)
    return None


def _guid(text):
    """A label or site id as the app compares them: no braces, lower case."""
    return _prop_text(text or "", 64).strip("{}").lower()


def _add_label_prop(labels, label_id, field, value):
    """One MSIP_Label_<id>_<field> property (custom.xml, a PDF's info or its XMP) into the labels by id."""
    field = _LABEL_FIELDS.get(field)
    label = labels.setdefault(_guid(label_id), {"id": _guid(label_id)})
    if field == "enabled":
        label["enabled"] = value if isinstance(value, bool) else str(value).strip().lower() in ("true", "1")
    elif field == "set_at":
        label["set_at"] = iso_date(str(value))
    elif field == "site_id" and value not in (None, ""):
        label["site_id"] = _guid(str(value))
    elif field and value not in (None, ""):
        label[field] = _prop_text(value, CUSTOM_VALUE_MAX)


def _labelinfo_labels(zf, name, labels):
    """docMetadata/LabelInfo.xml, where newer Office versions keep the label (architect note 2026-48-48 §3.1): an id,
    whether it is enabled, the method and the site, but no name. Where custom.xml has the same id, its name and date
    stay and this part's enabled, method and site win. A label marked removed is not on the file and is left out."""
    root = _xml_root(zf, name)
    if root is None:
        return
    for el in root.iter():
        if not isinstance(el.tag, str) or _xl_local(el.tag) != "label":
            continue
        lid = _guid(el.get("id"))
        if not lid or (el.get("removed") or "").strip().lower() in ("1", "true"):
            continue
        label = labels.setdefault(lid, {"id": lid})
        enabled = el.get("enabled")
        if enabled is not None and enabled.strip():
            label["enabled"] = enabled.strip().lower() in ("1", "true")
        if (el.get("method") or "").strip():
            label["method"] = _prop_text(el.get("method"), CUSTOM_VALUE_MAX)
        if (el.get("siteId") or "").strip():
            label["site_id"] = _guid(el.get("siteId"))


def _label_list(labels):
    return [dict(id=lb["id"], name=lb.get("name"), enabled=lb.get("enabled"), set_at=lb.get("set_at"),
                 method=lb.get("method"), site_id=lb.get("site_id")) for lb in labels.values()]


def office_properties(zf):
    """meta.doc, meta.labels and meta.custom of a Word, Excel or PowerPoint package. A part that is missing or
    can't be read is left out without failing the object; a property with no value is left out."""
    out = {}
    try:
        parts = _props_parts(zf)
    except Exception:
        return out
    doc = {}
    core = _xml_root(zf, parts["core"])
    if core is not None:
        for item in core:
            name = _CORE_NAMES.get(_xl_local(item.tag))
            text = (item.text or "").strip() if isinstance(item.tag, str) else ""
            if name and text:
                doc[name] = iso_date(text) if name in _DATE_NAMES else _prop_text(text)
    app = _xml_root(zf, parts["app"])
    if app is not None:
        for item in app:
            tag = _xl_local(item.tag) if isinstance(item.tag, str) else ""
            text = (item.text or "").strip()
            if not text:
                continue
            if tag in _APP_TEXT:
                doc[_APP_TEXT[tag]] = _prop_text(text)
            elif tag in _APP_COUNTS:
                try:
                    doc[_APP_COUNTS[tag]] = int(text)
                except ValueError:
                    pass
    if doc:
        out["doc"] = doc
    labels = collections.OrderedDict()
    custom_root = _xml_root(zf, parts["custom"])
    if custom_root is not None:
        custom = {}
        for prop in custom_root:
            name = (prop.get("name") or "").strip()
            if not name:
                continue
            value = _custom_value(prop)
            m = _LABEL_RE.match(name)
            if m:
                _add_label_prop(labels, m.group(1), m.group(2), value)
                continue
            if value in (None, "") or len(custom) >= CUSTOM_MAX:
                continue
            custom[_prop_text(name, CUSTOM_VALUE_MAX)] = value
        if custom:
            out["custom"] = custom
    _labelinfo_labels(zf, parts["labelinfo"], labels)
    if labels:
        out["labels"] = _label_list(labels)
    return out


_PDF_NAMES = {"title": "title", "subject": "subject", "keywords": "keywords", "author": "author", "creationDate": "created",
              "modDate": "modified", "creator": "application", "producer": "producer"}


def pdf_properties(info):
    doc = {}
    for key, name in _PDF_NAMES.items():
        v = (info or {}).get(key)
        if v and str(v).strip():
            doc[name] = iso_date(str(v)) if name in _DATE_NAMES else _prop_text(v)
    return {"doc": doc} if doc else {}


_RDF_NS = "{http://www.w3.org/1999/02/22-rdf-syntax-ns#}"
# XMP's names onto the vocabulary of note 2026-48-45 (note 2026-48-48 §3.2). dc:description is the PDF's Subject.
_XMP_NAMES = {("http://purl.org/dc/elements/1.1/", "title"): "title",
              ("http://purl.org/dc/elements/1.1/", "creator"): "author",
              ("http://purl.org/dc/elements/1.1/", "description"): "subject",
              ("http://purl.org/dc/elements/1.1/", "subject"): "keywords",
              ("http://purl.org/dc/elements/1.1/", "language"): "language",
              ("http://ns.adobe.com/pdf/1.3/", "Keywords"): "keywords",
              ("http://ns.adobe.com/pdf/1.3/", "Producer"): "producer",
              ("http://ns.adobe.com/xap/1.0/", "CreatorTool"): "application",
              ("http://ns.adobe.com/xap/1.0/", "CreateDate"): "created",
              ("http://ns.adobe.com/xap/1.0/", "ModifyDate"): "modified"}
_XMP_JOIN = {"author": "; ", "keywords": ", ", "language": ", "}
XMP_MAX = 1 * _MB


def _xmp_split(tag):
    if isinstance(tag, str) and tag.startswith("{"):
        ns, local = tag[1:].split("}", 1)
        return ns, local
    return "", tag if isinstance(tag, str) else ""


def _xmp_value(el):
    """An XMP property's value: its text, or the items of its rdf:Alt, rdf:Seq or rdf:Bag."""
    items = [(li.text or "").strip() for li in el.iter(_RDF_NS + "li")]
    items = [t for t in items if t]
    if items:
        return items
    text = (el.text or "").strip()
    return [text] if text else []


def pdf_xmp(xml_text):
    """A PDF's XMP packet: (the vocabulary's names it has, the MSIP_Label_* properties as {(id, field): value}).
    A packet that can't be read gives nothing."""
    from lxml import etree
    doc, label_props = {}, collections.OrderedDict()
    if not xml_text or len(xml_text) > XMP_MAX:
        return doc, label_props
    try:
        data = xml_text.encode("utf-8") if isinstance(xml_text, str) else xml_text
        root = etree.fromstring(data, parser=etree.XMLParser(resolve_entities=False, no_network=True, load_dtd=False,
                                                              huge_tree=False, recover=True))
    except Exception:
        return doc, label_props
    if root is None:
        return doc, label_props

    def take(ns, local, values):
        m = _LABEL_RE.match(local)
        if m:
            if values:
                label_props.setdefault((m.group(1), m.group(2)), values[0])
            return
        name = _XMP_NAMES.get((ns, local))
        if name and values and name not in doc:
            text = _XMP_JOIN.get(name, " ").join(values) if name in _XMP_JOIN else values[0]
            doc[name] = iso_date(text) if name in _DATE_NAMES else _prop_text(text)

    for desc in root.iter(_RDF_NS + "Description"):
        for attr, value in desc.attrib.items():          # properties written as attributes of rdf:Description
            ns, local = _xmp_split(attr)
            if ns != _RDF_NS[1:-1] and (value or "").strip():
                take(ns, local, [value.strip()])
        for el in desc:
            ns, local = _xmp_split(el.tag)
            take(ns, local, _xmp_value(el))
    return doc, label_props


_PDF_PERMS = (("print", 4), ("print_high", 2048), ("modify", 8), ("copy", 16), ("annotate", 32), ("fill_forms", 256),
              ("accessibility", 512), ("assemble", 1024))
PDF_FIELDS_MAX = 5000


def _embedded_entries(zf):
    out = []
    for info in zf.infolist():
        if info.is_dir():
            continue
        name = info.filename
        ext = name.rsplit(".", 1)[-1].lower() if "." in name.rsplit("/", 1)[-1] else ""
        if ext in _IMAGE_EXT or name.endswith(".xml") or name.endswith(".rels"):
            continue
        if "/embeddings/" in name or ext in _EMBED_EXT:
            out.append(info)
    return out


def _scan_embedded(zf, ctx):
    """The files a document carries inside it, each a part. Not opened past the depth limit."""
    entries = _embedded_entries(zf)
    if not entries:
        return 0, 0
    if ctx.depth >= ctx.settings.archive_max_depth:
        return 0, len(entries)
    for info in entries:
        ctx.check()
        scan_part(ctx, lambda info=info: zf.open(info), info.filename.rsplit("/", 1)[-1], info.filename,
                  declared=info.file_size, compressed=info.compress_size, encrypted=bool(info.flag_bits & 0x1), part_type="embedded")
    return len(entries), 0


def read_docx(src, ctx, ti):
    with src.open() as fh:
        zf = zipfile.ZipFile(fh)
        names = zf.namelist()
        meta = office_properties(zf)
        headers = sorted(n for n in names if re.match(r"^word/header\d*\.xml$", n))
        footers = sorted(n for n in names if re.match(r"^word/footer\d*\.xml$", n))
        sink = ctx.sink(_sink_ref(ctx), "text", "text") if ctx.scope.write else None
        try:
            if sink is not None:
                n = 0
                for region, files in (("header", headers), ("body", ["word/document.xml"]), ("footer", footers)):
                    for name in files:
                        if name not in names:
                            continue
                        for para in _iter_paragraphs(zf, name, _W_P, _W_T, _W_SPACE, _W_HYPHEN, _W_LF, ctx):
                            for row in split_unit(para):
                                n += 1
                                sink.add_text(row, n, {"data_region": region})
            embedded, not_opened = _scan_embedded(zf, ctx)
            if embedded:
                meta["embedded"] = embedded
            if not_opened:
                meta["embedded_not_opened"] = not_opened
            if sink is None:
                return no_classify_result(meta=meta)
            return read_result(True, meta=meta, sink=sink)
        except BaseException:
            if sink is not None:
                sink.abort()
            raise


def _pptx_slide_maps(zf):
    from lxml import etree
    display, notes = {}, {}
    p = etree.XMLParser(resolve_entities=False, no_network=True)
    try:
        names = set(zf.namelist())
        rels = {}
        if "ppt/_rels/presentation.xml.rels" in names:
            for rel in etree.fromstring(zf.read("ppt/_rels/presentation.xml.rels"), parser=p):
                rels[rel.get("Id")] = rel.get("Target") or ""
        if "ppt/presentation.xml" in names:
            order = 0
            for el in etree.fromstring(zf.read("ppt/presentation.xml"), parser=p).iter():
                if isinstance(el.tag, str) and el.tag.endswith("}sldId"):
                    rid = next((v for k, v in el.attrib.items() if k.endswith("}id")), None)
                    m = re.search(r"slide(\d+)\.xml$", rels.get(rid, ""))
                    if m:
                        order += 1
                        display[int(m.group(1))] = order
        for n in names:
            m = re.match(r"ppt/notesSlides/_rels/notesSlide(\d+)\.xml\.rels$", n)
            if m:
                for rel in etree.fromstring(zf.read(n), parser=p):
                    sm = re.search(r"slides/slide(\d+)\.xml$", rel.get("Target") or "")
                    if sm:
                        notes[int(m.group(1))] = int(sm.group(1))
    except Exception:
        pass
    return display, notes


def read_pptx(src, ctx, ti):
    with src.open() as fh:
        zf = zipfile.ZipFile(fh)
        names = zf.namelist()
        meta = office_properties(zf)
        display, notes_to_slide = _pptx_slide_maps(zf)
        slides = {}
        for name in names:
            m = re.match(r"^ppt/(slides/slide|notesSlides/notesSlide)(\d+)\.xml$", name)
            if not m:
                continue
            num = int(m.group(2))
            if m.group(1).startswith("notes"):
                num = notes_to_slide.get(num, num)
            slides.setdefault(num, []).append(name)
        meta["slides"] = len(display) or len([n for n in names if re.match(r"^ppt/slides/slide\d+\.xml$", n)])
        sink = ctx.sink(_sink_ref(ctx), "text", "text") if ctx.scope.write else None
        try:
            if sink is not None:
                for num in sorted(slides, key=lambda k: (display.get(k, k), k)):
                    ctx.check()
                    texts = []
                    for name in sorted(slides[num], key=lambda s: (("notes" in s), s)):
                        for para in _iter_paragraphs(zf, name, _A_P, _A_T, set(), None, _A_LF, ctx):
                            if para.strip():
                                texts.append(para)
                    shown = display.get(num, num)
                    for row in split_unit("\n".join(texts)):
                        sink.add_text(row, shown, {"data_region": "slide %d" % shown})
            embedded, not_opened = _scan_embedded(zf, ctx)
            if embedded:
                meta["embedded"] = embedded
            if not_opened:
                meta["embedded_not_opened"] = not_opened
            if sink is None:
                return no_classify_result(meta=meta)
            return read_result(True, meta=meta, sink=sink)
        except BaseException:
            if sink is not None:
                sink.abort()
            raise


# ---------------------------------------------------------------------------
# 6.10 zip: every entry is a part, nested archives included; the archive is a container
# ---------------------------------------------------------------------------
_ZIP_CLUTTER = (".DS_Store", "Thumbs.db", "desktop.ini")


def _zip_clutter(name):
    leaf = name.rsplit("/", 1)[-1]
    return name.startswith("__MACOSX/") or "/__MACOSX/" in name or leaf in _ZIP_CLUTTER or leaf.startswith("._")


def read_zip(src, ctx, ti):
    s = ctx.settings
    with src.open() as fh:
        try:
            zf = zipfile.ZipFile(fh)
            infos = [i for i in zf.infolist() if not i.is_dir() and not _zip_clutter(i.filename)]
        except (zipfile.BadZipFile, zipfile.LargeZipFile, EOFError, ValueError):
            raise ScanFail("object_unreadable", reason="not a readable zip archive")
        if len(infos) > s.archive_max_entries:
            raise ScanFail("archive_too_many_entries", limit=s.archive_max_entries)
        if sum(i.file_size for i in infos) > s.archive_max_mb * _MB:
            raise ScanFail("archive_too_large", limit_mb=s.archive_max_mb)
        for info in infos:
            ctx.check()
            scan_part(ctx, lambda info=info: zf.open(info), info.filename.rsplit("/", 1)[-1] or info.filename, info.filename,
                      declared=info.file_size, compressed=info.compress_size, encrypted=bool(info.flag_bits & 0x1))
        return read_result(False, "container", meta={"is_container": True, "entries": len(infos)})


READERS = {
    "txt": read_text,
    "csv": read_csv,
    "json": read_json,
    "xml": read_xml,
    "html": read_html,
    "pdf": read_pdf,
    "docx": read_docx,
    "pptx": read_pptx,
    "xlsx": read_xlsx,
    "xls": read_xls,
    "zip": read_zip,
}
CONTAINER_TYPES = {"zip"}


# ===========================================================================
# 7. THE PASS FOR ONE OBJECT: A FILE, AN ARCHIVE'S ENTRY, A TABLE
#   A file: open it under the root, take its SHA-256 in place, ask whether the installation knows it,
#   then read it. An entry: spool it (to disk for an archive) while hashing, then the same. A table:
#   read from the catalog, never from the queue row, in parts of 50,000 rows.
# ===========================================================================
# exceptions that mean the bytes aren't the format they claim to be: the object is unreadable, no more
_FORMAT_ERRORS = (zipfile.BadZipFile, zipfile.LargeZipFile, zlib.error, EOFError, NotImplementedError, UnicodeError,
                  csv.Error, OSError, ValueError, KeyError, IndexError, LookupError)


def _format_errors():
    errs = list(_FORMAT_ERRORS)
    try:
        from lxml import etree
        errs.append(etree.LxmlError)
    except ImportError:
        pass
    try:
        import xlrd
        errs.append(xlrd.biffh.XLRDError)
    except ImportError:
        pass
    return tuple(errs)


FORMAT_ERRORS = _format_errors()


def _failed(r):
    return {"outcome": "failed", "bytes_out": 0, "code": r["code"], "params": r["params"], "text": r["text"]}


def failed_from(exc):
    """A failure's fields from what went wrong. Only the exception's class and the function it was in are
    ever kept: an exception's message can carry a name, a path or a value."""
    if isinstance(exc, ScanFail):
        return _failed(reason(exc.code, **exc.params))
    if isinstance(exc, FORMAT_ERRORS):
        return _failed(reason("object_unreadable", reason=type(exc).__name__))
    cls, fn = where(exc)
    return _failed(reason("unexpected", reason="%s in %s" % (cls, fn)))


def skip_known(known, ti, write):
    """Ruling 7: skip what was extracted, and what wasn't when this build still can't read that type.
    A known container: its parts come from the database (ruling 6), unless parts_unread says some of them
    wait for a classify stage this run has (DB-82 §6). Known without a classify stage: read again only when
    this run has one.
    From db 2026-48-07 the answer has read_again (note 2026-48-54): the database's own rule, which replaces
    parts_unread and the no_classify_stage case. True: read it again with its extract, or open the container
    (only when this run writes extracts). False: skipped as known, a container and content held as
    no_classify_stage included; ruling 7 still reads a type this build can now read."""
    if not known:
        return False
    if "read_again" in known:
        if known.get("read_again") is True and write:
            return False
        if known.get("extracted") or known.get("why") in ("container", "no_classify_stage"):
            return True
        return ti.reader is None
    if known.get("extracted"):
        return True
    why = known.get("why")
    if why == "container":
        # note 2026-48-39: a known container with a part held as no_classify_stage is opened again in a run with
        # classify, so those parts reach it; its other parts are then skipped parts. Otherwise it is skipped.
        return not (write and known.get("parts_unread") is True)
    if why == "no_classify_stage":
        return not write
    return ti.reader is None


def _lookup(ctx, sha256):
    scope = ctx.scope
    if scope.full or scope.lookup is None:
        return None
    return scope.lookup(sha256, ctx)


def read_source(src, ctx):
    """One object's or part's bytes, already fingerprinted: skipped, done unread, or read. Raises ScanFail."""
    ti = identify(src)
    content = {"sha256": src.sha256, "bytes": src.size, "type": ti.type}
    if ti.encrypted:
        raise ScanFail("object_encrypted")
    if skip_known(_lookup(ctx, src.sha256), ti, ctx.scope.write):
        return {"outcome": "skipped", "content": content}
    out = {"outcome": "done", "content": content}
    if ti.reader is None:
        out.update(bytes_out=0, read={"extracted": False, "why": ti.why, "scan_version": VERSION}, meta={}, rows=None, chars=None,
                   columns=None, extract=None)
        return out
    if TYPE_GROUPS.get(ti.type, ti.type) in CONTAINER_TYPES and ctx.depth > ctx.settings.archive_max_depth:
        raise ScanFail("archive_too_deep", limit=ctx.settings.archive_max_depth)
    res = ti.reader(src, ctx, ti)
    out.update(_done_fields(res))
    return out


def scan_part(ctx, open_fn, name, inner_path, declared=None, compressed=None, encrypted=False, part_type=None):
    """One entry of an archive or one embedded file: a part of the object, at the next depth. It is listed
    before it is read, so its own parts follow it; when it fails, they and their working files go, and it
    fails alone. An archive-wide limit fails the archive instead."""
    s = ctx.settings
    ref = ctx.next_ref()
    clean_inner = pg_safe_str(inner_path or "") or pg_safe_str(name or "") or ref
    clean_name = pg_safe_str(name or "") or clean_inner.rsplit("/", 1)[-1] or ref
    part = {"ref": ref, "parent_ref": ctx.parent_ref, "inner_path": clean_inner[:INNER_PATH_MAX], "name": clean_name[:PART_NAME_MAX], "is_asset": True,
            "part_type": part_type or "entry"}
    index = len(ctx.parts)
    ctx.parts.append(part)
    child = ctx.child(ref)
    src = None
    try:
        if encrypted:
            raise ScanFail("object_encrypted")
        if declared is not None and declared > s.archive_entry_max_mb * _MB:
            raise ScanFail("object_too_large", limit_mb=s.archive_entry_max_mb)
        if (declared is not None and compressed is not None and declared > s.archive_ratio_min_mb * _MB
                and declared > s.archive_max_ratio * max(1, compressed)):
            raise ScanFail("archive_ratio_exceeded", limit=s.archive_max_ratio)
        with open_fn() as fh:
            src = spool_stream(fh.read, clean_name, child, declared=declared, compressed=compressed, archive_entry=True)
        part.update(read_source(src, child))
    except Stopped:
        raise
    except ScanFail as e:
        if e.whole_archive:
            raise
        ctx.discard_from(index + 1)
        part.update(failed_from(e))
    except MemoryError:
        raise
    except Exception as e:
        ctx.discard_from(index + 1)
        part.update(failed_from(e))
        if part["code"] == "unexpected":
            log.warning(kv("part_unexpected", location_id=ctx.location_id, ref=ref, error=where(e)[0], where=where(e)[1]))
    finally:
        if src is not None:
            src.cleanup()
    return part


# ---------------------------------------------------------------------------
# 7.1 the element handed in
# ---------------------------------------------------------------------------
_PART_KEYS = ("ref", "parent_ref", "inner_path", "name", "is_asset", "part_type")
_DONE_KEYS = ("outcome", "bytes_out", "content", "read", "meta", "rows", "chars", "columns", "extract")
_FAILED_KEYS = ("outcome", "bytes_out", "code", "params", "text")


def _shape(fields):
    out = fields.get("outcome")
    if out == "skipped":
        return {"outcome": "skipped", "content": fields.get("content")}
    if out == "failed":
        return {k: fields.get(k) for k in _FAILED_KEYS}
    d = {k: fields.get(k) for k in _DONE_KEYS}
    d["meta"] = cap_meta(d.get("meta"))
    return d


def part_element(part):
    e = {k: part.get(k) for k in _PART_KEYS}
    e.update(_shape(part))
    return e


def object_element(location_id, fields, parts=None):
    """{location_id, ...} as directive 2026-48-09 §2 asks: a skipped object sends its content only, a failed
    one its reason, a done one what was read and its parts."""
    e = {"location_id": location_id}
    e.update(_shape(fields))
    if fields.get("outcome") == "done" and parts:
        e["parts"] = [part_element(p) for p in parts]
    return e


def element_extracts(element):
    """The working-file paths an element names, its parts' included: removed when it isn't kept."""
    out = []
    ex = element.get("extract")
    if isinstance(ex, dict) and ex.get("path"):
        out.append(ex["path"])
    for p in element.get("parts") or ():
        ex = p.get("extract")
        if isinstance(ex, dict) and ex.get("path"):
            out.append(ex["path"])
    return out


# ---------------------------------------------------------------------------
# 7.2 a file under a directory data source's root
# ---------------------------------------------------------------------------
def _object_relpath(obj):
    """The path under the root as bytes: source.path_b64 when discovery gave one (a name that isn't clean
    UTF-8), else the key."""
    src = obj.get("source") if isinstance(obj.get("source"), dict) else {}
    b64 = src.get("path_b64")
    if b64:
        try:
            rel = base64.b64decode(str(b64), validate=True)
        except (ValueError, TypeError):
            raise ScanFail("object_unreadable", reason="the object's path_b64 isn't valid base64")
    else:
        rel = str(obj.get("key") or "").encode("utf-8", "surrogateescape")
    rel = rel.lstrip(b"/")
    if not rel or b"\x00" in rel:
        raise ScanFail("object_unreadable", reason="the object has no usable path")
    return rel


def _same_file(a, b):
    return a.st_size == b.st_size and a.st_mtime_ns == b.st_mtime_ns and a.st_ino == b.st_ino


def _fd_path(fd, fallback):
    p = "/proc/self/fd/%d" % fd
    return p if os.path.exists(p) else os.fsdecode(fallback)


def scan_file_object(obj, scope, root_real):
    """One file: (element, None) when handed in, None when a stop left it unread."""
    loc = obj["location_id"]
    ctx = ReadCtx(scope, loc)
    fd = None
    try:
        try:
            rel = _object_relpath(obj)
            root_b = os.fsencode(root_real).rstrip(b"/") or b"/"
            real = os.path.realpath(os.path.join(root_b, rel))
            if not (real.startswith(root_b + b"/") or (root_b == b"/" and real != b"/")):
                raise ScanFail("path_outside_root")
            try:
                fd, noatime = open_customer_fd(real)
            except FileNotFoundError:
                raise ScanFail("object_gone")
            except NotADirectoryError:
                raise ScanFail("object_gone")
            except PermissionError:
                raise ScanFail("object_unreadable", reason="permission denied")
            except IsADirectoryError:
                raise ScanFail("object_unreadable", reason="not a file")
            except OSError as e:
                if e.errno == 40:           # ELOOP: a link swapped in after the path was resolved
                    raise ScanFail("path_outside_root")
                raise ScanFail("object_unreadable", reason="the file couldn't be opened (%s)" % (errno_name(e.errno)))
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode):
                raise ScanFail("object_unreadable", reason="not a regular file")
            if st.st_size > scope.settings.object_max_mb * _MB:
                raise ScanFail("object_too_large", limit_mb=scope.settings.object_max_mb)
            fobj = os.fdopen(os.dup(fd), "rb", buffering=0)
            try:
                sha, n, head = hash_in_place(fobj, ctx)
            finally:
                fobj.close()
            if n != st.st_size or not _same_file(st, os.fstat(fd)):
                raise ScanFail("object_changed")
            name = str(obj.get("name") or "") or os.fsdecode(os.path.basename(rel))
            src = Source(name, path=_fd_path(fd, real), size=n, sha256=sha, head=head, noatime=noatime)
            fields = read_source(src, ctx)
            if not _same_file(st, os.fstat(fd)):
                raise ScanFail("object_changed")
        except Stopped:
            raise
        except ScanFail as e:
            ctx.discard_from(0)
            ctx.forget_all()
            return object_element(loc, failed_from(e))
        except MemoryError:
            raise
        except Exception as e:
            ctx.discard_from(0)
            ctx.forget_all()
            f = failed_from(e)
            if f["code"] == "unexpected":
                log.warning(kv("object_unexpected", location_id=loc, error=where(e)[0], where=where(e)[1]))
            return object_element(loc, f)
        if fields["outcome"] != "done":
            ctx.forget_all()
        return object_element(loc, fields, ctx.parts)
    except Stopped:
        ctx.forget_all()
        return None
    finally:
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass


def errno_name(num):
    import errno
    return errno.errorcode.get(num, str(num))


def _forget_all(self):
    for _ref, path in self.shared["written"]:
        remove_tree(path)
    self.shared["written"] = []


ReadCtx.forget_all = _forget_all


# ---------------------------------------------------------------------------
# 7.3 a table (ruling 5: nothing that arrives in a queue row is run as SQL)
#   The queue row's schema and name are only ever bound parameters of a catalog lookup. The SELECT is
#   built from the catalog's own names, each quoted as an identifier, every column cast to text,
#   bytea left out. A read-only transaction, a server-side cursor, parts of 50,000 rows.
# ---------------------------------------------------------------------------
_TABLE_CATALOG_SQL = (
    "select c.oid, n.nspname, c.relname, c.relkind"
    "  from pg_catalog.pg_class c join pg_catalog.pg_namespace n on n.oid = c.relnamespace"
    " where n.nspname = %s and c.relname = %s and c.relkind in ('r', 'p', 'v', 'm', 'f')")
_TABLE_COLUMNS_SQL = (
    "select a.attname, a.attnum, b.typname, b.typcategory, pg_catalog.format_type(a.atttypid, a.atttypmod),"
    "       coalesce(e.typname, '')"
    "  from pg_catalog.pg_attribute a"
    "  join pg_catalog.pg_type t on t.oid = a.atttypid"
    "  join pg_catalog.pg_type b on b.oid = case when t.typtype = 'd' then t.typbasetype else t.oid end"
    "  left join pg_catalog.pg_type e on e.oid = b.typelem and b.typcategory = 'A'"
    " where a.attrelid = %s and a.attnum > 0 and not a.attisdropped"
    " order by a.attnum")
_PG_DTYPES = {"N": "number", "D": "date", "B": "boolean"}


def _db_types_meta(types):
    """The columns' native types, as many as keep meta well under 16 KB; when the list is cut, meta says so
    (architect note 2026-48-17)."""
    out, size = [], 0
    for t in types:
        size += len(json.dumps(t, ensure_ascii=False).encode("utf-8")) + 2
        if size > META_DB_TYPES_MAX:
            return {"db_types": out, "db_types_cut": True, "db_types_count": len(types)}
        out.append(t)
    return {"db_types": out}


def _pg_left_out(typname, elem):
    return typname == "bytea" or elem == "bytea"


class TableConnections(object):
    """One psycopg2 connection per reading thread (a database handle is one per thread, ds_connect_lib),
    opened through ds_connect_lib, closed when the queue ends, dropped when it breaks."""

    def __init__(self, source_type, connection, settings):
        self.source_type = source_type
        self.connection = connection
        self.settings = settings
        self.local = threading.local()
        self.lock = threading.Lock()
        self.handles = []
        self.active = set()

    def get(self):
        h = getattr(self.local, "handle", None)
        if h is not None and not h.client.closed:
            return h.client
        try:
            h = ds_connect_lib.connect(self.source_type, self.connection, file_roots=self.settings.file_roots,
                                       ca_file=self.settings.ca_bundle, proxy=self.settings.proxy())
        except ds_connect_lib.ConnectError as e:
            raise QueueAbort(e.code, e.params)
        self.local.handle = h
        with self.lock:
            self.handles.append(h)
        return h.client

    def drop(self):
        h = getattr(self.local, "handle", None)
        self.local.handle = None
        if h is not None:
            h.close()

    def cancel_all(self):
        """A stop: the statements running now are canceled, so a slow fetch can't hold the stop limit."""
        with self.lock:
            conns = list(self.active)
        for c in conns:
            try:
                c.cancel()
            except Exception:
                pass

    def close(self):
        with self.lock:
            hs, self.handles = self.handles, []
        for h in hs:
            h.close()

    def check_source(self):
        """After a broken connection: is the data source there? A QueueAbort when it isn't."""
        res = ds_connect_lib.check(self.source_type, self.connection, file_roots=self.settings.file_roots,
                                   ca_file=self.settings.ca_bundle, proxy=self.settings.proxy())
        if res.status != "reachable":
            raise QueueAbort(res.code, res.params)


def scan_table_object(obj, scope, conns):
    """One table: (element) when handed in, None when a stop left it unread. A table has no fingerprint
    (ruling 4): content is null, and it is read on every run."""
    import psycopg2
    from psycopg2 import sql as pgsql
    from psycopg2 import errors as pgerr
    loc = obj["location_id"]
    ctx = ReadCtx(scope, loc)
    conn = None
    sink = None
    try:
        conn = conns.get()
        if conn.status != psycopg2.extensions.STATUS_READY:
            conn.rollback()
        conn.set_session(readonly=True, autocommit=False)
        with conns.lock:
            conns.active.add(conn)
        with conn.cursor() as cur:
            cur.execute(_TABLE_CATALOG_SQL, (str(obj.get("path") or ""), str(obj.get("name") or "")))
            found = cur.fetchone()
            if found is None:
                raise ScanFail("object_gone")
            oid, nsp, rel, kind = found
            cur.execute(_TABLE_COLUMNS_SQL, (oid,))
            catalog = cur.fetchall()
        kept = [c for c in catalog if not _pg_left_out(c[2], c[5])]
        left_out = len(catalog) - len(kept)
        names = []
        seen = {"ds_key": 1}
        for c in kept:
            base = pg_safe_str(c[0]) or "col"
            if base in seen:
                seen[base] += 1
                base = "%s_%d" % (base, seen[base])
            else:
                seen[base] = 1
            names.append(base)
        columns = [{"name": names[i], "pos": i, "dtype": _PG_DTYPES.get(c[3], "string")} for i, c in enumerate(kept)]
        meta = {"relkind": kind, "columns_left_out": left_out}
        meta.update(_db_types_meta([c[4] for c in kept]))
        if not kept:
            conn.rollback()
            fields = {"outcome": "done", "content": None}
            fields.update(_done_fields(read_result(True, meta=meta, columns=columns)))
            return object_element(loc, fields)
        statement = pgsql.SQL("select {} from {}.{}").format(
            pgsql.SQL(", ").join(pgsql.SQL("{}::text").format(pgsql.Identifier(c[0])) for c in kept),
            pgsql.Identifier(nsp), pgsql.Identifier(rel))
        sink = ctx.sink(None, "rows", "table", names)
        rows = 0
        with conn.cursor(name="ds_scan_%s" % uuid.uuid4().hex) as cur:
            cur.itersize = TABLE_FETCH_ROWS
            cur.execute(statement)
            while True:
                ctx.check()
                batch = cur.fetchmany(TABLE_FETCH_ROWS)
                if not batch:
                    break
                for row in batch:
                    rows += 1
                    sink.add_row([clean_text(v) if v is not None else None for v in row], rows)
        conn.rollback()
        meta["rows"] = rows
        if scope.write:
            res = read_result(True, meta=meta, sink=sink, columns=columns)
        else:
            res = no_classify_result(meta=meta, columns=columns)
        sink = None
        fields = {"outcome": "done", "content": None}
        fields.update(_done_fields(res))
        return object_element(loc, fields)
    except Stopped:
        if sink is not None:
            sink.abort()
        _pg_reset(conn, conns)
        ctx.forget_all()
        return None
    except QueueAbort:
        raise
    except ScanFail as e:
        if sink is not None:
            sink.abort()
        _pg_reset(conn, conns)
        ctx.forget_all()
        return object_element(loc, failed_from(e))
    except psycopg2.Error as e:
        if sink is not None:
            sink.abort()
        ctx.forget_all()
        if isinstance(e, pgerr.QueryCanceled) and scope.stop.is_set():
            _pg_reset(conn, conns)
            return None
        if isinstance(e, (psycopg2.OperationalError, psycopg2.InterfaceError)) and (conn is None or conn.closed):
            conns.drop()
            conns.check_source()
            return object_element(loc, _failed(reason("object_unreadable", reason="the connection was lost while reading")))
        _pg_reset(conn, conns)
        if isinstance(e, pgerr.UndefinedTable):
            return object_element(loc, _failed(reason("object_gone")))
        if isinstance(e, pgerr.InsufficientPrivilege):
            return object_element(loc, _failed(reason("object_unreadable", reason="permission denied")))
        return object_element(loc, _failed(reason("object_unreadable", reason="database error %s" % (e.pgcode or type(e).__name__))))
    except MemoryError:
        raise
    except Exception as e:
        if sink is not None:
            sink.abort()
        _pg_reset(conn, conns)
        ctx.forget_all()
        f = failed_from(e)
        if f["code"] == "unexpected":
            log.warning(kv("object_unexpected", location_id=loc, error=where(e)[0], where=where(e)[1]))
        return object_element(loc, f)
    finally:
        if conn is not None:
            with conns.lock:
                conns.active.discard(conn)


def _pg_reset(conn, conns):
    if conn is None:
        return
    try:
        conn.rollback()
    except Exception:
        conns.drop()


# ===========================================================================
# 8. THE DATABASE (standard §5)
#   One long-lived connection of the worker's own for LISTEN, with TCP keepalives and a cheap
#   statement at every poll; a pool of 4 for the function calls. Plain SQL as sentinel_worker, named
#   parameters, no prepared-statement cache. A refusal is matched on its HINT.
# ===========================================================================
CONTRACT_SQLSTATES = ("42883", "3F000", "42501", "42P01")
LISTEN_CHANNELS = ("run_work", "run_request")    # run_request: queues changed; an idle worker asks at once (DB-82 §3)
CALL_TIMEOUT_SEC = 120.0


def _set_keepalive(conn):
    """TCP keepalives on the client's side as well (idle 30 s, interval 10 s, 3 probes)."""
    try:
        import socket
        sock = conn._transport.get_extra_info("socket")
        if sock is None or sock.family not in (socket.AF_INET, socket.AF_INET6):
            return
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        for opt, val in (("TCP_KEEPIDLE", 30), ("TCP_KEEPINTVL", 10), ("TCP_KEEPCNT", 3)):
            if hasattr(socket, opt):
                sock.setsockopt(socket.IPPROTO_TCP, getattr(socket, opt), val)
    except Exception:
        pass


class Db(object):
    def __init__(self, settings, on_notify=None):
        self.s = settings
        self.on_notify = on_notify
        self.listen = None
        self.pool = None
        self.up = False
        self.optional = set()       # optional functions found at the contract check
        self.missing = []           # what the contract check found missing

    def _server_settings(self):
        return {"application_name": self.s.service, "tcp_keepalives_idle": "30", "tcp_keepalives_interval": "10",
                "tcp_keepalives_count": "3"}

    def _conn_kw(self):
        return dict(host=self.s.db_host, port=self.s.db_port, database=self.s.db_name, user=self.s.db_user,
                    password=self.s.read_password, statement_cache_size=0, server_settings=self._server_settings(), timeout=10)

    @staticmethod
    async def _init(conn):
        await conn.set_type_codec("json", encoder=json.dumps, decoder=json.loads, schema="pg_catalog")
        await conn.set_type_codec("jsonb", encoder=json.dumps, decoder=json.loads, schema="pg_catalog")

    async def open(self):
        """Both links, or DbAway. NotService when the login isn't the workers'."""
        import asyncpg
        await self.close()
        try:
            self.listen = await asyncpg.connect(**self._conn_kw())
            _set_keepalive(self.listen)
            await self._init(self.listen)
            self.pool = await asyncpg.create_pool(min_size=1, max_size=4, init=self._init, max_inactive_connection_lifetime=300,
                                                  **self._conn_kw())
            for ch in LISTEN_CHANNELS:
                await self.listen.add_listener(ch, self._notified)
            self.up = True
        except (OSError, asyncio.TimeoutError, asyncpg.InterfaceError, asyncpg.CannotConnectNowError,
                asyncpg.TooManyConnectionsError, asyncpg.InvalidPasswordError, asyncpg.InvalidAuthorizationSpecificationError,
                asyncpg.InvalidCatalogNameError, asyncpg.ConnectionDoesNotExistError) as e:
            await self.close()
            raise DbAway(type(e).__name__)
        except asyncpg.PostgresError as e:
            await self.close()
            raise DbAway(type(e).__name__)

    def _notified(self, conn, pid, channel, payload):
        if self.on_notify is not None:
            try:
                self.on_notify(channel, payload)
            except Exception:
                pass

    async def close(self):
        self.up = False
        listen, pool = self.listen, self.pool
        self.listen = None
        self.pool = None
        if listen is not None:
            try:
                await asyncio.wait_for(listen.close(), 5)
            except Exception:
                listen.terminate()
        if pool is not None:
            try:
                await asyncio.wait_for(pool.close(), 5)
            except Exception:
                pool.terminate()

    async def ping(self):
        """The cheap statement on the long-lived link at every poll: DbAway when it has gone."""
        import asyncpg
        if self.listen is None or self.listen.is_closed():
            raise DbAway("closed")
        try:
            await self.listen.fetchval("select 1", timeout=10)
        except (OSError, asyncio.TimeoutError, asyncpg.InterfaceError, asyncpg.ConnectionDoesNotExistError, asyncpg.PostgresError) as e:
            raise DbAway(type(e).__name__)

    async def call(self, fn, timeout=CALL_TIMEOUT_SEC, **params):
        """select sentinel.<fn>(name => $1::type, ...): the decoded answer. Raises Refused (matched on the
        HINT), ContractBroken, NotService or DbAway. fn and the names come from CONTRACT, never from data."""
        import asyncpg
        if fn not in CONTRACT:
            raise ValueError("not in the contract")
        if self.pool is None:
            raise DbAway("closed")
        names = [k for k in params if k in CONTRACT[fn]
                 and (k not in CONTRACT_OPTIONAL_PARAMS.get(fn, ()) or fn + "." + k in self.optional)]
        sql_text = "select sentinel.%s(%s)" % (fn, ", ".join("%s => $%d::%s" % (k, i + 1, PARAM_TYPES[k]) for i, k in enumerate(names)))
        args = [params[k] for k in names]
        try:
            async with self.pool.acquire(timeout=30) as c:
                return await c.fetchval(sql_text, *args, timeout=timeout)
        except asyncpg.PostgresError as e:
            state = getattr(e, "sqlstate", None) or ""
            hint = getattr(e, "hint", None)
            if state in CONTRACT_SQLSTATES:
                raise ContractBroken(state)
            if hint == "not_service":
                raise NotService()
            if state.startswith("PT"):
                raise Refused(state, hint, getattr(e, "detail", None))
            if isinstance(e, (asyncpg.ConnectionDoesNotExistError, asyncpg.AdminShutdownError, asyncpg.CannotConnectNowError,
                              asyncpg.QueryCanceledError)) or state.startswith("08") or state.startswith("57P"):
                raise DbAway(type(e).__name__)
            raise
        except (OSError, asyncio.TimeoutError, asyncpg.InterfaceError) as e:
            raise DbAway(type(e).__name__)

    async def check_contract(self):
        """Every function exists, may be run, and has the parameters sent. Returns the missing ones (names of
        functions, or function.parameter); the optional ones found are kept in self.optional."""
        import asyncpg
        if self.pool is None:
            raise DbAway("closed")
        try:
            async with self.pool.acquire(timeout=30) as c:
                rows = await c.fetch(
                    "select p.proname, coalesce(p.proargnames, '{}'::text[]) as names,"
                    "       has_function_privilege(p.oid, 'execute') as can"
                    "  from pg_catalog.pg_proc p join pg_catalog.pg_namespace n on n.oid = p.pronamespace"
                    " where n.nspname = 'sentinel' and p.proname = any($1::text[])", list(CONTRACT), timeout=30)
        except (OSError, asyncio.TimeoutError, asyncpg.InterfaceError, asyncpg.ConnectionDoesNotExistError) as e:
            raise DbAway(type(e).__name__)
        found = collections.defaultdict(list)
        for r in rows:
            found[r["proname"]].append((set(r["names"]), r["can"]))
        missing = []
        optional = set()
        for fn, all_params in CONTRACT.items():
            extra = CONTRACT_OPTIONAL_PARAMS.get(fn, ())
            params = tuple(x for x in all_params if x not in extra)
            variants = found.get(fn, [])
            ok = any(set(params) <= names and can for names, can in variants)
            if ok:
                if fn in CONTRACT_OPTIONAL:
                    optional.add(fn)
                for x in extra:
                    if any(set(params) | {x} <= names and can for names, can in variants):
                        optional.add(fn + "." + x)
                continue
            if fn in CONTRACT_OPTIONAL:
                continue
            if not variants:
                missing.append(fn)
            elif not any(can for _n, can in variants):
                missing.append(fn + " (no execute)")
            else:
                best = max(variants, key=lambda v: len(set(params) & v[0]))[0]
                missing.extend(fn + "." + p for p in params if p not in best)
        self.optional = optional
        self.missing = missing
        return missing


# ===========================================================================
# 9. THE WORKER: CHECK-IN, HEARTBEAT, CLAIMING, THE QUEUE, RENEWALS, HAND-INS, STOPPING
# ===========================================================================
import concurrent.futures


class Shutdown(Exception):
    """SIGTERM's allowance is used up while waiting for the database."""


def lib_version():
    return getattr(ds_connect_lib, "__version__", "?")


FILE_SYSTEM_TYPES = ("directory",)


def scan_reads(file_roots):
    """Every data source type scan's code can read, offered or not, and why not (standard 2026-48-37 §18.2).
    The capabilities come from this too, so the two agree. why: no_file_roots (DS_FILE_ROOTS isn't set),
    driver_missing (the library's driver for it isn't in the image), not_in_library (ds_connect_lib has no
    such type)."""
    try:
        available = ds_connect_lib.types()
    except Exception:
        available = {}
    out = []
    for t in SCAN_SOURCE_TYPES:
        info = available.get(t)
        if info is None:
            why = "not_in_library"
        elif not info.available:
            why = "driver_missing"
        elif t in FILE_SYSTEM_TYPES and not file_roots:
            why = "no_file_roots"
        else:
            why = None
        out.append({"type": t, "offered": why is None, "why": why})
    return out


def scan_reads_from_env(env):
    return scan_reads([x for x in (env.get("DS_FILE_ROOTS") or "").split(":") if x.strip()])


def scan_capabilities(settings):
    """Generated from code (standard §6): the types offered in scan_reads."""
    return {STAGE: {"types": [r["type"] for r in scan_reads(settings.file_roots) if r["offered"]]}}


# what each format's reader is built on: (format, library's distribution name or None for Python's own, module)
_READER_LIBRARIES = (("txt", None, None), ("csv", None, None), ("json", None, None), ("xml", "lxml", "lxml"), ("html", "lxml", "lxml"),
                     ("pdf",) + PdfDocument.LIBRARY, ("docx", "lxml", "lxml"), ("pptx", "lxml", "lxml"), ("xlsx", "lxml", "lxml"),
                     ("xls", "xlrd", "xlrd"), ("zip", None, None))


def scan_loaded():
    """What decides what scan can do (standard 2026-48-37 §18.2), each {kind, name, version, count, ok, why}.
    Kinds: reader (one per format, with the library it is built on), writer (the working files), ocr."""
    import importlib.metadata as _md
    import importlib.util as _iu

    def lib(dist, module):
        if dist is None:
            return "python " + sys.version.split()[0], True, None
        try:
            present = _iu.find_spec(module) is not None
        except (ImportError, ValueError):
            present = False
        if not present:
            return None, False, "not_installed"
        try:
            return "%s %s" % (dist.lower(), _md.version(dist)), True, None
        except _md.PackageNotFoundError:
            return dist.lower(), True, None

    out = []
    for name, dist, module in _READER_LIBRARIES:
        version, ok, why = lib(dist, module)
        out.append({"kind": "reader", "name": name, "version": version, "count": None, "ok": ok, "why": why})
    version, ok, why = lib("pyarrow", "pyarrow")
    out.append({"kind": "writer", "name": "parquet", "version": version, "count": None, "ok": ok, "why": why})
    out.append({"kind": "ocr", "name": "ocr", "version": None, "count": None, "ok": False, "why": "not_in_build"})
    return out


def scan_report(settings=None, env=None):
    """The report document sent at check-in and again when it changes: the same function as the log's."""
    title = {"worker": "scan", "version": VERSION, "connect": lib_version(), "python": sys.version.split()[0]}
    env = os.environ if env is None else env
    doc, _lines = worker_report(title, SETTINGS_SPEC, SECRET_FILES, env=env, required=REQUIRED_SETTINGS,
                                reads=scan_reads_from_env(env), loaded=scan_loaded(), standard=STANDARD_EDITION)
    return doc


def _now_iso():
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def _jitter(sec):
    return sec * random.uniform(0.8, 1.2)


def _has_classify(workers):
    if not isinstance(workers, dict) or "classify" not in workers:
        return False
    v = workers.get("classify")
    if isinstance(v, (int, float)) and not isinstance(v, bool):
        return v > 0
    return v is not None and v is not False


def run_writes(block):
    """Whether a run's scan writes extracts: its workers have a classify stage and, from db 2026-48-07, its
    classifications list isn't empty. A run whose list is empty has nothing to classify; scan works as in a run
    without a classify stage, whatever the claim says of the stage (note 2026-48-54 §3). Absent list: as before."""
    if not _has_classify((block or {}).get("workers")):
        return False
    names = (block or {}).get("classifications")
    return not (isinstance(names, list) and not names)


def _classifications_seen(block):
    names = (block or {}).get("classifications")
    return len(names) if isinstance(names, list) else "absent"


def check_folders(settings):
    """The folders the worker writes: DS_SCAN_TMP (its own subfolder), then DS_WORK_DIR. Each is created if
    missing, listed, and written to. On the way, this service's leftovers are removed and run folders older
    than seven days go (ruling 8). Returns (problem, removed): problem is None, or {setting, path, step,
    error} for the first step that failed (step: create, list or write; error: the errno's name)."""
    removed = {"spool": 0, "tmp": 0, "runs": 0}

    def failed(setting, path, step, exc):
        import errno as _errno
        return {"setting": setting, "path": path, "step": step,
                "error": _errno.errorcode.get(getattr(exc, "errno", None) or 0, type(exc).__name__)}

    def probe(folder):
        path = os.path.join(folder, ".probe-%s" % uuid.uuid4().hex)
        with open(path, "wb") as fh:
            fh.write(b"x")
        os.remove(path)

    spool = os.path.join(settings.scan_tmp, settings.service)
    for step, act in (("create", lambda: os.makedirs(spool, exist_ok=True)), ("list", lambda: os.listdir(spool)), ("write", lambda: probe(spool))):
        try:
            act()
        except OSError as e:
            return failed("DS_SCAN_TMP", settings.scan_tmp if step == "create" and not os.path.isdir(settings.scan_tmp) else spool, step, e), removed
    for name in os.listdir(spool):
        remove_tree(os.path.join(spool, name))
        removed["spool"] += 1

    work = settings.work_dir
    try:
        os.makedirs(work, exist_ok=True)
    except OSError as e:
        return failed("DS_WORK_DIR", work, "create", e), removed
    try:
        names = os.listdir(work)
    except OSError as e:
        return failed("DS_WORK_DIR", work, "list", e), removed
    try:
        probe(work)
    except OSError as e:
        return failed("DS_WORK_DIR", work, "write", e), removed
    limit = time.time() - STALE_RUN_FOLDER_DAYS * 86400
    prefix = ".tmp-%s-" % settings.service
    for name in names:
        run_dir = os.path.join(work, name)
        if not name.isdigit() or not os.path.isdir(run_dir):
            continue
        try:
            if os.stat(run_dir).st_mtime < limit:
                remove_tree(run_dir)
                removed["runs"] += 1
                continue
            for inner in os.listdir(run_dir):
                if inner.startswith(prefix):
                    remove_tree(os.path.join(run_dir, inner))
                    removed["tmp"] += 1
        except OSError:
            continue
    return None, removed


class Worker(object):
    def __init__(self, settings, request_exit=None):
        self.s = settings
        self.request_exit = request_exit
        self.db = Db(settings, on_notify=self._notified)
        self.worker_id = None
        self.status = "starting"
        self.step = "starting"
        self.problem = None
        self.work = health_item("starting")
        self.last_ask = None
        self.contract_ok = False
        self.contract_next = 0.0
        self.contract_tries = 0
        self.dir_problem = None         # {setting, path, step, error} while a folder can't be used
        self.dir_next = 0.0
        self.dir_tries = 0
        self.set_aside = None
        self.capabilities = scan_capabilities(settings)
        self.version = "%s (connect %s)" % (VERSION, lib_version())
        self.queue = None
        self.queues_done = 0
        self.closing = False
        self.sigterm_at = None
        self.exit_code = 0
        self.loop = None
        self.tasks = []
        self.db_ready = None
        self.wake = None
        self.keeper_wake = None
        self.done = None
        self.executor = None

    # ---------------------------------------------------------------- state
    @property
    def ready(self):
        return (self.db.up and self.contract_ok and self.worker_id is not None and self.dir_problem is None and self.set_aside is None
                and not self.closing)

    def health(self):
        problem = None
        if not self.ready:
            if self.closing:
                problem = health_item("stopping")
            elif not self.db.up:
                problem = health_item("reconnecting")
            elif not self.contract_ok and self.db.missing:
                problem = health_item("contract_missing", missing=list(self.db.missing)[:20])
            elif self.dir_problem:
                problem = health_item("work_dir_unusable", setting=self.dir_problem["setting"], step=self.dir_problem["step"])
            elif self.set_aside is not None:
                problem = health_item("queue_set_aside", **self.set_aside)
            else:
                problem = health_item("starting")
        detail = {"last_ask": self.last_ask, "queues_done": self.queues_done, "threads": self.s.threads,
                  "types": self.capabilities[STAGE]["types"], "noatime_refused": NOATIME_REFUSED[0]}
        if self.queue is not None:
            detail.update(self.queue.detail())
        out = {"ready": self.ready, "problem": problem, "work": self.work, "detail": detail}
        if len(json.dumps(out)) > 3900:
            out["detail"] = {"last_ask": self.last_ask}
        return out

    def status_json(self):
        return {"worker": {"name": self.s.service, "type": WORKER_TYPE, "version": self.version, "worker_id": self.worker_id,
                           "status": self.status, "step": self.step, "standard": STANDARD},
                "database": {"up": self.db.up, "contract_ok": self.contract_ok, "missing": list(self.db.missing),
                             "optional": sorted(self.db.optional)},
                "holding": self.queue.holding() if self.queue is not None else None,
                "health": self.health()}

    def set_work(self, code, **params):
        self.work = health_item(code, **params)

    # ---------------------------------------------------------------- the database
    def _notified(self, channel, payload):
        if channel == "run_work" and self.queue is not None:
            self.queue.notified(payload)
        elif channel == "run_request" and self.queue is None and self.wake is not None:
            self.wake.set()

    def db_lost(self):
        if self.db.up:
            log.warning(kv("database_lost"))
        self.db.up = False
        if self.db_ready is not None:
            self.db_ready.clear()
        if self.keeper_wake is not None:
            self.keeper_wake.set()

    def contract_broken(self):
        if self.contract_ok:
            log.warning(kv("contract_broken"))
        self.contract_ok = False
        self.contract_tries = 0
        self.contract_next = time.monotonic() + 5
        if self.db_ready is not None:
            self.db_ready.clear()
        if self.keeper_wake is not None:
            self.keeper_wake.set()

    def _contract_wait(self):
        waits = (5, 15, 30)
        w = waits[self.contract_tries] if self.contract_tries < len(waits) else CONTRACT_RECHECK_SEC
        self.contract_tries += 1
        return w

    async def keeper(self):
        """Keeps the links up and the contract checked: reconnect with a growing wait up to 30 seconds, never
        exit; after a reconnect the contract check, LISTEN, then read what is due at once."""
        delay = 1.0
        last_missing = None
        while not self.done.is_set():
            if not self.db.up:
                if self.worker_id is not None:
                    self.step = "reconnecting"
                try:
                    await self.db.open()
                    delay = 1.0
                    self.contract_ok = False
                    self.contract_next = 0.0
                    self.contract_tries = 0
                    log.info(kv("database_connected", links=2))
                except DbAway:
                    await self._sleep_or_wake(delay)
                    delay = min(delay * 2, RECONNECT_MAX_SEC)
                    continue
            if self.dir_problem is not None and time.monotonic() >= self.dir_next:
                await self.check_folders()
            if self.db.up and not self.contract_ok and time.monotonic() >= self.contract_next:
                try:
                    missing = await self.db.check_contract()
                except DbAway:
                    self.db_lost()
                    continue
                if missing:
                    if missing != last_missing:
                        log.error(kv("contract_missing", missing=",".join(missing)))
                        last_missing = list(missing)
                    self.step = "contract_missing"
                    self.contract_next = time.monotonic() + self._contract_wait()
                else:
                    if last_missing:
                        log.info(kv("contract_ok"))
                    last_missing = None
                    self.contract_ok = True
                    self.db_ready.set()
                    self.wake.set()
            await self._sleep_or_wake(1.0)

    async def check_folders(self):
        """Note 2026-48-22: a folder that can't be used is an error that names it and the step that failed;
        it is checked again at 5, 15, 30 and then every 60 seconds, and the worker becomes ready once it is fixed."""
        problem, removed = await self.loop.run_in_executor(self.executor, check_folders, self.s)
        if problem is None:
            if self.dir_problem is not None:
                log.info(kv("folders_usable", work="resumes"))
                self.wake.set()
                self.dir_problem = None
                await self.send_report()
            else:
                log.info(kv("start_up_cleanup", spool=removed["spool"], tmp=removed["tmp"], runs=removed["runs"]))
            self.dir_problem = None
            self.dir_tries = 0
            return
        self.dir_problem = problem
        waits = (5, 15, 30)
        wait = waits[self.dir_tries] if self.dir_tries < len(waits) else CONTRACT_RECHECK_SEC
        self.dir_tries += 1
        self.dir_next = time.monotonic() + wait
        log.error(kv("folder_unusable", setting=problem["setting"], path=problem["path"], tried=problem["step"], error=problem["error"],
                     work="none_until_fixed", next_check_sec=wait))

    async def _sleep_or_wake(self, sec):
        self.keeper_wake.clear()
        try:
            await asyncio.wait_for(self.keeper_wake.wait(), sec)
        except asyncio.TimeoutError:
            pass

    async def wait_db(self, deadline=None):
        while not (self.db.up and self.contract_ok):
            if self.done.is_set():
                raise Shutdown()
            timeout = None if deadline is None else deadline - time.monotonic()
            if timeout is not None and timeout <= 0:
                raise Shutdown()
            try:
                await asyncio.wait_for(self.db_ready.wait(), min(5.0, timeout) if timeout is not None else 5.0)
            except asyncio.TimeoutError:
                pass

    async def call(self, fn, deadline=None, retry=True, **params):
        """A function call that waits out a lost database (keeping its place) and a broken contract."""
        while True:
            await self.wait_db(deadline)
            try:
                return await self.db.call(fn, **params)
            except DbAway:
                self.db_lost()
                if not retry:
                    raise
            except ContractBroken:
                self.contract_broken()
                if not retry:
                    raise
            except NotService:
                self.fatal_not_service()
                raise Shutdown()

    def fatal_not_service(self):
        log.error(kv("not_service", db_user=self.s.db_user))
        self.exit_code = 1
        self.closing = True
        if self.done is not None:
            self.done.set()
        if self.request_exit is not None:
            self.request_exit(1)

    # ---------------------------------------------------------------- check-in and heartbeat
    async def checkin(self):
        while self.worker_id is None and not self.done.is_set():
            try:
                await self.wait_db_up()
                ans = await self.db.call("sys_post_worker_checkin", v_worker_type=WORKER_TYPE, v_worker_name=self.s.service,
                                         v_worker_version=self.version, v_address=self.s.external_host, v_port=self.s.external_port,
                                         v_capabilities=self.capabilities, v_report=self.report())
                self.worker_id = int(ans["worker_id"])
                self.status = "starting"
                log.info(kv("checked_in", worker_id=self.worker_id, types=",".join(self.capabilities[STAGE]["types"]) or "-",
                            report="sent" if "sys_post_worker_checkin.v_report" in self.db.optional else "not_taken"))
            except DbAway:
                self.db_lost()
            except ContractBroken:
                self.contract_broken()
                await asyncio.sleep(5)
            except NotService:
                self.fatal_not_service()
                return
            except Refused as e:
                log.error(kv("checkin_refused", hint=e.hint))
                await asyncio.sleep(30)

    def report(self):
        try:
            return scan_report()
        except Exception as e:
            log.warning(kv("report_failed", error=where(e)[0]))
            return None

    async def send_report(self):
        """Standard 2026-48-37 §18.2: the report again when something in it changes, when the database takes it."""
        if self.worker_id is None or "sys_post_worker_report" not in self.db.optional:
            return
        try:
            await self.db.call("sys_post_worker_report", timeout=20, v_worker_id=self.worker_id, v_report=self.report())
            log.info(kv("report_sent", worker_id=self.worker_id))
        except (Refused, DbAway, ContractBroken) as e:
            log.warning(kv("report_not_sent", error=type(e).__name__))

    async def wait_db_up(self):
        while not self.db.up:
            if self.done.is_set():
                raise Shutdown()
            await asyncio.sleep(0.5)

    async def heartbeat(self):
        if self.worker_id is None or not self.db.up:
            return
        health = self.health()
        try:
            await self.db.call("sys_post_worker_heartbeat", timeout=20, v_worker_id=self.worker_id, v_status=self.status, v_health=health)
        except Refused as e:
            if e.hint == "worker_not_found":
                log.warning(kv("worker_not_found", worker_id=self.worker_id))
                self.worker_id = None
                await self.checkin()
            elif e.hint == "health_invalid":
                log.warning(kv("health_invalid"))
                try:
                    await self.db.call("sys_post_worker_heartbeat", timeout=20, v_worker_id=self.worker_id, v_status=self.status)
                except (Refused, DbAway, ContractBroken):
                    pass
        except DbAway:
            self.db_lost()
        except ContractBroken:
            self.contract_broken()
        except NotService:
            self.fatal_not_service()

    async def heartbeat_loop(self):
        while not self.done.is_set():
            try:
                await self.heartbeat()
            except Exception as e:
                log.warning(kv("heartbeat_failed", error=where(e)[0]))
            try:
                await asyncio.wait_for(self.done.wait(), HEARTBEAT_SEC)
            except asyncio.TimeoutError:
                pass

    # ---------------------------------------------------------------- the main line
    async def run(self):
        self.loop = asyncio.get_running_loop()
        self.db_ready = asyncio.Event()
        self.wake = asyncio.Event()
        self.keeper_wake = asyncio.Event()
        self.done = asyncio.Event()
        self.executor = ThreadPoolExecutor(max_workers=self.s.threads + 2, thread_name_prefix="scan")
        await self.check_folders()
        self.tasks.append(asyncio.ensure_future(self.keeper()))
        self.tasks.append(asyncio.ensure_future(self.heartbeat_loop()))
        try:
            await self.checkin()
            if self.worker_id is None:
                return
            await self.heartbeat()
            await self.take_held()
            await self.idle_loop()
        except Shutdown:
            pass
        except asyncio.CancelledError:
            pass
        except Exception as e:
            cls, fn = where(e)
            log.error(kv("worker_failed", error=cls, where=fn))

    async def take_held(self):
        """At start, before anything else: a queue still held is carried on with, at the same attempt."""
        held = await self.call("sys_get_partitions_held", v_worker_id=self.worker_id)
        mine = [h for h in (held or []) if h.get("stage") == STAGE]
        if self.status == "starting":
            self.status = "active"
            await self.heartbeat()
        for h in mine:
            if self.closing:
                return
            await self.hold(h, resumed=True)

    async def idle_loop(self):
        while not self.closing:
            if not self.ready:
                await self._idle_wait(1.0)
                continue
            self.set_work("idle")
            try:
                await self.db.ping()
            except DbAway:
                self.db_lost()
                continue
            try:
                self.last_ask = _now_iso()
                ans = await self.db.call("sys_post_partition_claim_next", v_worker_id=self.worker_id)
            except DbAway:
                self.db_lost()
                continue
            except ContractBroken:
                self.contract_broken()
                continue
            except NotService:
                self.fatal_not_service()
                return
            except Refused as e:
                if e.hint == "worker_not_found":
                    self.worker_id = None
                    await self.checkin()
                    continue
                log.warning(kv("claim_refused", hint=e.hint))
                await self._idle_wait(_jitter(self.s.poll_sec))
                continue
            if ans and ans.get("claimed"):
                await self.hold(ans, resumed=False)
                continue
            why = (ans or {}).get("why")
            if why == "worker_busy":
                await self.take_held()
                continue
            await self._idle_wait(_jitter(self.s.poll_sec))

    async def _idle_wait(self, sec):
        self.wake.clear()
        try:
            await asyncio.wait_for(self.wake.wait(), sec)
        except asyncio.TimeoutError:
            pass

    async def hold(self, claim, resumed):
        if self.closing:
            log.info(kv("claim_kept_for_next_start", run_id=claim.get("run_id"), partition_id=claim.get("partition_id")))
            return
        q = QueueRun(self, claim, resumed)
        self.queue = q
        try:
            await q.run()
        finally:
            self.queue = None
            self.queues_done += 1
            if not self.closing:
                self.set_work("idle")

    # ---------------------------------------------------------------- SIGTERM
    async def shutdown(self):
        """Heartbeat stopping; no more work; the work in hand gets up to 30 seconds to stop and hand in;
        the claim is kept; the connections close."""
        if self.sigterm_at is not None:
            return
        self.sigterm_at = time.monotonic()
        deadline = self.sigterm_at + SIGTERM_LIMIT_SEC - 3
        self.closing = True
        self.status = "stopping"
        self.set_work("stopping")
        self.step = "stopping"
        log.info(kv("sigterm", holding=self.queue is not None))
        if self.wake is not None:
            self.wake.set()
        try:
            await asyncio.wait_for(self.heartbeat(), 5)
        except Exception:
            pass
        q = self.queue
        if q is not None:
            try:
                await asyncio.wait_for(q.sigterm(deadline), max(1.0, deadline - time.monotonic()))
            except Exception as e:
                log.warning(kv("sigterm_handin_incomplete", error=where(e)[0]))
        if self.done is not None:
            self.done.set()
        for t in self.tasks:
            t.cancel()
        try:
            await asyncio.wait_for(self.db.close(), 3)
        except Exception:
            pass
        if self.executor is not None:
            self.executor.shutdown(wait=False, cancel_futures=True)
        log.info(kv("stopped", seconds=round(time.monotonic() - self.sigterm_at, 1)))


class QueueRun(object):
    """One claimed scan queue: read its objects, hand in what was found, renew, finish."""

    def __init__(self, worker, claim, resumed):
        self.w = worker
        self.s = worker.s
        self.run_id = int(claim["run_id"])
        self.stage = claim.get("stage") or STAGE
        self.partition_id = int(claim["partition_id"])
        self.attempt = int(claim["attempt"])
        self.block = claim.get("run") or {}     # the claim's run block
        self.resumed = resumed
        self.source_type = str(self.block.get("source_type") or "")
        self.data_source_id = self.block.get("data_source_id")
        self.write = run_writes(self.block)
        self.full = str(self.block.get("run_mode") or "") == "force"
        cp = self.block.get("checkpoint")
        self.checkpoint = cp if isinstance(cp, dict) else {}
        self.stop_event = threading.Event()
        self.end = None                 # completed | held_lost | stop | cancel | pause | sigterm | abort | error | set_aside
        self.no_new = False
        self.abort = None
        self.error = None
        self.reading = {}
        self.inflight = set()
        self.pending = []
        self.pending_parts = 0
        self.last_handin = time.monotonic()
        self.counts = {"objects": 0, "bytes": 0, "done": 0, "skipped": 0, "failed": 0, "parts": 0}
        self.live_bytes = 0
        self.live_lock = threading.Lock()
        self.after = None
        self.more = asyncio.Event()
        self.renew_now = asyncio.Event()
        self.renewed = asyncio.Event()
        self.renew_lock = asyncio.Lock()
        self.finished = False
        self.scope = None
        self.root_real = None
        self.dir_handle = None
        self.conns = None
        self.known_queue = []
        self.known_task = None
        self.refusals = {}
        self.waiting_space = False
        self.kick = asyncio.Event()     # set by a stop: every wait of the queue wakes at once

    # ---------------------------------------------------------------- what the summary shows
    def holding(self):
        return {"run_id": self.run_id, "stage": self.stage, "partition_id": self.partition_id, "attempt": self.attempt,
                "source_type": self.source_type, "full": self.full, "classify": self.write}

    def detail(self):
        return {"run_id": self.run_id, "partition_id": self.partition_id, "attempt": self.attempt, "reading": len(self.reading),
                "handed_in": self.counts["objects"], "pending": len(self.pending)}

    def notified(self, payload):
        try:
            run_id, stage, part = str(payload).split(":")
            if int(run_id) == self.run_id and stage == self.stage and int(part) == self.partition_id:
                self.more.set()
        except (ValueError, TypeError):
            pass

    def _key(self):
        return dict(v_run_id=self.run_id, v_partition_id=self.partition_id, v_worker_id=self.w.worker_id, v_attempt=self.attempt)

    def _qkey(self):
        return dict(v_run_id=self.run_id, v_stage=self.stage, v_partition_id=self.partition_id, v_worker_id=self.w.worker_id,
                    v_attempt=self.attempt)

    # ---------------------------------------------------------------- the line of a queue
    async def run(self):
        log.info(kv("queue_taken", run_id=self.run_id, partition_id=self.partition_id, attempt=self.attempt, resumed=self.resumed,
                    source_type=self.source_type, full=self.full, classify=self.write,
                    classifications=_classifications_seen(self.block)))
        self.w.set_work("working", stage=self.stage, run_id=self.run_id)
        renew_task = asyncio.ensure_future(self.renew_loop())
        try:
            ans = await self.renew_once()
            if ans.get("held"):
                await self.prepare()
            if self.end is None and self.resumed:
                await self.resume_marking()
            if self.end is None:
                await self.work_loop()
        except QueueAbort as e:
            self.abort = e
            self.end = self.end or "abort"
        except Shutdown:
            self.end = self.end or "sigterm"
        except asyncio.CancelledError:
            self.end = self.end or "sigterm"
            raise
        except Exception as e:
            self.error = e
            self.end = self.end or "error"
            cls, fn = where(e)
            log.error(kv("queue_error", run_id=self.run_id, partition_id=self.partition_id, error=cls, where=fn))
        finally:
            try:
                await self.finish()
            finally:
                self.finished = True
                renew_task.cancel()
                self.cleanup()

    async def prepare(self):
        """The data source's connection, and a handle: the root for a file system, a connection per thread
        for a database. A data source that can't be reached ends the queue as retry with the library's code."""
        if self.source_type not in self.w.capabilities[STAGE]["types"]:
            raise QueueAbort("not_checkable", {})
        try:
            connection = await self.w.call("sys_get_data_source_connection", v_data_source_id=self.data_source_id)
        except Refused as e:
            raise QueueAbort("data_source_unusable", {"problem": e.hint or e.sqlstate})
        loop = asyncio.get_running_loop()
        if self.source_type == "directory":
            def _open():
                try:
                    return ds_connect_lib.connect("directory", connection, file_roots=self.s.file_roots, ca_file=self.s.ca_bundle,
                                                  proxy=self.s.proxy())
                except ds_connect_lib.ConnectError as err:
                    raise QueueAbort(err.code, err.params)
            self.dir_handle = await loop.run_in_executor(self.w.executor, _open)
            self.root_real = self.dir_handle.client
        elif self.source_type == "postgres":
            self.conns = TableConnections("postgres", connection, self.s)
            await loop.run_in_executor(self.w.executor, self.conns.get)
        lookup = self.lookup if (not self.full and "sys_get_known_content" in self.w.db.optional) else None
        self.scope = Scope(self.s, self.run_id, self.write, self.full, self.stop_event, lookup=lookup, on_bytes=self._on_bytes)
        connection = None

    def _on_bytes(self, n):
        with self.live_lock:
            self.live_bytes += n

    async def resume_marking(self):
        """The objects named in the checkpoint were being read when the last holder stopped: each is marked
        failed (worker_stopped) and not read again."""
        ids = [i for i in (self.checkpoint.get("reading") or []) if isinstance(i, int)]
        if not ids:
            return
        log.info(kv("resume_marking", run_id=self.run_id, partition_id=self.partition_id, objects=len(ids)))
        elements = [object_element(loc, _failed(reason("worker_stopped"))) for loc in ids]
        for e in elements:
            self._count(e, 0)
        self.pending.extend(elements)
        await self.flush()
        self.checkpoint = {}

    async def work_loop(self):
        complete_refusals = 0
        while self.end is None:
            page = await self.w.call("sys_get_partition_objects", v_after=self.after, v_limit=PAGE_LIMIT, **self._qkey())
            if not page or not page.get("held"):
                self.lost()
                break
            objs = page.get("objects") or []
            if objs:
                self.w.set_work("working", stage=self.stage, run_id=self.run_id)
                self.after = objs[-1].get("place", self.after)
                await self.read_page(objs)
                continue
            if self.inflight:
                await asyncio.wait(list(self.inflight))
            await self.flush()
            if self.end is not None:
                break
            if page.get("more_coming"):
                await self.wait_for_more()
                continue
            self.w.set_work("winding_down", run_id=self.run_id)
            try:
                ans = await self.w.call("sys_post_partition_complete", v_summary=self.summary(), **self._qkey())
            except Refused as e:
                complete_refusals += 1
                if complete_refusals >= 3:
                    self.set_aside("complete", e.hint)
                    break
                await self.nap(5)
                continue
            if ans.get("done"):
                self.end = "completed"
                log.info(kv("queue_completed", run_id=self.run_id, partition_id=self.partition_id, noatime_refused=NOATIME_REFUSED[0],
                            **self.counts))
                break
            why = ans.get("why")
            if why == "not_held":
                self.lost()
                break
            if why == "objects_waiting":
                self.after = None
                await self.nap(1)
                continue
            if why == "more_coming":
                await self.wait_for_more()
                continue

    async def wait_for_more(self):
        """An empty list with more_coming true: wait for discovery (run_work, or the renew answer's waiting)."""
        self.w.set_work("waiting_for_work", run_id=self.run_id)
        self.more.clear()
        try:
            await asyncio.wait_for(self.more.wait(), min(RENEW_SEC, 30.0))
        except asyncio.TimeoutError:
            pass

    async def read_page(self, objs):
        sem = asyncio.Semaphore(self.s.threads)
        for obj in objs:
            if self.end is not None or self.no_new:
                break
            if self.write and not await self.space_ok():
                break
            await sem.acquire()
            if self.end is not None or self.no_new:
                sem.release()
                break
            t = asyncio.ensure_future(self.read_one(obj, sem))
            self.inflight.add(t)
            t.add_done_callback(self.inflight.discard)
            if self.due():
                await self.flush()
        if self.inflight:
            await asyncio.wait(list(self.inflight))
        if self.due():
            await self.flush()

    async def space_ok(self):
        """Below the free-space threshold of the working folder: show waiting_for_space and read nothing."""
        need = self.s.work_min_free_mb * _MB
        while self.end is None and not self.no_new:
            try:
                free = shutil.disk_usage(self.s.work_dir).free
            except OSError:
                free = 0
            if free >= need:
                if self.waiting_space:
                    self.waiting_space = False
                    log.info(kv("space_back", run_id=self.run_id, free_mb=free // _MB))
                    self.w.set_work("working", stage=self.stage, run_id=self.run_id)
                return True
            if not self.waiting_space:
                self.waiting_space = True
                log.warning(kv("waiting_for_space", run_id=self.run_id, free_mb=free // _MB, need_mb=self.s.work_min_free_mb))
            self.w.set_work("waiting_for_space", run_id=self.run_id)
            if self.pending and not self.inflight:
                await self.flush()
            await self.nap(WORK_SPACE_RECHECK_SEC)
        return False

    async def read_one(self, obj, sem):
        loc = obj.get("location_id")
        size = int(obj.get("bytes") or 0)
        try:
            if not isinstance(loc, int):
                return
            self.reading[loc] = size
            if size >= CHECKPOINT_TOUCH_BYTES or self.source_type == "postgres":
                await self.renew_soon()
            loop = asyncio.get_running_loop()
            element = await loop.run_in_executor(self.w.executor, self.read_blocking, obj)
            if element is None or self.end in ("held_lost",):
                if element is not None:
                    self.drop([element])
                return
            self._count(element, size)
            self.pending.append(element)
            self.pending_parts += len(element.get("parts") or ())
            if self.w.s.log_level == "debug":
                log.debug(kv("object_read", location_id=loc, outcome=element.get("outcome"), code=element.get("code"),
                             parts=len(element.get("parts") or ())))
        except QueueAbort as e:
            if self.abort is None:
                self.abort = e
            self.stop_all("abort")
        except Exception as e:
            if self.error is None:
                self.error = e
            cls, fn = where(e)
            log.error(kv("object_error", location_id=loc, error=cls, where=fn))
            self.stop_all("error")
        finally:
            self.reading.pop(loc, None)
            sem.release()

    def read_blocking(self, obj):
        if self.stop_event.is_set():
            return None
        if self.source_type == "directory":
            return scan_file_object(obj, self.scope, self.root_real)
        if self.source_type == "postgres":
            return scan_table_object(obj, self.scope, self.conns)
        raise QueueAbort("not_checkable", {})

    def _count(self, element, size):
        out = element.get("outcome")
        self.counts["objects"] += 1
        self.counts["bytes"] += size
        if out in ("done", "skipped", "failed"):
            self.counts[out] += 1
        self.counts["parts"] += len(element.get("parts") or ())

    def summary(self):
        return {k: int(v) for k, v in self.counts.items()}

    def progress(self):
        p = self.summary()
        with self.live_lock:
            p["bytes_read"] = int(self.live_bytes)
        p["reading"] = len(self.reading)
        return p

    # ---------------------------------------------------------------- stopping
    def stop_all(self, end):
        if self.end is None:
            self.end = end
        self.stop_event.set()
        self.more.set()
        self.kick.set()
        if self.conns is not None:
            self.conns.cancel_all()

    async def nap(self, sec):
        """A wait that a stop cuts short."""
        if self.kick.is_set():
            return
        try:
            await asyncio.wait_for(self.kick.wait(), sec)
        except asyncio.TimeoutError:
            pass

    def lost(self):
        """held false: stop at once and write nothing more for this queue."""
        if self.end != "held_lost":
            log.warning(kv("queue_lost", run_id=self.run_id, partition_id=self.partition_id))
        self.end = "held_lost"
        self.stop_event.set()
        self.more.set()
        self.kick.set()
        if self.conns is not None:
            self.conns.cancel_all()
        self.drop(self.pending)
        self.pending = []
        self.pending_parts = 0

    def set_aside(self, what, hint):
        self.end = "set_aside"
        self.stop_event.set()
        self.w.set_aside = {"run_id": self.run_id, "partition_id": self.partition_id, "call": what, "hint": hint or "-"}
        log.error(kv("queue_set_aside", run_id=self.run_id, partition_id=self.partition_id, call=what, hint=hint))

    async def sigterm(self, deadline):
        """Hand in what is done, keep the claim. The objects in hand get until 8 seconds before the deadline."""
        self.no_new = True
        if self.inflight:
            await asyncio.wait(list(self.inflight), timeout=max(0.0, deadline - 8 - time.monotonic()))
        self.stop_all("sigterm")
        if self.inflight:
            await asyncio.wait(list(self.inflight), timeout=max(0.0, deadline - 5 - time.monotonic()))
        # finish() (run()'s finally) hands in; wait for it
        t_end = deadline
        while not self.finished and time.monotonic() < t_end:
            await asyncio.sleep(0.1)

    async def finish(self):
        end = self.end
        if self.inflight:
            limit = STOP_LIMIT_SEC - 3 if end in ("stop", "cancel", "pause") else 5
            await asyncio.wait(list(self.inflight), timeout=limit)
        if self.known_task is not None:
            self.known_task.cancel()
        if end in ("held_lost", "set_aside"):
            self.drop(self.pending)
            self.pending = []
            return
        deadline = None
        if end == "sigterm" and self.w.sigterm_at is not None:
            deadline = self.w.sigterm_at + SIGTERM_LIMIT_SEC - 3
        elif end in ("stop", "cancel", "pause"):
            deadline = time.monotonic() + STOP_LIMIT_SEC
        try:
            if self.pending:
                await self.flush(deadline=deadline)
            if self.end == "held_lost":
                return
            if end in ("stop", "cancel", "pause"):
                await self.renew_once(deadline=deadline)
                outcome = {"stop": "stopped", "cancel": "cancelled", "pause": "paused"}[end]
                await self.release(outcome, deadline=deadline)
            elif end == "sigterm":
                await self.renew_once(deadline=deadline)
                log.info(kv("queue_kept", run_id=self.run_id, partition_id=self.partition_id, **self.counts))
            elif end == "abort":
                r = reason(self.abort.code, **(self.abort.params or {}))
                await self.release("retry", r)
            elif end == "error":
                cls, fn = where(self.error) if self.error is not None else ("Exception", "?")
                await self.release("retry", reason("unexpected", reason=cls))
        except Shutdown:
            pass

    async def release(self, outcome, r=None, deadline=None):
        params = dict(v_outcome=outcome)
        if r is not None:
            params.update(v_code=r["code"], v_params=r["params"], v_text=r["text"])
        tries = 0
        while True:
            try:
                ans = await self.w.call("sys_post_partition_release", deadline=deadline, **params, **self._qkey())
            except Refused as e:
                tries += 1
                if tries >= 3:
                    self.set_aside("release", e.hint)
                    return
                await asyncio.sleep(2)
                continue
            log.info(kv("queue_released", run_id=self.run_id, partition_id=self.partition_id, outcome=outcome,
                        code=(r or {}).get("code"), released=ans.get("released"), why=ans.get("why"), **self.counts))
            return ans

    # ---------------------------------------------------------------- renewals
    async def renew_loop(self):
        while not self.finished:
            try:
                await asyncio.wait_for(self.renew_now.wait(), RENEW_SEC)
            except asyncio.TimeoutError:
                pass
            self.renew_now.clear()
            if self.finished:
                break
            try:
                await self.renew_once()
            except Shutdown:
                return
            except Exception as e:
                log.warning(kv("renew_failed", error=where(e)[0]))

    async def renew_soon(self, timeout=10.0):
        """A renewal now, so the checkpoint names the object about to be read."""
        self.renewed.clear()
        self.renew_now.set()
        try:
            await asyncio.wait_for(self.renewed.wait(), timeout)
        except asyncio.TimeoutError:
            pass

    async def renew_once(self, deadline=None):
        async with self.renew_lock:
            checkpoint = {"reading": sorted(self.reading), "attempt": self.attempt}
            ans = await self.w.call("sys_post_partition_renew", deadline=deadline, v_progress=self.progress(),
                                    v_checkpoint=checkpoint, **self._qkey())
            self.renewed.set()
        ans = ans or {}
        if not ans.get("held"):
            self.lost()
            return ans
        if self.end is None:
            for key, end in (("cancel", "cancel"), ("stop", "stop"), ("pause", "pause")):
                if ans.get(key):
                    log.info(kv("queue_" + end + "_asked", run_id=self.run_id, partition_id=self.partition_id))
                    self.stop_all(end)
                    break
        waiting = ans.get("waiting") or {}
        if isinstance(waiting, dict) and (waiting.get("objects") or 0) > 0:
            self.more.set()
        return ans

    # ---------------------------------------------------------------- hand-ins
    def due(self):
        if not self.pending:
            return False
        return (len(self.pending) >= BATCH_OBJECTS or self.pending_parts >= PARTS_PER_CALL
                or time.monotonic() - self.last_handin >= BATCH_SEC)

    def _calls(self, batch):
        """The batch as calls of at most BATCH_OBJECTS objects and PARTS_PER_CALL parts in all (db 2026-48-02:
        10,000 and 50,000); an object with more parts than a call holds goes over several, parts_final false
        on all but the last."""
        limit = max(1, BATCH_OBJECTS)
        per_call_parts = max(1, PARTS_PER_CALL)
        calls = []
        cur = []
        size = 0
        for e in batch:
            parts = e.get("parts") or []
            if len(parts) <= per_call_parts:
                if cur and (len(cur) + 1 > limit or size + len(parts) > per_call_parts):
                    calls.append(cur)
                    cur, size = [], 0
                cur.append(e)
                size += len(parts)
                continue
            if cur:
                calls.append(cur)
                cur, size = [], 0
            chunks = [parts[i:i + per_call_parts] for i in range(0, len(parts), per_call_parts)]
            for i, chunk in enumerate(chunks):
                piece = dict(e)
                piece["parts"] = chunk
                piece["parts_final"] = (i == len(chunks) - 1)
                calls.append([piece])
        if cur:
            calls.append(cur)
        return calls

    async def flush(self, deadline=None):
        """Renew first; not held, the batch is dropped and its working files removed."""
        if not self.pending:
            return True
        batch, self.pending = self.pending, []
        self.pending_parts = 0
        ans = await self.renew_once(deadline=deadline)
        if not ans.get("held"):
            self.drop(batch)
            return False
        calls = self._calls(batch)
        for i, elements in enumerate(calls):
            ok = await self.handin(elements, deadline=deadline)
            if not ok:
                for rest in calls[i + 1:]:
                    self.drop(rest)
                return False
        self.last_handin = time.monotonic()
        return True

    async def handin(self, elements, deadline=None):
        tries = 0
        while True:
            try:
                ans = await self.w.call("sys_post_scan_batch", deadline=deadline, v_objects=elements, **self._key())
                break
            except Refused as e:
                tries += 1
                if e.hint != "objects_invalid" or tries >= 3:
                    log.error(kv("handin_refused", run_id=self.run_id, hint=e.hint, tries=tries))
                    if tries >= 3 or e.hint != "objects_invalid":
                        self.set_aside("scan_batch", e.hint)
                        self.drop(elements)
                        return False
                elements = self._replace_refused(elements, e.detail)
        ans = ans or {}
        if ans.get("marked") is False:
            if ans.get("why") == "not_held":
                self.drop(elements)
                self.lost()
                return False
        by_loc = {}
        for e in elements:
            by_loc.setdefault(e.get("location_id"), []).append(e)
        # db 2026-48-02: became_skipped holds objects, became_skipped_parts and refused_parts hold [{location_id, ref}]
        for item in ans.get("became_skipped") or ():
            for e in by_loc.get(item, ()):
                self._remove_files(e)
        for key in ("became_skipped_parts", "refused_parts"):
            for item in ans.get(key) or ():
                if isinstance(item, dict):
                    for e in by_loc.get(item.get("location_id"), ()):
                        self._remove_part_files(e, item.get("ref"))
        if ans.get("refused_parts"):
            log.warning(kv("parts_refused", run_id=self.run_id, parts=len(ans.get("refused_parts"))))
        log.info(kv("handed_in", run_id=self.run_id, partition_id=self.partition_id, received=ans.get("received"), done=ans.get("done"),
                    skipped=ans.get("skipped"), failed=ans.get("failed"), already=ans.get("already"), waiting=ans.get("waiting"),
                    parts=ans.get("parts"), became_skipped=len(ans.get("became_skipped") or ()),
                    became_skipped_parts=len(ans.get("became_skipped_parts") or ()), refused_parts=len(ans.get("refused_parts") or ())))
        return True

    def _replace_refused(self, elements, detail):
        """objects_invalid: each element named is sent again as failed (handin_refused), its working files
        removed; the rest are sent as they were."""
        try:
            problems = json.loads(detail) if isinstance(detail, str) else (detail or [])
        except ValueError:
            problems = []
        bad = {}
        for p in problems if isinstance(problems, list) else []:
            if isinstance(p, dict) and isinstance(p.get("index"), int) and p["index"] not in bad:
                word = str(p.get("problem") or "invalid")[:60]
                bad[p["index"]] = word if not isinstance(p.get("part"), int) else "%s in part %d" % (word, p["part"])
        if not bad:
            bad = {i: "the batch was refused" for i in range(len(elements))}
        out = []
        for i, e in enumerate(elements):
            if i in bad:
                self._remove_files(e)
                log.warning(kv("element_refused", run_id=self.run_id, location_id=e.get("location_id"), problem=bad[i]))
                f = object_element(e.get("location_id"), _failed(reason("handin_refused", problem=bad[i])))
                out.append(f)
            else:
                out.append(e)
        return out

    def _remove_files(self, element):
        for rel in element_extracts(element):
            remove_tree(os.path.join(self.s.work_dir, rel))

    def _remove_part_files(self, element, ref):
        for p in element.get("parts") or ():
            if p.get("ref") == ref:
                ex = p.get("extract")
                if isinstance(ex, dict) and ex.get("path"):
                    remove_tree(os.path.join(self.s.work_dir, ex["path"]))

    def drop(self, elements):
        for e in elements:
            self._remove_files(e)

    # ---------------------------------------------------------------- the fingerprint lookup
    def lookup(self, sha256, ctx):
        """From a reading thread: the installation's answer for a fingerprint, or None. Waits for the
        database, but never past a stop."""
        loop = self.w.loop
        fut = asyncio.run_coroutine_threadsafe(self._known(sha256), loop)
        while True:
            try:
                return fut.result(timeout=0.25)
            except concurrent.futures.TimeoutError:
                if self.stop_event.is_set():
                    fut.cancel()
                    raise Stopped()
            except concurrent.futures.CancelledError:
                raise Stopped()

    async def _known(self, sha256):
        fut = asyncio.get_running_loop().create_future()
        self.known_queue.append((sha256, fut))
        if self.known_task is None or self.known_task.done():
            self.known_task = asyncio.ensure_future(self._known_drain())
        return await fut

    async def _known_drain(self):
        """Every fingerprint asked meanwhile goes in one call, up to 1,000."""
        while self.known_queue:
            await asyncio.sleep(0)
            items = self.known_queue[:1000]
            del self.known_queue[:1000]
            shas = sorted(set(s for s, _f in items))
            answer = {}
            try:
                # db 2026-48-02: {held: true, known: [{sha256, object_id, extracted, why, scan_version}]} or {held: false, why: not_held}
                ans = await self.w.call("sys_get_known_content", v_sha256=shas, **self._key()) or {}
                if ans.get("held") is False:
                    self.lost()
                for r in ans.get("known") or ():
                    if isinstance(r, dict) and r.get("sha256"):
                        answer[str(r["sha256"]).lower()] = r
            except Refused as e:
                log.warning(kv("lookup_refused", run_id=self.run_id, hint=e.hint))
            except Exception as e:
                log.warning(kv("lookup_failed", run_id=self.run_id, error=where(e)[0]))
            for s, f in items:
                if not f.done():
                    f.set_result(answer.get(s))

    def cleanup(self):
        if self.conns is not None:
            self.conns.close()
        if self.dir_handle is not None:
            self.dir_handle.close()
        try:
            spool = os.path.join(self.s.scan_tmp, self.s.service)
            if os.path.isdir(spool) and not self.inflight:
                for name in os.listdir(spool):
                    remove_tree(os.path.join(spool, name))
        except OSError:
            pass


# ===========================================================================
# 10. THE ENDPOINTS AND serve()  (standard §14: /health, /ready, /status; no /run, no /stop)
# ===========================================================================
def create_app(worker):
    from quart import Quart, jsonify

    app = Quart("ds_scan")
    app.config["PROVIDE_AUTOMATIC_OPTIONS"] = False
    state = {"task": None}

    @app.before_serving
    async def _start():
        state["task"] = asyncio.ensure_future(worker.run())

    @app.after_serving
    async def _stop():
        await worker.shutdown()
        t = state["task"]
        if t is not None and not t.done():
            t.cancel()
            try:
                await asyncio.wait_for(t, 2)
            except BaseException:
                pass

    @app.route("/health", methods=["GET"])
    async def health():
        return jsonify({"ok": True, "service": worker.s.service, "version": VERSION})

    @app.route("/ready", methods=["GET"])
    async def ready():
        if worker.ready:
            return jsonify({"ready": True})
        h = worker.health()
        return jsonify({"ready": False, "step": worker.step, "problem": h.get("problem")}), 503

    @app.route("/status", methods=["GET"])
    async def status():
        return jsonify(worker.status_json())

    return app


def serve(settings):
    """Runs the service until SIGTERM. Returns the process's exit code."""
    import uvicorn
    setup_logging(settings)
    log.info(kv("starting", worker=WORKER_TYPE, version=VERSION, connect=lib_version(), python=sys.version.split()[0],
                standard=STANDARD.replace(" ", "_"), **settings.summary()))
    holder = {}

    def request_exit(code):
        srv = holder.get("server")
        if srv is not None:
            srv.should_exit = True

    worker = Worker(settings, request_exit=request_exit)
    app = create_app(worker)
    config = uvicorn.Config(app, host="0.0.0.0", port=settings.port, log_config=None, access_log=False, lifespan="on",
                            timeout_graceful_shutdown=2, server_header=False, date_header=False)
    class _Server(uvicorn.Server):
        def handle_exit(self, sig, frame):
            # uvicorn raises a captured SIGTERM again once it has shut down; the standard wants exit 0 (§15)
            super().handle_exit(sig, frame)
            self._captured_signals.clear()

    server = _Server(config)
    holder["server"] = server
    try:
        server.run()
    except SystemExit as e:
        if worker.exit_code == 0 and isinstance(e.code, int) and e.code:
            return e.code
    return worker.exit_code
