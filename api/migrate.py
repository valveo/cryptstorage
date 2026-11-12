"""
migrate.py - Brings an existing database up to the schema this version of the server expects.

New tables come from create_all() (database.init_db). What create_all() cannot do, a change to a
table that already exists (a new column, a wider type, a moved value), is a numbered SQL file in
migrations/, applied here once, in order, when the API starts:

    migrations/014_add_something.sql              runs on every database
    migrations/014_add_something.sqlite.sql       used instead on SQLite (development, tests), if present

The table schema_version records what has been applied. The rules:

  - A new, empty database gets the current schema from create_all() and is marked as up to date;
    no file runs.
  - A database from before this runner (v0.1.0 and v0.1.1 have the same schema) is marked as
    BASELINE, then every later file runs.
  - A database that is NEWER than this code stops the start: an older server would otherwise run on
    a schema it does not know. Deploy the newer version again, or restore the backup taken before
    the upgrade (docs/UPGRADE.md).
  - A file that fails stops the start, and the files before it stay applied. MariaDB cannot undo
    schema changes inside a transaction, so write each file so that it can be run again.

The files up to BASELINE are history: they are never run, and are kept for databases managed by hand.
There are no down-migrations: going back means restoring the backup.
"""

import logging
import os
import re
from datetime import datetime

from sqlalchemy import inspect, text
from sqlalchemy.engine import Engine

logger = logging.getLogger(__name__)

BASELINE = 13
MIGRATIONS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "migrations")
TABLE = "schema_version"
_NAME = re.compile(r"(\d{3})_([a-z0-9_]+?)(?:\.([a-z]+))?\.sql")


class MigrationError(RuntimeError):
    """The database cannot be brought to this version's schema; the API must not start."""


def available(directory: str = MIGRATIONS_DIR, dialect: str = "") -> list[tuple[int, str, str]]:
    """(number, name, path) of the files after BASELINE, in order; the dialect's own variant wins."""
    found: dict[int, dict] = {}
    for fn in sorted(os.listdir(directory)) if os.path.isdir(directory) else []:
        m = _NAME.fullmatch(fn)
        if not m:
            continue
        number, name, variant = int(m.group(1)), m.group(2), m.group(3)
        if number <= BASELINE or variant not in (None, dialect):
            continue
        entry = found.setdefault(number, {"name": name})
        if entry["name"] != name or ("own" if variant else "any") in entry:
            raise MigrationError(f"Two migrations have the number {number:03d} in {directory}.")
        entry["own" if variant else "any"] = os.path.join(directory, fn)
    out = []
    for number in sorted(found):
        e = found[number]
        if "any" not in e:
            raise MigrationError(f"Migration {number:03d} has only a variant for one database, no general file.")
        out.append((number, e["name"], e.get("own", e["any"])))
    return out


def statements(sql: str) -> list[str]:
    """The statements of a file: comment lines dropped, split at a ';' that ends a line."""
    lines = [ln for ln in sql.splitlines() if not ln.strip().startswith("--")]
    return [s.strip() for s in re.split(r";[ \t]*(?:\n|$)", "\n".join(lines)) if s.strip()]


def current(engine: Engine) -> int | None:
    with engine.connect() as conn:
        return conn.execute(text(f"SELECT MAX(version) FROM {TABLE}")).scalar()


def _record(conn, version: int, name: str) -> None:
    conn.execute(text(f"INSERT INTO {TABLE} (version, name, applied_at) VALUES (:v, :n, :t)"),
                 {"v": version, "n": name[:64], "t": datetime.utcnow()})


def had_data(engine: Engine) -> bool:
    """Call before create_all(): True if this is an existing database, not a new one."""
    return inspect(engine).has_table("users")


def run(engine: Engine, existing: bool, directory: str = MIGRATIONS_DIR) -> list[int]:
    """Apply what is missing; returns the numbers applied. Call after create_all()."""
    files = available(directory, engine.dialect.name)
    newest = max([BASELINE] + [n for n, _, _ in files])
    at = current(engine)
    if at is None:
        with engine.begin() as conn:
            if existing:
                _record(conn, BASELINE, "baseline")
                at = BASELINE
            else:
                _record(conn, newest, "new database")
                return []
    if at > newest:
        raise MigrationError(
            f"The database is at schema version {at}, but this server only knows up to {newest}: it was "
            "used by a newer version. Deploy that version again or restore the backup taken before the "
            "upgrade (docs/UPGRADE.md).")
    applied = []
    for number, name, path in files:
        if number <= at:
            continue
        logger.info(f"Applying database migration {number:03d}_{name}.")
        try:
            with open(path, encoding="utf-8") as f:
                todo = statements(f.read())
            with engine.begin() as conn:
                for stmt in todo:
                    conn.execute(text(stmt))
                _record(conn, number, name)
        except Exception as e:
            raise MigrationError(
                f"Database migration {os.path.basename(path)} failed: {e}. The API does not start with a "
                "half-upgraded database. Fix the cause and start again, or restore the backup taken before "
                "the upgrade (docs/UPGRADE.md).") from e
        applied.append(number)
    return applied
