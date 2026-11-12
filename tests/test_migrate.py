"""The schema migration runner (api/migrate.py), on throw-away SQLite databases."""
import pytest
from sqlalchemy import create_engine, inspect, text

import database
import migrate
import models  # noqa: F401  (registers the tables)


def _engine(tmp_path, name="m.db"):
    return create_engine(f"sqlite:///{tmp_path}/{name}")


def _old_database(tmp_path):
    """A database as v0.1.1 left it: the tables, but no schema_version."""
    engine = _engine(tmp_path)
    database.Base.metadata.create_all(bind=engine)
    with engine.begin() as conn:
        conn.execute(text("DROP TABLE schema_version"))
        conn.execute(text("INSERT INTO server_settings (name, value) VALUES ('kept', 'yes')"))
    return engine


def _upgrade(engine, directory):
    existing = migrate.had_data(engine)
    database.Base.metadata.create_all(bind=engine)
    return migrate.run(engine, existing, str(directory))


def _files(tmp_path, **files):
    d = tmp_path / "migrations"
    d.mkdir(exist_ok=True)
    for name, sql in files.items():
        (d / name.replace("__", ".")).write_text(sql)
    return d


def test_the_shipped_migrations_are_numbered_once_and_in_order():
    numbers = [n for n, _, _ in migrate.available()]
    assert numbers == sorted(set(numbers)) and all(n > migrate.BASELINE for n in numbers)
    assert numbers == list(range(migrate.BASELINE + 1, migrate.BASELINE + 1 + len(numbers)))   # no gaps


def test_a_new_database_is_marked_current_and_runs_nothing(tmp_path):
    d = _files(tmp_path, **{"014_boom__sql": "THIS IS NOT SQL;"})
    engine = _engine(tmp_path)
    assert _upgrade(engine, d) == []
    assert migrate.current(engine) == 14
    assert _upgrade(engine, d) == []                     # and again at the next start


def test_an_old_database_gets_the_baseline_then_every_later_file_once(tmp_path):
    engine = _old_database(tmp_path)
    d = _files(tmp_path, **{
        "014_add_note__sql": "-- a comment; with a semicolon\nALTER TABLE server_settings ADD COLUMN note VARCHAR(20);\n"
                             "UPDATE server_settings SET note = 'a;b'\n  WHERE name = 'kept';\n",
        "015_add_more__sql": "ALTER TABLE server_settings ADD COLUMN more INTEGER DEFAULT 7",
        "013_history__sql": "THIS IS NEVER RUN;", "notes.txt": "ignored",
    })
    assert _upgrade(engine, d) == [14, 15]
    with engine.connect() as conn:
        assert conn.execute(text("SELECT value, note, more FROM server_settings")).one() == ("yes", "a;b", 7)
        assert [r[0] for r in conn.execute(text("SELECT version FROM schema_version ORDER BY version"))] == [13, 14, 15]
    assert _upgrade(engine, d) == []
    _files(tmp_path, **{"016_last__sql": "UPDATE server_settings SET more = 8;"})
    assert _upgrade(engine, d) == [16]


def test_a_failing_file_stops_the_start_and_is_tried_again(tmp_path):
    engine = _old_database(tmp_path)
    d = _files(tmp_path, **{"014_ok__sql": "ALTER TABLE server_settings ADD COLUMN a INTEGER;",
                            "015_bad__sql": "ALTER TABLE no_such_table ADD COLUMN b INTEGER;"})
    with pytest.raises(migrate.MigrationError, match="015_bad.sql"):
        _upgrade(engine, d)
    assert migrate.current(engine) == 14
    _files(tmp_path, **{"015_bad__sql": "ALTER TABLE server_settings ADD COLUMN b INTEGER;"})
    assert _upgrade(engine, d) == [15]


def test_a_database_from_a_newer_version_is_refused(tmp_path):
    engine = _engine(tmp_path)
    _upgrade(engine, _files(tmp_path, **{"014_x__sql": "SELECT 1;", "015_y__sql": "SELECT 1;"}))
    older = tmp_path / "older"
    older.mkdir()
    with pytest.raises(migrate.MigrationError, match="newer version"):
        _upgrade(engine, older)


def test_database_specific_variant_and_duplicate_numbers(tmp_path):
    engine = _old_database(tmp_path)
    d = _files(tmp_path, **{
        "014_widen__sql": "ALTER TABLE server_settings MODIFY value VARCHAR(500);",      # MariaDB only
        "014_widen__sqlite__sql": "SELECT 1;",
        "014_widen__mysql__sql": "THIS IS FOR ANOTHER DATABASE;"})
    assert [p.rsplit("/", 1)[1] for _, _, p in migrate.available(str(d), "sqlite")] == ["014_widen.sqlite.sql"]
    assert [p.rsplit("/", 1)[1] for _, _, p in migrate.available(str(d), "postgresql")] == ["014_widen.sql"]
    assert _upgrade(engine, d) == [14]
    _files(tmp_path, **{"014_other__sql": "SELECT 1;"})
    with pytest.raises(migrate.MigrationError, match="number 014"):
        migrate.available(str(d), "sqlite")


def test_the_api_database_itself_is_versioned():
    """The test database was made by init_db(): new, so current, and the table is a model."""
    database.init_db()
    assert inspect(database.engine).has_table("schema_version")
    assert migrate.current(database.engine) >= migrate.BASELINE
