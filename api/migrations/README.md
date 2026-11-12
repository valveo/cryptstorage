# Database migrations

New tables are created at start-up by `create_all()`. A change to a table that already exists
goes here as a numbered SQL file, which `migrate.py` applies once, in order, when the API starts,
and records in the table `schema_version`. See the top of [`../migrate.py`](../migrate.py) for the rules.

- `001` to `013` are history from before the runner (the schema of v0.1.0 and v0.1.1). They are
  never run; they stay for reference. Two of them share the number 009, which the runner would refuse
  in a new file.
- The next file is `014_<what_it_does>.sql`. Write it for MariaDB; if SQLite needs other SQL
  (development and tests), add `014_<what_it_does>.sqlite.sql` next to it.
- Write each file so that it can be run again (`ADD COLUMN IF NOT EXISTS`, ...): MariaDB cannot undo
  schema changes when a later statement fails.
- Also change `models.py`, so that a new database gets the same schema from `create_all()`.
  `tests/test_migrate.py` checks the numbering.
- There are no down-migrations. Going back means restoring the backup ([docs/UPGRADE.md](../../docs/UPGRADE.md)).
