from sqlalchemy.dialects import mysql
from sqlalchemy.schema import CreateTable

import models


def test_quota_column_is_64_bit_on_mariadb():
    """The 10 GB default quota does not fit MariaDB's 32-bit INT (max 2147483647).
    SQLite does not enforce it, so check the generated MariaDB DDL instead."""
    ddl = str(CreateTable(models.User.__table__).compile(dialect=mysql.dialect()))
    quota_line = next(line for line in ddl.splitlines() if "quota_bytes" in line)
    assert "BIGINT" in quota_line
