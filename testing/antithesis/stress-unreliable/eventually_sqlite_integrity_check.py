#!/usr/bin/env -S python3 -u

import os
import sqlite3
import sys

from antithesis.assertions import always, unreachable

db_file = "/tmp/stress.db"

db_exists = os.path.exists(db_file)
always(db_exists, "database file exists for sqlite integrity check", {"path": db_file})
if not db_exists:
    sys.exit(1)

try:
    con = sqlite3.connect(db_file)
    rows = [row[0] for row in con.execute("pragma integrity_check")]
except sqlite3.Error as e:
    unreachable("error performing sqlite integrity check", {"path": db_file, "error": str(e)})
    sys.exit(1)

always(len(rows) > 0, "sqlite integrity check returned rows", {"path": db_file})

ok = len(rows) > 0 and rows[0].lower() == "ok"
always(ok, "sqlite integrity check passed", {"path": db_file, "rows": rows})

sys.exit(0 if ok else 1)
