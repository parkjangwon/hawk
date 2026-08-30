# ruleid: korea.py.sql-injection
curs.execute("UPDATE board SET name='" + name + "'")
# ok: korea.py.sql-injection
curs.execute("UPDATE board SET name=?", (name,))
