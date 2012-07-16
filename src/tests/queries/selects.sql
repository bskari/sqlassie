SELECT a.* AS b FROM foo
SELECT * FROM foo
SELECT a FROM foo
SELECT a, b, c FROM foo
SELECT a.* FROM foo
SELECT a.name FROM foo
SELECT a.flags & 0x40 FROM foo
SELECT a.flags & 0x40 > 0 FROM foo
SELECT a.flags & 0x40 < 0 FROM foo
SELECT a.flags & 0x40 >= 0 FROM foo
SELECT a.flags & 0x40 <= 0 FROM foo
SELECT a.flags & 0x40 = 0 FROM foo
SELECT a.flags & 0x40 != 0 FROM foo
SELECT a.flags | 0x40 FROM foo
SELECT a.flags ^ 0x40 FROM foo
SELECT a AS b FROM foo
SELECT a.age AS b FROM foo
SELECT a.flags & 0x40 AS b FROM foo
SELECT a.flags & 0x40 > 0 AS b FROM foo
