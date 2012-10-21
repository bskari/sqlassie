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
SELECT a, (SELECT b, c, (SELECT d, e, f FROM foo), (SELECT g, h, i, j FROM foo) FROM foo) WHERE 1 = 1
SELECT database_.table_.field_ AS database_table_field_ WHERE database_.table_.field_ > 0
SELECT * FROM foo WHERE 'age' LIKE 'age' ESCAPE 'e';
