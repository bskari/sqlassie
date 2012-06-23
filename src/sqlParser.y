/*
 * SQLassie - database firewall
 * Copyright (C) 2011 Brandon Skari <brandon.skari@gmail.com>
 *
 * This file is part of SQLassie.
 *
 * SQLassie is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * SQLassie is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with SQLassie. If not, see <http://www.gnu.org/licenses/>.
 */

/**
 * Parser for MySQL queries. Derived from the parser for SQLite.
 * @author Brandon Skari
 * @date June 16 2012
 */

// The name of the generated procedure that implements the parser
// is as follows:
%name sqlassieParse

%token_type {const char*}
%extra_argument {ScannerContext* scannerContext}

// The following text is included near the beginning of the C source
// code file that implements the parser.
//
%include {

#include <cassert>

#include "ScannerContext.hpp"

// Give up parsing as soon as the first error is encountered
#define YYNOERRORRECOVERY 1

} // end %include

// Input is a single SQL command
input ::= cmdlist.
cmdlist ::= cmdlist ecmd.
cmdlist ::= ecmd.
ecmd ::= SEMI.
ecmd ::= explain cmdx SEMI.
explain ::= .           {}
explain ::= EXPLAIN.              {}
explain ::= EXPLAIN QUERY PLAN.   {}
cmdx ::= cmd.           {}

///////////////////// Begin and end transactions. ////////////////////////////
//

cmd ::= START TRANSACTION start_opt.
cmd ::= BEGIN_KW work_opt.
cmd ::= COMMIT work_opt chain_opt release_opt.     {}
cmd ::= ROLLBACK work_opt chain_opt release_opt.   {}
work_opt ::= .
work_opt ::= WORK.
start_opt ::= .
start_opt ::= WITH CONSISTENT SNAPSHOT.
chain_opt ::= .
chain_opt ::= AND no_opt CHAIN.
release_opt ::= .
release_opt ::= no_opt RELEASE.
no_opt ::= .
no_opt ::= NO.

// An IDENTIFIER can be a generic identifier, or one of several
// keywords.  Any non-standard keyword can also be an identifier.
//
id(A) ::= ID(X).         {A;X; scannerContext->identifiers.pop();}
id(A) ::= INDEXED(X).    {A;X;}

// The following directive causes tokens ABORT, AFTER, ASC, etc. to
// fallback to ID if they will not parse as their original value.
// This obviates the need for the "id" nonterminal.
//
%fallback ID
  ABORT ACTION AFTER ANALYZE ASC ATTACH BEFORE BEGIN_KW BY CASCADE CAST COLUMNKW
  CONFLICT DATABASE DEFERRED DESC DETACH EACH END EXCLUSIVE EXPLAIN FAIL FOR
  IGNORE IMMEDIATE INITIALLY INSTEAD LIKE_KW MATCH_KW NO PLAN
  QUERY KEY OF OFFSET PRAGMA RAISE RELEASE REPLACE RESTRICT ROW ROLLBACK
  SAVEPOINT TEMP TRIGGER VACUUM VIEW VIRTUAL
  // MySQL specific stuff
  LOW_PRIORITY DELAYED HIGH_PRIORITY CONSISTENT SNAPSHOT WORK CHAIN QUICK
  SOUNDS OUTFILE SQL_BIG_RESULT SQL_SMALL_RESULT SQL_BUFFER_RESULT SQL_CACHE
  SQL_NO_CACHE LOCK SHARE MODE BOOLEAN EXPANSION
%ifdef SQLITE_OMIT_COMPOUND_SELECT
  EXCEPT INTERSECT UNION
%endif SQLITE_OMIT_COMPOUND_SELECT
  REINDEX RENAME CTIME_KW IF
  .
%wildcard ANY.

// Define operator precedence early so that this is the first occurance
// of the operator tokens in the grammer.  Keeping the operators together
// causes them to be assigned integer values that are close together,
// which keeps parser tables smaller.
//
// The token values assigned to these symbols is determined by the order
// in which lemon first sees them.  It must be the case that ISNULL/NOTNULL,
// NE/EQ, GT/LE, and GE/LT are separated by only a single value.  See
// the sqlite3ExprIfFalse() routine for additional information on this
// constraint.
//
%left OR.
%left XOR.
%left AND.
%right NOT.
%left IS MATCH_KW LIKE_KW SOUNDS BETWEEN IN ISNULL NOTNULL NE EQ.
%left GT LE LT GE.
%right ESCAPE.
%left BITAND BITOR BITXOR LSHIFT RSHIFT.
%left PLUS MINUS.
%left STAR SLASH REM INTEGER_DIVIDE.
%left CONCAT.
%left COLLATE.
%right BITNOT.

// And "ids" is an identifer-or-string.
//
ids(A) ::= ID|STRING(X).   {A;X;}

// The name of a column or table can be any of the following:
//
nm(A) ::= id(X).         {A;X;}
nm(A) ::= STRING(X).     {A;X;}
nm(A) ::= JOIN_KW(X).    {A;X;}

// A typetoken is really one or more tokens that form a type name such
// as can be found after the column name in a CREATE TABLE statement.
// Multiple tokens are concatenated to form the value of the typetoken.
//
typetoken(A) ::= typename(X).   {A;X;}
typetoken(A) ::= typename(X) LP signed RP(Y). {A;X;Y;}
typetoken(A) ::= typename(X) LP signed COMMA signed RP(Y). {A;X;Y;}
typename(A) ::= ids(X).             {A;X;}
typename(A) ::= typename(X) ids(Y). {A;X;Y;}
plus_num(A) ::= number(X).          {A;X;}
minus_num(A) ::= MINUS number(X).   {A;X;}
number(A) ::= INTEGER|FLOAT(X).     {A;X; scannerContext->numbers.pop();}
signed ::= plus_num.
signed ::= minus_num.

//////////////////////// The SHOW statement /////////////////////////////////
//
cmd ::= SHOW TABLES.
cmd ::= SHOW TABLES LIKE_KW STRING.
cmd ::= SHOW DATABASES.
cmd ::= SHOW DATABASES LIKE_KW STRING.
cmd ::= SHOW GLOBAL VARIABLES.
cmd ::= SHOW GLOBAL VARIABLES LIKE_KW STRING.

//////////////////////// The DESCRIBE statement ///////////////////////////////
//
cmd ::= DESCRIBE id.
// You can specify an individual column, or give a regex and show all columns
// that match it.
cmd ::= DESCRIBE id id(column).     {column;}

//////////////////////// The USE statement ////////////////////////////////////
//
cmd ::= USE id.

//////////////////////// The LOCK statement ///////////////////////////////////
//
cmd ::= LOCK TABLES lock_tables_list.
lock_tables_list ::= as lock_type.
lock_tables_list ::= as lock_type COMMA lock_tables_list.
lock_type ::= READ local_opt.
lock_type ::= low_priority_opt WRITE.
local_opt ::= .
local_opt ::= LOCAL.
cmd ::= UNLOCK TABLES lock_tables_list.

//////////////////////// The SELECT statement /////////////////////////////////
//
cmd ::= select_opt select(X) outfile_opt lock_read_opt .   {X;}

select(A) ::= oneselect(X).                  {A;X;}
%ifndef SQLITE_OMIT_COMPOUND_SELECT
select(A) ::= select(X) multiselect_op(Y) oneselect(Z).  {A;X;Y;Z;}
multiselect_op(A) ::= UNION(OP).             {A;OP;}
multiselect_op(A) ::= UNION ALL.             {A;}
multiselect_op(A) ::= EXCEPT|INTERSECT(OP).  {A;OP;}
%endif SQLITE_OMIT_COMPOUND_SELECT
oneselect(A) ::= SELECT distinct(D) selcollist(W) from(X) where_opt(Y)
                 groupby_opt(P) having_opt(Q) orderby_opt(Z) limit_opt(L). {A;D;W;X;Y;P;Q;Z;L;}
// MySQL match statement
oneselect(A) ::= SELECT distinct(D) selcollist(W) from(X) WHERE mysql_match(Y)
                 groupby_opt(P) having_opt(Q) orderby_opt(Z) limit_opt(L). {A;D;W;X;Y;P;Q;Z;L;}

// The "distinct" nonterminal is true (1) if the DISTINCT keyword is
// present and false (0) if it is not.
//
distinct(A) ::= DISTINCT.       {A;}
distinct(A) ::= ALL.            {A;}
distinct(A) ::= DISTINCTROW.    {A;}
distinct(A) ::= .               {A;}

// MySQL specific select options
select_opt ::= high_priority_opt straight_join_opt
          sql_small_result_opt sql_big_result_opt sql_buffer_result_opt
          sql_cache_opt sql_calc_found_rows_opt .
high_priority_opt ::= .
high_priority_opt ::= HIGH_PRIORITY.
straight_join_opt ::= .
straight_join_opt ::= STRAIGHT_JOIN.
sql_small_result_opt ::= .
sql_small_result_opt ::= SQL_SMALL_RESULT.
sql_big_result_opt ::= .
sql_big_result_opt ::= SQL_BIG_RESULT.
sql_buffer_result_opt ::= .
sql_buffer_result_opt ::= SQL_BUFFER_RESULT.
sql_cache_opt ::= .
sql_cache_opt ::= SQL_CACHE.
sql_cache_opt ::= SQL_NO_CACHE.
sql_calc_found_rows_opt ::= .
sql_calc_found_rows_opt ::= SQL_CALC_FOUND_ROWS.

// MySQL specific outfile
outfile_opt ::= .
outfile_opt ::= INTO OUTFILE.

// MySQL specific read locking
lock_read_opt ::= .
lock_read_opt ::= FOR UPDATE.
lock_read_opt ::= LOCK IN SHARE MODE.

// selcollist is a list of expressions that are to become the return
// values of the SELECT statement.  The "*" in statements like
// "SELECT * FROM ..." is encoded as a special expression with an
// opcode of TK_ALL.
//
sclp(A) ::= selcollist(X) COMMA.             {A;X;}
sclp(A) ::= .                                {A;}
selcollist(A) ::= sclp(P) expr(X) as(Y).     {A;X;Y;P;}
selcollist(A) ::= sclp(P) STAR. {A;P;}
selcollist(A) ::= sclp(P) nm(X) DOT STAR(Y). {A;X;Y;P;}
selcollist(A) ::= sclp(P) mysql_match(X). {A;X;P;}

// An option "AS <id>" phrase that can follow one of the expressions that
// define the result set, or one of the tables in the FROM clause.
//
as(X) ::= AS nm(Y).    {X;Y;}
as(X) ::= ids(Y).      {X;Y;}
as(X) ::= .            {X;}


// A complete FROM clause.
//
from(A) ::= .                {A;}
from(A) ::= FROM seltablist(X). {A;X;}

// MySQL match statement
//
mysql_match ::= MATCH_KW LP inscollist RP AGAINST LP expr againstmodifier_opt RP.
againstmodifier_opt ::= .
againstmodifier_opt ::= IN NATURAL LANGUAGE MODE.
againstmodifier_opt ::= IN BOOLEAN MODE.
againstmodifier_opt ::= WITH QUERY EXPANSION.

// "seltablist" is a "Select Table List" - the content of the FROM clause
// in a SELECT statement.  "stl_prefix" is a prefix of this list.
//
stl_prefix(A) ::= seltablist(X) joinop(Y).    {A;X;Y;}
stl_prefix(A) ::= .                           {A;}
seltablist(A) ::= stl_prefix(X) nm(Y) dbnm(D)
                as(Z) index_hint_list_opt indexed_opt(I) on_opt(N) using_opt(U). {A;X;Y;D;Z;I;N;U;}
seltablist(A) ::= stl_prefix(X) LP select(S) RP
                as(Z) index_hint_list_opt on_opt(N) using_opt(U). {A;X;S;Z;N;U;}
seltablist(A) ::= stl_prefix(X) LP seltablist(F) RP
                as(Z) index_hint_list_opt on_opt(N) using_opt(U). {A;X;F;Z;N;U;}

// A seltablist_paren nonterminal represents anything in a FROM that
// is contained inside parentheses.  This can be either a subquery or
// a grouping of table and subqueries.
//
//  %type seltablist_paren {Select*}
//  %destructor seltablist_paren {sqlite3SelectDelete(pParse->db, $$);}
//  seltablist_paren(A) ::= select(S).      {A = S;}
//  seltablist_paren(A) ::= seltablist(F).  {
//     sqlite3SrcListShiftJoinType(F);
//     A = sqlite3SelectNew(pParse,0,F,0,0,0,0,0,0,0);
//  }

dbnm(A) ::= .          {A;}
dbnm(A) ::= DOT nm(X). {A;X;}

fullname(A) ::= nm(X) dbnm(Y).  {A;X;Y;}

joinop(X) ::= COMMA.                 {X;}
joinop(X) ::= join_opt JOIN.         {X;}
joinop(X) ::= join_opt nm(B) JOIN.   {X;B;}
joinop(X) ::= join_opt nm(B) nm(C) JOIN. {X;B;C;}

join_opt ::= INNER.
join_opt ::= CROSS.
join_opt ::= LEFT.
join_opt ::= RIGHT.
join_opt ::= LEFT OUTER.
join_opt ::= RIGHT OUTER.
join_opt ::= NATURAL LEFT.
join_opt ::= NATURAL RIGHT.
join_opt ::= NATURAL LEFT OUTER.
join_opt ::= NATURAL RIGHT OUTER.

on_opt(N) ::= ON expr(E).   {N;E;}
on_opt(N) ::= .             {N;}

// MySQL specific indexing hints
index_hint_list_opt ::= .
index_hint_list_opt ::= index_hint_list.
/// @TODO Make index_hint_list a list
index_hint_list ::= index_hint.
index_hint ::= USE index_or_key index_hint_for_opt LP RP.
index_hint ::= USE index_or_key index_hint_for_opt LP index_list RP.
index_hint ::= IGNORE index_or_key index_hint_for_opt LP index_list RP.
index_hint ::= FORCE index_or_key index_hint_for_opt LP index_list RP.
index_or_key ::= INDEX.
index_or_key ::= KEY.
index_hint_for_opt ::= FOR JOIN.
index_hint_for_opt ::= FOR ORDER BY.
index_hint_for_opt ::= FOR GROUP BY.
index_list ::= nm .
index_list ::= nm COMMA index_list .

// Note that this block abuses the Token type just a little. If there is
// no "INDEXED BY" clause, the returned token is empty (z==0 && n==0). If
// there is an INDEXED BY clause, then the token is populated as per normal,
// with z pointing to the token data and n containing the number of bytes
// in the token.
//
// If there is a "NOT INDEXED" clause, then (z==0 && n==1), which is 
// normally illegal. The sqlite3SrcListIndexedBy() function 
// recognizes and interprets this as a special case.
//
indexed_opt(A) ::= .                 {A;}
indexed_opt(A) ::= INDEXED BY nm(X). {A;X;}
indexed_opt(A) ::= NOT INDEXED.      {A;}

using_opt(U) ::= USING LP inscollist(L) RP.  {U;L;}
using_opt(U) ::= .                        {U;}

orderby_opt(A) ::= .                          {A;}
orderby_opt(A) ::= ORDER BY sortlist(X).      {A;X;}
sortlist(A) ::= sortlist(X) COMMA expr(Y) sortorder(Z). {A;X;Y;Z;}
sortlist(A) ::= expr(Y) sortorder(Z). {A;Y;Z;}

sortorder(A) ::= ASC.           {A;}
sortorder(A) ::= DESC.          {A;}
sortorder(A) ::= .              {A;}

groupby_opt(A) ::= .                      {A;}
groupby_opt(A) ::= GROUP BY nexprlist(X). {A;X;}

having_opt(A) ::= .                {A;}
having_opt(A) ::= HAVING expr(X).  {A;X;}

// The destructor for limit_opt will never fire in the current grammar.
// The limit_opt non-terminal only occurs at the end of a single production
// rule for SELECT statements.  As soon as the rule that create the 
// limit_opt non-terminal reduces, the SELECT statement rule will also
// reduce.  So there is never a limit_opt non-terminal on the stack 
// except as a transient.  So there is never anything to destroy.
//
//%destructor limit_opt {
//  sqlite3ExprDelete(pParse->db, $$.pLimit);
//  sqlite3ExprDelete(pParse->db, $$.pOffset);
//}
limit_opt(A) ::= .                    {A;}
limit_opt(A) ::= LIMIT expr(X).       {A;X;}
limit_opt(A) ::= LIMIT expr(X) OFFSET expr(Y). {A;X;Y;}
limit_opt(A) ::= LIMIT expr(X) COMMA expr(Y). {A;X;Y;}

/////////////////////////// The DELETE statement /////////////////////////////
//
cmd ::= DELETE delete_opt FROM fullname(X) indexed_opt(I) where_opt(W)
        orderby_opt(O) limit_opt(L). {X;I;W;O;L;}

delete_opt ::= low_priority_opt quick_opt ignore_opt.
low_priority_opt ::= .
low_priority_opt ::= LOW_PRIORITY.
quick_opt ::= .
quick_opt ::= QUICK.
ignore_opt ::= .
ignore_opt ::= IGNORE.
where_opt(A) ::= .                    {A;}
where_opt(A) ::= WHERE expr(X).       {A;X;}

////////////////////////// The UPDATE command ////////////////////////////////
//
cmd ::= UPDATE fullname(X) indexed_opt(I) SET setlist(Y)
    where_opt(W) orderby_opt(O) limit_opt(L).  {X;I;Y;W;O;L;}

setlist(A) ::= setlist(Z) COMMA nm(X) EQ expr(Y). {A;X;Y;Z;}
setlist(A) ::= nm(X) EQ expr(Y). {A;X;Y;}

////////////////////////// The INSERT command /////////////////////////////////
//
/** @TODO Handle 'ON DUPLICATE KEY UPDATE col_name=expr [, col_name=expr] ... */
cmd ::= insert_cmd(R) insert_opt into_opt fullname(X) inscollist_opt(F) valuelist(Y). {R;X;Y;F;}
cmd ::= insert_cmd(R) insert_opt into_opt fullname(X) inscollist_opt(F) select(S). {R;X;F;S;}
cmd ::= insert_cmd(R) insert_opt into_opt fullname(X) inscollist_opt(F) DEFAULT VALUES. {R;X;F;}

into_opt ::= .
into_opt ::= INTO.

insert_opt ::= insert_priority_opt ignore_opt.
insert_priority_opt ::= .
insert_priority_opt ::= LOW_PRIORITY.
insert_priority_opt ::= DELAYED.
insert_priority_opt ::= HIGH_PRIORITY.

insert_cmd(A) ::= INSERT.   {A;}
insert_cmd(A) ::= REPLACE.  {A;}

// A ValueList is either a single VALUES clause or a comma-separated list
// of VALUES clauses.  If it is a single VALUES clause then the
// ValueList.pList field points to the expression list of that clause.
// If it is a list of VALUES clauses, then those clauses are transformed
// into a set of SELECT statements without FROM clauses and connected by
// UNION ALL and the ValueList.pSelect points to the right-most SELECT in
// that compound.
valuelist(A) ::= VALUES LP nexprlist(X) RP. {A;X;}

// Since a list of VALUEs is inplemented as a compound SELECT, we have
// to disable the value list option if compound SELECTs are disabled.
%ifndef SQLITE_OMIT_COMPOUND_SELECT
valuelist(A) ::= valuelist(X) COMMA LP exprlist(Y) RP. {A;X;Y;}
%endif SQLITE_OMIT_COMPOUND_SELECT

inscollist_opt(A) ::= .                      {A;}
inscollist_opt(A) ::= LP inscollist(X) RP.   {A;X;}
inscollist(A) ::= inscollist(X) COMMA nm(Y). {A;X;Y;}
inscollist(A) ::= nm(Y). {A;Y;}

/////////////////////////// Expression Processing /////////////////////////////
//

expr(A) ::= term(X).             {A;X;}
expr(A) ::= LP(B) expr(X) RP(E). {A;X;B;E;}
term(A) ::= NULL_KW(X).          {A;X;}
expr(A) ::= id(X).               {A;X;}
expr(A) ::= JOIN_KW(X).          {A;X;}
expr(A) ::= nm(X) DOT nm(Y).    {A;X;Y;}
expr(A) ::= nm(X) DOT nm(Y) DOT nm(Z). {A;X;Y;Z;}
term(A) ::= INTEGER|FLOAT.      {A; scannerContext->numbers.pop();}
term(A) ::= BLOB(X).  {A;X;}
term(A) ::= STRING(X).              {A;X;}
/* MySQL allows date intervals */
term(A) ::= INTERVAL expr TIME_UNIT RP.    {A;}
expr(A) ::= REGISTER(X).     {A;X;}
expr(A) ::= VARIABLE(X).     {A;X;}
expr(A) ::= expr(E) COLLATE ids(C). {A;E;C;}
%ifndef SQLITE_OMIT_CAST
expr(A) ::= CAST(X) LP expr(E) AS typetoken(T) RP(Y). {A;X;Y;E;T;}
%endif  SQLITE_OMIT_CAST
expr(A) ::= ID(X) LP distinct(D) exprlist(Y) RP(E). {A;X;Y;D;E;}
expr(A) ::= ID(X) LP STAR RP(E). {A;X;E;}
term(A) ::= CTIME_KW(OP). {A;OP;}

expr(A) ::= expr(X) AND(OP) expr(Y).    {A;X;Y;OP;}
expr(A) ::= expr(X) OR(OP) expr(Y).     {A;X;Y;OP;}
expr(A) ::= expr(X) XOR(OP) expr(Y).    {A;X;Y;OP;}
expr(A) ::= expr(X) LT|GT|GE|LE(OP) expr(Y). {A;X;Y;OP;}
expr(A) ::= expr(X) EQ|NE(OP) expr(Y).  {A;X;Y;OP;}
expr(A) ::= expr(X) BITAND|BITOR|LSHIFT|RSHIFT(OP) expr(Y). {A;X;Y;OP;}
expr(A) ::= expr(X) PLUS|MINUS(OP) expr(Y). {A;X;Y;OP;}
expr(A) ::= expr(X) STAR|SLASH|REM|INTEGER_DIVIDE(OP) expr(Y). {A;X;Y;OP;}
expr(A) ::= expr(X) CONCAT(OP) expr(Y). {A;X;Y;OP;}
likeop(A) ::= LIKE_KW(X).     {A;X;}
likeop(A) ::= NOT LIKE_KW(X). {A;X;}
likeop(A) ::= MATCH_KW(X).       {A;X;}
likeop(A) ::= NOT MATCH_KW(X).   {A;X;}
likeop(A) ::= SOUNDS LIKE_KW(X).     {A;X;}
expr(A) ::= expr(X) likeop(OP) expr(Y).  [LIKE_KW]  {A;X;Y;OP;}
expr(A) ::= expr(X) likeop(OP) expr(Y) ESCAPE expr(E).  [LIKE_KW]  {A;X;Y;OP;E;}

expr(A) ::= expr(X) ISNULL|NOTNULL(E).  {A;X;E;}
expr(A) ::= expr(X) NOT NULL_KW(E).     {A;X;E;}

//    expr1 IS expr2
//    expr1 IS NOT expr2
//
// If expr2 is NULL then code as TK_ISNULL or TK_NOTNULL.  If expr2
// is any other expression, code as TK_IS or TK_ISNOT.
// 
expr(A) ::= expr(X) IS expr(Y).     {A;X;Y;}
expr(A) ::= expr(X) IS NOT expr(Y). {A;X;Y;}

expr(A) ::= NOT(B) expr(X).    {A;X;B;}
expr(A) ::= BITNOT(B) expr(X). {A;X;B;}
expr(A) ::= MINUS(B) expr(X). [BITNOT] {A;X;B;}
expr(A) ::= PLUS(B) expr(X). [BITNOT] {A;X;B;}

between_op(A) ::= BETWEEN.     {A;}
between_op(A) ::= NOT BETWEEN. {A;}
expr(A) ::= expr(W) between_op(N) expr(X) AND expr(Y). [BETWEEN] {A;X;Y;W;N;}
in_op(A) ::= IN.      {A;}
in_op(A) ::= NOT IN.  {A;}
expr(A) ::= expr(X) in_op(N) LP exprlist(Y) RP(E). [IN] {A;X;Y;N;E;}
expr(A) ::= expr(X) in_op(N) LP select(Y) RP(E).  [IN] {A;X;Y;N;E;}
expr(A) ::= expr(X) in_op(N) nm(Y) dbnm(Z). [IN] {A;X;Y;N;Z;}

/* CASE expressions */
expr(A) ::= CASE(C) case_operand(X) case_exprlist(Y) case_else(Z) END(E). {A;X;Y;C;Z;E;}
case_exprlist(A) ::= case_exprlist(X) WHEN expr(Y) THEN expr(Z). {A;X;Y;Z;}
case_exprlist(A) ::= WHEN expr(Y) THEN expr(Z). {A;Y;Z;}
case_else(A) ::=  ELSE expr(X).         {A;X;}
case_else(A) ::=  .                     {A;}
case_operand(A) ::= expr(X).            {A;X;}
case_operand(A) ::= .                   {A;}

exprlist(A) ::= nexprlist(X).                {A;X;}
exprlist(A) ::= .                            {A;}
nexprlist(A) ::= nexprlist(X) COMMA expr(Y). {A;X;Y;}
nexprlist(A) ::= expr(Y). {A;Y;}
