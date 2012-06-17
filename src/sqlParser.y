/*
** 2001 September 15
**
** The author disclaims copyright to this source code.  In place of
** a legal notice, here is a blessing:
**
**    May you do good and not evil.
**    May you find forgiveness for yourself and forgive others.
**    May you share freely, never taking more than you give.
**
*************************************************************************
** This file contains SQLite's grammar for SQL.  Process this file
** using the lemon parser generator to generate C code that runs
** the parser.  Lemon will also generate a header file containing
** numeric codes for all of the tokens.
*/

// The name of the generated procedure that implements the parser
// is as follows:
%name sqlite3Parser

// The following text is included near the beginning of the C source
// code file that implements the parser.
//
%include {

} // end %include

// Input is a single SQL command
input ::= cmdlist.
cmdlist ::= cmdlist ecmd.
cmdlist ::= ecmd.
ecmd ::= SEMI.
ecmd ::= explain cmdx SEMI.
explain ::= .           {}
%ifndef SQLITE_OMIT_EXPLAIN
explain ::= EXPLAIN.              {}
explain ::= EXPLAIN QUERY PLAN.   {}
%endif  SQLITE_OMIT_EXPLAIN
cmdx ::= cmd.           {}

///////////////////// Begin and end transactions. ////////////////////////////
//

cmd ::= BEGIN transtype(Y) trans_opt.  {}
trans_opt ::= .
trans_opt ::= TRANSACTION.
trans_opt ::= TRANSACTION nm.
transtype(A) ::= .             {}
transtype(A) ::= DEFERRED(X).  {}
transtype(A) ::= IMMEDIATE(X). {}
transtype(A) ::= EXCLUSIVE(X). {}
cmd ::= COMMIT trans_opt.      {}
cmd ::= END trans_opt.         {}
cmd ::= ROLLBACK trans_opt.    {}

savepoint_opt ::= SAVEPOINT.
savepoint_opt ::= .
cmd ::= SAVEPOINT nm(X). {}
cmd ::= RELEASE savepoint_opt nm(X). {}
cmd ::= ROLLBACK trans_opt TO savepoint_opt nm(X). {}

// An IDENTIFIER can be a generic identifier, or one of several
// keywords.  Any non-standard keyword can also be an identifier.
//
id(A) ::= ID(X).         {}
id(A) ::= INDEXED(X).    {}

// The following directive causes tokens ABORT, AFTER, ASC, etc. to
// fallback to ID if they will not parse as their original value.
// This obviates the need for the "id" nonterminal.
//
%fallback ID
  ABORT ACTION AFTER ANALYZE ASC ATTACH BEFORE BEGIN BY CASCADE CAST COLUMNKW
  CONFLICT DATABASE DEFERRED DESC DETACH EACH END EXCLUSIVE EXPLAIN FAIL FOR
  IGNORE IMMEDIATE INITIALLY INSTEAD LIKE_KW MATCH NO PLAN
  QUERY KEY OF OFFSET PRAGMA RAISE RELEASE REPLACE RESTRICT ROW ROLLBACK
  SAVEPOINT TEMP TRIGGER VACUUM VIEW VIRTUAL
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
%left AND.
%right NOT.
%left IS MATCH LIKE_KW BETWEEN IN ISNULL NOTNULL NE EQ.
%left GT LE LT GE.
%right ESCAPE.
%left BITAND BITOR LSHIFT RSHIFT.
%left PLUS MINUS.
%left STAR SLASH REM.
%left CONCAT.
%left COLLATE.
%right BITNOT.

// And "ids" is an identifer-or-string.
//
ids(A) ::= ID|STRING(X).   {}

// The name of a column or table can be any of the following:
//
nm(A) ::= id(X).         {}
nm(A) ::= STRING(X).     {}
nm(A) ::= JOIN_KW(X).    {}

// A typetoken is really one or more tokens that form a type name such
// as can be found after the column name in a CREATE TABLE statement.
// Multiple tokens are concatenated to form the value of the typetoken.
//
type ::= .
type ::= typetoken(X).          {}
typetoken(A) ::= typename(X).   {}
typetoken(A) ::= typename(X) LP signed RP(Y). {}
typetoken(A) ::= typename(X) LP signed COMMA signed RP(Y). {}
typename(A) ::= ids(X).             {}
typename(A) ::= typename(X) ids(Y). {}
signed ::= plus_num.
signed ::= minus_num.

// "carglist" is a list of additional constraints that come after the
// column name and column type in a CREATE TABLE statement.
//
carglist ::= carglist ccons.
carglist ::= .
ccons ::= CONSTRAINT nm(X).           {}
ccons ::= DEFAULT term(X).            {}
ccons ::= DEFAULT LP expr(X) RP.      {}
ccons ::= DEFAULT PLUS term(X).       {}
ccons ::= DEFAULT MINUS(A) term(X).   {}
ccons ::= DEFAULT id(X).              {}

// In addition to the type name, we also care about the primary key and
// UNIQUE constraints.
//
ccons ::= NULL onconf.
ccons ::= NOT NULL onconf(R).    {}
ccons ::= PRIMARY KEY sortorder(Z) onconf(R) autoinc(I). {}
ccons ::= UNIQUE onconf(R).      {}
ccons ::= CHECK LP expr(X) RP.   {}
ccons ::= REFERENCES nm(T) idxlist_opt(TA) refargs(R). {}
ccons ::= defer_subclause(D).    {}
ccons ::= COLLATE ids(C).        {}

// The optional AUTOINCREMENT keyword
autoinc(X) ::= .          {}
autoinc(X) ::= AUTOINCR.  {}

// The next group of rules parses the arguments to a REFERENCES clause
// that determine if the referential integrity checking is deferred or
// or immediate and which determine what action to take if a ref-integ
// check fails.
//
refargs(A) ::= .                  {}
refargs(A) ::= refargs(X) refarg(Y). {}
refarg(A) ::= MATCH nm.              {}
refarg(A) ::= ON INSERT refact.      {}
refarg(A) ::= ON DELETE refact(X).   {}
refarg(A) ::= ON UPDATE refact(X).   {}
refact(A) ::= SET NULL.              {}
refact(A) ::= SET DEFAULT.           {}
refact(A) ::= CASCADE.               {}
refact(A) ::= RESTRICT.              {}
refact(A) ::= NO ACTION.             {}
defer_subclause(A) ::= NOT DEFERRABLE init_deferred_pred_opt.     {}
defer_subclause(A) ::= DEFERRABLE init_deferred_pred_opt(X).      {}
init_deferred_pred_opt(A) ::= .                       {}
init_deferred_pred_opt(A) ::= INITIALLY DEFERRED.     {}
init_deferred_pred_opt(A) ::= INITIALLY IMMEDIATE.    {}

conslist_opt(A) ::= .                         {}
conslist_opt(A) ::= COMMA(X) conslist.        {}
conslist ::= conslist tconscomma tcons.
conslist ::= tcons.
tconscomma ::= COMMA.            {}
tconscomma ::= .
tcons ::= CONSTRAINT nm(X).      {}
tcons ::= PRIMARY KEY LP idxlist(X) autoinc(I) RP onconf(R). {}
tcons ::= UNIQUE LP idxlist(X) RP onconf(R). {}
tcons ::= CHECK LP expr(E) RP onconf. {}
tcons ::= FOREIGN KEY LP idxlist(FA) RP
          REFERENCES nm(T) idxlist_opt(TA) refargs(R) defer_subclause_opt(D). {}
defer_subclause_opt(A) ::= .                    {}
defer_subclause_opt(A) ::= defer_subclause(X).  {}

// The following is a non-standard extension that allows us to declare the
// default behavior when there is a constraint conflict.
//
onconf(A) ::= .                              {}
onconf(A) ::= ON CONFLICT resolvetype(X).    {}
orconf(A) ::= .                              {}
orconf(A) ::= OR resolvetype(X).             {}
resolvetype(A) ::= raisetype(X).             {}
resolvetype(A) ::= IGNORE.                   {}
resolvetype(A) ::= REPLACE.                  {}

//////////////////////// The SELECT statement /////////////////////////////////
//
cmd ::= select(X).  {}

select(A) ::= oneselect(X).                      {}
%ifndef SQLITE_OMIT_COMPOUND_SELECT
select(A) ::= select(X) multiselect_op(Y) oneselect(Z).  {}
multiselect_op(A) ::= UNION(OP).             {}
multiselect_op(A) ::= UNION ALL.             {}
multiselect_op(A) ::= EXCEPT|INTERSECT(OP).  {}
%endif SQLITE_OMIT_COMPOUND_SELECT
oneselect(A) ::= SELECT distinct(D) selcollist(W) from(X) where_opt(Y)
                 groupby_opt(P) having_opt(Q) orderby_opt(Z) limit_opt(L). {}

// The "distinct" nonterminal is true (1) if the DISTINCT keyword is
// present and false (0) if it is not.
//
distinct(A) ::= DISTINCT.   {}
distinct(A) ::= ALL.        {}
distinct(A) ::= .           {}

// selcollist is a list of expressions that are to become the return
// values of the SELECT statement.  The "*" in statements like
// "SELECT * FROM ..." is encoded as a special expression with an
// opcode of TK_ALL.
//
sclp(A) ::= selcollist(X) COMMA.             {}
sclp(A) ::= .                                {}
selcollist(A) ::= sclp(P) expr(X) as(Y).     {}
selcollist(A) ::= sclp(P) STAR. {}
selcollist(A) ::= sclp(P) nm(X) DOT STAR(Y). {}

// An option "AS <id>" phrase that can follow one of the expressions that
// define the result set, or one of the tables in the FROM clause.
//
as(X) ::= AS nm(Y).    {}
as(X) ::= ids(Y).      {}
as(X) ::= .            {}


// A complete FROM clause.
//
from(A) ::= .                {}
from(A) ::= FROM seltablist(X). {}

// "seltablist" is a "Select Table List" - the content of the FROM clause
// in a SELECT statement.  "stl_prefix" is a prefix of this list.
//
stl_prefix(A) ::= seltablist(X) joinop(Y).    {}
stl_prefix(A) ::= .                           {}
seltablist(A) ::= stl_prefix(X) nm(Y) dbnm(D) as(Z) indexed_opt(I) on_opt(N) using_opt(U). {}
%ifndef SQLITE_OMIT_SUBQUERY
  seltablist(A) ::= stl_prefix(X) LP select(S) RP
                    as(Z) on_opt(N) using_opt(U). {}
  seltablist(A) ::= stl_prefix(X) LP seltablist(F) RP
                    as(Z) on_opt(N) using_opt(U). {}
  
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
%endif  SQLITE_OMIT_SUBQUERY

dbnm(A) ::= .          {}
dbnm(A) ::= DOT nm(X). {}

fullname(A) ::= nm(X) dbnm(Y).  {A = sqlite3SrcListAppend(pParse->db,0,&X,&Y);}

joinop(X) ::= COMMA|JOIN.              {}
joinop(X) ::= JOIN_KW(A) JOIN.         {}
joinop(X) ::= JOIN_KW(A) nm(B) JOIN.   {}
joinop(X) ::= JOIN_KW(A) nm(B) nm(C) JOIN. {}

on_opt(N) ::= ON expr(E).   {}
on_opt(N) ::= .             {}

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
indexed_opt(A) ::= .                 {}
indexed_opt(A) ::= INDEXED BY nm(X). {}
indexed_opt(A) ::= NOT INDEXED.      {}

using_opt(U) ::= USING LP inscollist(L) RP.  {}
using_opt(U) ::= .                        {}

orderby_opt(A) ::= .                          {}
orderby_opt(A) ::= ORDER BY sortlist(X).      {}
sortlist(A) ::= sortlist(X) COMMA expr(Y) sortorder(Z). {}
sortlist(A) ::= expr(Y) sortorder(Z). {}

sortorder(A) ::= ASC.           {}
sortorder(A) ::= DESC.          {}
sortorder(A) ::= .              {}

groupby_opt(A) ::= .                      {}
groupby_opt(A) ::= GROUP BY nexprlist(X). {}

having_opt(A) ::= .                {}
having_opt(A) ::= HAVING expr(X).  {}

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
limit_opt(A) ::= .                    {}
limit_opt(A) ::= LIMIT expr(X).       {}
limit_opt(A) ::= LIMIT expr(X) OFFSET expr(Y). {}
limit_opt(A) ::= LIMIT expr(X) COMMA expr(Y). {}

/////////////////////////// The DELETE statement /////////////////////////////
//
%ifdef SQLITE_ENABLE_UPDATE_DELETE_LIMIT
cmd ::= DELETE FROM fullname(X) indexed_opt(I) where_opt(W) 
        orderby_opt(O) limit_opt(L). {}
%endif
%ifndef SQLITE_ENABLE_UPDATE_DELETE_LIMIT
cmd ::= DELETE FROM fullname(X) indexed_opt(I) where_opt(W). {}
%endif

where_opt(A) ::= .                    {}
where_opt(A) ::= WHERE expr(X).       {}

////////////////////////// The UPDATE command ////////////////////////////////
//
%ifdef SQLITE_ENABLE_UPDATE_DELETE_LIMIT
cmd ::= UPDATE orconf(R) fullname(X) indexed_opt(I) SET setlist(Y)
    where_opt(W) orderby_opt(O) limit_opt(L).  {}
%endif
%ifndef SQLITE_ENABLE_UPDATE_DELETE_LIMIT
cmd ::= UPDATE orconf(R) fullname(X) indexed_opt(I) SET setlist(Y) where_opt(W).  {}
%endif

setlist(A) ::= setlist(Z) COMMA nm(X) EQ expr(Y). {}
setlist(A) ::= nm(X) EQ expr(Y). {}

////////////////////////// The INSERT command /////////////////////////////////
//
cmd ::= insert_cmd(R) INTO fullname(X) inscollist_opt(F) valuelist(Y). {}
cmd ::= insert_cmd(R) INTO fullname(X) inscollist_opt(F) select(S). {}
cmd ::= insert_cmd(R) INTO fullname(X) inscollist_opt(F) DEFAULT VALUES. {}

insert_cmd(A) ::= INSERT orconf(R).   {}
insert_cmd(A) ::= REPLACE.            {}

// A ValueList is either a single VALUES clause or a comma-separated list
// of VALUES clauses.  If it is a single VALUES clause then the
// ValueList.pList field points to the expression list of that clause.
// If it is a list of VALUES clauses, then those clauses are transformed
// into a set of SELECT statements without FROM clauses and connected by
// UNION ALL and the ValueList.pSelect points to the right-most SELECT in
// that compound.
valuelist(A) ::= VALUES LP nexprlist(X) RP. {}

// Since a list of VALUEs is inplemented as a compound SELECT, we have
// to disable the value list option if compound SELECTs are disabled.
%ifndef SQLITE_OMIT_COMPOUND_SELECT
valuelist(A) ::= valuelist(X) COMMA LP exprlist(Y) RP. {}
%endif SQLITE_OMIT_COMPOUND_SELECT

inscollist_opt(A) ::= .                      {}
inscollist_opt(A) ::= LP inscollist(X) RP.   {}
inscollist(A) ::= inscollist(X) COMMA nm(Y). {}
inscollist(A) ::= nm(Y). {}

/////////////////////////// Expression Processing /////////////////////////////
//

expr(A) ::= term(X).             {}
expr(A) ::= LP(B) expr(X) RP(E). {}
term(A) ::= NULL(X).             {}
expr(A) ::= id(X).               {}
expr(A) ::= JOIN_KW(X).          {}
expr(A) ::= nm(X) DOT nm(Y). {}
expr(A) ::= nm(X) DOT nm(Y) DOT nm(Z). {}
term(A) ::= INTEGER|FLOAT|BLOB(X).  {}
term(A) ::= STRING(X).              {}
expr(A) ::= REGISTER(X).     {}
expr(A) ::= VARIABLE(X).     {}
expr(A) ::= expr(E) COLLATE ids(C). {}
%ifndef SQLITE_OMIT_CAST
expr(A) ::= CAST(X) LP expr(E) AS typetoken(T) RP(Y). {}
%endif  SQLITE_OMIT_CAST
expr(A) ::= ID(X) LP distinct(D) exprlist(Y) RP(E). {}
expr(A) ::= ID(X) LP STAR RP(E). {}
term(A) ::= CTIME_KW(OP). {}

expr(A) ::= expr(X) AND(OP) expr(Y).    {}
expr(A) ::= expr(X) OR(OP) expr(Y).     {}
expr(A) ::= expr(X) LT|GT|GE|LE(OP) expr(Y). {}
expr(A) ::= expr(X) EQ|NE(OP) expr(Y).  {}
expr(A) ::= expr(X) BITAND|BITOR|LSHIFT|RSHIFT(OP) expr(Y). {}
expr(A) ::= expr(X) PLUS|MINUS(OP) expr(Y). {}
expr(A) ::= expr(X) STAR|SLASH|REM(OP) expr(Y). {}
expr(A) ::= expr(X) CONCAT(OP) expr(Y). {}
likeop(A) ::= LIKE_KW(X).     {}
likeop(A) ::= NOT LIKE_KW(X). {}
likeop(A) ::= MATCH(X).       {}
likeop(A) ::= NOT MATCH(X).   {}
expr(A) ::= expr(X) likeop(OP) expr(Y).  [LIKE_KW]  {}
expr(A) ::= expr(X) likeop(OP) expr(Y) ESCAPE expr(E).  [LIKE_KW]  {}

expr(A) ::= expr(X) ISNULL|NOTNULL(E).   {}
expr(A) ::= expr(X) NOT NULL(E). {}

//    expr1 IS expr2
//    expr1 IS NOT expr2
//
// If expr2 is NULL then code as TK_ISNULL or TK_NOTNULL.  If expr2
// is any other expression, code as TK_IS or TK_ISNOT.
// 
expr(A) ::= expr(X) IS expr(Y).     {}
expr(A) ::= expr(X) IS NOT expr(Y). {}

expr(A) ::= NOT(B) expr(X).    {}
expr(A) ::= BITNOT(B) expr(X). {}
expr(A) ::= MINUS(B) expr(X). [BITNOT] {}
expr(A) ::= PLUS(B) expr(X). [BITNOT] {}

between_op(A) ::= BETWEEN.     {}
between_op(A) ::= NOT BETWEEN. {}
expr(A) ::= expr(W) between_op(N) expr(X) AND expr(Y). [BETWEEN] {}
%ifndef SQLITE_OMIT_SUBQUERY
  in_op(A) ::= IN.      {}
  in_op(A) ::= NOT IN.  {}
  expr(A) ::= expr(X) in_op(N) LP exprlist(Y) RP(E). [IN] {}
  expr(A) ::= expr(X) in_op(N) LP select(Y) RP(E).  [IN] {}
  expr(A) ::= expr(X) in_op(N) nm(Y) dbnm(Z). [IN] {}
%endif SQLITE_OMIT_SUBQUERY

/* CASE expressions */
expr(A) ::= CASE(C) case_operand(X) case_exprlist(Y) case_else(Z) END(E). {}
case_exprlist(A) ::= case_exprlist(X) WHEN expr(Y) THEN expr(Z). {}
case_exprlist(A) ::= WHEN expr(Y) THEN expr(Z). {}
case_else(A) ::=  ELSE expr(X).         {}
case_else(A) ::=  .                     {}
case_operand(A) ::= expr(X).            {}
case_operand(A) ::= .                   {}

exprlist(A) ::= nexprlist(X).                {}
exprlist(A) ::= .                            {}
nexprlist(A) ::= nexprlist(X) COMMA expr(Y). {}
nexprlist(A) ::= expr(Y). {}

raisetype(A) ::= ROLLBACK.  {}
raisetype(A) ::= ABORT.     {}
raisetype(A) ::= FAIL.      {}
