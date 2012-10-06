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

%token_type {TokenInfo*}
%extra_argument {ScannerContext* sc}

%type like_op       {LikeOpInfo}
%type in_op         {InOpInfo}
%type between_op    {BetweenOpInfo}

%type id    {TokenInfo*}
%type ids   {TokenInfo*}
%type nm    {TokenInfo*}

// The following text is included near the beginning of the C source
// code file that implements the parser.
//
%include {

#include <boost/cast.hpp>
#include <cassert>
#include <stack>

#ifndef NDEBUG
#include "sqlParser.h"
#include <iostream>
#endif

#include "AlwaysSomethingNode.hpp"
#include "AstNode.hpp"
#include "BinaryOperatorNode.hpp"
#include "BooleanLogicNode.hpp"
#include "ComparisonNode.hpp"
#include "ExpressionNode.hpp"
#include "FunctionNode.hpp"
#include "InValuesListNode.hpp"
#include "NegationNode.hpp"
#include "NullNode.hpp"
#include "nullptr.hpp"
#include "ScannerContext.hpp"
#include "TerminalNode.hpp"
#include "TokenInfo.hpp"

struct LikeOpInfo
{
    int tokenType;
    bool negation;
};
struct BetweenOpInfo
{
    int tokenType;
    bool negation;
};
struct InOpInfo
{
    int inOpType;
    int comparisonType;  // Used for ANY and SOME
    bool negation;
};


// Give up parsing as soon as the first error is encountered
#define YYNOERRORRECOVERY 1

/**
 * Pushes a new BooleanLogicNode with two ExpressionNodes as leaves (taken from
 * the stack) and the given operator.
 */
static void addBooleanLogicNode(
    ScannerContext* const sc,
    const int operator_
)
{
    ExpressionNode* const expr2 =
        boost::polymorphic_downcast<ExpressionNode*>(sc->getTopNode());
    sc->popNode();
    ExpressionNode* const expr1 =
        boost::polymorphic_downcast<ExpressionNode*>(sc->getTopNode());
    sc->popNode();

    AstNode* const e = new BooleanLogicNode(
        expr1,
        operator_,
        expr2
    );

    sc->pushNode(e);
}


/**
 * Pushes a new BinaryOperatorNode with two ExpressionNodes as leaves (taken
 * from the stack) and the given operator.
 */
static void addBinaryOperatorNode(
    ScannerContext* const sc,
    const int operator_
)
{
    ExpressionNode* const expr2 =
        boost::polymorphic_downcast<ExpressionNode*>(sc->getTopNode());
    sc->popNode();
    ExpressionNode* const expr1 =
        boost::polymorphic_downcast<ExpressionNode*>(sc->getTopNode());
    sc->popNode();

    sc->pushNode(new BinaryOperatorNode(expr1, operator_, expr2));
}


/**
 * Pushes a new ComparisonNode with two ExpressionNodes as leaves (taken from
 * the stack) and the given comparison type.
 */
static void addComparisonNode(
    ScannerContext* sc,
    const int comparisonType,
    bool negation = false
)
{
    ExpressionNode* const rightExpr =
        boost::polymorphic_downcast<ExpressionNode*>(sc->getTopNode());
    sc->popNode();
    ExpressionNode* const leftExpr =
        boost::polymorphic_downcast<ExpressionNode*>(sc->getTopNode());
    sc->popNode();

    ComparisonNode* const c = new ComparisonNode(
        leftExpr,
        comparisonType,
        rightExpr
    );

    if (c->isAlwaysTrue())
    {
        ++sc->qrPtr->alwaysTrueConditionals;
    }

    sc->qrPtr->updatePasswordRisk(c->emptyPassword());

    if (
        (leftExpr->isHex() && rightExpr->resultsInString())
        || (rightExpr->isHex() && leftExpr->resultsInString())
    )
    {
        ++sc->qrPtr->hexStrings;
    }

    if (negation)
    {
        AstNode* const negationNode = new NegationNode(c);
        sc->pushNode(negationNode);
    }
    else
    {
        sc->pushNode(c);
    }
}


// I don't want to incur the overhead of including <algorithm>
template <typename T>
static T max(const T& t1, const T& t2)
{
    return ((t1 > t2) ? t1 : t2);
}

} // end %include

%syntax_error {
    // Mark the query as invalid
    sc->qrPtr->valid = false;
}
// parse_failure is normally only called when Lemon's error recovery scheme
// fails miserably and the parser is hopelessly lost. syntax_failure is called
// for normal errors. Because I've defined YYNOERRORRECOVERY above, this
// should never be called, but just in case, I'll add it in.
%parse_failure {
    // Mark the query as invalid
    sc->qrPtr->valid = false;
    assert(
        false
        && "parse_failure should never be called if Lemon's error recovery is"
        " disabled. Check that error recovery is actually disabled."
    );
}

///////////////////// Begin parsing rules. ////////////////////////////
//

// Input is a single SQL command
input ::= cmd ecmd.
ecmd ::= .
ecmd ::= SEMI ecmd.

///////////////////// Begin and end transactions. ////////////////////////////
//

cmd ::= START TRANSACTION start_opt.
    {sc->qrPtr->queryType = QueryRisk::TYPE_TRANSACTION;}
cmd ::= BEGIN_KW work_opt.
    {sc->qrPtr->queryType = QueryRisk::TYPE_TRANSACTION;}
cmd ::= COMMIT work_opt chain_opt release_opt.
    {sc->qrPtr->queryType = QueryRisk::TYPE_TRANSACTION;}
cmd ::= ROLLBACK work_opt chain_opt release_opt.
    {sc->qrPtr->queryType = QueryRisk::TYPE_TRANSACTION;}
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
id(A) ::= ID(X).            {A = X;}
id(A) ::= ID_FALLBACK(X).
{
    A = X;
    // I really don't want to include the header file that's generated from
    // this file just to access the scan token value for ID, because that just
    // seems like a terrible hack.
    const int ID_TOKEN = 15;
    assert(ID_TOKEN == ID);
    A->token_ = ID_TOKEN;
}

// The following directive causes tokens ABORT, AFTER, ASC, etc. to
// fallback to ID if they will not parse as their original value.
// This obviates the need for the "id" nonterminal.
%fallback ID_FALLBACK
  ASC BEGIN_KW BY CAST
  DATABASE DESC END EXPLAIN FOR
  IGNORE LIKE_KW MATCH_KW
  QUERY KEY OFFSET RELEASE REPLACE ROLLBACK
  // MySQL specific stuff
  LOW_PRIORITY DELAYED HIGH_PRIORITY CONSISTENT SNAPSHOT WORK CHAIN QUICK
  SOUNDS OUTFILE SQL_BIG_RESULT SQL_SMALL_RESULT SQL_BUFFER_RESULT SQL_CACHE
  SQL_NO_CACHE LOCK SHARE MODE BOOLEAN EXPANSION
  UNION JOIN_KW
  FULL TABLES SCHEMA
  DEFAULT
  SOME ANY
  READ WRITE SESSION
  .

// I don't know what this does, so I'm going to remove it
//%wildcard ANY.

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
%right STRING.
%left OR.
%left XOR.
%left AND.
%right NOT SOME ANY.
%left IS MATCH_KW LIKE_KW SOUNDS BETWEEN IN NE EQ.
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
ids(A) ::= ID(X).       {A = X;}
ids(A) ::= string(X).   {A = X;}

// The name of a column or table can be any of the following:
//
nm(A) ::= id(X).         {A = X;}
nm(A) ::= string(X).     {A = X;}
nm(A) ::= JOIN_KW(X).    {A = X;}

// MySQL implicitly concatenates adjacent strings.
string(A) ::= STRING(X) string(Y).
{
    A = X;
    A->scannedString_ += Y->scannedString_;
    ++sc->qrPtr->mySqlStringConcat;
}
string(A) ::= STRING(X).    {A = X;}

// A typetoken is really one or more tokens that form a type name such
// as can be found after the column name in a CREATE TABLE statement.
// Multiple tokens are concatenated to form the value of the typetoken.
//
typetoken ::= typename.
typetoken ::= typename LP signed RP.
typetoken ::= typename LP signed COMMA signed RP.
typename ::= ids.
typename ::= typename ids.
plus_num ::= number.
minus_num ::= MINUS number.
number ::= INTEGER|FLOAT.
number ::= HEX_NUMBER.
signed ::= plus_num.
signed ::= minus_num.

//////////////////////// The SHOW statement /////////////////////////////////
//
cmd ::= SHOW DATABASES where_opt.
{
    sc->qrPtr->queryType = QueryRisk::TYPE_SHOW;
    // Pop the where_opt node
    sc->popNode();
}
// MySQL doesn't allow NOT LIKE statements here, so don't use like_op
cmd ::= SHOW DATABASES LIKE_KW string.
{
    sc->qrPtr->queryType = QueryRisk::TYPE_SHOW;
}

cmd ::= SHOW global_opt VARIABLES where_opt.
{
    /// @TODO(bskari|2012-07-08) Are any global variables risky?
    sc->qrPtr->queryType = QueryRisk::TYPE_SHOW;
    // Pop the where_opt node
    sc->popNode();
}
cmd ::= SHOW global_opt VARIABLES LIKE_KW string.
{
    /// @TODO(bskari|2012-07-08) Are any global variables risky?
    sc->qrPtr->queryType = QueryRisk::TYPE_SHOW;
}
global_opt ::= GLOBAL.
global_opt ::= .

cmd ::= SHOW CREATE TABLE id.
{
    sc->qrPtr->queryType = QueryRisk::TYPE_SHOW;
}
cmd ::= SHOW CREATE SCHEMA id.
{
    sc->qrPtr->queryType = QueryRisk::TYPE_SHOW;
}
cmd ::= SHOW CREATE DATABASE id.
{
    sc->qrPtr->queryType = QueryRisk::TYPE_SHOW;
}

// There are other commands too, like "SHOW FULL PROCESSLIST", "SHOW USERS"
cmd ::= SHOW id.
{
    sc->qrPtr->queryType = QueryRisk::TYPE_SHOW;
}
cmd ::= SHOW id like_op expr.
{
    sc->qrPtr->queryType = QueryRisk::TYPE_SHOW;
}
cmd ::= SHOW id id.
{
    sc->qrPtr->queryType = QueryRisk::TYPE_SHOW;
}
cmd ::= SHOW id id like_op expr.
{
    sc->qrPtr->queryType = QueryRisk::TYPE_SHOW;
}

// Using full_opt here wasn't working, so just copy/paste
cmd ::= SHOW TABLES show_from_in_id_opt where_opt.
{
    sc->qrPtr->queryType = QueryRisk::TYPE_SHOW;
    // Pop the where_opt node
    sc->popNode();
}
cmd ::= SHOW FULL TABLES show_from_in_id_opt where_opt.
{
    sc->qrPtr->queryType = QueryRisk::TYPE_SHOW;
    // Pop the where_opt node
    sc->popNode();
}
cmd ::= SHOW TABLES show_from_in_id_opt LIKE_KW string.
{
    sc->qrPtr->queryType = QueryRisk::TYPE_SHOW;
}
cmd ::= SHOW FULL TABLES show_from_in_id_opt LIKE_KW string.
{
    sc->qrPtr->queryType = QueryRisk::TYPE_SHOW;
}

cmd ::= SHOW full_opt COLUMNS where_opt.
{
    sc->qrPtr->queryType = QueryRisk::TYPE_SHOW;
    // Pop the where_opt node
    sc->popNode();
}
cmd ::= SHOW full_opt COLUMNS LIKE_KW string.
{
    sc->qrPtr->queryType = QueryRisk::TYPE_SHOW;
}
cmd ::= SHOW full_opt COLUMNS from_in show_columns_id show_from_in_id_opt
    where_opt.
{
    sc->qrPtr->queryType = QueryRisk::TYPE_SHOW;
    // Pop the where_opt node
    sc->popNode();
}
cmd ::= SHOW full_opt COLUMNS from_in show_columns_id show_from_in_id_opt
    LIKE_KW string.
{
    sc->qrPtr->queryType = QueryRisk::TYPE_SHOW;
}

show_from_in_id_opt ::= .
show_from_in_id_opt ::= from_in id.

from_in ::= FROM.
from_in ::= IN.

show_columns_id ::= id.
show_columns_id ::= id DOT id.

full_opt ::= .
full_opt ::= FULL.

//////////////////////// The DESCRIBE statement ///////////////////////////////
//
// MySQL lets you use the DESC and EXPLAIN keyword for DESCRIBE
/// @TODO(bskari|2012-06-30) Support EXPLAIN keyword here.
describe_kw ::= DESC|DESCRIBE.
cmd ::= describe_kw id.
{
    sc->qrPtr->queryType = QueryRisk::TYPE_DESCRIBE;
}
cmd ::= describe_kw id id.
{
    sc->qrPtr->queryType = QueryRisk::TYPE_DESCRIBE;
}
// You can specify an individual column, or give a regex and show all columns
// that match it.
cmd ::= describe_kw id string.
{
    sc->qrPtr->queryType = QueryRisk::TYPE_DESCRIBE;
}

//////////////////////// The EXPLAIN statement ///////////////////////////////
//
cmd ::= explain select_statement.
{
    sc->qrPtr->queryType = QueryRisk::TYPE_EXPLAIN;
}
explain ::= EXPLAIN extended_opt.
extended_opt ::= .
extended_opt ::= EXTENDED.

//////////////////////// The USE statement ////////////////////////////////////
//
cmd ::= USE id.
{
    sc->qrPtr->queryType = QueryRisk::TYPE_USE;
}

//////////////////////// The SET statement ////////////////////////////////////
//
cmd ::= SET set_assignments.    {sc->qrPtr->queryType = QueryRisk::TYPE_SET;}
// Set assignments are usually of the form "SET foo = 'bar'", but they can
// also look like "SET NAMES utf8"
set_assignments ::= set_assignment.
set_assignments ::= set_assignments COMMA set_assignment.
set_assignment ::= set_opt id EQ expr.
set_assignment ::= set_opt id expr.
set_assignment ::= GLOBAL_VARIABLE EQ expr.
{
    ++sc->qrPtr->globalVariables;
}
set_assignment ::= GLOBAL_VARIABLE DOT nm EQ expr.
{
    ++sc->qrPtr->globalVariables;
}
set_assignment ::= VARIABLE EQ expr.
set_assignment ::= VARIABLE DOT nm EQ expr.
// MySQL also has some long SET statements, like:
// SET GLOBAL TRANSACTION ISOLATION LEVEL REPEATABLE READ UNCOMMITTED
cmd ::= SET set_opt TRANSACTION bunch_of_ids.
{
    sc->qrPtr->queryType = QueryRisk::TYPE_SET;
}
bunch_of_ids ::= .
bunch_of_ids ::= id bunch_of_ids.
set_opt ::= GLOBAL.
set_opt ::= SESSION.
set_opt ::= .

//////////////////////// The LOCK statement ///////////////////////////////////
//
cmd ::= LOCK TABLES lock_tables_list.
{
    sc->qrPtr->queryType = QueryRisk::TYPE_LOCK;
}
lock_tables_list ::= as lock_type.
lock_tables_list ::= as lock_type COMMA lock_tables_list.
lock_type ::= READ local_opt.
lock_type ::= low_priority_opt WRITE.
local_opt ::= .
local_opt ::= LOCAL.
cmd ::= UNLOCK TABLES lock_tables_list.
{
    sc->qrPtr->queryType = QueryRisk::TYPE_LOCK;
}

//////////////////////// The SELECT statement /////////////////////////////////
//
cmd ::= select_statement.   {sc->qrPtr->queryType = QueryRisk::TYPE_SELECT;}
select_statement ::= select_opt select outfile_opt lock_read_opt.

select ::= oneselect.
select ::= select multiselect_op oneselect.
multiselect_op ::= UNION.       {++sc->qrPtr->unionStatements;}
multiselect_op ::= UNION ALL.
{
    ++sc->qrPtr->unionStatements;
    ++sc->qrPtr->unionAllStatements;
}
// EXCEPT and INTERSECT are not supported in MySQL
//multiselect_op(A) ::= EXCEPT|INTERSECT(OP).  {A;OP;}
oneselect ::= SELECT distinct selcollist from where_opt
                groupby_opt having_opt orderby_opt limit_opt.
{
    const ExpressionNode* const whereNode =
        boost::polymorphic_cast<const ExpressionNode*>(sc->getTopNode());
    sc->popNode();
    sc->qrPtr->alwaysTrue = whereNode->isAlwaysTrue();
    delete whereNode;
}

// The "distinct" nonterminal is true (1) if the DISTINCT keyword is
// present and false (0) if it is not.
//
distinct ::= DISTINCT.
distinct ::= ALL.
distinct ::= DISTINCTROW.
distinct ::= .

// MySQL specific select options
select_opt ::= high_priority_opt sql_small_result_opt sql_big_result_opt
    sql_buffer_result_opt sql_cache_opt sql_calc_found_rows_opt .
high_priority_opt ::= .
high_priority_opt ::= HIGH_PRIORITY.
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
sclp ::= selcollist COMMA.
sclp ::= .
selcollist ::= sclp expr as.
{
    delete sc->getTopNode();
    sc->popNode();
}
selcollist ::= sclp STAR.
selcollist ::= sclp nm DOT STAR as.

// An option "AS <id>" phrase that can follow one of the expressions that
// define the result set, or one of the tables in the FROM clause.
//
as ::= AS nm.
as ::= ID.
// MySQL allows you to use a string for an as clause, but does not allow
// implicitly concatenated strings
as ::= STRING.
as ::= .


// A complete FROM clause.
//
from ::= .
from ::= FROM seltablist.

// MySQL match statement
//
mysql_match ::= MATCH_KW LP inscollist RP
            AGAINST LP expr againstmodifier_opt RP.
againstmodifier_opt ::= .
againstmodifier_opt ::= IN NATURAL LANGUAGE MODE.
againstmodifier_opt ::= IN BOOLEAN MODE.
againstmodifier_opt ::= WITH QUERY EXPANSION.

// "seltablist" is a "Select Table List" - the content of the FROM clause
// in a SELECT statement.  "stl_prefix" is a prefix of this list.
//
stl_prefix ::= seltablist joinop.
stl_prefix ::= .
seltablist ::= stl_prefix select_table
                as index_hint_list_opt on_opt using_opt.
seltablist ::= stl_prefix LP select RP as index_hint_list_opt on_opt using_opt.
seltablist ::= stl_prefix LP seltablist RP
                as index_hint_list_opt on_opt using_opt.

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

select_table ::= id(X).
{
    sc->qrPtr->checkTable(X->scannedString_);
}
select_table ::= string(X).
{
    sc->qrPtr->checkTable(X->scannedString_);
}
// I tried to just include this in the ID_FALLBACK, but it caused a lot of
// other parse problems
select_table ::= COLUMNS.
select_table ::= id(X) DOT id(Y).
{
    sc->qrPtr->checkDatabase(X->scannedString_);
    sc->qrPtr->checkTable(Y->scannedString_);
}
select_table ::= id(X) DOT string(Y).
{
    sc->qrPtr->checkDatabase(X->scannedString_);
    sc->qrPtr->checkTable(Y->scannedString_);
}
select_table ::= id DOT COLUMNS.

table_name ::= id(X).
{
    sc->qrPtr->checkTable(X->scannedString_);
}
table_name ::= string(X).
{
    sc->qrPtr->checkTable(X->scannedString_);
}

dbnm ::= .
dbnm ::= DOT nm(X).
{
    sc->qrPtr->checkTable(X->scannedString_);
}

fullname ::= nm(X).
{
    sc->qrPtr->checkTable(X->scannedString_);
}
fullname ::= nm DOT nm(X).
{
    sc->qrPtr->checkTable(X->scannedString_);
}

joinop ::= COMMA.               {++sc->qrPtr->joinStatements;}
joinop ::= join_opt JOIN_KW.    {++sc->qrPtr->joinStatements;}
joinop ::= STRAIGHT_JOIN.       {++sc->qrPtr->joinStatements;}

join_opt ::= INNER.
// CROSS JOIN statements normally don't have an ON statement, and other JOIN
// statements that don't have ON statements behave like (and are counted as)
// CROSS JOINs, so we don't need to count them here.
join_opt ::= CROSS.
join_opt ::= natural_opt left_right_opt outer_opt.
left_right_opt ::= .
left_right_opt ::= LEFT.
left_right_opt ::= RIGHT.
natural_opt ::= .
natural_opt ::= NATURAL.
outer_opt ::= .
outer_opt ::= OUTER.

on_opt ::= ON expr.
{
    // ON expressions are only valid after a JOIN has been seen
    if (0 == sc->qrPtr->joinStatements)
    {
        sc->qrPtr->valid = false;
    }
    // Because the parser allows ON statements in the first SELECT, we only
    // want to increment crossJoinStatements if there has been a JOIN. For
    // example, "SELECT * FROM user" shouldn't count as a CROSS JOIN.
    else
    {
        // Any join with an always true conditional is equivalent to a CROSS JOIN,
        // modulo the JOIN type's behavior when dealing with NULL values.
        ExpressionNode* const expr =
            boost::polymorphic_downcast<ExpressionNode*>(sc->getTopNode());
        sc->popNode();
        if (expr->isAlwaysTrue())
        {
            ++sc->qrPtr->crossJoinStatements;
        }
    }
}
on_opt ::= .
{
    // Any join with an always true conditional is equivalent to a CROSS JOIN,
    // modulo the JOIN type's behavior when dealing with NULL values.
    // Because the parser allows ON statements in the first SELECT, we only
    // want to increment crossJoinStatements if there has been a JOIN. For
    // example, "SELECT * FROM user" shouldn't count as a CROSS JOIN.
    if (sc->qrPtr->joinStatements > 0)
    {
        ++sc->qrPtr->crossJoinStatements;
    }
}

// MySQL specific indexing hints
index_hint_list_opt ::= .
index_hint_list_opt ::= index_hint_list.
index_hint_list ::= index_hint_list index_hint.
index_hint_list ::= index_hint.
index_hint ::= USE index_or_key_opt index_hint_for_opt LP index_list RP.
index_hint ::= IGNORE index_or_key_opt index_hint_for_opt LP index_list RP.
index_hint ::= FORCE index_or_key_opt index_hint_for_opt LP index_list RP.
index_or_key_opt ::= .
index_or_key_opt ::= INDEX.
index_or_key_opt ::= KEY.
index_hint_for_opt ::= .
index_hint_for_opt ::= FOR JOIN_KW.
index_hint_for_opt ::= FOR ORDER BY.
index_hint_for_opt ::= FOR GROUP BY.
index_list ::= nm .
index_list ::= nm COMMA index_list .

using_opt ::= USING LP inscollist RP.
using_opt ::= .

orderby_opt ::= .
orderby_opt ::= ORDER BY expr sortorder sortlistremainder.
{
    // The first expression in a sort list is special, because ordering by a
    // number (ORDER BY 1) is dangerous, but only if it's first in the list.
    const ExpressionNode* const expr =
        boost::polymorphic_downcast<const ExpressionNode*>(sc->getTopNode());
    if (expr->resultsInValue())
    {
        sc->qrPtr->orderByNumber = true;
    }
}
sortlistremainder ::= .
sortlistremainder ::= COMMA sortlist.
sortlist ::= sortlist COMMA expr sortorder.
{
    delete sc->getTopNode();
    sc->popNode();
}
sortlist ::= expr sortorder.
{
    delete sc->getTopNode();
    sc->popNode();
}

sortorder ::= ASC.
sortorder ::= DESC.
sortorder ::= .

groupby_opt ::= .
groupby_opt ::= GROUP BY nexprbegin nexprlist.
{
    while (sc->isTopNodeFromCurrentDepth())
    {
        sc->popNode();
    }
    sc->decreaseNodeDepth();
}


having_opt ::= .
having_opt ::= HAVING expr.

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
limit_opt ::= .
limit_opt ::= LIMIT expr.
limit_opt ::= LIMIT expr OFFSET expr.
limit_opt ::= LIMIT expr COMMA expr.

// Subselects have some different semantics.
// 1) We care about the risks in them, because attackers can use them to
// access more information. So, we will process them and set the QueryRisk
// appropriately.
// 2) They are considered an expression, because they return some values.
// We can't really determine what that expression is, so we'll default to
// returning a fummy identifier, so that comparisons won't be mistakenly
// assumed as true.
subselect ::= subselectbegin select.
{
    while (sc->isTopNodeFromCurrentDepth())
    {
        sc->popNode();
    }
    sc->decreaseNodeDepth();
    sc->pushNode(TerminalNode::createDummyIdentifierTerminalNode());
}
subselectbegin ::= .
{
    sc->increaseNodeDepth();
}

/////////////////////////// The DELETE statement /////////////////////////////
//
cmd ::= DELETE delete_opt FROM fullname where_opt
        orderby_opt limit_opt.
{
    sc->qrPtr->queryType = QueryRisk::TYPE_DELETE;
    // Pop the where_opt node
    delete sc->getTopNode();
    sc->popNode();
}

delete_opt ::= low_priority_opt quick_opt ignore_opt.
low_priority_opt ::= .
low_priority_opt ::= LOW_PRIORITY.
quick_opt ::= .
quick_opt ::= QUICK.
ignore_opt ::= .
ignore_opt ::= IGNORE.
where_opt ::= .
{
    AstNode* const whereNode = new AlwaysSomethingNode(true);
    sc->pushNode(whereNode);
}
where_opt ::= WHERE expr.
{
    // Just leave the expr node on top of the nodes stack
}

////////////////////////// The UPDATE command ////////////////////////////////
//
cmd ::= UPDATE update_opt fullname SET setlist
    where_opt orderby_opt limit_opt.
    {sc->qrPtr->queryType = QueryRisk::TYPE_UPDATE;}

setlist ::= setlist COMMA nm EQ expr.
setlist ::= nm EQ expr.

update_opt ::= .
update_opt ::= LOW_PRIORITY.
update_opt ::= IGNORE.

////////////////////////// The INSERT command /////////////////////////////////
//
/**
@TODO(bskari|2012-07-04)
 * Handle 'ON DUPLICATE KEY UPDATE col_name=expr [, col_name=expr] ...
 */
cmd ::= insert_cmd insert_opt into_opt fullname inscollist_opt valuelist.
    {sc->qrPtr->queryType = QueryRisk::TYPE_INSERT;}
cmd ::= insert_cmd insert_opt into_opt fullname inscollist_opt select.
    {sc->qrPtr->queryType = QueryRisk::TYPE_INSERT;}
cmd ::= insert_cmd insert_opt into_opt fullname inscollist_opt DEFAULT VALUES.
    {sc->qrPtr->queryType = QueryRisk::TYPE_INSERT;}

into_opt ::= .
into_opt ::= INTO.

insert_opt ::= insert_priority_opt ignore_opt.
insert_priority_opt ::= .
insert_priority_opt ::= LOW_PRIORITY.
insert_priority_opt ::= DELAYED.
insert_priority_opt ::= HIGH_PRIORITY.

insert_cmd ::= INSERT.
insert_cmd ::= REPLACE.

// A ValueList is either a single VALUES clause or a comma-separated list
// of VALUES clauses.  If it is a single VALUES clause then the
// ValueList.pList field points to the expression list of that clause.
// If it is a list of VALUES clauses, then those clauses are transformed
// into a set of SELECT statements without FROM clauses and connected by
// UNION ALL and the ValueList.pSelect points to the right-most SELECT in
// that compound.
valuelist ::= VALUES LP nexprbegin nexprlist RP.
{
    /// @TODO(bskari|2012-07-29) Do something?
    while (sc->isTopNodeFromCurrentDepth())
    {
        delete sc->getTopNode();
        sc->popNode();
    }
    sc->decreaseNodeDepth();
}

// Since a list of VALUEs is inplemented as a compound SELECT, we have
// to disable the value list option if compound SELECTs are disabled.
valuelist ::= valuelist COMMA LP exprlist RP.
{
    /// @TODO(bskari|2012-07-29) Do something?
    while (sc->isTopNodeFromCurrentDepth())
    {
        delete sc->getTopNode();
        sc->popNode();
    }
    sc->decreaseNodeDepth();
}

inscollist_opt ::= .
inscollist_opt ::= LP inscollist RP.
inscollist ::= inscollist COMMA nm.
inscollist ::= nm.

/////////////////////////// Expression Processing /////////////////////////////
//

expr ::= term.
expr ::= LP expr RP.
expr ::= LP subselect RP.
{
    /// @TODO(bskari|2012-07-04) What should I do here?
    sc->pushNode(new AlwaysSomethingNode(true));
}
term ::= NULL_KW.   {sc->pushNode(new NullNode);}
expr ::= id(X).
{
    ExpressionNode* e = new TerminalNode(X->scannedString_, X->token_);
    sc->pushNode(e);
}
expr ::= nm(X) DOT id(Y).
{
    sc->qrPtr->checkTable(X->scannedString_);
    ExpressionNode* const e = new TerminalNode(Y->scannedString_, Y->token_);
    sc->pushNode(e);
}
expr ::= nm DOT table_name DOT id(X).
{
    ExpressionNode* const e = new TerminalNode(X->scannedString_, X->token_);
    sc->pushNode(e);
}
term ::= INTEGER|FLOAT(X).
{
    ExpressionNode* const ex = new TerminalNode(X->scannedString_, X->token_);
    sc->pushNode(ex);
}
term ::= HEX_NUMBER(X).
{
    /// @TODO Translate this to a decimal number?
    ExpressionNode* const ex = new TerminalNode(X->scannedString_, X->token_);
    sc->pushNode(ex);
}
term ::= string(X).
{
    ExpressionNode* const ex = new TerminalNode(X->scannedString_, X->token_);
    sc->pushNode(ex);
}
term ::= GLOBAL_VARIABLE(X).
{
    /// @TODO(bskari|2012-07-04) Check risky stuff?
    ExpressionNode* const ex = new TerminalNode(X->scannedString_, X->token_);
    sc->pushNode(ex);
    ++sc->qrPtr->globalVariables;
}
term ::= GLOBAL_VARIABLE DOT id(X).
{
    /// @TODO(bskari|2012-07-04) Check risky stuff?
    ExpressionNode* const ex = new TerminalNode(X->scannedString_, X->token_);
    sc->pushNode(ex);
    ++sc->qrPtr->globalVariables;
}
/* MySQL allows date intervals */
term ::= INTERVAL expr TIME_UNIT RP.
expr ::= VARIABLE.
expr ::= expr COLLATE ids.
expr ::= CAST LP expr AS typetoken RP.
expr ::= id(X) LP distinct exprlist RP.
{
    /// @TODO(bskari|2012-07-04) I should probably handle a bunch of possible
    /// functions here. For example, IF(1, 1, 0) should always be true.
    FunctionNode* fn = new FunctionNode(X->scannedString_);

    while (sc->isTopNodeFromCurrentDepth())
    {
        fn->addChild(sc->getTopNode());
        sc->popNode();
    }
    sc->decreaseNodeDepth();

    sc->pushNode(new FunctionNode(X->scannedString_));

    sc->qrPtr->checkFunction(X->scannedString_);
}
// INSERT is a reserved word in MySQL, but it's also the name of a built-in
// string manipulation function
expr ::= INSERT(X) LP distinct exprlist RP.
{
    /// @TODO(bskari|2012-07-04) I should probably handle a bunch of possible
    /// functions here. For example, IF(1, 1, 0) should always be true.
    FunctionNode* fn = new FunctionNode(X->scannedString_);

    while (sc->isTopNodeFromCurrentDepth())
    {
        fn->addChild(sc->getTopNode());
        sc->popNode();
    }
    sc->decreaseNodeDepth();

    sc->pushNode(new FunctionNode(X->scannedString_));

    sc->qrPtr->checkFunction(X->scannedString_);
}
expr ::= id(X) LP STAR RP.
{
    /// @TODO(bskari|2012-07-04) I should probably handle a bunch of possible
    /// functions here. For example, IF (1, 1, 0) should always be true.
    sc->pushNode(new FunctionNode(X->scannedString_));
    sc->qrPtr->checkFunction(X->scannedString_);
}
expr ::= expr AND(OP) expr.
{
    addBooleanLogicNode(sc, OP->token_);
}
expr ::= expr OR(OP) expr.
{
    addBooleanLogicNode(sc, OP->token_);
    ++sc->qrPtr->orStatements;
}
expr ::= expr XOR(OP) expr.
{
    addBooleanLogicNode(sc, OP->token_);
}
expr ::= expr EQ|LT|GT|LE|GE|NE(OP) expr.
{
    addComparisonNode(sc, OP->token_);
}
expr ::= expr BITAND|BITOR|BITXOR|LSHIFT|RSHIFT(OP) expr.
{
    addBinaryOperatorNode(sc, OP->token_);
}
expr ::= expr PLUS|MINUS(OP) expr.
{
    addBinaryOperatorNode(sc, OP->token_);
}
expr ::= expr STAR|SLASH|REM|INTEGER_DIVIDE(OP) expr.
{
    addBinaryOperatorNode(sc, OP->token_);
}
expr ::= expr CONCAT expr.
{
    // Screw it, let's just handle it here
    ExpressionNode* const expr2 =
        boost::polymorphic_downcast<ExpressionNode*>(sc->getTopNode());
    sc->popNode();
    ExpressionNode* const expr1 =
        boost::polymorphic_downcast<ExpressionNode*>(sc->getTopNode());
    sc->popNode();

    sc->pushNode(
        TerminalNode::createStringTerminalNode(
            expr1->getValue() + expr2->getValue()
        )
    );

    delete expr1;
    delete expr2;
}

like_op(A) ::= MATCH_KW(OP).
{
    A.negation = false; A.tokenType = OP->token_;
}
like_op(A) ::= NOT MATCH_KW(OP).
{
    A.negation = true; A.tokenType = OP->token_;
}
like_op(A) ::= LIKE_KW(OP).
{
    A.negation = false; A.tokenType = OP->token_;
}
like_op(A) ::= NOT LIKE_KW(OP).
{
    A.negation = true; A.tokenType = OP->token_;
}
like_op(A) ::= SOUNDS(OP) LIKE_KW.
{
    A.negation = false; A.tokenType = OP->token_;
}

expr ::= expr like_op(B) expr. [LIKE_KW]
{
    const ExpressionNode* const rightExpr =
        boost::polymorphic_downcast<const ExpressionNode*>(sc->getTopNode());
    if (rightExpr->resultsInString())
    {
        sc->qrPtr->checkRegex(rightExpr->getValue());
    }

    sc->popNode();
    const ExpressionNode* const leftExpr =
        boost::polymorphic_downcast<const ExpressionNode*>(sc->getTopNode());
    sc->pushNode(const_cast<ExpressionNode*>(rightExpr));

    // Normally we can't know the type of a field from here, but like
    // statements imply that the field is a string, so we can do an extra
    // check for hex digits being used as strings.
    if (
        (leftExpr->isHex() && rightExpr->isField())
        || (rightExpr->isHex() && leftExpr->isField())
    )
    {
        ++sc->qrPtr->hexStrings;
    }

    addComparisonNode(sc, B.tokenType, B.negation);
}
expr ::= expr like_op(B) expr ESCAPE expr. [LIKE_KW]
{
    /// @TODO(bskari|2012-07-04) Do I need to do anything with the escape expr?
    delete sc->getTopNode();
    sc->popNode();

    const ExpressionNode* const rightExpr =
        boost::polymorphic_downcast<const ExpressionNode*>(sc->getTopNode());

    sc->popNode();
    const ExpressionNode* const leftExpr =
        boost::polymorphic_downcast<const ExpressionNode*>(sc->getTopNode());
    sc->pushNode(const_cast<ExpressionNode*>(rightExpr));

    if (rightExpr->resultsInString())
    {
        sc->qrPtr->checkRegex(rightExpr->getValue());
    }

    // Normally we can't know the type of a field from here, but like
    // statements imply that the field is a string, so we can do an extra
    // check for hex digits being used as strings.
    if (
        (leftExpr->isHex() && rightExpr->isField())
        || (rightExpr->isHex() && leftExpr->isField())
    )
    {
        ++sc->qrPtr->hexStrings;
    }

    addComparisonNode(sc, B.tokenType, B.negation);
}

expr ::= expr IS NULL_KW.
{
    const ExpressionNode* const ex =
        boost::polymorphic_downcast<ExpressionNode*>(sc->getTopNode());
    // NULL IS NULL is always true, everything else is false, or safe enough
    // to always be considered false
    const bool alwaysTrue = (ex->resultsInValue() && "NULL" != ex->getValue());
    AstNode* const asn = new AlwaysSomethingNode(alwaysTrue);
    asn->addChild(sc->getTopNode());
    sc->popNode();
    asn->addChild(new NullNode);
    sc->pushNode(asn);
}
expr ::= expr IS NOT NULL_KW.
{
    const ExpressionNode* const ex =
        boost::polymorphic_downcast<ExpressionNode*>(sc->getTopNode());
    // NULL IS NOT NULL is always false, everything else is true, or safe
    // enough to always be considered false
    const bool alwaysTrue = !(!ex->resultsInValue() && "NULL" != ex->getValue());
    AstNode* const asn = new AlwaysSomethingNode(alwaysTrue);
    asn->addChild(sc->getTopNode());
    sc->popNode();
    asn->addChild(new NullNode);
    sc->pushNode(asn);
}
expr ::= NOT expr.
{
    const ExpressionNode* const expr =
        boost::polymorphic_downcast<ExpressionNode*>(sc->getTopNode());
    sc->popNode();
    AstNode* const negationNode = new NegationNode(expr);
    sc->pushNode(negationNode);
}

/// @TODO(bskari|2012-07-04) Do something with these unary operators.
expr ::= BITNOT expr.
expr ::= MINUS(X) expr. [BITNOT]
{
    ExpressionNode* const negatedExpr =
        boost::polymorphic_cast<ExpressionNode*>(sc->getTopNode());
    sc->popNode();

    AstNode* minus = new BinaryOperatorNode(
        TerminalNode::createNumberTerminalNode("0"),
        X->token_,
        negatedExpr
    );
    sc->pushNode(minus);
}
expr ::= PLUS expr. [BITNOT]

between_op(A) ::= BETWEEN(X).
{
    A.negation = false;
    A.tokenType = X->token_;
}
between_op(A) ::= NOT BETWEEN(X).
{
    A.negation = true;
    A.tokenType = X->token_;
}
expr ::= expr between_op(N) expr AND expr. [BETWEEN]
{
    ExpressionNode* const expr2 =
        boost::polymorphic_downcast<ExpressionNode*>(sc->getTopNode());
    sc->popNode();
    ExpressionNode* const expr1 =
        boost::polymorphic_downcast<ExpressionNode*>(sc->getTopNode());
    sc->popNode();

    ExpressionNode* const comparisonNode = new ComparisonNode(
        expr1,
        N.tokenType,
        expr2
    );
    comparisonNode->addChild(sc->getTopNode());
    sc->popNode();

    if (N.negation)
    {
        NegationNode* const negationNode = new NegationNode(comparisonNode);
        sc->pushNode(negationNode);

        // The counting of alwaysTrueConditionals is normally handled in the
        // addComparisonNode function, but BETWEEN doesn't use that function
        // because it has three expressions instead of two
        if (negationNode->isAlwaysTrue())
        {
            ++sc->qrPtr->alwaysTrueConditionals;
        }
    }
    else
    {
        sc->pushNode(comparisonNode);

        // The counting of alwaysTrueConditionals is normally handled in the
        // addComparisonNode function, but BETWEEN doesn't use that function
        // because it has three expressions instead of two
        if (comparisonNode->isAlwaysTrue())
        {
            ++sc->qrPtr->alwaysTrueConditionals;
        }
    }

}
in_op(A) ::= IN(OP).        {A.negation = false; A.inOpType = OP->token_;}
in_op(A) ::= NOT IN(OP).    {A.negation = true; A.inOpType = OP->token_;}
expr ::= expr in_op(N) LP exprlist RP. [IN]
{
    std::stack<AstNode*> expressionListNodes;

    while (sc->isTopNodeFromCurrentDepth())
    {
        expressionListNodes.push(sc->getTopNode());
        sc->popNode();
    }
    sc->decreaseNodeDepth();

    ExpressionNode* const inValuesListNode = new InValuesListNode(
        boost::polymorphic_cast<ExpressionNode*>(sc->getTopNode())
    );
    sc->popNode();

    while (!expressionListNodes.empty())
    {
        inValuesListNode->addChild(expressionListNodes.top());
        expressionListNodes.pop();
    }

    if (N.negation)
    {
        ExpressionNode* negationNode = new NegationNode(inValuesListNode);
        sc->pushNode(negationNode);
        if (negationNode->isAlwaysTrue())
        {
            ++sc->qrPtr->alwaysTrueConditionals;
        }
    }
    else
    {
        sc->pushNode(inValuesListNode);
        if (inValuesListNode->isAlwaysTrue())
        {
            ++sc->qrPtr->alwaysTrueConditionals;
        }
    }
}
expr ::= expr in_op LP subselect RP.
expr ::= expr in_op nm dbnm. [IN]
//// MySQL ANY/SOME operators: = > < >= <= <> !=
//anyOrSome(A) ::= ANY|SOME.
//expr(A) ::= expr(X) EQ|NE(OP1) anyOrSome(OP2) LP select(Y) RP(E). [IN]
//expr(A) ::= expr(X) LT|GT|LE|GT(OP1) anyOrSome(OP2) LP select(Y) RP(E). [IN]

/* CASE expressions */
expr ::= CASE case_operand case_exprlist case_else END.
{
    sc->decreaseNodeDepth();
}
case_exprlist ::= case_exprlist WHEN expr THEN expr.
{
}
case_exprlist ::= WHEN expr THEN expr.
case_else ::=  ELSE expr.
case_else ::=  .
case_operand ::= expr.
case_operand ::= .

exprlist ::= nexprbegin nexprlist.
exprlist ::= .
{
    // Just increase the node depth so that we can decrease it later
    sc->increaseNodeDepth();
}
nexprbegin ::= .
{
    sc->increaseNodeDepth();
}
nexprlist ::= nexprlist COMMA expr.
nexprlist ::= expr.

expr ::= mysql_match.
