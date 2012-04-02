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
 * Parser for MySQL queries (excludes commands that alter the database, as those
 * should not be used by a web application anyway).
 * @author Brandon Skari
 * @date October 15 2010
 */

%parse-param { QueryRisk* const qr }
%parse-param { ParserInterface* const pi }
%lex-param { QueryRisk* const qr }
%lex-param { ParserInterface* const pi }
%glr-parser
%pure-parser

// Include this before defining the union
%code requires
{
	#include "AstNode.hpp"
}

%union
{
	AstNode* node;
	int comparisonType;
}

%start command

/* Tokens */
%token AGAINST
%token ALL
%token AND
%token AS
%token ASCENDING
%token ASTERISK
%token BEGIN_TOKEN
%token BETWEEN
%token BITWISE_AND
%token BITWISE_NEGATION
%token BITWISE_OR
%token BITWISE_XOR
%token BOOLEAN
%token BY
%token COMMA
%token COMMIT
%token CROSS
%token DOT
%token DEFAULT
%token DELAYED
%token DELETE
%token DESCENDING
%token DESCRIBE
%token DISTINCT
%token DIVIDE
%token EQUAL
%token ERROR
%token EXPANSION
%token EXPLAIN
%token FOR
%token FORCE
%token FROM
%token FULL
%token GLOBAL_VARIABLE
%token GREATER
%token GREATER_EQUAL
%token GROUP
%token HAVING
%token HIGH_PRIORITY
%token IDENTIFIER
%token IGNORE
%token IN
%token INDEX
%token INNER
%token INSERT
%token INTEGER_DIVIDE
%token INTERVAL
%token INTO
%token IS
%token JOIN
%token KEY
%token LANGUAGE
%token LEFT
%token LEFT_BIT_SHIFT
%token LEFT_PARENTHESE
%token LESS
%token LESS_EQUAL
%token LIKE
%token LIMIT
%token LOCK
%token LOW_PRIORITY
%token MATCH
%token MINUS
%token MODE
%token MODULO
%token NATURAL
%token NOT
%token NOT_EQUAL
%token NULL_TOKEN
%token NUMBER
%token ON
%token OR
%token ORDER
%token OUTER
%token OUTFILE
%token PROCEDURE
%token PLUS
%token QUERY
%token QUICK
%token QUOTED_STRING
%token REPLACE
%token RIGHT
%token RIGHT_BIT_SHIFT
%token RIGHT_PARENTHESE
%token ROLLBACK
%token SELECT
%token SEMICOLON
%token SET
%token SHARE
%token SHOW
%token SOUNDS
%token START
%token STRAIGHT
%token SQL_BIG_RESULT
%token SQL_BUFFER_RESULT
%token SQL_CACHE
%token SQL_CALC_FOUND_ROWS
%token SQL_NO_CACHE
%token SQL_SMALL_RESULT
%token TABLES
%token TRANSACTION
%token UPDATE
%token UNION
%token UNLOCK
%token USE
%token USING
%token VALUES
%token WITH
%token WHERE
%token WORK
%token XOR

/* Types */
%type <node> conditionalList2
%type <node> expression
%type <node> comparison
%type <node> conditional
%type <node> simpleExpression
%type <node> simpleIdentifier
%type <node> string
%type <node> number
%type <comparisonType> anyComparison

/* Associativity and precedence */
/* TODO I don't know if these are correct in MySQL - these are the C++ rules */
%left NOT
%left PLUS MINUS OR XOR
%left LEFT_BIT_SHIFT RIGHT_BIT_SHIFT
%left ASTERISK DIVIDE INTEGER_DIVIDE MODULO AND
%left EQUAL NOT_EQUAL
%left LESS LESS_EQUAL GREATER GREATER_EQUAL
%left BITWISE_AND
%left BITWISE_OR
%left BITWISE_XOR
%left UNARY

%{
#include "AlwaysSomethingNode.hpp"
#include "AstNode.hpp"
#include "ComparisonNode.hpp"
#include "ConditionalListNode.hpp"
#include "ConditionalNode.hpp"
#include "ExpressionNode.hpp"
#include "InSubselectNode.hpp"
#include "InValuesListNode.hpp"
#include "NegationNode.hpp"
#include "ParserInterface.hpp"
#include "QueryRisk.hpp"
class ScannerContext;

#include <stack>
#include <string>

typedef void* const yyscan_t;

/* These declarations are needed so the compiler doesn't barf */
int yylex(
    YYSTYPE* lvalp,
    QueryRisk* qr,
	ParserInterface* pi
);
void yyerror(
	QueryRisk* const qr,
	yyscan_t scanner,
	const char* const s
);
void checkIdentifierComparison(
	AstNode** const node,
	const AstNode* const expr,
	const int compareType,
	const AstNode* const field,
	QueryRisk* const qr
);
extern char* yytext;

std::stack<AstNode*> valuesList;
std::stack<bool> isValuesListStack;

const int OTHER_COMPARISON = 0;
const int LIKE_COMPARISON = 1;
const int NOT_LIKE_COMPARISON = 2;

%}

%%

command:
	command2 semicolonStar
		{
		}
	;

semicolonStar:
	SEMICOLON semicolonStar
		{
			/*
			We don't allow multiple queries, e.g.
			SELECT * FROM foo; UPDATE user SET password = '' WHERE name = 'admin';
			but MediaWiki sometimes puts multiple semicolons at the end of a
			statement, so explicitly allow that
			*/
		}
	| /* blank */
		{
		}
	;

command2:
	select
		{
			qr->queryType = QueryRisk::TYPE_SELECT;
		}
	| insert
		{
			qr->queryType = QueryRisk::TYPE_INSERT;
		}
	| update
		{
			qr->queryType = QueryRisk::TYPE_UPDATE;
		}
	| delete
		{
			qr->queryType = QueryRisk::TYPE_DELETE;
		}
	| transactionStuff
		{
			qr->queryType = QueryRisk::TYPE_TRANSACTION;
		}
	| SET
		{
			qr->queryType = QueryRisk::TYPE_SET;
			YYACCEPT;
		}
	| EXPLAIN
		{
			qr->queryType = QueryRisk::TYPE_EXPLAIN;
			YYACCEPT;
		}
	| SHOW
		{
			qr->queryType = QueryRisk::TYPE_SHOW;
			YYACCEPT;
		}
	| DESCRIBE
		{
			qr->queryType = QueryRisk::TYPE_DESCRIBE;
			YYACCEPT;
		}
	;

select:
	SELECT selectOptions selectList FROM tableList optionalIndex optionalWhere optionalGroup optionalHaving optionalOrderBy optionalLimit optionalProcedure optionalUnion optionalForUpdate
		{}
	| LEFT_PARENTHESE selectParenthese RIGHT_PARENTHESE optionalUnion
		{}
	| SELECT selectOptions selectList FROM tableList optionalIndex joins optionalWhere optionalGroup optionalHaving optionalOrderBy optionalLimit optionalProcedure optionalUnion optionalForUpdate
		{}
	| SELECT selectOptions selectList FROM optionalIndex parentheseJoins optionalWhere optionalGroup optionalHaving optionalOrderBy optionalLimit optionalProcedure optionalUnion optionalForUpdate
		{}
	| SELECT selectOptions selectList optionalOrderBy optionalLimit optionalUnion optionalForUpdate
		{}
	;

insert:
	INSERT optionalLock optionalIgnore optionalInto table insertFields
		{}
	| /* Replace commands work exactly like insert commands, except that if an
		old row already exists with a certain primary key, then that row is
		deleted first */
		REPLACE optionalLock optionalIgnore optionalInto table insertFields
		{}
	;

delete:
	DELETE optionalDeleteOptions singleMulti
		{}
	;

update:
	UPDATE optionalPriority optionalIgnore joinTables SET updateList optionalWhere optionalOrderBy optionalLimit
		{}
	;

selectOptions:
	/* empty */
		{}
	| selectOption selectOptions
		{}
	;

selectOption:
	STRAIGHT JOIN
		{}
	| LOW_PRIORITY
		{}
	| HIGH_PRIORITY
		{}
	| DISTINCT
		{}
	| SQL_SMALL_RESULT
		{}
	| SQL_BIG_RESULT
		{}
	| SQL_BUFFER_RESULT
		{}
	| SQL_CALC_FOUND_ROWS
		{}
	| SQL_NO_CACHE
		{}
	| SQL_CACHE
		{}
	| ALL
		{}
	;

selectList:
	selectItem
		{}
	| ASTERISK
		{}
	| selectItem COMMA selectList
		{}
	| ASTERISK COMMA selectList
		{}
	;

selectItem:
	tableWild
		{}
	| tableWild AS identifier
		{
			pi->scannerContext_.identifiers.pop();
		}
	| expression
		{
			delete $1;
		}
	| expression AS identifier
		{
			pi->scannerContext_.identifiers.pop();
			delete $1;
		}
	| GLOBAL_VARIABLE DOT identifier
		{
			++qr->globalVariables;
			std::stack<std::string>& identifiers = pi->scannerContext_.identifiers;
			identifiers.pop();
			identifiers.pop();
		}
	| subSelect
		{}
	| subSelect AS identifier
		{
			pi->scannerContext_.identifiers.pop();
		}
	| comparison
		{
			delete $1;
		}
	| comparison AS identifier
		{
			delete $1;
			pi->scannerContext_.identifiers.pop();
		}
	;

subSelect:
	LEFT_PARENTHESE subSelect RIGHT_PARENTHESE
		{
		}
	| subSelect2
		{
			///@TODO could subselects ever be dangerous?
			/// If so, they should be inspected here
		}
	;

subSelect2:
	SELECT expression
		{
			delete $2;
		}
	| SELECT expression FROM table
		{
			delete $2;
		}
	| SELECT expression AS identifier FROM tableList optionalWhere
		{
			pi->scannerContext_.identifiers.pop();
			delete $2;
		}
	;

tableOptionalWildList:
	tableOptionalWild
		{}
	| tableOptionalWild COMMA tableOptionalWildList
		{}
	;

tableOptionalWild:
	identifier optionalWild optionalTableAlias
		{
			pi->scannerContext_.identifiers.pop();
		}
	| identifier DOT identifier optionalWild optionalTableAlias
		{
			std::stack<std::string>& identifiers = pi->scannerContext_.identifiers;
			identifiers.pop();
			identifiers.pop();
		}
	;

optionalWild:
	/* empty */
		{}
	| DOT ASTERISK
		{}
	;

tableWild:
	identifier DOT ASTERISK
		{
			pi->scannerContext_.identifiers.pop();
		}
	| identifier DOT identifier DOT ASTERISK
		{
			std::stack<std::string>& identifiers = pi->scannerContext_.identifiers;
			identifiers.pop();
			identifiers.pop();
		}
	;

table:
	identifier
		{
			std::stack<std::string>& identifiers = pi->scannerContext_.identifiers;
			qr->checkTable(identifiers.top());
			identifiers.pop();
		}
	| identifier DOT identifier
		{
			std::stack<std::string>& identifiers = pi->scannerContext_.identifiers;
			// It's a stack, so check in reverse order
			qr->checkTable(identifiers.top());
			identifiers.pop();
			qr->checkDatabase(identifiers.top());
			identifiers.pop();
		}
	| identifier DOT ASTERISK
		{
			pi->scannerContext_.identifiers.pop();
		}
	| DOT identifier
		{
			pi->scannerContext_.identifiers.pop();
		}
	| /* aliased */
		identifier identifier
		{
			std::stack<std::string>& identifiers = pi->scannerContext_.identifiers;
			identifiers.pop();
			qr->checkTable(identifiers.top());
			identifiers.pop();
		}
	;

optionalTableAlias:
	/* empty */
		{}
	| AS identifier
		{
			pi->scannerContext_.identifiers.pop();
		}
	| EQUAL identifier
		{
			pi->scannerContext_.identifiers.pop();
		}
	;

simpleIdentifier:
	identifier
		{
			std::stack<std::string>& identifiers = pi->scannerContext_.identifiers;
			$$ = new ExpressionNode(identifiers.top(), true);
			identifiers.pop();
		}
	| identifier DOT identifier
		{
			std::stack<std::string>& identifiers = pi->scannerContext_.identifiers;
			const std::string field(identifiers.top());
			identifiers.pop();
			const std::string fullIdentifier(identifiers.top() + "." + field);
			identifiers.pop();
			$$ = new ExpressionNode(fullIdentifier, true);
		}
	| DOT identifier DOT identifier
		{
			std::stack<std::string>& identifiers = pi->scannerContext_.identifiers;
			const std::string field(identifiers.top());
			identifiers.pop();
			const std::string fullIdentifier(identifiers.top() + "." + field);
			identifiers.pop();
			$$ = new ExpressionNode(fullIdentifier, true);
		}
	| identifier DOT identifier DOT identifier
		{
			std::stack<std::string>& identifiers = pi->scannerContext_.identifiers;
			const std::string field(identifiers.top());
			identifiers.pop();
			const std::string table(identifiers.top());
			identifiers.pop();
			const std::string fullIdentifier(
				identifiers.top() + "." + table + "." + field);
			identifiers.pop();
			$$ = new ExpressionNode(fullIdentifier, true);
		}
	;

identifier:
	/* So, MySQL isn't context free, so certain keywords can be used as
		identifiers - hence this separate portion in Bison */
	IDENTIFIER
		{
		}
	| LANGUAGE
		{
			pi->scannerContext_.identifiers.push("language");
		}
	| QUERY
		{
			pi->scannerContext_.identifiers.push("query");
		}
	| TABLES
		{
			pi->scannerContext_.identifiers.push("tables");
		}
	;

optionalProcedure:
	/* empty */
		{}
	| PROCEDURE
		{}
	;

conditionalList:
	conditionalList2
		{
			if (NULL == $1)
			{
				qr->valid = false;
			}
			else
			{
				const ConditionalNode* const list =
					dynamic_cast<const ConditionalNode*>($1);
				assert(NULL != list &&
					"Bison expected a ConditionalNode* to be returned for conditionalList2");
				qr->alwaysTrue = list->isAlwaysTrue();
				qr->alwaysTrueConditional = list->anyIsAlwaysTrue();
				qr->emptyPassword = list->emptyPassword();
				delete list;
			}
		}
	;

conditionalList2:
	conditional
		{
			$$ = $1;
		}
	| conditionalList2 AND conditionalList2
		{
			$$ = new ConditionalListNode('&');
			$$->addChild($1);
			$$->addChild($3);
		}
	| conditionalList2 OR conditionalList2
		{
			++qr->orStatements;
			$$ = new ConditionalListNode('|');
			$$->addChild($1);
			$$->addChild($3);
		}
	| conditionalList2 XOR conditionalList2
		{
			$$ = new ConditionalListNode('^');
			$$->addChild($1);
			$$->addChild($3);
		}
	| LEFT_PARENTHESE conditionalList2 RIGHT_PARENTHESE
		{
			$$ = $2;
		}
	;

conditional:
	comparison
		{
			$$ = $1;
		}
	| expression IN inValuesList
		{
			const ExpressionNode* const expr =
				dynamic_cast<const ExpressionNode*>($1);
			assert(NULL != expr);
			// The value from inValuesList is true if it was a regular list,
			// and false if it was a subselect
			bool isValuesList = isValuesListStack.top();
			isValuesListStack.pop();
			if (isValuesList)
			{
				$$ = new InValuesListNode(true, expr);
				
				while (!valuesList.empty())
				{
					$$->addChild(valuesList.top());
					valuesList.pop();
				}
			}
			else // Subselect
			{
				$$ = new InSubselectNode(expr);
			}
		}
	| expression NOT IN inValuesList
		{
			const ExpressionNode* const expr =
				dynamic_cast<const ExpressionNode*>($1);
			assert(NULL != expr);
			$$ = new InValuesListNode(false, expr);
			while (!valuesList.empty())
			{
				$$->addChild(valuesList.top());
				valuesList.pop();
			}
		}
	| expression BETWEEN expression AND expression
		{
			// Between expects the lower expression to be first
			// If it's not, then MySQL just returns false
			$$ = new ConditionalListNode('&');
			
			ComparisonNode* const first = new ComparisonNode(">=");
			first->addChild($1);
			first->addChild($3);
			
			ComparisonNode* const second = new ComparisonNode("<=");
			second->addChild($1);
			second->addChild($5);
			
			$$->addChild(first);
			$$->addChild(second);
		}
	| MATCH LEFT_PARENTHESE tableList RIGHT_PARENTHESE AGAINST LEFT_PARENTHESE expression optionalMatchModifier RIGHT_PARENTHESE
		{
			/// @TODO figure out if I need to do something here
			/// In the meantime, just simulate that it's not always true
			$$ = new AlwaysSomethingNode(false, "=");
			$$->addChild($7);
			// Comparison Nodes are always required to have 2 children, so for
			// now, until I fix this to be something better, just simulate it
			// so it doesn't crash elsewhere
			$$->addChild(new ExpressionNode("NULL", false));
		}
	| /* Because 'WHERE 1' is a valid conditional */
		expression
		{
			$$ = $1;
		}
	;

expressionList:
	expression
		{
			delete $1;
		}
	| expression COMMA expressionList
		{
			delete $1;
		}
	;

expression:
	simpleExpression
		{
			$$ = $1;
		}
	| LEFT_PARENTHESE expression RIGHT_PARENTHESE
		{
			$$ = $2;
		}
	| /* All these operators need to be done inline so that Bison can handle
		the precedence of all the operators */
	expression PLUS expression 
		{
			$$ = new ExpressionNode();
			$$->addChild($1);
			$$->addChild(new AstNode("+"));
			$$->addChild($3);
		}
	| expression MINUS expression
		{
			$$ = new ExpressionNode();
			$$->addChild($1);
			$$->addChild(new AstNode("-"));
			$$->addChild($3);
		}
	| expression ASTERISK expression
		{
			$$ = new ExpressionNode();
			$$->addChild($1);
			$$->addChild(new AstNode("*"));
			$$->addChild($3);
		}
	| expression DIVIDE expression
		{
			$$ = new ExpressionNode();
			$$->addChild($1);
			$$->addChild(new AstNode("/"));
			$$->addChild($3);
		}
	| expression INTEGER_DIVIDE expression
		{
			$$ = new ExpressionNode();
			$$->addChild($1);
			$$->addChild(new AstNode("DIV"));
			$$->addChild($3);
		}
	| expression MODULO expression
		{
			$$ = new ExpressionNode();
			$$->addChild($1);
			$$->addChild(new AstNode("MOD"));
			$$->addChild($3);
		}
	| expression BITWISE_AND expression
		{
			$$ = new ExpressionNode();
			$$->addChild($1);
			$$->addChild(new AstNode("&"));
			$$->addChild($3);
		}
	| expression BITWISE_OR expression
		{
			$$ = new ExpressionNode();
			$$->addChild($1);
			$$->addChild(new AstNode("|"));
			$$->addChild($3);
		}
	| expression BITWISE_XOR expression
		{
			$$ = new ExpressionNode();
			$$->addChild($1);
			$$->addChild(new AstNode("^"));
			$$->addChild($3);
		}
	| expression LEFT_BIT_SHIFT expression
		{
			$$ = new ExpressionNode();
			$$->addChild($1);
			$$->addChild(new AstNode("<<"));
			$$->addChild($3);
		}
	| expression RIGHT_BIT_SHIFT expression
		{
			$$ = new ExpressionNode();
			$$->addChild($1);
			$$->addChild(new AstNode(">>"));
			$$->addChild($3);
		}
	| NOT expression
		{
			$$ = new NegationNode();
			$$->addChild($2);
		}
	;

simpleExpression:
	string
		{
			$$ = $1;
		}
	| number
		{
			$$ = $1;
		}
	| /* function */
		identifier LEFT_PARENTHESE optionalDistinct expressionList RIGHT_PARENTHESE
		{
			std::stack<std::string>& identifiers = pi->scannerContext_.identifiers;
			/// @TODO I should probably handle a bunch of possible functions here
			/// Like, IF (1, 1, 0) should always be true
			$$ = new ExpressionNode(" ", false);
			qr->checkFunction(identifiers.top());
			identifiers.pop();
		}
	| /* function, such as VERSION() */
		identifier LEFT_PARENTHESE RIGHT_PARENTHESE
		{
			std::stack<std::string>& identifiers = pi->scannerContext_.identifiers;
			/// @TODO I should probably handle a bunch of possible functions here
			/// Like, IF (1, 1, 0) should always be true
			$$ = new ExpressionNode(" ", false);
			qr->checkFunction(identifiers.top());
			identifiers.pop();
		}
	| /* function, such as COUNT(*) */
		identifier LEFT_PARENTHESE ASTERISK RIGHT_PARENTHESE
		{
			std::stack<std::string>& identifiers = pi->scannerContext_.identifiers;
			/// @TODO I should probably handle a bunch of possible functions here
			/// Like, IF (1, 1, 0) should always be true
			$$ = new ExpressionNode(" ", false);
			qr->checkFunction(identifiers.top());
			identifiers.pop();
		}
	| /* there is an INSERT function for inserting into strings */
		INSERT LEFT_PARENTHESE expression COMMA number COMMA number COMMA expression RIGHT_PARENTHESE
		{
			delete $3;
			delete $5;
			delete $9;
			$$ = NULL;
		}
	| GLOBAL_VARIABLE
		{
			std::stack<std::string>& identifiers = pi->scannerContext_.identifiers;
			++qr->globalVariables;
			$$ = new ExpressionNode(identifiers.top(), false);
			identifiers.pop();
		}
	| /* MySQL has some weird date things, like "INTERVAL 30 DAY" or "INTERVAL 120 MINUTE" */
		INTERVAL number IDENTIFIER
		{
			delete $2;
			$$ = NULL;
			pi->scannerContext_.identifiers.pop();
		}
	| simpleIdentifier
		{
			$$ = $1;
		}
	;

optionalDistinct:
	/* empty */
		{}
	| DISTINCT
		{}
	;

number:
	NUMBER
		{
			std::stack<std::string>& numbers = pi->scannerContext_.numbers;
			$$ = new ExpressionNode(numbers.top(), false);
			numbers.pop();
		}
	| PLUS %prec UNARY NUMBER
		{
			std::stack<std::string>& numbers = pi->scannerContext_.numbers;
			$$ = new ExpressionNode(numbers.top(), false);
			numbers.pop();
		}
	| MINUS %prec UNARY NUMBER
		{
			std::stack<std::string>& numbers = pi->scannerContext_.numbers;
			$$ = new ExpressionNode("-" + numbers.top(), false);
			numbers.pop();
		}
	| BITWISE_NEGATION %prec UNARY NUMBER
		{
			std::stack<std::string>& numbers = pi->scannerContext_.numbers;
			$$ = new ExpressionNode("~" + numbers.top(), false);
			numbers.pop();
		}
	;

comparison:
	expression LESS expression
		{
			$$ = new ComparisonNode("<");
			$$->addChild($1);
			$$->addChild($3);
		}
	| expression GREATER expression
		{
			$$ = new ComparisonNode(">");
			$$->addChild($1);
			$$->addChild($3);
		}
	| expression LESS_EQUAL expression
		{
			$$ = new ComparisonNode("<=");
			$$->addChild($1);
			$$->addChild($3);
		}
	| expression GREATER_EQUAL expression
		{
			$$ = new ComparisonNode(">=");
			$$->addChild($1);
			$$->addChild($3);
		}
	| expression EQUAL expression
		{
			$$ = new ComparisonNode("=");
			$$->addChild($1);
			$$->addChild($3);
		}
	| expression NOT_EQUAL expression
		{
			$$ = new ComparisonNode("!=");
			$$->addChild($1);
			$$->addChild($3);
		}
	| expression LIKE expression
		{
			$$ = new ComparisonNode("like");
			$$->addChild($1);
			$$->addChild($3);
			
			const ExpressionNode* const expr = 
				dynamic_cast<const ExpressionNode*>($3);
			assert(NULL != expr &&
				"Expected ExpressionNode in LIKE statement");
			qr->checkRegex(expr->getValue());
		}
	| expression NOT LIKE expression
		{
			$$ = new ComparisonNode("not like");
			$$->addChild($1);
			$$->addChild($4);
			
			const ExpressionNode* const expr = 
				dynamic_cast<const ExpressionNode*>($4);
			assert(NULL != expr &&
				"Expected ExpressionNode in LIKE statement");
			qr->checkRegex(expr->getValue());
		}
	| expression SOUNDS LIKE expression
		{
			$$ = new ComparisonNode("sounds like");
			$$->addChild($1);
			$$->addChild($4);
		}
	| expression IS NULL_TOKEN
		{
			$$ = new AlwaysSomethingNode(false, "=");
			$$->addChild($1);
			$$->addChild(new ExpressionNode("NULL", false));
		}
	| expression EQUAL NULL_TOKEN
		{
			$$ = new AlwaysSomethingNode(false, "=");
			$$->addChild($1);
			$$->addChild(new ExpressionNode("NULL", false));
		}
	| expression IS NOT NULL_TOKEN
		{
			$$ = new AlwaysSomethingNode(false, "!=");
			$$->addChild($1);
			$$->addChild(new ExpressionNode("NULL", false));
		}
	;

anyComparison:
	LESS
		{
			$$ = OTHER_COMPARISON;
		}
	| GREATER
		{
			$$ = OTHER_COMPARISON;
		}
	| LESS_EQUAL
		{
			$$ = OTHER_COMPARISON;
		}
	| GREATER_EQUAL
		{
			$$ = OTHER_COMPARISON;
		}
	| EQUAL
		{
			$$ = OTHER_COMPARISON;
		}
	| NOT_EQUAL
		{
			$$ = OTHER_COMPARISON;
		}
	| LIKE
		{
			$$ = LIKE_COMPARISON;
		}
	| NOT LIKE
		{
			$$ = NOT_LIKE_COMPARISON;
		}
	| SOUNDS LIKE
		{
			$$ = OTHER_COMPARISON;
		}
	;

tableList:
	table
		{}
	| table AS identifier
		{
			pi->scannerContext_.identifiers.pop();
		}
	| table COMMA tableList
		{}
	| table AS identifier COMMA tableList
		{
			pi->scannerContext_.identifiers.pop();
		}
	| LEFT_PARENTHESE select RIGHT_PARENTHESE
		{
			// @TODO fill this in!
		}
	;

joins:
	parentheseJoins
		{}
	| normalJoin table ON joinConditional joins
		{}
	| normalJoin table ON joinConditional
		{}
	| normalJoin table AS identifier ON joinConditional joins
		{
			pi->scannerContext_.identifiers.pop();
		}
	| normalJoin table AS identifier ON joinConditional
		{
			pi->scannerContext_.identifiers.pop();
		}
	| /* Cross joins don't have any join conditionals */ 
		CROSS JOIN table
		{
			++qr->joinStatements;
			++qr->crossJoinStatements;
		}
	| CROSS JOIN table joins
		{
			++qr->joinStatements;
			++qr->crossJoinStatements;
		}
	| CROSS JOIN table AS identifier
		{
			++qr->joinStatements;
			++qr->crossJoinStatements;
		}
	| CROSS JOIN table AS identifier joins
		{
			++qr->joinStatements;
			++qr->crossJoinStatements;
		}
	;

parentheseJoins:
	LEFT_PARENTHESE parentheseJoins normalJoin table ON joinConditional RIGHT_PARENTHESE
		{}
	| LEFT_PARENTHESE table normalJoin table ON joinConditional RIGHT_PARENTHESE
		{}
	| LEFT_PARENTHESE parentheseJoins RIGHT_PARENTHESE
		{}
	;

joinConditional:
	joinConditional AND joinConditional
		{}
	| joinConditional OR joinConditional
		{}
	| joinConditional XOR joinConditional
		{}
	| expression anyComparison expression
		{
			delete $1;
			delete $3;
		}
	| expression IN inValuesList
		{
			delete $1;
		}
	| expression NOT IN inValuesList
		{
			delete $1;
		}
	| LEFT_PARENTHESE joinConditional RIGHT_PARENTHESE
		{}
	;

insertFields:
	insertValues
		{}
	| LEFT_PARENTHESE fields RIGHT_PARENTHESE insertValues
		{}
	;

fields:
	simpleIdentifier
		{
			delete $1;
		}
	| tableWild
		{}
	| simpleIdentifier COMMA fields
		{
			delete $1;
		}
	| tableWild COMMA fields
		{}
	;

insertValues:
	VALUES valuesList
		{}
	| createSelect optionalUnion
		{}
	| LEFT_PARENTHESE createSelect RIGHT_PARENTHESE optionalUnion
		{}
	;

valuesList:
	LEFT_PARENTHESE optionalValues RIGHT_PARENTHESE
		{}
	| LEFT_PARENTHESE optionalValues RIGHT_PARENTHESE COMMA valuesList
		{}
	;

inValuesList:
	LEFT_PARENTHESE inOptionalValues RIGHT_PARENTHESE
		{
			// Save true to tell the caller that it was a values list (The
			// list values are stored in a vector that the caller will handle).
			isValuesListStack.push(true);
		}
	| LEFT_PARENTHESE select RIGHT_PARENTHESE
		{
			// Save false to tell the caller that it was a subselect
			isValuesListStack.push(false);
		}
	;

optionalValues:
	/* empty */
		{}
	| values
		{}
	;

inOptionalValues:
	/* empty */
		{}
	| inValues
		{}
	;

values:
	expression
		{
			delete $1;
		}
	| DEFAULT
		{}
	| NULL_TOKEN
		{}
	| expression COMMA values
		{
			delete $1;
		}
	| DEFAULT COMMA values
		{}
	| NULL_TOKEN COMMA values
		{}
	;

inValues:
	expression
		{
			valuesList.push($1);
		}
	| expression COMMA inValues
		{
			valuesList.push($1);
		}
	;

createSelect:
	SELECT selectOptions selectList optionalFrom
		{}
	;

optionalWhere:
	/* empty */
		{}
	| WHERE conditionalList
		{}
	;

optionalIndex:
	/* empty */
		{}
	| USE indexOrKey LEFT_PARENTHESE indexList
		{}
	| IGNORE indexOrKey LEFT_PARENTHESE indexList
		{}
	| FORCE indexOrKey LEFT_PARENTHESE indexList
		{}
	;

indexOrKey:
	INDEX
		{}
	| KEY
		{}
	;

optionalMatchModifier:
	IN BOOLEAN MODE
		{}
	| IN NATURAL LANGUAGE MODE
		{}
	| IN NATURAL LANGUAGE MODE WITH QUERY EXPANSION
		{}
	| WITH QUERY EXPANSION
		{}
	;

indexList:
	identifier RIGHT_PARENTHESE
		{
			pi->scannerContext_.identifiers.pop();
		}
	| identifier COMMA indexList
		{
			pi->scannerContext_.identifiers.pop();
		}
	;

optionalLimit:
	/* empty */
		{}
	| LIMIT NUMBER
		{
			pi->scannerContext_.numbers.pop();
		}
	| LIMIT NUMBER COMMA NUMBER
		{
			std::stack<std::string>& numbers = pi->scannerContext_.numbers;
			numbers.pop();
			numbers.pop();
		}
	;

optionalGroup:
	/* empty */
		{}
	| GROUP BY groupList
		{}
	;

optionalFrom:
	optionalLimit
		{}
	| FROM joinTables optionalWhere optionalGroup optionalHaving optionalOrderBy optionalLimit optionalProcedure
		{}
	;

optionalForUpdate:
	/* empty */
		{}
	| FOR UPDATE
		{}
	;

groupList:
	expression ascendingOrDescending
		{
			delete $1;
		}
	| expression ascendingOrDescending COMMA groupList
		{
			delete $1;
		}
	;

ascendingOrDescending:
	/* empty */
		{}
	| ASCENDING
		{}
	| DESCENDING
		{}
	;

selectParenthese:
	SELECT selectOptions selectList selectInto optionalSelectLockType
		{}
	;

selectInto:
	optionalOrderBy optionalLimit
		{}
	| INTO OUTFILE string
		{}
	;

string:
	QUOTED_STRING
		{
			std::stack<std::string>& quotedStrings = pi->scannerContext_.quotedStrings;
			$$ = new ExpressionNode(quotedStrings.top(), false);
			quotedStrings.pop();
		}
	| /* MySQL lets you append strings without using any kind of operator */
	  /* Seriously... so 'a string' is the same as 'a ' 'str' 'ing' */
		QUOTED_STRING string
		{
			std::stack<std::string>& quotedStrings = pi->scannerContext_.quotedStrings;
			const ExpressionNode* const expr =
				dynamic_cast<const ExpressionNode*>($2);
			assert(NULL != expr);
			$$ = new ExpressionNode(
				quotedStrings.top() + expr->getValue(), false);
			delete $2;
			quotedStrings.pop();
			
			++qr->mySqlStringConcat;
		}
	;

optionalSelectLockType:
	/* empty */
		{}
	| FOR UPDATE
		{}
	| LOCK IN SHARE MODE
		{}
	;

optionalDeleteOptions:
	/* empty */
		{}
	| QUICK optionalDeleteOptions
		{}
	| LOW_PRIORITY optionalDeleteOptions
		{}
	| IGNORE optionalDeleteOptions
		{}
	;

optionalPriority:
	/* empty */
		{}
	| LOW_PRIORITY
		{}
	;

optionalInto:
	/* empty */
		{}
	| INTO
		{}
	;

optionalOrderBy:
	/* empty */
		{}
	| ORDER BY orderByGroupList
		{
			// orderByGroupList will check if it's ordered by a number
		}
	;

orderByGroupList:
	expression ascendingOrDescending
		{
			const ExpressionNode* const expr =
				dynamic_cast<const ExpressionNode*>($1);
			assert(NULL != expr &&
				"ExpressionNode expected in orderByGroupList");
			qr->orderByNumber = expr->isNumber();
			delete expr;
		}
	| expression ascendingOrDescending COMMA groupList
		{
			const ExpressionNode* const expr =
				dynamic_cast<const ExpressionNode*>($1);
			assert(NULL != expr &&
				"ExpressionNode expected in orderByGroupList");
			qr->orderByNumber = expr->isNumber();
			delete expr;
		}
	;

joinTables:
	identifier
		{
			std::stack<std::string>& identifiers = pi->scannerContext_.identifiers;
			qr->checkTable(identifiers.top());
			identifiers.pop();
		}
	| identifier ON expression
		{
			std::stack<std::string>& identifiers = pi->scannerContext_.identifiers;
			qr->checkTable(identifiers.top());
			identifiers.pop();
			delete $3;
		}
	| identifier USING LEFT_PARENTHESE usingList RIGHT_PARENTHESE
		{
			std::stack<std::string>& identifiers = pi->scannerContext_.identifiers;
			qr->checkTable(identifiers.top());
			identifiers.pop();
		}
	| identifier COMMA joinTables
		{
			std::stack<std::string>& identifiers = pi->scannerContext_.identifiers;
			qr->checkTable(identifiers.top());
			identifiers.pop();
		}
	| identifier normalJoin joinTables
		{
			std::stack<std::string>& identifiers = pi->scannerContext_.identifiers;
			qr->checkTable(identifiers.top());
			identifiers.pop();
		}
	;

normalJoin:
	JOIN
		{
			++qr->joinStatements;
		}
	| INNER JOIN
		{
			++qr->joinStatements;
		}
	| LEFT JOIN
		{
			++qr->joinStatements;
		}
	| RIGHT JOIN
		{
			++qr->joinStatements;
		}
	| OUTER JOIN
		{
			++qr->joinStatements;
		}
	| LEFT OUTER JOIN
		{
			++qr->joinStatements;
		}
	| RIGHT OUTER JOIN
		{
			++qr->joinStatements;
		}
	| FULL OUTER JOIN
		{
			++qr->joinStatements;
		}
	;

optionalLock:
	/* empty */
		{}
	| LOW_PRIORITY
		{}
	| DELAYED
		{}
	| HIGH_PRIORITY
		{}
	;

optionalHaving:
	/* empty */
		{}
	| HAVING conditional
		{
			delete $2;
		}
	;

usingList:
	identifier
		{
			std::stack<std::string>& identifiers = pi->scannerContext_.identifiers;
			qr->checkTable(identifiers.top());
			identifiers.pop();
		}
	| identifier COMMA usingList
		{
			std::stack<std::string>& identifiers = pi->scannerContext_.identifiers;
			qr->checkTable(identifiers.top());
			identifiers.pop();
		}
	;

optionalIgnore:
	/* empty */
		{}
	| IGNORE
		{}
	;

optionalUnion:
	/* empty */
		{}
	| UNION optionalUnionOption select
		{
			/* Let optionalUnionOption handle incrementing union count*/
		}
	;

optionalUnionOption:
	/* empty */
		{
			++qr->unionStatements;
		}
	| DISTINCT
		{}
	| ALL
		{
			++qr->unionAllStatements;
		}
	;

singleMulti:
	FROM table optionalWhere optionalOrderBy optionalLimit
		{}
	| tableOptionalWildList FROM joinTables optionalWhere
		{}
	| FROM tableOptionalWildList USING joinTables optionalWhere
		{}
	;

updateList:
	updateElement
		{}
	| updateElement COMMA updateList
		{}
	;

updateElement:
	simpleIdentifier EQUAL expression
		{
			delete $1;
			delete $3;
		}
	| simpleIdentifier EQUAL DEFAULT
		{
			delete $1;
		}
	| simpleIdentifier EQUAL NULL_TOKEN
		{
			delete $1;
		}
	;

transactionStuff:
	BEGIN_TOKEN
		{}
	| BEGIN_TOKEN WORK
		{}
	| START TRANSACTION
		{}
	| ROLLBACK
		{}
	| COMMIT
		{}
	| UNLOCK TABLES
		{}
	;

%%
	void yyerror(QueryRisk* const qr, yyscan_t, const char* const)
	{
		qr->valid = false;
	}

	/**
	 * Checks the identifier comparisons for bad things.
	 */
	void checkIdentifierComparison(
		AstNode** const node,
		const AstNode* const expr,
		const int compareType,
		const AstNode* const field,
		QueryRisk* const qr
	)
	{
		// Normally comparing things from a table to an expression
		// won't always be true - but, if they use "LIKE '%' " or
		// "LIKE '_%' or "NOT LIKE 23482493" then we have a problem
		
		assert(NULL != dynamic_cast<const ExpressionNode*>(expr));
		
		// If using the like flag
		if (LIKE_COMPARISON == compareType || NOT_LIKE_COMPARISON == compareType)
		{
			const bool like = (LIKE_COMPARISON == compareType);
			
			bool specialChars = false;
			bool nonSpecialChars = false;
			// Make sure there are some special and non-special characters
			const ExpressionNode* const exprNode = 
				dynamic_cast<const ExpressionNode*>(expr);
			assert(NULL != exprNode
				&& "Expected ExpressionNode in LIKE statement");
			const std::string exprValue(exprNode->getValue());
			for (size_t i = 0; i < exprValue.length(); ++i)
			{
				if ('_' != exprValue.at(i) && '%' != exprValue.at(i))
				{
					nonSpecialChars = true;
				}
				else
				{
					specialChars = true;
				}
			}
			
			// Empty expressions are only dangerous if used with NOT LIKE
			if (exprValue.empty())
			{
				if (!like)
				{
					*node = new AlwaysSomethingNode(true, "not like");
				}
				else
				{
					*node = new AlwaysSomethingNode(false, "like");
				}
			}
			// Like with only special characters is bad: LIKE '%'
			// Not like without special characters is bad: NOT LIKE 'a'
			else if ((like && !nonSpecialChars) ||
				(!like && !specialChars))
			{
				if (like)
				{
					*node = new AlwaysSomethingNode(true, "like");
				}
				else
				{
					*node = new AlwaysSomethingNode(true, "not like");
				}
			}
			else
			{
				if (like)
				{
					*node = new AlwaysSomethingNode(false, "like");
				}
				else
				{
					*node = new AlwaysSomethingNode(false, "not like");
				}
			}
			
			// Check to make sure that the regex is ok
			qr->checkRegex(exprNode->getValue());
		}
		// It's not a like statement, so it should be ok
		else
		{
			*node = new AlwaysSomethingNode(false, "=");
		}
		
		// Add the two expressions so we can check for empty passwords
		(*node)->addChild(field);
		(*node)->addChild(expr);
	}
