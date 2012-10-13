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
 * Parser for MySQL queries.
 * @author Brandon Skari
 * @date November 11 2010
 */

%{
    #define YY_DECL int sql_lex( \
        ScannerContext* const context, \
        yyscan_t yyscanner \
    )

    #include "AstNode.hpp"
    #include "Logger.hpp"
    // Include file produced by Lemon
    #include "sqlParser.h"
    #define ERROR_TOKEN -1
    #include "QueryRisk.hpp"
    #include "ScannerContext.hpp"

    #include <cassert>
    #include <string>

    static int hexToNum(const char c)
    {
        if (c >= '0' && c <= '9')
        {
            return c - '0';
        }
        else if (c >= 'a' && c <= 'z')
        {
            return c - 'a';
        }
        else if (c >= 'A' && c <= 'Z')
        {
            return c - 'A';
        }
        else
        {
            Logger::log(Logger::ERROR) << "Bad hex digit (" << c << ") provided by scanner";
            assert(false);
            return 0;
        }
    }

    /**
     * If the type of the QueryRisk hasn't been set yet (i.e. it's still set
     * to TYPE_UNKNOWN), then set it to the passed in type.
     */
    static void maybeSetType(
        QueryRisk* const qr,
        const QueryRisk::QueryType type
    )
    {
        if (QueryRisk::TYPE_UNKNOWN == qr->queryType)
        {
            qr->queryType = type;
        }
    }
%}

%option prefix="sql_"
%option reentrant

%x MULTI_LINE_COMMENT
%x SINGLE_LINE_COMMENT
%x QUOTED
%x DOUBLE_QUOTED

WHITE_SPACE [ \t\n\r\v\f]
WORD_BOUNDARY [^A-Za-z]

ID  ([a-zA-Z_][a-zA-Z0-9_]*)|("{"[a-zA-Z_][a-zA-Z0-9_]*"}")
QUOTED_IDENTIFIER    "`"[a-zA-Z_][a-zA-Z0-9_]*"`"
INTEGER     [0-9]+
FLOAT       ([0-9]*"."[0-9]+)|([0-9]+"."[0-9]*)
GLOBAL_VARIABLE     "@@"{ID}
VARIABLE            "@"{ID}

HEX_NUMBER  0(x|X)[0-9A-Fa-f]+

 /* Conditionals that are suspicious if they're find in a comment */
CONDITIONAL    ("AND"|"OR"|"XOR"|"WHERE")

%%
 /* Multi-line comments */
"/*!"[0-9]{5} {
    BEGIN(MULTI_LINE_COMMENT);
    ++context->qrPtr->mySqlVersionedComments;
}
"/*!"[0-9]{5}{CONDITIONAL}{WORD_BOUNDARY} {
    BEGIN(MULTI_LINE_COMMENT);
    ++context->qrPtr->mySqlVersionedComments;
    ++context->qrPtr->commentedConditionals;
}
"/*!" {
    BEGIN(MULTI_LINE_COMMENT);
    ++context->qrPtr->mySqlComments;
}
"/*!"{CONDITIONAL}{WORD_BOUNDARY} {
    BEGIN(MULTI_LINE_COMMENT);
    ++context->qrPtr->mySqlComments;
    ++context->qrPtr->commentedConditionals;
}
"/*'" {
    BEGIN(MULTI_LINE_COMMENT);
    ++context->qrPtr->mySqlComments;
    ++context->qrPtr->commentedQuotes;
}
"/*"[^!'] {
    BEGIN(MULTI_LINE_COMMENT);
    ++context->qrPtr->multiLineComments;
}
"/*"[^!]{CONDITIONAL}{WORD_BOUNDARY} {
    BEGIN(MULTI_LINE_COMMENT);
    ++context->qrPtr->multiLineComments;
    ++context->qrPtr->commentedConditionals;
}
"/*"{CONDITIONAL}{WORD_BOUNDARY} {
    BEGIN(MULTI_LINE_COMMENT);
    ++context->qrPtr->multiLineComments;
    ++context->qrPtr->commentedConditionals;
}
"/*!*/"     {++context->qrPtr->mySqlComments;}
"/**/"      {++context->qrPtr->multiLineComments;}
<MULTI_LINE_COMMENT>"*"+[^*/]   {}
<MULTI_LINE_COMMENT>"*"         {}
<MULTI_LINE_COMMENT>[^*']       {}
<MULTI_LINE_COMMENT>"*/"        {BEGIN(INITIAL);}
<MULTI_LINE_COMMENT><<EOF>> {
    BEGIN(INITIAL);
    context->qrPtr->valid =false;
}

 /* Single line comments */
"--"{WHITE_SPACE} {
    BEGIN(SINGLE_LINE_COMMENT);
    ++context->qrPtr->dashDashComments;
}
"--"{WHITE_SPACE}{CONDITIONAL}{WORD_BOUNDARY} {
    BEGIN(SINGLE_LINE_COMMENT);
    ++context->qrPtr->dashDashComments;
    ++context->qrPtr->commentedConditionals;
}
"#" {
    BEGIN(SINGLE_LINE_COMMENT);
    ++context->qrPtr->hashComments;
}
"#"{CONDITIONAL}{WORD_BOUNDARY} {
    BEGIN(SINGLE_LINE_COMMENT);
    ++context->qrPtr->hashComments;
    ++context->qrPtr->commentedConditionals;
}
<SINGLE_LINE_COMMENT>[^\n']   {}
<SINGLE_LINE_COMMENT>[\n]     {BEGIN(INITIAL);}
<SINGLE_LINE_COMMENT><<EOF>>  {BEGIN(INITIAL);}


 /* Rules in any comment state */
<MULTI_LINE_COMMENT,SINGLE_LINE_COMMENT>"'" {++context->qrPtr->commentedQuotes;}
<MULTI_LINE_COMMENT,SINGLE_LINE_COMMENT>{WORD_BOUNDARY}{CONDITIONAL}{WORD_BOUNDARY} {
    ++context->qrPtr->commentedConditionals;
}

{WHITE_SPACE}        {}

"'"             {context->quotedString = ""; BEGIN(QUOTED);}
<QUOTED>[^'\\]+ {context->quotedString += yytext;}
<QUOTED>"\\\\"  {context->quotedString += '\\';}
<QUOTED>"\\'"   {context->quotedString += '\'';}
<QUOTED>"\\".   {context->quotedString += yytext;}
<QUOTED>"'"+    {
            /* If we matched an odd number of quotes, then it's
            the terminating quote */
            if (yyleng % 2)
            {
                BEGIN(INITIAL);
                return STRING;
            }
            else
            {
                // Skip the escaping quote
                context->quotedString += (yytext + 1);
            }
}
<QUOTED><<EOF>>     {context->qrPtr->valid = false; BEGIN(INITIAL);}

{HEX_NUMBER}    {
    // The determination of whether this is a hex string or not (and then to
    // update the query risk accordingly) will have to be done in the parser,
    // because hex integers can be used in certain contexts.
    return HEX_NUMBER;
}

 /* Double quoted strings don't count as string literals in strict ANSI SQL;
 they count as identifiers. MySQL defaults to using them as strings unless
 you enable ANSI_QUOTES, but I'm just going to assume the latter and let the
 user deal with it. */
\"        {context->quotedString = ""; BEGIN(DOUBLE_QUOTED);}
<DOUBLE_QUOTED>[^\"]+    {context->quotedString += yytext;}
<DOUBLE_QUOTED>["]    {
                BEGIN(INITIAL);
                return STRING;
}
<DOUBLE_QUOTED><<EOF>>    {context->qrPtr->valid = false; BEGIN(INITIAL);}


 /* Normally, the parser would set these types, but if the query is invalid,
    the rules that set these won't have a chance to run. */
"select"    {maybeSetType(context->qrPtr, QueryRisk::TYPE_SELECT); return SELECT;}
"insert"    {maybeSetType(context->qrPtr, QueryRisk::TYPE_INSERT); return INSERT;}
"update"    {maybeSetType(context->qrPtr, QueryRisk::TYPE_UPDATE); return UPDATE;}
"replace"   {maybeSetType(context->qrPtr, QueryRisk::TYPE_UPDATE); return REPLACE;}
"delete"    {maybeSetType(context->qrPtr, QueryRisk::TYPE_DELETE); return DELETE;}
"explain"   {maybeSetType(context->qrPtr, QueryRisk::TYPE_EXPLAIN); return EXPLAIN;}
"extended"  {return EXTENDED;}

"begin"         {maybeSetType(context->qrPtr, QueryRisk::TYPE_TRANSACTION); return BEGIN_KW;}
"work"          {return WORK;}
"commit"        {maybeSetType(context->qrPtr, QueryRisk::TYPE_TRANSACTION); return COMMIT;}
"start"         {maybeSetType(context->qrPtr, QueryRisk::TYPE_TRANSACTION); return START;}
"transaction"   {return TRANSACTION;}
"session"       {return SESSION;}
"rollback"      {maybeSetType(context->qrPtr, QueryRisk::TYPE_TRANSACTION); return ROLLBACK;}
"consistent"    {return CONSISTENT;}
"snapshot"      {return SNAPSHOT;}
"chain"         {return CHAIN;}
"no"            {return NO;}
"release"       {return RELEASE;}

"low_priority"  {return LOW_PRIORITY;}
"high_priority" {return HIGH_PRIORITY;}
"straight_join" {return STRAIGHT_JOIN;}
"delayed"       {return DELAYED;}
"quick"         {return QUICK;}
"distinct"      {return DISTINCT;}
"all"           {return ALL;}
"distinctrow"   {return DISTINCTROW;}
"collate"       {return COLLATE;}
"sql_small_result"      {return SQL_SMALL_RESULT;}
"sql_big_result"        {return SQL_BIG_RESULT;}
"sql_cache"             {return SQL_CACHE;}
"sql_no_cache"          {return SQL_NO_CACHE;}
"sql_calc_found_rows"   {return SQL_CALC_FOUND_ROWS;}
"sql_buffer_result"     {return SQL_BUFFER_RESULT;}

"left"      {return LEFT;}
"right"     {return RIGHT;}
"outer"     {return OUTER;}
"inner"     {return INNER;}
"cross"     {return CROSS;}
"natural"   {return NATURAL;}
"join"      {return JOIN_KW;}
"on"        {return ON;}
"using"     {return USING;}

"as"    {return AS;}
"cast"  {return CAST;}

("not"|"!")     {return NOT;}
"in"            {return IN;}
"any"           {return ANY;}
"some"          {return SOME;}
"between"       {return BETWEEN;}
"or"            {return OR;}
"xor"           {return XOR;}
"and"           {return AND;}
"sounds"        {return SOUNDS;}

"<"             {return LT;}
">"             {return GT;}
"<="            {return LE;}
">="            {return GE;}
("="|"<=>")     {return EQ;}
 /**
   @TODO(bskari|2012-07-21) != is a nonstandard MySQL extension and should be
   counted in the QueryRisk for MySQL specific statements.
  */
("!="|"<>")     {return NE;}
"like"          {return LIKE_KW;}
"escape"        {return ESCAPE;}

"div"   {return INTEGER_DIVIDE;}
"/"     {return SLASH;}
"%"|"mod"   {return REM;}
"+"     {return PLUS;}
"-"     {return MINUS;}

"&"     {return BITAND;}
"|"     {return BITOR;}
"^"     {return BITXOR;}
"~"     {return BITNOT;}
"<<"    {return LSHIFT;}
">>"    {return RSHIFT;}

","     {return COMMA;}
"*"     {return STAR;}
"."     {return DOT;}
";"     {return SEMI;}

"("     {return LP;}
")"     {return RP;}

"order"                 {return ORDER;}
"group"                 {return GROUP;}
"by"                    {return BY;}
("ascending"|"asc")     {return ASC;}
("descending"|"desc")   {return DESC;}

"set"   {return SET;}

"ignore"    {return IGNORE;}
"into"      {return INTO;}
"outfile"   {return OUTFILE;}
"dumpfile"  {return OUTFILE;}

"from"      {return FROM;}
"where"     {return WHERE;}
"having"    {return HAVING;}

"union"     {return UNION;}

"limit"     {return LIMIT;}
"offset"    {return OFFSET;}

"default"   {return DEFAULT;}

"values"    {return VALUES;}

"for"       {return FOR;}
"lock"      {return LOCK;}
"share"     {return SHARE;}
"mode"      {return MODE;}
"local"     {return LOCAL;}
"read"      {return READ;}
"write"     {return WRITE;}

"force"     {return FORCE;}
"use"       {return USE;}
"index"     {return INDEX;}
"key"       {return KEY;}

"null"      {return NULL_KW;}

"is"        {return IS;}

"with"      {return WITH;}
"query"     {return QUERY;}
"match"     {return MATCH_KW;}
"expansion" {return EXPANSION;}
"against"   {return AGAINST;}
"language"  {return LANGUAGE;}
"boolean"   {return BOOLEAN;}

"show"              {return SHOW;}
"describe"|"desc"   {return DESCRIBE;}
"global"            {return GLOBAL;}
"variables"         {return VARIABLES;}
"create"            {return CREATE;}
"table"             {return TABLE;}
"database"          {return DATABASE;}
"databases"         {return DATABASES;}
"schema"            {return SCHEMA;}

"interval"              {return INTERVAL;}

"unlock"    {return UNLOCK;}
"tables"    {return TABLES;}
"columns"   {return COLUMNS;}
"full"      {return FULL;}

"microsecond"           {return TIME_UNIT;}
"second"                {return TIME_UNIT;}
"hour"                  {return TIME_UNIT;}
"day"                   {return TIME_UNIT;}
"week"                  {return TIME_UNIT;}
"month"                 {return TIME_UNIT;}
"quarter"               {return TIME_UNIT;}
"year"                  {return TIME_UNIT;}
"second_microsecond"    {return TIME_UNIT;}
"minute_microsecond"    {return TIME_UNIT;}
"minute_second"         {return TIME_UNIT;}
"hour_microsecond"      {return TIME_UNIT;}
"hour_second"           {return TIME_UNIT;}
"day_microsecond"       {return TIME_UNIT;}
"day_second"            {return TIME_UNIT;}
"day_minute"            {return TIME_UNIT;}
"day_hour"              {return TIME_UNIT;}
"year_month"            {return TIME_UNIT;}

"case"  {return CASE;}
"when"  {return WHEN;}
"then"  {return THEN;}
"else"  {return ELSE;}
"end"   {return END;}

{ID}    {return ID;}
{QUOTED_IDENTIFIER}    {
    std::string str(yytext);
    return ID;
}
{INTEGER}           {return INTEGER;}
{FLOAT}             {return FLOAT;}
{GLOBAL_VARIABLE}   {return GLOBAL_VARIABLE;}
{VARIABLE}          {return VARIABLE;}

.    {return ERROR_TOKEN;}

%%

int yywrap(void* scanner)
{
    // Non-zero indicates that we are done
    return 1;
}
