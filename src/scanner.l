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
    #define YY_EXTRA_TYPE QueryRisk*
    #define YY_DECL int sql_lex( \
        void* const lvalp, \
        ScannerContext* const context, \
        QueryRisk* const qr, \
        yyscan_t yyscanner \
    )

    #include "AstNode.hpp"
    #include "Logger.hpp"
    // Include file produced by Lemon
    #include "sqlParser.hpp"
    #define ERROR_TOKEN -1
    #include "QueryRisk.hpp"
    #include "ScannerContext.hpp"

    #include <cassert>
    #include <stack>
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

    static std::string hexStringToString(const char* const str)
    {
        assert(
            NULL != str
            && '\0' != str[0]
            && '\0' != str[1] && '\0' != str[2]
            && '\0' != str[3] && "MySQL hex string is too short"
        );
        assert(
            '0' == str[0]
            && 'x' == str[1]
            && "MySQL hex string must start with '0x'"
        );

        std::string value;

        // MySQL starts at the end, so for example, the string
        // 0x444 is interpreted as 0x4 ('EOT') + 0x44 ('D')
        const char* iter = str + 2;
        while (*iter)
        {
            ++iter;
        }
        iter -= 2;
        for (; iter >= str + 2; iter -= 2)
        {
            int sixteens = hexToNum(*iter) << 4;
            int ones = hexToNum(*(iter + 1));
            value = static_cast<char>(sixteens + ones) + value;
        }

        // If the user gave an odd number of hex digits, then parse the last
        // digit singly
        if (iter == str + 1)
        {
            value = static_cast<char>(hexToNum(*(iter + 1))) + value;
        }

        return value;
    }
%}

%option prefix="sql_"
%option reentrant

%x GENERIC_MULTI_LINE_COMMENT
%x MYSQL_MULTI_LINE_COMMENT
%x MYSQL_VERSION_MULTI_LINE_COMMENT
%x DASH_DASH_COMMENT
%x HASH_COMMENT
%x QUOTED
%x DOUBLE_QUOTED

WHITE_SPACE [ \t\n\r\v\f]

ID  ([a-zA-Z_][a-zA-Z0-9_]*)|("{"[a-zA-Z_][a-zA-Z0-9_]*"}")
QUOTED_IDENTIFIER    "`"[a-zA-Z_][a-zA-Z0-9_]*"`"
INTEGER     ([0-9][0-9]*)
FLOAT       ([0-9]*"."[0-9]+)|([0-9]+"."[0-9]*)
GLOBAL_VARIABLE    "@@"{ID}

HEX_STRING    0x[0-9A-Fa-f]{2,}

%%
 /* Comments */
"/*!"[0-9]{5}    BEGIN(MYSQL_VERSION_MULTI_LINE_COMMENT); {}
<MYSQL_VERSION_MULTI_LINE_COMMENT>"AND"{WHITE_SPACE}    {++qr->commentedConditionals;}
<MYSQL_VERSION_MULTI_LINE_COMMENT>"OR"{WHITE_SPACE}     {++qr->commentedConditionals;}
<MYSQL_VERSION_MULTI_LINE_COMMENT>"XOR"{WHITE_SPACE}    {++qr->commentedConditionals;}
<MYSQL_VERSION_MULTI_LINE_COMMENT>"WHERE"{WHITE_SPACE}  {++qr->commentedConditionals;}
<MYSQL_VERSION_MULTI_LINE_COMMENT>"*"+[^*/]             {}
<MYSQL_VERSION_MULTI_LINE_COMMENT>"*"                   {}
<MYSQL_VERSION_MULTI_LINE_COMMENT>"'"                   {++qr->commentedQuotes;}
<MYSQL_VERSION_MULTI_LINE_COMMENT>[^*']                 {}
<MYSQL_VERSION_MULTI_LINE_COMMENT>"*/" BEGIN(INITIAL);  {++qr->mySqlVersionedComments;}
<MYSQL_VERSION_MULTI_LINE_COMMENT><<EOF>>               {qr->valid = false; BEGIN(INITIAL);}

"/*!*/"     {++qr->mySqlComments;}
"/*!"                                           {BEGIN(MYSQL_MULTI_LINE_COMMENT);}
<MYSQL_MULTI_LINE_COMMENT>"AND"{WHITE_SPACE}    {++qr->commentedConditionals;}
<MYSQL_MULTI_LINE_COMMENT>"OR"{WHITE_SPACE}     {++qr->commentedConditionals;}
<MYSQL_MULTI_LINE_COMMENT>"XOR"{WHITE_SPACE}    {++qr->commentedConditionals;}
<MYSQL_MULTI_LINE_COMMENT>"WHERE"{WHITE_SPACE}  {++qr->commentedConditionals;}
<MYSQL_MULTI_LINE_COMMENT>"*"+[^*/]             {}
<MYSQL_MULTI_LINE_COMMENT>"*"                   {}
<MYSQL_MULTI_LINE_COMMENT>"'"                   {++qr->commentedQuotes;}
<MYSQL_MULTI_LINE_COMMENT>[^*]                  {}
<MYSQL_MULTI_LINE_COMMENT>"*/"  BEGIN(INITIAL); {++qr->mySqlComments;}
<MYSQL_MULTI_LINE_COMMENT><<EOF>>               {qr->valid = false; BEGIN(INITIAL);}

"/**/"        {++qr->multiLineComments;}
"/*"[^!]                                            {BEGIN(GENERIC_MULTI_LINE_COMMENT);}
<GENERIC_MULTI_LINE_COMMENT>"AND"{WHITE_SPACE}      {++qr->commentedConditionals;}
<GENERIC_MULTI_LINE_COMMENT>"OR"{WHITE_SPACE}       {++qr->commentedConditionals;}
<GENERIC_MULTI_LINE_COMMENT>"XOR"{WHITE_SPACE}      {++qr->commentedConditionals;}
<GENERIC_MULTI_LINE_COMMENT>"WHERE"{WHITE_SPACE}    {++qr->commentedConditionals;}
<GENERIC_MULTI_LINE_COMMENT>"*"+[^*/]               {}
<GENERIC_MULTI_LINE_COMMENT>"*"                     {}
<GENERIC_MULTI_LINE_COMMENT>"'"                     {++qr->commentedQuotes;}
<GENERIC_MULTI_LINE_COMMENT>[^*']                   {}
<GENERIC_MULTI_LINE_COMMENT>"*/"    BEGIN(INITIAL); {++qr->multiLineComments;}
<GENERIC_MULTI_LINE_COMMENT><<EOF>>                 {qr->valid = false; BEGIN(INITIAL);}

"--"{WHITE_SPACE}           {BEGIN(DASH_DASH_COMMENT); ++qr->dashDashComments;}
<DASH_DASH_COMMENT>"AND"    {++qr->commentedConditionals;}
<DASH_DASH_COMMENT>"OR"     {++qr->commentedConditionals;}
<DASH_DASH_COMMENT>"XOR"    {++qr->commentedConditionals;}
<DASH_DASH_COMMENT>"WHERE"  {++qr->commentedConditionals;}
<DASH_DASH_COMMENT>"'"      {++qr->commentedQuotes;}
<DASH_DASH_COMMENT>[^\n']   {}
<DASH_DASH_COMMENT>[\n]     {BEGIN(INITIAL);}
<DASH_DASH_COMMENT><<EOF>>  {BEGIN(INITIAL);}

"#"                     {BEGIN(HASH_COMMENT); ++qr->hashComments;}
<HASH_COMMENT>"AND"     {++qr->commentedConditionals;}
<HASH_COMMENT>"OR"      {++qr->commentedConditionals;}
<HASH_COMMENT>"XOR"     {++qr->commentedConditionals;}
<HASH_COMMENT>"WHERE"   {++qr->commentedConditionals;}
<HASH_COMMENT>"'"       {++qr->commentedQuotes;}
<HASH_COMMENT>[^\n']    {}
<HASH_COMMENT>[\n]      {BEGIN(INITIAL);}
<HASH_COMMENT><<EOF>>   {BEGIN(INITIAL);}

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
                context->quotedStrings.push(context->quotedString);
                return STRING;
            }
            else
            {
                // Skip the escaping quote
                context->quotedString += (yytext + 1);
            }
}
<QUOTED><<EOF>>     {qr->valid = false; BEGIN(INITIAL);}

{HEX_STRING}    {
    ++qr->hexStrings;
    context->quotedStrings.push(hexStringToString(yytext));
    return STRING;
}

 /* Double quoted strings don't count as string literals in strict ANSI SQL;
 they count as identifiers. MySQL defaults to using them as strings unless
 you enable ANSI_QUOTES, but I'm just going to assume the latter and let the
 user deal with it. */
\"        {context->quotedString = ""; BEGIN(DOUBLE_QUOTED);}
<DOUBLE_QUOTED>[^\"]+    {context->quotedString += yytext;}
<DOUBLE_QUOTED>["]    {
                BEGIN(INITIAL);
                context->quotedStrings.push(context->quotedString);
                return STRING;
}
<DOUBLE_QUOTED><<EOF>>    {qr->valid = false; BEGIN(INITIAL);}


"select"    {return SELECT;}
"insert"    {return INSERT;}
"update"    {return UPDATE;}
"replace"   {return REPLACE;}
"delete"    {return DELETE;}
"explain"   {return EXPLAIN;}

"begin"         {return BEGIN_KW;}
"work"          {return WORK;}
"commit"        {return COMMIT;}
"start"         {return START;}
"transaction"   {return TRANSACTION;}
"rollback"      {return ROLLBACK;}
"consistent"    {return CONSISTENT;}
"snapshot"      {return SNAPSHOT;}
"chain"         {return CHAIN;}
"release"       {return RELEASE;}

"low_priority"  {return INSERT_KW;}
"high_priority" {return INSERT_KW;}
"straight_join" {return STRAIGHT_JOIN;}
"delayed"       {return INSERT_KW;}
"quick"         {return QUICK;}
"distinct"      {return DISTINCT;}
"all"           {return ALL;}
"distinctrow"   {return DISTINCTROW;}
 /** @TODO SQL small result, SQL big result, SQL buffer result */
 /** @TODO SQL calc found rows, SQL no cache, SQL cache all */

"left"      {return LEFT;}
"right"     {return RIGHT;}
"outer"     {return OUTER;}
"inner"     {return INNER;}
"cross"     {return CROSS;}
"natural"   {return NATURAL;}
"join"      {return JOIN;}
"on"        {return ON;}
"using"     {return USING;}

"as"    {return AS;}

("not"|"!")     {return NOT;}
"in"            {return IN;}
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
("!="|"<>")     {return NE;}
"like"          {return LIKE_KW;}
"escape"        {return ESCAPE;}

"div"   {return INTEGER_DIVIDE;}
"/"     {return SLASH;}
"%"     {return REM;}
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

"procedure" {return PROCEDURE;}

"default"   {return DEFAULT;}

"values"    {return VALUES;}

"for"       {return FOR;}
"lock"      {return LOCK;}
"share"     {return SHARE;}
"mode"      {return MODE;}

"force"     {return FORCE;}
"use"       {return USE;}
"index"     {return INDEX;}
"key"       {return KEY;}

"null"      {return NULL_KW;}

"is"        {return IS;}

"with"      {return WITH;}
"query"     {return QUERY;}
"match"     {return MATCH;}
"expansion" {return EXPANSION;}
"against"   {return AGAINST;}
"language"  {return LANGUAGE;}
"boolean"   {return BOOLEAN;}

"show"      {return SHOW;}
"describe"  {return DESCRIBE;}
"global"    {return GLOBAL;}
"variables" {return VARIABLES;}

"interval"              {return INTERVAL;}
"sql_calc_found_rows"   {return SQL_CALC_FOUND_ROWS;}

"unlock"    {return UNLOCK;}
"tables"    {return TABLES;}

"sql_big_result"    {return SQL_BIG_RESULT;}
"sql_small_result"  {return SQL_SMALL_RESULT;}
"sql_buffer_result" {return SQL_BUFFER_RESULT;}
"sql_cache"         {return SQL_CACHE;}
"sql_no_cache"      {return SQL_NO_CACHE;}

{ID}    {context->identifiers.push(std::string(yytext)); return ID;}
{QUOTED_IDENTIFIER}    {
    std::string str(yytext);
    context->identifiers.push(str.substr(1, str.length() - 2));
    return ID;
}
{INTEGER}           {context->numbers.push(std::string(yytext)); return INTEGER;}
{FLOAT}             {context->numbers.push(std::string(yytext)); return FLOAT;}
{GLOBAL_VARIABLE}   {context->identifiers.push(std::string(yytext)); return STRING;}

.    {return ERROR_TOKEN;}

%%

int yywrap(void* scanner)
{
    // Non-zero indicates that we are done
    return 1;
}
