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
 * Parser for Hugins format Bayesian network files.
 * @author Brandon Skari
 * @date May 8 2011
 */

%{
    // Include file produced by Bison
    #include "huginParser.tab.hpp"
    #include <iostream>
    #include <stack>
    #include <string>
    #include <map>

    std::stack<std::string> hugin_identifiers;
    std::map<std::string, int> hugin_nodesNumbers;
    std::stack<std::string> hugin_numbers;

    #define YY_DECL int hugin_lex(yyscan_t yyscanner)
%}

%option reentrant
%option prefix="hugin_"

%x QUOTED

WHITE_SPACE [ \t\n\r\v\f]
IDENTIFIER    [a-zA-Z_][a-zA-Z0-9_]*
FLOAT        "-"?[0-9]+"."[0-9]+
INTEGER        "-"?[0-9]+
SCIENTIFIC    {FLOAT}[eE]"-"?[0-9]
NUMBER        ({FLOAT}|{SCIENTIFIC}|{INTEGER})

%%

"potential"    {return POTENTIAL;}
"data"        {return DATA;}
"pipe"        {return PIPE;}
"states"    {return STATES;}
"label"        {return LABEL;}
"node"        {return NODE;}
"net"        {return NET;}

{IDENTIFIER}    {hugin_identifiers.push(yytext); return IDENTIFIER;}
{NUMBER}        {hugin_numbers.push(yytext); return NUMBER;}

"\""    {BEGIN(QUOTED);}
<QUOTED>[^"]*"\""    {BEGIN(INITIAL); return STRING;}
<QUOTED>.    {return ERROR;}

"="        {return EQUAL;}
"{"        {return LEFT_BRACE;}
"}"        {return RIGHT_BRACE;}
"("        {return LEFT_PARENTHESE;}
")"        {return RIGHT_PARENTHESE;}
";"        {return SEMICOLON;}
"|"        {return PIPE;}

{WHITE_SPACE}    {}

.    {return ERROR;}

%%

int hugin_wrap(void* scanner)
{
    // Non-zero indicates that we are done
    return 1;
}
