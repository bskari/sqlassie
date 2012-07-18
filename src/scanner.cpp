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

// This needs to be declared prior to including the scanner header
#define YY_DECL int sql_lex( \
    ScannerContext* const context, \
    yyscan_t yyscanner \
)

#include "Logger.hpp"
#include "nullptr.hpp"
#include "QueryRisk.hpp"
#include "sqlParser.h"
#include "scanner.yy.hpp"
#include "ScannerContext.hpp"

#include <boost/lexical_cast.hpp>
#include <cassert>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <map>
#include <string>

using boost::lexical_cast;
using std::cerr;
using std::cin;
using std::cout;
using std::endl;
using std::ifstream;
using std::map;
using std::string;

/**
 * Scans MySQL queries and prints out the tokens.
 * @author Brandon Skari
 * @date November 15 2010
 */

map<int, string> tokenCodes;
void loadTokensFromFile(const char* fileName);
extern YY_DECL;

int main()
{
    Logger::initialize();
    loadTokensFromFile("sqlParser.h");

    string x;
    cout << "Enter MySQL query: ";

    QueryRisk qr;
    ScannerContext context(&qr);
    while (getline(cin, x))
    {
        yyscan_t scanner;
        sql_lex_init(&scanner);
        YY_BUFFER_STATE bufferState = sql__scan_string(x.c_str(), scanner);
        int lexCode = sql_lex(&context, scanner);
        do
        {
            assert(
                tokenCodes.end() != tokenCodes.find(lexCode)
                && "Token code doesn't have an associated name"
            );
            cout << '"'
                << sql_get_text(scanner)
                << "\": "
                << lexCode
                << ", "
                << tokenCodes[lexCode]
                << endl;
            lexCode = sql_lex(&context, scanner);
        }
        while (lexCode != 0);

        sql__delete_buffer(bufferState, scanner);
        sql_lex_destroy(scanner);

        cout << "Enter MySQL query: ";
    }
}

void loadTokensFromFile(const char* const fileName)
{
    ifstream fin(fileName);
    if (!fin)
    {
        cerr << "Unable to load tokens from file " << fileName << endl;
        exit(EXIT_FAILURE);
    }

    string keyword;
    int lexCode;
    // Each line has a definition like this:
    // #define SELECT      1
    const int defineLength = strlen("#define ");
    while (fin.ignore(defineLength) && !fin.eof())
    {
        fin >> keyword;
        fin >> lexCode;
        tokenCodes[lexCode] = keyword;
    }
    fin.close();
}
