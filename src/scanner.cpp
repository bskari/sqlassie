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

#include "Logger.hpp"
#include "nullptr.hpp"
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

int main()
{
    Logger::initialize();
    loadTokensFromFile("sqlParser.h");

    string x;
    cout << "Enter MySQL query: ";

    ScannerContext context;
    while (getline(cin, x))
    {
        yyscan_t scanner;
        sql_lex_init(&scanner);
        YY_BUFFER_STATE bufferState = sql__scan_string(x.c_str(), scanner);
        int lexCode = sql_lex(scanner);
        do
        {
            assert(tokenCodes.end() != tokenCodes.find(lexCode) &&
                "Token code doesn't have an associated name");
            cout << '"'
                << sql_get_text(scanner)
                << "\": "
                << lexCode
                << ", "
                << tokenCodes[lexCode]
                << endl;
            lexCode = sql_lex(scanner);
        }
        while (lexCode > 255);

        sql__delete_buffer(bufferState, scanner);
        sql_lex_destroy(scanner);

        cout << "Enter MySQL query: ";
    }
    cout << endl;

    cout << "Identifiers found:" << endl;
    while (!context.identifiers.empty())
    {
        cout << context.identifiers.top() << endl;
        context.identifiers.pop();
    }

    cout << "Quoted strings found:" << endl;
    while (!context.quotedStrings.empty())
    {
        cout << context.quotedStrings.top() << endl;
        context.quotedStrings.pop();
    }

    cout << "Numbers found:" << endl;
    while (!context.numbers.empty())
    {
        cout << context.numbers.top() << endl;
        context.numbers.pop();
    }
}

void loadTokensFromFile(const char* const fileName)
{
    ifstream fin(fileName);
    if (!fin)
    {
        cerr << "Unable to load tokens from file " << fileName << endl;
        exit(1);
    }

    string line;
    while (getline(fin, line))
    {
        // Find the definition of the tokens
        if (string::npos != line.find("yytokentype"))
        {
            break;
        }
    }
    // Keep reading lines until we hit the close of the enum
    while (getline(fin, line), string::npos == line.find("}"))
    {
        // Each line is formatted like this:
        // TOKEN = ###,
        const size_t tokenBegin = line.find_first_not_of(" \t");
        const size_t tokenEnd = line.find_first_of(" \t", tokenBegin + 1);

        if (string::npos == tokenBegin || string::npos == tokenEnd)
        {
            continue;
        }

        const size_t numberBegin =
            line.find_first_of("0123456789", tokenEnd + 1);
        const size_t numberEnd = line.rfind(',');

        if (string::npos == numberBegin || string::npos == numberEnd)
        {
            continue;
        }

        const string token(line.substr(tokenBegin, tokenEnd - tokenBegin));
        int lexCode;
        try
        {
            lexCode = lexical_cast<int>(
                line.substr(numberBegin, numberEnd - numberBegin));
        }
        catch (...)
        {
            Logger::log(Logger::ERROR) << "Malformatted lex code";
            assert(false);
            continue;
        }

        assert(tokenCodes.end() == tokenCodes.find(lexCode) &&
            "Token value already has a string associated with it");
        tokenCodes[lexCode] = token;

        // End of enum, we're done processing the file
    }
    fin.close();
}
