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

// This needs to be defined prior to including the scanner header
#define YY_DECL int sql_lex( \
    ScannerContext* const context, \
    yyscan_t yyscanner \
)

#include "AstNode.hpp"
#include "Logger.hpp"
#include "nullptr.hpp"
#include "ParserInterface.hpp"
#include "QueryRisk.hpp"
#include "scanner.yy.hpp"
#include "SensitiveNameChecker.hpp"

#include <fstream>
#include <ostream>
#include <string>

using std::cerr;
using std::cin;
using std::cout;
using std::endl;
using std::ifstream;
using std::istream;
using std::ostream;
using std::string;

void printParseErrorLocation(const string& query, ostream& out = cout);

// Methods from the parser
extern void* sqlassieParseAlloc(void* (*allocProc)(size_t numBytes));
extern void* sqlassieParse(
    void* parser,
    int token,
    const int _,
    ScannerContext* qrPtr
);
extern void* sqlassieParseFree(void* parser, void(*freeProc)(void*));
// Methods from the scanner
extern YY_DECL;

/**
 * Parses MySQL queries. Testing code for parser.y
 * @author Brandon Skari
 * @date November 29 2010
 */


int main(int argc, char* argv[])
{
    Logger::initialize();
    SensitiveNameChecker::initialize();
    SensitiveNameChecker::get().setPasswordSubstring("password");
    SensitiveNameChecker::get().setUserSubstring("user");
    bool file = false;

    ifstream fin;
    if (argc > 1)
    {
        fin.open(argv[1]);
        file = true;
    }
    istream& stream = (fin.is_open() ? fin : cin);
    if (argc > 1 && !fin)
    {
        cerr << "Unable to open file '" << argv[1] << "', aborting" << endl;
        return 0;
    }

    string query;
    while (!stream.eof())
    {
        if (!file)
        {
            cout << "Enter MySQL query: ";
        }
        getline(stream, query);

        if (0 == query.length())
        {
            continue;
        }

        QueryRisk qr;
        ParserInterface parser(query);

        const bool successfullyParsed = parser.parse(&qr);

        // If the query was successfully parsed (i.e. was a valid query)'
        if (successfullyParsed && qr.valid)
        {
            // Don't print valid lines if we're reading from a file
            if (!file)
            {
                cout << "Hash: " << parser.getHash().hash << "\n" << qr << endl;
            }
        }
        else
        {
            // Only print the line if we're reading from a file
            if (!file)
            {
                cout << "Invalid: \"" << query << '"' << endl;
                cout << "Parsing failed near '";
                printParseErrorLocation(query);
                cout << '\'' << endl;
            }
            else
            {
                cout << query << endl;
            }
        }
    }
    return 0;
}

void printParseErrorLocation(const string& query, ostream& out)
{
    // Try to find where parsing failed
    QueryRisk qr;
    ScannerContext sc(&qr);
    yyscan_t scanner = nullptr;
    YY_BUFFER_STATE bufferState = nullptr;
    void* lemonParser = nullptr;

    if (0 != sql_lex_init(&scanner))
    {
        goto ERROR;
    }

    bufferState = sql__scan_string(query.c_str(), scanner);
    if (nullptr == bufferState)
    {
        goto ERROR;
    }

    lemonParser = sqlassieParseAlloc(malloc);
    if (nullptr == lemonParser)
    {
        goto ERROR;
    }

    // Keep parsing until we hit an error
    while (qr.valid)
    {
        const int lexToken = sql_lex(&sc, scanner);
        if (qr.valid)
        {
            sqlassieParse(lemonParser, lexToken, nullptr, &sc);
        }
    }

    if (!qr.valid)
    {
        int lexToken;
        // We hit an error, so print the reamining tokens
        do
        {
            out << sql_get_text(scanner) << ' ';
            lexToken = sql_lex(&sc, scanner);
        }
        while (0 != lexToken);
    }
    goto CLEANUP;

ERROR:
    cout << " (unknown)";
CLEANUP:
    if (nullptr != lemonParser)
    {
        sqlassieParseFree(lemonParser, free);
    }
    if (nullptr != bufferState)
    {
        sql__delete_buffer(bufferState, scanner);
    }
    if (nullptr != scanner)
    {
        sql_lex_destroy(scanner);
    }
}
