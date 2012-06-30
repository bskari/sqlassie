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
 * Tests the scanner.
 * @author Brandon Skari
 * @date June 29 2012
 */

#include "testScanner.hpp"
// Artificial include to force dependency generation by my dependency script
//#include ../scanner
//#include ../sqlParser.h

// Newer versions of the Boost filesystem (1.44+) changed the interface; to
// keep compatibility, default to the old version
#define BOOST_FILESYSTEM_VERSION 2
#include <boost/regex.hpp>
#include <boost/test/unit_test.hpp>
#include <fstream>
#include <limits>
#include <set>
#include <string>

using boost::smatch;
using boost::regex;
using std::ifstream;
using std::numeric_limits;
using std::set;
using std::streamsize;
using std::string;

static set<string> loadScannerTokens(const char* const filename);
static set<string> loadParserTokens(const char* const filename);


void testAllTokensScan()
{
    set<string> scannerTokens = loadScannerTokens("../src/scanner.l");
    set<string> parserTokens = loadParserTokens("../src/sqlParser.h");

    const set<string>::const_iterator end(parserTokens.end());
    for (
        set<string>::const_iterator parserTokenIter(parserTokens.begin());
        parserTokenIter != end;
        ++parserTokenIter
    )
    {
        // Make sure the scanner is returning the parser's token
        if (scannerTokens.end() == scannerTokens.find(*parserTokenIter))
        {
            BOOST_CHECK_MESSAGE(
                false,
                "Scanner does not return the token " << *parserTokenIter
            );
        }
    }
}


set<string> loadScannerTokens(const char* const filename)
{
    ifstream fin(filename);
    BOOST_REQUIRE_MESSAGE(fin, "Unable to open scanner");
    set<string> tokens;

    regex returnStatementRegex("return ([A-Z_]+);");
    string line;
    while (getline(fin, line))
    {
        smatch m;
        if (!regex_search(line, m, returnStatementRegex))
        {
            continue;
        }
        tokens.insert(m[1]);
    }
    return tokens;
}


set<string> loadParserTokens(const char* const filename)
{
    ifstream fin(filename);
    BOOST_REQUIRE_MESSAGE(fin, "Unable to open parser");
    set<string> tokens;

    string token, _;
    while (fin.ignore(numeric_limits<streamsize>::max(), ' '), fin >> token)
    {
        // The ID_FALLBACK token is a dummy token that;s used for keywords
        // that can also be used as identifiers, e.g. 'MATCH'. The scanner
        // should never return this keyword, so don't check for it.
        if (token != "ID_FALLBACK")
        {
            tokens.insert(token);
        }
        fin.ignore(numeric_limits<streamsize>::max(), '\n');
    }
    return tokens;
}
