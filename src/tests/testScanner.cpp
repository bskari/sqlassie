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

// This needs to be defined prior to including the scanner header
#define YY_DECL int sql_lex( \
    ScannerContext* const context, \
    yyscan_t yyscanner \
)

#include "../nullptr.hpp"
#include "../scanner.yy.hpp"
#include "../ScannerContext.hpp"
#include "../sqlParser.h"
#include "testScanner.hpp"
#include "../QueryRisk.hpp"

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
static void checkScanTokens(
    const int expectedTokens[],
    const int numTokens,
    const char* const tokenStream
);
static void checkFailure(const char* const tokenStream);
// Methods from the scanner
extern YY_DECL;


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


void testScanNumbers()
{
    const int INT = INTEGER;
    const int intTokens[] = {INT, INT, INT, INT};
    const char* intString = "0    1    000  001";
    checkScanTokens(
        intTokens,
        sizeof(intTokens) / sizeof(intTokens[0]),
        intString
    );

    const int FLT = FLOAT;
    const int floatTokens[] = {FLT, FLT, FLT, FLT};
    const char* floatString = "0.0  1.0  .1   1.";
    checkScanTokens(
        floatTokens,
        sizeof(floatTokens) / sizeof(floatTokens[0]),
        floatString
    );

    const int HEX = HEX_NUMBER;
    const int hexDecimalTokens[] = {HEX, HEX, HEX, HEX, HEX, HEX, HEX, HEX, HEX, HEX};
    const char* hexDecimalString = "0x0  0x1  0x2  0x3  0x4  0x5  0x6  0x7  0x8  0x9";
    checkScanTokens(
        hexDecimalTokens,
        sizeof(hexDecimalTokens) / sizeof(hexDecimalTokens[0]),
        hexDecimalString
    );

    const int hexLetterTokens[] = {HEX, HEX, HEX, HEX, HEX, HEX, HEX, HEX, HEX, HEX, HEX, HEX};
    const char* hexLetterString = "0xA  0xB  0xC  0xD  0xE  0xF  0xa  0xb  0xc  0xd  0xe  0xf";
    checkScanTokens(
        hexLetterTokens,
        sizeof(hexLetterTokens) / sizeof(hexLetterTokens[0]),
        hexLetterString
    );

    const int hexUpperTokens[] = {HEX, HEX, HEX, HEX};
    const char* hexUpperString = "0X0  0XA9 0XFF 0xC0";
    checkScanTokens(
        hexUpperTokens,
        sizeof(hexUpperTokens) / sizeof(hexUpperTokens[0]),
        hexUpperString
    );

    const int hexMixedCaseTokens[] = {HEX, HEX, HEX, HEX, HEX};
    const char* hexMixedCaseString = "0xaF 0xAf 0xaA 0xAa 0xaAbBcCdDeEfF";
    checkScanTokens(
        hexMixedCaseTokens,
        sizeof(hexMixedCaseTokens) / sizeof(hexMixedCaseTokens[0]),
        hexMixedCaseString
    );

    // Make sure we don't scan partial hex strings as hex
    const int nonHexTokens[] = {INT, ID, INT, ID, ID, ID, ID, ID};
    const char* nonHexString = "0x       0X       X0  x0  x   X";
    checkScanTokens(
        nonHexTokens,
        sizeof(nonHexTokens) / sizeof(nonHexTokens[0]),
        nonHexString
    );

}


void testScanComments()
{
    const int INT = INTEGER;

    // Dash dash comments need whitespace
    const int dashDashNoWhiteSpaceTokens[] = {ID, MINUS, MINUS, INT};
    const char* dashDashNoWhiteSpaceString = "x   --1";
    checkScanTokens(
        dashDashNoWhiteSpaceTokens,
        sizeof(dashDashNoWhiteSpaceTokens) / sizeof(dashDashNoWhiteSpaceTokens[0]),
        dashDashNoWhiteSpaceString
    );

    // Dash dash comments can end a query
    const int dashDashEndTokens[] = {ID};
    const char* dashDashEndString = "x --";
    checkScanTokens(
        dashDashEndTokens,
        sizeof(dashDashEndTokens) / sizeof(dashDashEndTokens[0]),
        dashDashEndString
    );

    // Hash comments can end a query
    const int HashEndTokens[] = {ID};
    const char* HashEndString = "x #";
    checkScanTokens(
        HashEndTokens,
        sizeof(HashEndTokens) / sizeof(HashEndTokens[0]),
        HashEndString
    );

    // Short comments
    const int shortCommentsTokens[] = {ID};
    const char* shortCommentsString = "x /**/ /*!*/ /*!12345*/ /*/ x */";
    checkScanTokens(
        shortCommentsTokens,
        sizeof(shortCommentsTokens) / sizeof(shortCommentsTokens[0]),
        shortCommentsString
    );

    // There are invalid comments too
    checkFailure("SELECT * FROM foo /* ");
    checkFailure("SELECT * FROM foo /*! ");
    checkFailure("SELECT * FROM foo /*!12345 ");
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


void checkScanTokens(
    const int expectedTokens[],
    const int numTokens,
    const char* const tokenStream
)
{
    yyscan_t scanner;
    BOOST_REQUIRE(0 == sql_lex_init(&scanner));
    YY_BUFFER_STATE bufferState = sql__scan_string(tokenStream, scanner);
    BOOST_REQUIRE(nullptr != bufferState);

    QueryRisk qr;
    ScannerContext sc(&qr);
    for (int i = 0; i < numTokens; ++i)
    {
        const int lexCode = sql_lex(&sc, scanner);
        BOOST_CHECK(lexCode == expectedTokens[i]);
    }
    const int lastLexCode = sql_lex(&sc, scanner);
    const int endOfTokensLexCode = 0;
    BOOST_CHECK(endOfTokensLexCode == lastLexCode);

    sql__delete_buffer(bufferState, scanner);
    sql_lex_destroy(scanner);
}


void checkFailure(const char* const tokenStream)
{
    yyscan_t scanner;
    BOOST_REQUIRE(0 == sql_lex_init(&scanner));
    YY_BUFFER_STATE bufferState = sql__scan_string(tokenStream, scanner);
    BOOST_REQUIRE(nullptr != bufferState);

    QueryRisk qr;
    ScannerContext sc(&qr);
    const int endOfTokensLexCode = 0;
    int lexCode;
    do
    {
        lexCode = sql_lex(&sc, scanner);
    }
    while (endOfTokensLexCode != lexCode);

    BOOST_CHECK_MESSAGE(
        !qr.valid,
        '"' << tokenStream << "\" should not have parsed"
    );

    sql__delete_buffer(bufferState, scanner);
    sql_lex_destroy(scanner);
}
