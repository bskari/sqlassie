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

#include "../ParserInterface.hpp"
#include "../QueryRisk.hpp"
#include "../QueryWhitelist.hpp"

#include <boost/test/unit_test.hpp>
#include <string>

using std::string;

/**
 * Helper functions so that I don't have to manually make a new ParseInterface
 * and QueryRisk time I want to analyze a query.
 */
///@{
static void checkParseWhitelisted(const string& query);
static void checkParseNotWhitelisted(const string& query);
static void checkRiskWhitelisted(const string &query);
static void checkRiskNotWhitelisted(const string &query);
///@}


/**
 * Individual tests for each line in the whitelist file. Each function here
 * should have a corresponding query entry in the whitelist file.
 */
///@{
static void testParseBlank();
static void testParseKeywords();
static void testParseChangingStrings();
static void testRiskChangedRisks();
///@}


// Called directly from the test suite
void testParseWhitelist()
{
    testParseBlank();
    testParseKeywords();
    testParseChangingStrings();
}


// Called directly from the test suite
void testRiskWhitelist()
{
    testRiskChangedRisks();
}


void testParseBlank()
{
    checkParseWhitelisted(";");
    checkParseNotWhitelisted(";;");
}


void testParseKeywords()
{
    checkParseWhitelisted(
        "SELECT select FROM from WHERE where = not AND and = or"
    );
}


void testParseChangingStrings()
{
    // Identical to the query in the whitelist
    checkParseWhitelisted("SELECT \"foo\" FROM \"bar\" JOIN \"baz\"");

    // Different string literals
    checkParseWhitelisted("SELECT \"bar\" FROM \"baz\" JOIN \"foo\"");
    checkParseWhitelisted("SELECT \"foo\" FROM \"foo\" JOIN \"foo\"");

    // Changing quotation marks
    checkParseWhitelisted("SELECT 'foo' FROM 'foo' JOIN 'foo'");
    checkParseWhitelisted("SELECT \"foo\" FROM 'foo' JOIN \"foo\"");
}


void testRiskChangedRisks()
{
    // The original query to be blocked is:
    // SELECT * FROM something WHERE age > '21' OR 1 = 1 UNION SELECT
    // username, password FROM user -- '

    string longQuery;

    // Test that changing the literal values still blocks the query
    longQuery = "SELECT * FROM something WHERE age > '80' OR 1 = 1 ";
    longQuery += "UNION SELECT username, password FROM user -- '";
    checkRiskWhitelisted(longQuery);
    longQuery = "SELECT * FROM something WHERE age > '21' OR -1 = -1 ";
    longQuery += "UNION SELECT username, password FROM user -- '";
    checkRiskWhitelisted(longQuery);
    longQuery = "SELECT * FROM something WHERE age > '80' OR -1 = -1 ";
    longQuery += "UNION SELECT username, password FROM user -- '";
    checkRiskWhitelisted(longQuery);
    /// @TODO(bskari) should this be blocked? The lexeme stream differs, but
    /// nothing significantly changed
    longQuery = "SELECT * FROM something WHERE age > '80' OR 2 = 1 + 1 ";
    longQuery += "UNION SELECT username, password FROM user -- '";
    checkRiskWhitelisted(longQuery);

    // Test that changing the comment type still blocks the query
    longQuery = "SELECT * FROM something WHERE age > '21' OR -1 = -1 ";
    longQuery += "UNION SELECT username, password FROM user #'";
    checkRiskWhitelisted(longQuery);

    // Test that changing the query risks won't block the query

    // Drop the commented out quote
    longQuery = "SELECT * FROM something WHERE age > '21' OR -1 = -1 ";
    longQuery += "UNION SELECT username, password FROM user";
    checkRiskNotWhitelisted(longQuery);
    longQuery = "SELECT * FROM something WHERE age > '21' OR -1 = -1 ";
    longQuery += "UNION SELECT username, password FROM user -- ";
    checkRiskNotWhitelisted(longQuery);

    // UNION something other than password
    longQuery = "SELECT * FROM something WHERE age > '21' OR -1 = -1 ";
    longQuery += "UNION SELECT favorite_color, age FROM user -- '";
    checkRiskNotWhitelisted(longQuery);

    // UNION against a table other than user
    longQuery = "SELECT * FROM something WHERE age > '21' OR -1 = -1 ";
    longQuery += "UNION SELECT username, password FROM diamonds -- '";
    checkRiskNotWhitelisted(longQuery);

    // Get rid of the always true conditional
    longQuery = "SELECT * FROM something WHERE age > '21' OR 1 = 0 ";
    longQuery += "UNION SELECT username, password FROM user -- '";
    checkRiskNotWhitelisted(longQuery);
    longQuery = "SELECT * FROM something WHERE age > '21' AND -1 = -1 ";
    longQuery += "UNION SELECT username, password FROM user -- '";
    checkRiskNotWhitelisted(longQuery);
}


#if GCC_VERSION >= 40600
    #pragma GCC diagnostic push
#endif
#pragma GCC diagnostic ignored "-Wunused-variable"
void checkParseWhitelisted(const string& query)
{
    ParserInterface pi(query);
    QueryRisk qr;
    // Save the return code so that I don't get compiler warnings
    const int _ = pi.parse(&qr);
    BOOST_CHECK_MESSAGE(
        QueryWhitelist::isParseWhitelisted(pi.getHash()),
        '"' << query << "\" should be parse whitelisted"
    );
}


void checkParseNotWhitelisted(const string& query)
{
    ParserInterface pi(query);
    QueryRisk qr;
    // Save the return code so that I don't get compiler warnings
    const int _ = pi.parse(&qr);
    BOOST_CHECK_MESSAGE(
        !QueryWhitelist::isParseWhitelisted(pi.getHash()),
        '"' << query << "\" should not be parse whitelisted"
    );
}


void checkRiskWhitelisted(const string &query)
{
    ParserInterface pi(query);
    QueryRisk qr;
    // Save the return code so that I don't get compiler warnings
    const int _ = pi.parse(&qr);
    BOOST_CHECK_MESSAGE(
        QueryWhitelist::isBlockWhitelisted(pi.getHash(), qr),
        '"' << query << "\" should be risk whitelisted"
    );
}


void checkRiskNotWhitelisted(const string &query)
{
    ParserInterface pi(query);
    QueryRisk qr;
    // Save the return code so that I don't get compiler warnings
    const int _ = pi.parse(&qr);
    BOOST_CHECK_MESSAGE(
        !QueryWhitelist::isBlockWhitelisted(pi.getHash(), qr),
        '"' << query << "\" should not be risk whitelisted"
    );
}


#if GCC_VERSION >= 40600
    #pragma GCC diagnostic pop
#else
    #pragma GCC diagnostic warning "-Wunused-variable"
#endif
