/*
 * SQLassie - database firewall
 * Copyright (C) 2012 Brandon Skari <brandon.skari@gmail.com>
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
 * Tests that various properties of queries that can be indicative of an
 * attack, like always true, are correctly identified.
 * @author Brandon Skari
 * @date July 21 2012
 */

#include "testParser.hpp"
#include "../ParserInterface.hpp"
#include "../QueryRisk.hpp"

#include <boost/algorithm/string.hpp>
// Newer versions of the Boost filesystem (1.44+) changed the interface; to
// keep compatibility, default to the old version
#define BOOST_FILESYSTEM_VERSION 2
#include <boost/filesystem.hpp>
#include <boost/test/unit_test.hpp>
#include <fstream>
#include <string>

using std::ifstream;
using std::string;

/**
 * Parses a query and returns the risks found.
 * @param query The query to be parsed.
 */
static QueryRisk parseQuery(const string& query);


void testQueryRiskSafe()
{
    QueryRisk qr;
    // No risk
    qr = parseQuery("SELECT * FROM foo");
    BOOST_CHECK(0 == qr.multiLineComments);
    BOOST_CHECK(0 == qr.hashComments);
    BOOST_CHECK(0 == qr.dashDashComments);
    BOOST_CHECK(0 == qr.mySqlComments);
    BOOST_CHECK(0 == qr.mySqlVersionedComments);
    BOOST_CHECK(0 == qr.sensitiveTables);
    BOOST_CHECK(0 == qr.orStatements);
    BOOST_CHECK(0 == qr.unionStatements);
    BOOST_CHECK(0 == qr.unionAllStatements);
    BOOST_CHECK(0 == qr.bruteForceCommands);
    BOOST_CHECK(0 == qr.ifStatements);
    BOOST_CHECK(0 == qr.hexStrings);
    BOOST_CHECK(0 == qr.benchmarkStatements);
    BOOST_CHECK(0 == qr.userStatements);
    BOOST_CHECK(0 == qr.fingerprintingStatements);
    BOOST_CHECK(0 == qr.mySqlStringConcat);
    BOOST_CHECK(0 == qr.stringManipulationStatements);
    BOOST_CHECK(0 == qr.alwaysTrueConditional);
    BOOST_CHECK(0 == qr.commentedConditionals);
    BOOST_CHECK(0 == qr.commentedQuotes);
    BOOST_CHECK(0 == qr.globalVariables);
    BOOST_CHECK(0 == qr.joinStatements);
    BOOST_CHECK(0 == qr.crossJoinStatements);
    BOOST_CHECK(0 == qr.regexLength);
    BOOST_CHECK(0 == qr.slowRegexes);
    BOOST_CHECK(QueryRisk::PASSWORD_NOT_USED == qr.emptyPassword);
}


void testQueryRiskComments()
{
    QueryRisk qr;

    qr = parseQuery("SELECT * FROM foo /* multi line C-style comment */");
    BOOST_CHECK(1 == qr.multiLineComments);

    qr = parseQuery("SELECT * FROM foo /* /* ///* /*embedded*******/");
    BOOST_CHECK(1 == qr.multiLineComments);

    qr = parseQuery("SELECT * FROM foo /*Even**/");
    BOOST_CHECK(1 == qr.multiLineComments);

    qr = parseQuery("SELECT * FROM foo /*Odd***/");
    BOOST_CHECK(1 == qr.multiLineComments);

    qr = parseQuery("SELECT * FROM foo /*\nMultiple\nlines\n*/");
    BOOST_CHECK(1 == qr.multiLineComments);

    qr = parseQuery("SELECT * FROM foo /*\nMultiple*/\n/*comments\n*/");
    BOOST_CHECK(2 == qr.multiLineComments);

    qr = parseQuery("SELECT * FROM foo /**/ # Short comment");
    BOOST_CHECK(1 == qr.multiLineComments);

    qr = parseQuery("SELECT * FROM foo /**//**/ # Double short comment");
    BOOST_CHECK(2 == qr.multiLineComments);

    qr = parseQuery("SELECT * FROM foo # MySQL hash style comments");
    BOOST_CHECK(1 == qr.hashComments);

    qr = parseQuery("SELECT * FROM foo #compact");
    BOOST_CHECK(1 == qr.hashComments);

    qr = parseQuery("SELECT * FROM foo #line 1\n#line 2");
    BOOST_CHECK(2 == qr.hashComments);

    qr = parseQuery("SELECT * FROM foo ######### Still one comment");
    BOOST_CHECK(1 == qr.hashComments);

    qr = parseQuery("SELECT * FROM foo -- Line comment");
    BOOST_CHECK(1 == qr.dashDashComments);

    // According to the MySQL docs, this is not a comment!
    // See http://dev.mysql.com/doc/refman/5.0/en/ansi-diff-comments.html
    qr = parseQuery("UPDATE account SET credit=credit--1");
    BOOST_CHECK(0 == qr.dashDashComments);

    // But this is
    qr = parseQuery("UPDATE account SET credit=credit-- 1");
    BOOST_CHECK(1 == qr.dashDashComments);

    qr = parseQuery("UPDATE account SET credit=credit-- 1 -- more comments");
    BOOST_CHECK(1 == qr.dashDashComments);

    qr = parseQuery("UPDATE account SET credit=credit--\n ");
    BOOST_CHECK(1 == qr.dashDashComments);

    qr = parseQuery("UPDATE account SET credit=credit--\t ");
    BOOST_CHECK(1 == qr.dashDashComments);

    qr = parseQuery("SELECT * FROM foo /*! MySQL specific */");
    BOOST_CHECK(0 == qr.multiLineComments);
    BOOST_CHECK(1 == qr.mySqlComments);
    BOOST_CHECK(0 == qr.mySqlVersionedComments);

    qr = parseQuery("SELECT * FROM foo /*!compacted*/");
    BOOST_CHECK(0 == qr.multiLineComments);
    BOOST_CHECK(1 == qr.mySqlComments);
    BOOST_CHECK(0 == qr.mySqlVersionedComments);

    // I don't know what the canonical MySQL behavior here is...
    // I don't think it matters either way though
    qr = parseQuery("SELECT * FROM foo /*!*/");
    BOOST_CHECK(0 == qr.multiLineComments);
    BOOST_CHECK(1 == qr.mySqlComments);
    BOOST_CHECK(0 == qr.mySqlVersionedComments);

    qr = parseQuery("SELECT * FROM foo /*! /* /* nested! */");
    BOOST_CHECK(0 == qr.multiLineComments);
    BOOST_CHECK(1 == qr.mySqlComments);
    BOOST_CHECK(0 == qr.mySqlVersionedComments);

    qr = parseQuery("SELECT * FROM foo /* ! space => regular */");
    BOOST_CHECK(1 == qr.multiLineComments);
    BOOST_CHECK(0 == qr.mySqlComments);
    BOOST_CHECK(0 == qr.mySqlVersionedComments);


    qr = parseQuery("SELECT * FROM foo /*!12345 */");
    BOOST_CHECK(0 == qr.multiLineComments);
    BOOST_CHECK(0 == qr.mySqlComments);
    BOOST_CHECK(1 == qr.mySqlVersionedComments);

    qr = parseQuery("SELECT * FROM foo /*!12345 more versioned */");
    BOOST_CHECK(0 == qr.multiLineComments);
    BOOST_CHECK(0 == qr.mySqlComments);
    BOOST_CHECK(1 == qr.mySqlVersionedComments);

    qr = parseQuery(
        "SELECT * FROM foo /*!123457 long still counts as version */"
    );
    BOOST_CHECK(0 == qr.multiLineComments);
    BOOST_CHECK(0 == qr.mySqlComments);
    BOOST_CHECK(1 == qr.mySqlVersionedComments);

    qr = parseQuery("SELECT * FROM foo /*!1237 too short! not version */");
    BOOST_CHECK(0 == qr.multiLineComments);
    BOOST_CHECK(1 == qr.mySqlComments);
    BOOST_CHECK(0 == qr.mySqlVersionedComments);

    qr = parseQuery("SELECT * FROM foo /*!1 too short! not version */");
    BOOST_CHECK(0 == qr.multiLineComments);
    BOOST_CHECK(1 == qr.mySqlComments);
    BOOST_CHECK(0 == qr.mySqlVersionedComments);
}


void testQueryRiskSensitiveTables()
{
    QueryRisk qr;

    // Sensitive tables as of July 15 2012 (taken from QueryRisk.cpp)
    // customer member admin user permission session

    qr = parseQuery("SELECT * FROM customer");
    BOOST_CHECK(1 == qr.sensitiveTables);

    qr = parseQuery("SELECT name, password FROM user WHERE name = 'quote'");
    BOOST_CHECK(1 == qr.sensitiveTables);

    qr = parseQuery(
        "SELECT COUNT(*) FROM benign_table "
        "UNION SELECT password FROM user"
    );
    BOOST_CHECK(1 == qr.sensitiveTables);

    qr = parseQuery(
        "SELECT u.name, u.password, s.csrf, s.token "
        "FROM user u JOIN session s ON u.id = s.user_id"
    );
    BOOST_CHECK(2 == qr.sensitiveTables);

    qr = parseQuery("DELETE FROM admin WHERE id = 1");
    BOOST_CHECK(1 == qr.sensitiveTables);

    qr = parseQuery("INSERT INTO permission (user_id, flags) VALUES (1, 2)");
    BOOST_CHECK(1 == qr.sensitiveTables);
}


void testQueryRiskOrStatements()
{
    QueryRisk qr;

    qr = parseQuery("SELECT * FROM user WHERE flags & 0x01 = 0");
    BOOST_CHECK(0 == qr.orStatements);

    qr = parseQuery("SELECT * FROM user WHERE flags & 0x01 = 0 OR age > 21");
    BOOST_CHECK(1 == qr.orStatements);

    qr = parseQuery(
        "SELECT * FROM user u JOIN email e ON e.user_id = u.id"
        " WHERE flags & 0x01 = 0 OR age > 21 OR"
        " (SELECT COUNT(*) FROM email WHERE flags & 0x01 = 0 OR time > NOW()"
        " GROUP BY user_id);"
    );
    BOOST_CHECK(3 == qr.orStatements);

    qr = parseQuery("SELECT * FROM user WHERE 1 = 1 OR 1 OR 1 OR 1 OR 1 OR 1");
    BOOST_CHECK(5 == qr.orStatements);
}


void testQueryRiskUnionStatements()
{
    QueryRisk qr;

    qr = parseQuery("SELECT * FROM user WHERE flags & 0x01 = 0");
    BOOST_CHECK(0 == qr.unionStatements);

    qr = parseQuery("SELECT * FROM user WHERE id = 5 UNION SELECT 1, 'admin'");
    BOOST_CHECK(1 == qr.unionStatements);

    // UNION ALL statements also count as UNIONs
    qr = parseQuery("SELECT * FROM user WHERE id = 5 UNION ALL SELECT 1, 'a'");
    BOOST_CHECK(1 == qr.unionStatements);

    qr = parseQuery(
        "SELECT * FROM user u JOIN email e ON e.user_id = u.id"
        " UNION SELECT 1, (SELECT MAX(age) FROM user) AS max_age, 'admin'"
        " UNION SELECT 2, (SELECT MIN(age) FROM user) AS min_age, 'admin'"
    );
    BOOST_CHECK(2 == qr.unionStatements);
}


void testQueryRiskUnionAllStatements()
{
    QueryRisk qr;

    qr = parseQuery("SELECT * FROM user WHERE flags & 0x01 = 0");
    BOOST_CHECK(0 == qr.unionAllStatements);

    // UNION statements shouldn't be counted as UNION ALL statements
    qr = parseQuery("SELECT * FROM user WHERE id = 5 UNION SELECT 1, 'admin'");
    BOOST_CHECK(0 == qr.unionAllStatements);

    qr = parseQuery("SELECT * FROM user WHERE id = 5 UNION ALL SELECT 1, 'a'");
    BOOST_CHECK(1 == qr.unionStatements);

    qr = parseQuery(
        "SELECT * FROM user u JOIN email e ON e.user_id = u.id"
        " UNION ALL SELECT 1, (SELECT MAX(age) FROM user) AS max_age, 'admin'"
        " UNION ALL SELECT 2, (SELECT MIN(age) FROM user) AS min_age, 'admin'"
    );
    BOOST_CHECK(2 == qr.unionStatements);
}


void testQueryRiskBruteForceCommands()
{
    QueryRisk qr;

    // Current list of brute force commands
    // mid substr substring load_file char

    // Check for mid (upper and lowercase)
    qr = parseQuery(
        "SELECT * FROM user WHERE username = 'u' AND password = 'p'"
        " AND (SELECT MID(password, 1, 1) AS p FROM user u WHERE p < 'n')"
    );
    BOOST_CHECK(1 == qr.bruteForceCommands);
    qr = parseQuery(
        "SELECT * FROM user WHERE username = 'u' AND password = 'p'"
        " AND (SELECT mid(password, 1, 1) AS p FROM user u WHERE p < 'n')"
    );
    BOOST_CHECK(1 == qr.bruteForceCommands);

    // Check for substr and substring (upper and lowercase)
    qr = parseQuery(
        "SELECT * FROM user WHERE username = 'u' AND password = 'p'"
        " AND (SELECT SUBSTR(password, 1, 1) AS p FROM user u WHERE p < 'n')"
    );
    BOOST_CHECK(1 == qr.bruteForceCommands);
    qr = parseQuery(
        "SELECT * FROM user WHERE username = 'u' AND password = 'p'"
        " AND (SELECT substr(password, 1, 1) AS p FROM user u WHERE p < 'n')"
    );
    BOOST_CHECK(1 == qr.bruteForceCommands);
    qr = parseQuery(
        "SELECT * FROM user WHERE username = 'u' AND password = 'p'"
        " AND (SELECT SUBSTRING(password, 1, 1) AS p FROM user u WHERE p < 'n')"
    );
    BOOST_CHECK(1 == qr.bruteForceCommands);
    qr = parseQuery(
        "SELECT * FROM user WHERE username = 'u' AND password = 'p'"
        " AND (SELECT substring(password, 1, 1) AS p FROM user u WHERE p < 'n')"
    );
    BOOST_CHECK(1 == qr.bruteForceCommands);

    // Check for load_file (upper and lowercase)
    BOOST_CHECK(1 == qr.bruteForceCommands);
    qr = parseQuery(
        "SELECT * FROM user WHERE username = 'u' AND password = 'p'"
        " UNION SELECT LOAD_FILE('/etc/passwd')"
    );
    BOOST_CHECK(1 == qr.bruteForceCommands);
    qr = parseQuery(
        "SELECT * FROM user WHERE username = 'u' AND password = 'p'"
        " UNION SELECT load_file('/etc/passwd')"
    );
    BOOST_CHECK(1 == qr.bruteForceCommands);

    // Check for char (upper and lowercase)
    BOOST_CHECK(1 == qr.bruteForceCommands);
    qr = parseQuery(
        "SELECT * FROM post WHERE id = 729"
        " UNION SELECT * FROM user "
        " WHERE name LIKE CHAR(34, 37, 97, 100, 109, 105, 110, 37, 34)"
    );
    BOOST_CHECK(1 == qr.bruteForceCommands);
    qr = parseQuery(
        "SELECT * FROM post WHERE id = 729"
        " UNION SELECT * FROM user "
        " WHERE name LIKE char(34, 37, 97, 100, 109, 105, 110, 37, 34)"
    );
    BOOST_CHECK(1 == qr.bruteForceCommands);
}


void testQueryRiskIfStatements()
{
    BOOST_CHECK_MESSAGE(false, "Not implemented");
}


void testQueryRiskHexStrings()
{
    BOOST_CHECK_MESSAGE(false, "Not implemented");
}


void testQueryRiskBenchmarkStatements()
{
    BOOST_CHECK_MESSAGE(false, "Not implemented");
}


void testQueryRiskUserStatements()
{
    BOOST_CHECK_MESSAGE(false, "Not implemented");
}


void testQueryRiskFingerprintingStatements()
{
    BOOST_CHECK_MESSAGE(false, "Not implemented");
}


void testQueryRiskMySqlStringConcat()
{
    BOOST_CHECK_MESSAGE(false, "Not implemented");
}


void testQueryRiskStringManipulationStatements()
{
    BOOST_CHECK_MESSAGE(false, "Not implemented");
}


void testQueryRiskAlwaysTrueConditional()
{
    QueryRisk qr;

    // ------------------------------------------------------------------------
    // expression IN (expression, expression, expression, ...)
    // ------------------------------------------------------------------------

    qr = parseQuery("SELECT * FROM foo WHERE 1 IN (1)");
    BOOST_CHECK(qr.alwaysTrue);

    qr = parseQuery("SELECT * FROM foo WHERE 1 IN (1, 2, 3)");
    BOOST_CHECK(qr.alwaysTrue);

    qr = parseQuery("SELECT * FROM foo WHERE 1 IN (4, 3, 2, 1)");
    BOOST_CHECK(qr.alwaysTrue);

    qr = parseQuery(
        "SELECT * FROM foo WHERE 1 IN (4, 3, 2, (SELECT age FROM user), 1)"
    );
    BOOST_CHECK(qr.alwaysTrue);

    qr = parseQuery("SELECT * FROM foo WHERE -45 IN (-50, -45, -40)");
    BOOST_CHECK(qr.alwaysTrue);

    qr = parseQuery("SELECT * FROM foo WHERE 1 IN ('1')");
    BOOST_CHECK(qr.alwaysTrue);

    qr = parseQuery("SELECT * FROM foo WHERE '1' IN (1)");
    BOOST_CHECK(qr.alwaysTrue);

    qr = parseQuery("SELECT * FROM foo WHERE '1' IN ('3' - '2')");
    BOOST_CHECK(qr.alwaysTrue);

    qr = parseQuery(
        "SELECT * FROM foo WHERE 'a' IN ('aa', 'ab', 'ac', 'a', 'ad')"
    );
    BOOST_CHECK(qr.alwaysTrue);

    // ------------------------------------------------------------------------
    // expression NOT IN (expression, expression, expression, ...)
    // ------------------------------------------------------------------------

    // Subselects shouldn't be detectable as always true
    qr = parseQuery("SELECT * FROM foo WHERE 1 NOT IN (SELECT 1)");
    BOOST_CHECK(!qr.alwaysTrue);

    qr = parseQuery("SELECT * FROM foo WHERE 1 NOT IN (0)");
    BOOST_CHECK(qr.alwaysTrue);

    qr = parseQuery("SELECT * FROM foo WHERE 1 NOT IN (0, 2, 3)");
    BOOST_CHECK(qr.alwaysTrue);

    qr = parseQuery("SELECT * FROM foo WHERE 1 IN (4, 3, 2, 0)");
    BOOST_CHECK(!qr.alwaysTrue);

    qr = parseQuery(
        "SELECT * FROM foo WHERE 1 NOT IN (4, 3, 2, (SELECT age FROM user), 0)"
    );
    BOOST_CHECK(qr.alwaysTrue);

    qr = parseQuery("SELECT * FROM foo WHERE -45 NOT IN (-50, -40)");
    BOOST_CHECK(qr.alwaysTrue);

    qr = parseQuery("SELECT * FROM foo WHERE 1 NOT IN ('2')");
    BOOST_CHECK(qr.alwaysTrue);

    qr = parseQuery("SELECT * FROM foo WHERE '1' NOT IN ('2')");
    BOOST_CHECK(qr.alwaysTrue);

    qr = parseQuery("SELECT * FROM foo WHERE '1' NOT IN ('3' + '2')");
    BOOST_CHECK(qr.alwaysTrue);

    qr = parseQuery(
        "SELECT * FROM foo WHERE 'a' NOT IN ('aa', 'ab', 'ac', 'ad')"
    );
    BOOST_CHECK(qr.alwaysTrue);

    // ------------------------------------------------------------------------
    // expression BETWEEN expression AND expression
    // ------------------------------------------------------------------------
    qr = parseQuery("SELECT * FROM f WHERE 2 BETWEEN 1 AND 3");
    BOOST_CHECK(qr.alwaysTrue);

    qr = parseQuery("SELECT * FROM f WHERE 0 BETWEEN -1 AND 1");
    BOOST_CHECK(qr.alwaysTrue);

    qr = parseQuery("SELECT * FROM f WHERE 1 BETWEEN -1 AND 1");
    BOOST_CHECK(qr.alwaysTrue);

    qr = parseQuery("SELECT * FROM f WHERE -1 BETWEEN -1 AND 1");
    BOOST_CHECK(qr.alwaysTrue);

    qr = parseQuery("SELECT * FROM f WHERE 0 BETWEEN 1 AND -1");
    BOOST_CHECK(!qr.alwaysTrue);

    qr = parseQuery("SELECT * FROM f WHERE 1 BETWEEN 1 AND 1");
    BOOST_CHECK(qr.alwaysTrue);

    // ------------------------------------------------------------------------
    // mathematical comparisons
    // ------------------------------------------------------------------------

    qr = parseQuery("SELECT * FROM foo WHERE 1 = 1");
    BOOST_CHECK(qr.alwaysTrue);

    qr = parseQuery("SELECT * FROM foo WHERE 1 != 2");
    BOOST_CHECK(qr.alwaysTrue);

    qr = parseQuery("SELECT * FROM foo WHERE 1 = '1'");
    BOOST_CHECK(qr.alwaysTrue);

    qr = parseQuery("SELECT * FROM foo WHERE '1' = 1");
    BOOST_CHECK(qr.alwaysTrue);

    qr = parseQuery("SELECT * FROM foo WHERE 2 > 1");
    BOOST_CHECK(qr.alwaysTrue);

    qr = parseQuery("SELECT * FROM foo WHERE 1 >= 1");
    BOOST_CHECK(qr.alwaysTrue);

    qr = parseQuery("SELECT * FROM foo WHERE 1 < 2");
    BOOST_CHECK(qr.alwaysTrue);

    qr = parseQuery("SELECT * FROM foo WHERE 1 <= 2");
    BOOST_CHECK(qr.alwaysTrue);

    qr = parseQuery("SELECT * FROM foo WHERE NOT (1 > 2)");
    BOOST_CHECK(qr.alwaysTrue);

    qr = parseQuery("SELECT * FROM foo WHERE !(1 > 2)");
    BOOST_CHECK(qr.alwaysTrue);

    qr = parseQuery("SELECT * FROM foo WHERE !!!(1 > 2)");
    BOOST_CHECK(qr.alwaysTrue);

    qr = parseQuery("SELECT * FROM foo WHERE NOT NOT !!!(1 > 2)");
    BOOST_CHECK(qr.alwaysTrue);

    qr = parseQuery("SELECT * FROM foo WHERE 1 + 1 = 2");
    BOOST_CHECK(qr.alwaysTrue);

    qr = parseQuery("SELECT * FROM foo WHERE 1 > 2");
    BOOST_CHECK(!qr.alwaysTrue);

    qr = parseQuery("SELECT * FROM foo WHERE 2 <= 1");
    BOOST_CHECK(!qr.alwaysTrue);

    qr = parseQuery("SELECT * FROM foo WHERE (1 + 1) & 0x01 = 1");
    BOOST_CHECK(qr.alwaysTrue);

    qr = parseQuery("SELECT * FROM foo WHERE (1 << 4) = 0x10");
    BOOST_CHECK(qr.alwaysTrue);

    qr = parseQuery("SELECT * FROM foo WHERE (1 << 2) | 0x10 = 0x14");
    BOOST_CHECK(qr.alwaysTrue);

    qr = parseQuery(
        "SELECT * FROM foo WHERE (0x08 >> 3) |"
        " (0x04 >> 2) | (0x02 >> 1) | (0x01 >> 0) = 0x01"
    );
    BOOST_CHECK(qr.alwaysTrue);

    qr = parseQuery(
        "SELECT * FROM foo WHERE (1 << 0) |"
        "(1 << 1) | (1 << 2) | (1 << 4) = 15"
    );
    BOOST_CHECK(qr.alwaysTrue);

    qr = parseQuery("SELECT * FROM foo WHERE 1 = 1.0");
    BOOST_CHECK(qr.alwaysTrue);

    qr = parseQuery("SELECT * FROM foo WHERE 1.0 = 1");
    BOOST_CHECK(qr.alwaysTrue);

    qr = parseQuery("SELECT * FROM foo WHERE 1.0000 = 1.0");
    BOOST_CHECK(qr.alwaysTrue);

    const char* const zeroes[] = {"0", "0.", ".0", "0.0"};
    string s("SELECT * FROM f WHERE ");
    for (size_t i = 0; i < sizeof(zeroes) / sizeof(zeroes[0]); ++i)
    {
        for (size_t j = 0; j < sizeof(zeroes) / sizeof(zeroes[0]); ++j)
        {
            qr = parseQuery(s + zeroes[i] + " = " + zeroes[j]);
            BOOST_CHECK(qr.alwaysTrue);
        }
    }

    qr = parseQuery("SELECT * FROM u WHERE age + 1 = age + 1");
    BOOST_CHECK(qr.alwaysTrue);

    qr = parseQuery("SELECT * FROM u WHERE age + 1 = 1 + age");
    BOOST_CHECK(qr.alwaysTrue);

    qr = parseQuery("SELECT * FROM u WHERE age + 3 = 1 + age * 1 + 2");
    BOOST_CHECK(qr.alwaysTrue);

    // ------------------------------------------------------------------------
    // string comparisons
    // ------------------------------------------------------------------------

    // MySQL is case insensitive
    qr = parseQuery("SELECT * FROM foo WHERE 'brandon' = 'BRANDON'");
    BOOST_CHECK(qr.alwaysTrue);

    qr = parseQuery("SELECT * FROM foo WHERE 'bRaNdOn' = 'brandon'");
    BOOST_CHECK(qr.alwaysTrue);

    qr = parseQuery("SELECT * FROM foo WHERE 'bRaNdOn' != 'not brandon'");
    BOOST_CHECK(qr.alwaysTrue);

    qr = parseQuery("SELECT * FROM foo WHERE 'brandon' != 'not brandon'");
    BOOST_CHECK(qr.alwaysTrue);

    // ------------------------------------------------------------------------
    // and/or/xor statements
    // ------------------------------------------------------------------------
    qr = parseQuery("SELECT * FROM foo WHERE 1 = 1 AND 1 = 2");
    BOOST_CHECK(!qr.alwaysTrue);

    qr = parseQuery("SELECT * FROM foo WHERE 1 = 0 OR 1 = 1");
    BOOST_CHECK(qr.alwaysTrue);

    qr = parseQuery("SELECT * FROM foo WHERE (1 = 2 OR 1 = 1) AND 1 = 2");
    BOOST_CHECK(!qr.alwaysTrue);

    qr = parseQuery("SELECT * FROM foo WHERE (1 = 2 OR 2 = 2) AND (1 = 1)");
    BOOST_CHECK(qr.alwaysTrue);

    qr = parseQuery(
        "SELECT * FROM foo WHERE ((1 = 1) AND (1 = 2)) "
        "OR (1 = 1 AND (1 = 2 OR 2 = 3))"
    );
    BOOST_CHECK(!qr.alwaysTrue);

    qr = parseQuery("SELECT * FROM foo WHERE (1 = 2) XOR (2 = 3)");
    BOOST_CHECK(qr.alwaysTrue);

    qr = parseQuery("SELECT * FROM foo WHERE (1 = 2) XOR (2 = 2)");
    BOOST_CHECK(!qr.alwaysTrue);
}


void testQueryRiskCommentedConditionals()
{
    BOOST_CHECK_MESSAGE(false, "Not implemented");
}


void testQueryRiskCommentedQuotes()
{
    BOOST_CHECK_MESSAGE(false, "Not implemented");
}


void testQueryRiskGlobalVariables()
{
    QueryRisk qr;

    qr = parseQuery("SELECT @@host");
    BOOST_CHECK(1 == qr.globalVariables);

    qr = parseQuery(
        "SELECT @@version, @@version_comment, "
        "@@version_compile_machine, @@version_compile_os"
    );
    BOOST_CHECK(4 == qr.globalVariables);

    qr = parseQuery(
        "SELECT @@version, @@version_comment "
        "UNION SELECT @@version_compile_machine, @@version_compile_os"
    );
    BOOST_CHECK(4 == qr.globalVariables);

    qr = parseQuery(
        "SELECT CONCAT(@@version, ' ', @@version_comment, "
        "' ', @@version_compile_machine, ' ', @@version_compile_os)"
    );
    BOOST_CHECK(4 == qr.globalVariables);
}


void testQueryRiskJoinStatements()
{
    BOOST_CHECK_MESSAGE(false, "Not implemented");
}


void testQueryRiskCrossJoinStatements()
{
    BOOST_CHECK_MESSAGE(false, "Not implemented");
}


void testQueryRiskRegexLength()
{
    BOOST_CHECK_MESSAGE(false, "Not implemented");
}


void testQueryRiskSlowRegexes()
{
    BOOST_CHECK_MESSAGE(false, "Not implemented");
}


void testQueryRiskEmptyPassword()
{
    BOOST_CHECK_MESSAGE(false, "Not implemented");
}


void testQueryRiskMultipleQueries()
{
    BOOST_CHECK_MESSAGE(false, "Not implemented");
}


void testQueryRiskOrderByNumber()
{
    BOOST_CHECK_MESSAGE(false, "Not implemented");
}


void testQueryRiskAlwaysTrue()
{
    BOOST_CHECK_MESSAGE(false, "Not implemented");
}


void testQueryRiskInformationSchema()
{
    BOOST_CHECK_MESSAGE(false, "Not implemented");
}


void testQueryRiskValid()
{
    BOOST_CHECK_MESSAGE(false, "Not implemented");
}


void testQueryRiskUserTable()
{
    BOOST_CHECK_MESSAGE(false, "Not implemented");
}


QueryRisk parseQuery(const string& query)
{
    QueryRisk qr;
    ParserInterface parser(query);
    const bool successfullyParsed = parser.parse(&qr);
    BOOST_CHECK_MESSAGE(
        successfullyParsed,
        "Query failed to parse: " << query
    );
    return qr;
}
