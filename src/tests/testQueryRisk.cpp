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
    BOOST_CHECK(0 == qr.alwaysTrueConditionals);
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
    QueryRisk qr;

    qr = parseQuery(
        "INSERT INTO USER (name, password, age) VALUES ('B', 'p', IF("
        " (SELECT SUBSTR(password, 1, 1) FROM user WHERE name = 'admin') < 'f',"
        " BENCHMARK(1000000, MD5('f')),"
        " 1"
        "))"
    );
    BOOST_CHECK(1 == qr.ifStatements);
}


void testQueryRiskHexStrings()
{
    QueryRisk qr;

    // --------------------------------------------------------
    // Situations where hex digits are used as numbers are okay
    // --------------------------------------------------------

    // Binary operators should imply that it's a number
    qr = parseQuery("SELECT * FROM user WHERE flags & 0x01 = 0");
    BOOST_CHECK(0 == qr.hexStrings);

    // This should be determinable as a number because it's being compared to
    // an integer
    qr = parseQuery("SELECT * FROM user WHERE flags + 0x01 = 0");
    BOOST_CHECK(0 == qr.hexStrings);

    // ----------------------------------------------------
    // Situations where hex digits are strings are not okay
    // ----------------------------------------------------

    // Like statements always use strings
    qr = parseQuery("SELECT * FROM user WHERE name LIKE 0x61646d696e");
    BOOST_CHECK(1 == qr.hexStrings);

    // Comparing strings should imply that it's a string
    qr = parseQuery("SELECT * FROM user WHERE 'admin' = 0x61646D696E");
    BOOST_CHECK(1 == qr.hexStrings);

    // -----------------------------------------------------------------------
    // Some cases depend on the schema and are indeterminate from SQLassie, so
    // they shouldn't be counted
    // -----------------------------------------------------------------------

    qr = parseQuery("SELECT * FROM user WHERE name = 0x61646D696E");
    BOOST_CHECK(0 == qr.hexStrings);
}


void testQueryRiskBenchmarkStatements()
{
    QueryRisk qr;

    qr = parseQuery(
        "INSERT INTO USER (name, password, age) VALUES ('B', 'p', IF("
        " (SELECT SUBSTR(password, 1, 1) FROM user WHERE name = 'admin') < 'f',"
        " BENCHMARK(1000000, MD5('f')),"
        " 1"
        "))"
    );
    BOOST_CHECK(1 == qr.benchmarkStatements);
}


void testQueryRiskUserStatements()
{
    QueryRisk qr;

    // User tables are OK - MySQL user functions are not
    qr = parseQuery("SELECT * FROM user WHERE username = 'f'");
    BOOST_CHECK(0 == qr.userStatements);

    qr = parseQuery("SELECT user()");
    BOOST_CHECK(1 == qr.userStatements);
    qr = parseQuery("SELECT USER()");
    BOOST_CHECK(1 == qr.userStatements);
    qr = parseQuery("SELECT current_user()");
    BOOST_CHECK(1 == qr.userStatements);
    // current_user is both a function and a reserved word that returns the
    // value of the function call
    qr = parseQuery("SELECT current_user");
    BOOST_CHECK(1 == qr.userStatements);
    qr = parseQuery("SELECT session_user()");
    BOOST_CHECK(1 == qr.userStatements);
    qr = parseQuery("SELECT system_user()");
    BOOST_CHECK(1 == qr.userStatements);

    qr = parseQuery("SELECT * FROM permission UNION SELECT user(), host()");
    BOOST_CHECK(1 == qr.userStatements);

    qr = parseQuery(
        "SELECT * FROM email WHERE SUBSTR(current_user(), 1, 1) < 'f'"
    );
    BOOST_CHECK(1 == qr.userStatements);
}


void testQueryRiskFingerprintingStatements()
{
    QueryRisk qr;

    qr = parseQuery("SELECT id FROM user UNION SELECT schema()");
    BOOST_CHECK(1 == qr.fingerprintingStatements);
    qr = parseQuery("SELECT id FROM user UNION SELECT SCHEMA()");
    BOOST_CHECK(1 == qr.fingerprintingStatements);
    qr = parseQuery("SELECT id FROM user UNION SELECT database()");
    BOOST_CHECK(1 == qr.fingerprintingStatements);
    qr = parseQuery("SELECT id FROM user UNION SELECT version()");
    BOOST_CHECK(1 == qr.fingerprintingStatements);
    qr = parseQuery("SELECT id FROM user UNION SELECT connection_id()");
    BOOST_CHECK(1 == qr.fingerprintingStatements);
    qr = parseQuery("SELECT id FROM user UNION SELECT last_insert_id()");
    BOOST_CHECK(1 == qr.fingerprintingStatements);
    qr = parseQuery("SELECT id FROM user UNION SELECT row_count()");
    BOOST_CHECK(1 == qr.fingerprintingStatements);
}


void testQueryRiskMySqlStringConcat()
{
    // MySQL implicitly concatenates adjacent strings, just like C++
    QueryRisk qr;

    qr = parseQuery("SELECT 'a' 'b'");
    BOOST_CHECK(1 == qr.mySqlStringConcat);
    qr = parseQuery("SELECT 'a' 'b' 'c'");
    BOOST_CHECK(2 == qr.mySqlStringConcat);
    qr = parseQuery("SELECT 'a' 'b' 'c' 'd'");
    BOOST_CHECK(3 == qr.mySqlStringConcat);

    qr = parseQuery("SELECT * FROM user WHERE 'a' 'bc' = 'a' 'bc'");
    BOOST_CHECK(2 == qr.mySqlStringConcat);
}


void testQueryRiskStringManipulationStatements()
{
    QueryRisk qr;

    qr = parseQuery(
        "SELECT id FROM user UNION SELECT concat(name, password) FROM user"
    );
    BOOST_CHECK(1 == qr.stringManipulationStatements);
    qr = parseQuery(
        "SELECT id FROM user UNION SELECT CONCAT(name, password) FROM user"
    );
    BOOST_CHECK(1 == qr.stringManipulationStatements);
    qr = parseQuery(
        "SELECT id FROM user WHERE name = 'Brandon'"
        " OR name LIKE CHAR(34, 37, 97, 100, 109, 105, 110, 37, 34) -- ' "
    );
    BOOST_CHECK(1 == qr.stringManipulationStatements);
    qr = parseQuery(
        "SELECT id, password FROM user WHERE name = 'Brandon'"
        " OR name LIKE INSERT('admn', 4, 0, 'i') -- '"
    );
    BOOST_CHECK(1 == qr.stringManipulationStatements);
    qr = parseQuery(
        "SELECT id, password FROM user WHERE name = 'Brandon'"
        " OR HEX(name) = '61646D696E' -- '"
    );
    BOOST_CHECK(1 == qr.stringManipulationStatements);
    qr = parseQuery(
        "SELECT id, password FROM user WHERE name = 'Brandon'"
        " OR name = MID('zzzadminzzz', 4, 5) -- '"
    );
    BOOST_CHECK(1 == qr.stringManipulationStatements);
    qr = parseQuery(
        "SELECT id, password FROM user WHERE name = 'Brandon'"
        " OR name = REPLACE('zzzadminzzz', 'zzz', '') -- '"
    );
    BOOST_CHECK(1 == qr.stringManipulationStatements);
    qr = parseQuery(
        "SELECT id, password FROM user WHERE name = 'Brandon'"
        " OR name = REVERSE('nimda') -- '"
    );
    BOOST_CHECK(1 == qr.stringManipulationStatements);
    qr = parseQuery(
        "SELECT id, password FROM user WHERE name = 'Brandon'"
        " OR name = SUBSTR('zzzadminzzz', 4, 5) -- '"
    );
    BOOST_CHECK(1 == qr.stringManipulationStatements);
    qr = parseQuery(
        "SELECT id, password FROM user WHERE name = 'Brandon'"
        " OR name = SUBSTRING('zzzadminzzz', 4, 5) -- '"
    );
    BOOST_CHECK(1 == qr.stringManipulationStatements);
}


void testQueryRiskAlwaysTrueConditionals()
{
    QueryRisk qr;

    qr = parseQuery("SELECT * FROM foo WHERE 1 IN (1)");
    BOOST_CHECK(1 == qr.alwaysTrueConditionals);

    qr = parseQuery(
        "SELECT * FROM foo WHERE 1 IN (1, 2, 3)"
        " AND 1 = 1"
        " AND 5 > 0 + 4"
    );
    BOOST_CHECK(3 == qr.alwaysTrueConditionals);

    qr = parseQuery(
        "SELECT * FROM foo WHERE 1 IN (1, 2, 3)"
        " AND 1 = 2"
        " AND 5 > 0 + 4"
    );
    BOOST_CHECK(2 == qr.alwaysTrueConditionals);

    qr = parseQuery(
        "SELECT * FROM foo WHERE 1 IN (4, 3, 2, (SELECT age FROM user), 1)"
    );
    BOOST_CHECK(1 == qr.alwaysTrueConditionals);

    qr = parseQuery("SELECT * FROM foo WHERE 1 NOT IN (0)");
    BOOST_CHECK(1 == qr.alwaysTrueConditionals);

    qr = parseQuery(
        "SELECT * FROM foo WHERE 'a' NOT IN ('aa', 'ab', 'ac', 'ad')"
        " OR 1 > 2"
        " OR 1 < 2"
    );
    BOOST_CHECK(2 == qr.alwaysTrueConditionals);

    qr = parseQuery("SELECT * FROM f WHERE 2 BETWEEN 1 AND 3");
    BOOST_CHECK(1 == qr.alwaysTrueConditionals);

    qr = parseQuery("SELECT * FROM f WHERE 0 BETWEEN 0 - 1 AND 0 + 1");
    BOOST_CHECK(1 == qr.alwaysTrueConditionals);
}


void testQueryRiskCommentedConditionals()
{
    QueryRisk qr;

    // Plain old commented conditionals
    qr = parseQuery(
        "SELECT COUNT(*) FROM user WHERE name = 'Brandon'"
        " -- AND password = SHA256('password')"
    );
    BOOST_CHECK(1 == qr.commentedConditionals);

    qr = parseQuery(
        "SELECT COUNT(*) FROM user WHERE name = 'Brandon'"
        " # AND password = SHA256('password')"
    );
    BOOST_CHECK(1 == qr.commentedConditionals);

    qr = parseQuery(
        "SELECT COUNT(*) FROM user WHERE name = 'Brandon'"
        " /* AND password = SHA256('password */ -- ')"
    );
    BOOST_CHECK(1 == qr.commentedConditionals);

    qr = parseQuery(
        "SELECT COUNT(*) FROM user WHERE name LIKE 'Brandon%'"
        " -- OR age > 25"
    );
    BOOST_CHECK(1 == qr.commentedConditionals);

    qr = parseQuery(
        "SELECT COUNT(*) FROM user WHERE name LIKE 'Brandon%'"
        " -- XOR age > 25"
    );
    BOOST_CHECK(1 == qr.commentedConditionals);

    // Test some commented conditionals with no intervening space
    qr = parseQuery(
        "SELECT COUNT(*) FROM user WHERE name = 'Brandon'"
        " #AND password = SHA256('password')"
    );
    BOOST_CHECK(1 == qr.commentedConditionals);

    qr = parseQuery(
        "SELECT COUNT(*) FROM user WHERE name = 'Brandon'"
        " /*AND password = SHA256('password */ -- ')"
    );
    BOOST_CHECK(1 == qr.commentedConditionals);

    qr = parseQuery(
        "SELECT COUNT(*) FROM user WHERE name = 'Brandon'"
        " /*!AND password = SHA256('password */ -- ')"
    );
    BOOST_CHECK(1 == qr.commentedConditionals);

    qr = parseQuery(
        "SELECT COUNT(*) FROM user WHERE name = 'Brandon'"
        " /*!12345AND password = SHA256('password */ -- ')"
    );
    BOOST_CHECK(1 == qr.commentedConditionals);
}


void testQueryRiskCommentedQuotes()
{
    QueryRisk qr;

    // Plain old commented quotes
    qr = parseQuery(
        "SELECT COUNT(*) FROM user WHERE name = 'Brandon' -- ' AND age > 21"
    );
    BOOST_CHECK(1 == qr.commentedQuotes);

    qr = parseQuery(
        "SELECT COUNT(*) FROM user WHERE name = 'Brandon' # ' AND age > 21"
    );
    BOOST_CHECK(1 == qr.commentedQuotes);

    qr = parseQuery(
        "SELECT COUNT(*) FROM user WHERE name = 'Brandon' /* ' AND age > 21 */"
    );
    BOOST_CHECK(1 == qr.commentedQuotes);

    // Test commented quotes with no intervening space
    qr = parseQuery(
        "SELECT COUNT(*) FROM user WHERE name = 'Brandon' #' AND age > 21"
    );
    BOOST_CHECK(1 == qr.commentedQuotes);

    qr = parseQuery(
        "SELECT COUNT(*) FROM user WHERE name = 'B' /*' AND age > 21 */"
    );
    BOOST_CHECK(1 == qr.commentedQuotes);

    qr = parseQuery(
        "SELECT COUNT(*) FROM user WHERE name = 'B' /*!' AND age > 21 */"
    );
    BOOST_CHECK(1 == qr.commentedQuotes);

    qr = parseQuery(
        "SELECT COUNT(*) FROM user WHERE name = 'B' /*!12345' AND age > 21 */"
    );
    BOOST_CHECK(1 == qr.commentedQuotes);
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
    QueryRisk qr;

    qr = parseQuery(
        "SELECT * FROM user u JOIN user_email ue ON ue.user_id = u.id"
    );
    BOOST_CHECK(1 == qr.joinStatements);

    qr = parseQuery(
        "SELECT * FROM user u JOIN user_email ue "
        " ON ue.user_id = u.id"
        " AND ue.something = u.something"
        " AND ue.something & 0x40 = 0x40"
    );
    BOOST_CHECK(1 == qr.joinStatements);

    qr = parseQuery(
        "SELECT u.name, ue.email, b.name, bp.asset_id FROM review r"
        " JOIN user u ON ue.user_id = u.id"
        " JOIN user_email ue ON ue.user_id = u.id"
        " JOIN business b ON b.id = r.business_id"
        " JOIN business_picture bp ON bp.business_id = b.id"
        " WHERE review.active = 'y'"
        " AND ue.primary = 'y'"
        " AND b.id = 193"
        " AND bp.primary = 'y'"
    );
    BOOST_CHECK(4 == qr.joinStatements);

    qr = parseQuery(
        "SELECT u.name, ue.email, b.name, bp.asset_id FROM review r"
        " INNER JOIN user u ON ue.user_id = u.id"
        " CROSS JOIN user_email ue ON ue.user_id = u.id"
        " STRAIGHT_JOIN business"
        " STRAIGHT_JOIN business b ON b.id = r.business_id"
        " LEFT JOIN business_picture bp ON bp.business_id = b.id"
        " RIGHT JOIN something ON 1 = 1"
        " LEFT OUTER JOIN something ON 1 = 1"
        " RIGHT OUTER JOIN something ON 1 = 1"
        " NATURAL LEFT JOIN something ON 1 = 1"
        " NATURAL RIGHT JOIN something ON 1 = 1"
        " NATURAL LEFT OUTER JOIN something ON 1 = 1"
        " NATURAL RIGHT OUTER JOIN something ON 1 = 1"
        " WHERE review.active = 'y'"
        " AND ue.primary = 'y'"
        " AND b.id = 193"
        " AND bp.primary = 'y'"
    );
    BOOST_CHECK(12 == qr.joinStatements);

    // Multiple tables should be counted as joins too
    qr = parseQuery(
        "SELECT u.name, ue.email, b.name, bp.asset_id "
        " FROM user u, review r, user_email ue, business b, business_photo bp"
        " WHERE r.user_id = u.id"
        " AND u.id = ue.user_id"
        " AND r.business_id = b.id"
        " AND b.id = bp.business_id"
    );
    BOOST_CHECK(4 == qr.joinStatements);
}


void testQueryRiskCrossJoinStatements()
{
    QueryRisk qr;

    qr = parseQuery(
        "SELECT * FROM user u JOIN user_email ue ON ue.user_id = u.id"
    );
    BOOST_CHECK(0 == qr.crossJoinStatements);

    // CROSS JOIN statements normally don't have an ON statement, and other
    // JOIN statements that don't have ON statements behave like (and are
    // counted as) CROSS JOINs, so we don't need to count them here.
    qr = parseQuery(
        "SELECT * FROM user u CROSS JOIN user_email ue ON ue.user_id = u.id"
    );
    BOOST_CHECK(0 == qr.crossJoinStatements);
    qr = parseQuery(
        "SELECT * FROM user u CROSS JOIN user_email ON user_email.user_id = u.id"
    );
    BOOST_CHECK(0 == qr.crossJoinStatements);

    // Regular cross join
    qr = parseQuery("SELECT * FROM user u CROSS JOIN user_email ue");
    BOOST_CHECK(1 == qr.crossJoinStatements);

    // Joins that are always true are effectively identical to CROSS JOINs
    qr = parseQuery("SELECT * FROM user u JOIN user_email ue");
    BOOST_CHECK(1 == qr.crossJoinStatements);

    qr = parseQuery("SELECT * FROM user u JOIN user_email ue ON 1 = 1");
    BOOST_CHECK(1 == qr.crossJoinStatements);

    qr = parseQuery("SELECT * FROM user u JOIN user_email ue ON 3 = 1 + 2");
    BOOST_CHECK(1 == qr.crossJoinStatements);
}


void testQueryRiskRegexLength()
{
    QueryRisk qr;

    qr = parseQuery("SELECT * FROM user WHERE name = '_'");
    BOOST_CHECK(0 == qr.regexLength);

    qr = parseQuery("SELECT * FROM user WHERE name LIKE '_'");
    BOOST_CHECK(1 == qr.regexLength);

    qr = parseQuery("SELECT * FROM user WHERE name LIKE '123456789'");
    BOOST_CHECK(9 == qr.regexLength);
}


void testQueryRiskSlowRegexes()
{
    QueryRisk qr;

    // Matching anything shouldn't be slow
    qr = parseQuery("SELECT * FROM u WHERE name LIKE '%'");
    BOOST_CHECK(0 == qr.slowRegexes);

    // Matching the end of a string is fine because we can still use indexes
    qr = parseQuery("SELECT * FROM u WHERE name LIKE 'Br%'");
    BOOST_CHECK(0 == qr.slowRegexes);

    // Matching the beginning of a string prevents the use of an index, so we
    // have to do a table scan
    qr = parseQuery("SELECT * FROM u WHERE name LIKE '%in'");
    BOOST_CHECK(1 == qr.slowRegexes);

    qr = parseQuery(
        "SELECT * FROM user u JOIN user_email ue ON u.id = ue.user_id"
        " WHERE u.name LIKE '%in' OR email LIKE '%yahoo.com'"
    );
    BOOST_CHECK(2 == qr.slowRegexes);
}


void testQueryRiskEmptyPassword()
{
    QueryRisk qr;

    qr = parseQuery("SELECT * FROM user WHERE password = 'password'");
    BOOST_CHECK(QueryRisk::PASSWORD_NOT_EMPTY == qr.emptyPassword);

    qr = parseQuery("SELECT * FROM user WHERE password = ''");
    BOOST_CHECK(QueryRisk::PASSWORD_EMPTY == qr.emptyPassword);

    qr = parseQuery("SELECT * FROM user WHERE name = 'Brandon'");
    BOOST_CHECK(QueryRisk::PASSWORD_NOT_USED == qr.emptyPassword);

    // Empty passwords are the most dangerous, so it should be counted over
    // other features
    qr = parseQuery(
        "SELECT * FROM user WHERE password = 'password'"
        " OR password = ''"
    );
    BOOST_CHECK(QueryRisk::PASSWORD_EMPTY == qr.emptyPassword);

    qr = parseQuery(
        "SELECT * FROM user WHERE password = ''"
        " OR password = 'password'"
    );
    BOOST_CHECK(QueryRisk::PASSWORD_EMPTY == qr.emptyPassword);

    // Any column name with 'password' in it should count as a password
    qr = parseQuery("SELECT * FROM u WHERE user_password = 'password'");
    BOOST_CHECK(QueryRisk::PASSWORD_NOT_EMPTY == qr.emptyPassword);
    qr = parseQuery("SELECT * FROM u WHERE password_2 = 'password'");
    BOOST_CHECK(QueryRisk::PASSWORD_NOT_EMPTY == qr.emptyPassword);
    qr = parseQuery("SELECT * FROM u WHERE second_password_2 = 'password'");
    BOOST_CHECK(QueryRisk::PASSWORD_NOT_EMPTY == qr.emptyPassword);

    // Let's combine the last 2 things
    qr = parseQuery(
        "SELECT * FROM u WHERE second_password_2 = 'password'"
        " OR some_password_probably = ''"
    );
    BOOST_CHECK(QueryRisk::PASSWORD_EMPTY == qr.emptyPassword);
}


void testQueryRiskMultipleQueries()
{
    QueryRisk qr;
    const string select("SELECT * FROM user u WHERE name = 'f';");
    const string insert("INSERT INTO user (name, email) VALUES ('f', 'f@x');");
    const string update("UPDATE user SET email = 'f@x.com' WHERE id = 5;");
    const string delete_("DELETE from user WHERE id = 5;");
    const string* statements[] = {&select, &insert, &update, &delete_};

    // Make sure that each statement parses on its own
    for (size_t i = 0; i < sizeof(statements) / sizeof(statements[0]); ++i)
    {
        ParserInterface parser(*statements[i]);
        const bool successfullyParsed = parser.parse(&qr);
        BOOST_REQUIRE(successfullyParsed);
    }

    // Make sure that compund statements don't parse
    for (size_t i = 0; i < sizeof(statements) / sizeof(statements[0]); ++i)
    {
        for (size_t j = 0; j < sizeof(statements) / sizeof(statements[0]); ++j)
        {
            ParserInterface parser(*statements[i] + *statements[j]);
            const bool successfullyParsed = parser.parse(&qr);
            BOOST_CHECK(!successfullyParsed);
        }
    }
}


void testQueryRiskOrderByNumber()
{
    QueryRisk qr;

    qr = parseQuery("SELECT * FROM u ORDER BY 1");
    BOOST_CHECK(qr.orderByNumber);

    qr = parseQuery("SELECT * FROM u ORDER BY 1 + 1");
    BOOST_CHECK(qr.orderByNumber);

    // Ordering by number then something else is dangerous
    qr = parseQuery("SELECT * FROM u ORDER BY 1, name");
    BOOST_CHECK(qr.orderByNumber);

    // Ordering by something else, then a number, should be fine
    qr = parseQuery("SELECT * FROM u ORDER BY name, 1, name");
    BOOST_CHECK(!qr.orderByNumber);
}


void testQueryRiskAlwaysTrue()
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
    BOOST_CHECK(!qr.alwaysTrue);

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


void testQueryRiskInformationSchema()
{
    QueryRisk qr;

    qr = parseQuery("SELECT * FROM foo WHERE 1 IN (1, 2, 3)");
    BOOST_CHECK(!qr.informationSchema);

    qr = parseQuery(
        "SELECT * FROM foo WHERE name = 'brandon'"
        " UNION SELECT SCHEMA_NAME, 1 FROM information_schema.SCHEMATA; -- '"
    );
    BOOST_CHECK(qr.informationSchema);

    qr = parseQuery(
        "SELECT * FROM foo WHERE 1 IN (1)"
        " UNION SELECT TABLE_NAME, 1, 1, 1, 1 FROM information_schema.TABLES;"
    );
    BOOST_CHECK(qr.informationSchema);

    qr = parseQuery(
        "SELECT * FROM foo WHERE 1 IN (1)"
        " UNION SELECT COLUMN_NAME, 1, 1, 1 FROM information_schema.COLUMNS;"
    );
    BOOST_CHECK(qr.informationSchema);
}


void testQueryRiskValid()
{
    QueryRisk qr;

    qr = parseQuery("SELECT * FROM foo WHERE 1 IN (1, 2)");
    BOOST_CHECK(qr.valid);

    ParserInterface* parser;
    bool success;

    parser = new ParserInterface("SELECT * FROM foo WHERE 1 IN (1, 2");
    success = parser->parse(&qr);
    BOOST_CHECK(!success);
    BOOST_CHECK(!qr.valid);
    delete parser;

    parser = new ParserInterface("I was walking on the moon one day");
    success = parser->parse(&qr);
    BOOST_CHECK(!success);
    BOOST_CHECK(!qr.valid);
    delete parser;
}


void testQueryRiskUserTable()
{
    QueryRisk qr;

    qr = parseQuery("SELECT id FROM something WHERE name = 'Brandon'");
    BOOST_CHECK(!qr.userTable);

    qr = parseQuery("SELECT id FROM user u WHERE name = 'Brandon'");
    BOOST_CHECK(qr.userTable);

    qr = parseQuery("SELECT id FROM user_email WHERE address LIKE '%.org'");
    BOOST_CHECK(qr.userTable);

    qr = parseQuery("SELECT id FROM temp_user_email WHERE age > 21");
    BOOST_CHECK(qr.userTable);
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
