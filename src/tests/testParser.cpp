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
 * Tests the parser. Two things are tested: that the parser successfully
 * parses known correct queries (it tries to parse each line in each file
 * in the directory "queries") and second, that it correctly identifies
 * the various indications of an attack, like always true.
 * @author Brandon Skari
 * @date December 18 2011
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
 * Parses a query and sets the provided QueryRisk to the risks found.
 * @param query The query to be parsed.
 * @param qr Will be updated to reflect the risks in the query.
 * @param
 */
static QueryRisk parseQuery(const string& query);
/**
 * Parses a query and sets the provided QueryRisk to the risks found.
 * @param query The query to be parsed.
 * @param qr Will be updated to reflect the risks in the query.
 * @param
 */
static void checkQueryType(const string& query, const QueryRisk::QueryType type);


void testParseKnownGoodQueries()
{
    namespace fs = boost::filesystem;
    namespace ba = boost::algorithm;

    // Open the .sql files in the queries directory and try to parse them
    fs::path queriesPath("../src/tests/queries");
    BOOST_REQUIRE(fs::exists(queriesPath));
    BOOST_REQUIRE(fs::is_directory(queriesPath));

    const fs::directory_iterator end;
    for (fs::directory_iterator entry(queriesPath);
        entry != end;
        ++entry)
    {
        BOOST_MESSAGE(entry->string());
        if (
            ba::ends_with(entry->string(), ".sql")
            || ba::ends_with(entry->string(), ".mysql")
        )
        {
            ifstream fin(entry->string().c_str());
            BOOST_REQUIRE(fin.is_open());
            BOOST_MESSAGE("Parsing queries from " << entry->filename());
            string line;
            while (getline(fin, line))
            {
                if (line.empty())
                {
                    continue;
                }
                ParserInterface parser(line);
                QueryRisk qr;
                const bool successfullyParsed = parser.parse(&qr);
                BOOST_CHECK_MESSAGE(
                    successfullyParsed && qr.valid,
                    "Failed to parse: " << line
                );
            }
            fin.close();
        }
    }
}


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


void testQueryRiskAlwaysTrue()
{
    QueryRisk qr;
    string longQuery;

    // ------------------------------------------------------------------------
    // expression IN (expression, expression, expression, ...)
    // ------------------------------------------------------------------------

    // Subselects shouldn't be detectable as always true
    qr = parseQuery("SELECT * FROM foo WHERE 1 IN (SELECT 1)");
    BOOST_CHECK(!qr.alwaysTrue);

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

    longQuery = "SELECT * FROM foo WHERE (0x08 >> 3) |";
    longQuery += " (0x04 >> 2) | (0x02 >> 1) | (0x01 >> 0) = 0x01";
    qr = parseQuery(longQuery);
    BOOST_CHECK(qr.alwaysTrue);

    longQuery = "SELECT * FROM foo WHERE (1 << 0) |";
    longQuery += "(1 << 1) | (1 << 2) | (1 << 4) = 15";
    qr = parseQuery(longQuery);
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
    BOOST_CHECK(!qr.alwaysTrue);

    qr = parseQuery("SELECT * FROM foo WHERE 'brandon' != 'not brandon'");
    BOOST_CHECK(!qr.alwaysTrue);

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

    longQuery = "SELECT * FROM foo WHERE ((1 = 1) AND (1 = 2)) ";
    longQuery += "OR (1 = 1 AND (1 = 2 OR 2 = 3))";
    qr = parseQuery(longQuery);
    BOOST_CHECK(!qr.alwaysTrue);

    qr = parseQuery("SELECT * FROM foo WHERE (1 = 2) XOR (2 = 3)");
    BOOST_CHECK(qr.alwaysTrue);

    qr = parseQuery("SELECT * FROM foo WHERE (1 = 2) XOR (2 = 2)");
    BOOST_CHECK(!qr.alwaysTrue);
}


void testQueryType()
{
    checkQueryType("SELECT * FROM a", QueryRisk::TYPE_SELECT);
    checkQueryType("SELECT a, b, c, d FROM u WHERE 1 = 1", QueryRisk::TYPE_SELECT);
    checkQueryType("SELECT a, b, c, d FROM u UNION SELECT 1", QueryRisk::TYPE_SELECT);
    checkQueryType("SELECT 1", QueryRisk::TYPE_SELECT);
    checkQueryType("SELECT '1'", QueryRisk::TYPE_SELECT);

    checkQueryType("INSERT INTO a (b, c) VALUES ('a', 1)", QueryRisk::TYPE_INSERT);
    checkQueryType("INSERT INTO a (b) VALUES ((SELECT MAX(id) FROM u))", QueryRisk::TYPE_INSERT);

    checkQueryType("UPDATE u SET x = 0", QueryRisk::TYPE_UPDATE);
    checkQueryType("UPDATE u SET x = (SELECT MAX(id) FROM u)", QueryRisk::TYPE_UPDATE);
    checkQueryType("UPDATE u SET x = (SELECT 1)", QueryRisk::TYPE_UPDATE);

    checkQueryType("DELETE FROM a WHERE id = 1", QueryRisk::TYPE_DELETE);

    checkQueryType("BEGIN", QueryRisk::TYPE_TRANSACTION);
    checkQueryType("START TRANSACTION", QueryRisk::TYPE_TRANSACTION);
    checkQueryType("START TRANSACTION WITH CONSISTENT SNAPSHOT", QueryRisk::TYPE_TRANSACTION);
    checkQueryType("COMMIT", QueryRisk::TYPE_TRANSACTION);
    checkQueryType("ROLLBACK", QueryRisk::TYPE_TRANSACTION);

    checkQueryType("SET autocommit = 1", QueryRisk::TYPE_SET);
    checkQueryType("SET NAMES utf8", QueryRisk::TYPE_SET);
    checkQueryType("SET @@global.a = 1, GLOBAL a = 1", QueryRisk::TYPE_SET);

    checkQueryType("EXPLAIN SELECT 1", QueryRisk::TYPE_EXPLAIN);
    checkQueryType("EXPLAIN SELECT a FROM u", QueryRisk::TYPE_EXPLAIN);
    checkQueryType("EXPLAIN SELECT a FROM u UNION SELECT 1", QueryRisk::TYPE_EXPLAIN);

    checkQueryType("SHOW DATABASES", QueryRisk::TYPE_SHOW);
    checkQueryType("SHOW TABLES", QueryRisk::TYPE_SHOW);
    checkQueryType("SHOW CREATE TABLE a", QueryRisk::TYPE_SHOW);

    checkQueryType("DESCRIBE a", QueryRisk::TYPE_DESCRIBE);
    checkQueryType("DESC a", QueryRisk::TYPE_DESCRIBE);
    checkQueryType("EXPLAIN a", QueryRisk::TYPE_DESCRIBE);

    checkQueryType("LOCK TABLES a READ", QueryRisk::TYPE_LOCK);
    checkQueryType("LOCK TABLES a READ, b WRITE", QueryRisk::TYPE_LOCK);
    checkQueryType("LOCK TABLES a READ LOCAL", QueryRisk::TYPE_LOCK);
    checkQueryType("LOCK TABLES b LOW_PRIORITY WRITE", QueryRisk::TYPE_LOCK);

    checkQueryType("USE a", QueryRisk::TYPE_USE);
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


void checkQueryType(const string& query, const QueryRisk::QueryType type)
{
    QueryRisk qr;
    ParserInterface parser(query);
    const bool successfullyParsed = parser.parse(&qr);
    BOOST_CHECK(successfullyParsed);
    if (successfullyParsed)
    {
        BOOST_CHECK_MESSAGE(
            type == qr.queryType,
            "Expected '"
                << query
                << "' to be "
                << type
                << " but instead found "
                << qr.queryType
        );
    }
}
