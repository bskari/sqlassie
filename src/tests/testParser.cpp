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
 * Checks that the type of the query is correctly set.
 * @param query The query to be parsed.
 * @param type The expected type of the query.
 * @param checkParsing True if the query should successfully parse.
 */
static void checkQueryType(
    const string& query,
    const QueryRisk::QueryType type,
    const bool checkSuccessfullyParsed = true
);
/**
 * Tests that a query does not parse correctly.
 */
static void checkQueryIsInvalid(const string& query);


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

    // The parser should still be able to figure out the types when invalid
    // queries are provided

    checkQueryType("SELECT COUNT(*) FRM user", QueryRisk::TYPE_SELECT, false);
    checkQueryType("UPDATE f SET x=1", QueryRisk::TYPE_UPDATE, false);
    checkQueryType("REPLACE f SET x=1", QueryRisk::TYPE_UPDATE, false);

    // "DESCRIBE table_name column_name" is valid; this one is tricky, because
    // there's a different keyword being used for a different type of query,
    // which means that it's up to the parser instead of the scanner to
    // determine the type, which probably won't work because the parser fails.
    // I'm rather pessimistic about this one ever passing.
    checkQueryType("EXPLAIN tab col other", QueryRisk::TYPE_DESCRIBE, false);

    checkQueryType(
        "INSERT INTO user (name, age) VALUES ('b', 7,)",
        QueryRisk::TYPE_INSERT,
        false
    );
    checkQueryType(
        "SELECT a, b, c FROM d WHERE a = ''; SELECT a FROM b; -- ' AND b = ''",
        QueryRisk::TYPE_SELECT,
        false
    );
    checkQueryType(
        "SELECT a, b, c FROM d WHERE a = ''; SELECT a FROM b; -- ' AND b = ''",
        QueryRisk::TYPE_SELECT,
        false
    );
    checkQueryType(
        "BEGIN SELECT INSERT UPDATE",
        QueryRisk::TYPE_TRANSACTION,
        false
    );
    checkQueryType(
        "dance for me SQL",
        QueryRisk::TYPE_UNKNOWN,
        false
    );
}


void testInvalidQueries()
{
    // ON statements can only happen after a JOIN
    checkQueryIsInvalid("SELECT * FROM user u /* JOIN user u */ ON u.age > 5");

    // ESCAPE statements can only have a single character
    checkQueryIsInvalid("SELECT * FROM u WHERE 'foo' LIKE 'bar' ESCAPE 'baz'");
}


void checkQueryType(
    const string& query,
    const QueryRisk::QueryType type,
    const bool checkSuccessfullyParsed
)
{
    QueryRisk qr;
    ParserInterface parser(query);
    const bool successfullyParsed = parser.parse(&qr);
    if (checkSuccessfullyParsed)
    {
        BOOST_CHECK_MESSAGE(
            successfullyParsed,
            '"' << query << "\" failed to parse"
        );
        if (!successfullyParsed)
        {
            return;
        }
    }
    BOOST_CHECK_MESSAGE(
        type == qr.queryType,
        "Expected \""
            << query
            << "\" to be "
            << type
            << " but instead found "
            << qr.queryType
    );
}


void checkQueryIsInvalid(const string& query)
{
    QueryRisk qr;
    ParserInterface parser(query);
    const bool successfullyParsed = parser.parse(&qr);
    BOOST_CHECK_MESSAGE(
        !successfullyParsed,
        '"' << query << "\" should have been marked invalid but was not"
    );
}
