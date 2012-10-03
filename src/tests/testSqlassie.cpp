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
 * Tests the full SQLassie program.
 * @author Brandon Skari
 * @date August 18 2012
 */
#include "../nullptr.hpp"
#include "../DescribedException.hpp"
#include "testSqlassie.hpp"
#include "../warnUnusedResult.h"

#include <boost/test/unit_test.hpp>
#include <mysql/mysql.h>
#include <signal.h>
#include <string>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <vector>

using std::string;
using std::vector;

/**
 * Initializes test necessities (like forking and execing SQLassie and
 * initializing a MySQL connection) in a RAII safe manner.
 */
class SqlassieTestConnection
{
public:
    /**
     * Initializes a connection to MySQL through SQLassie and creates some
     * test data.
     */
    SqlassieTestConnection();

    ~SqlassieTestConnection();

    /**
     * Runs a non-SELECT MySQL command.
     * @return The success status of the command.
     */
    void runCommand(const char* const command);

    /**
     * Runs a SELECT MySQL query.
     * @param query The SELECT query to rub.
     * @param rows A vector to append rows returned from the query.
     * @return The success status of the query.
     */
    void runQuery(const char* const query, vector<vector<string> >* const rows);
private:
    pid_t sqlassiePid_;
    MYSQL* connection_;

    bool createTestData() WARN_UNUSED_RESULT;
    void deleteTestData();

    // Hidden methods
    SqlassieTestConnection(const SqlassieTestConnection&);
    SqlassieTestConnection operator=(const SqlassieTestConnection&);
};


void testSafeQueriesForwarded()
{
    SqlassieTestConnection connection;

    vector<vector<string> > results;

    const char* safeSelects[] = {
        "SELECT * FROM alphabet;",
        "SELECT * FROM alphabet a1 JOIN alphabet a2 ON a1.id = a2.id"
            " WHERE letter IN ('A', 'B');",
        "SELECT number FROM alphabet WHERE letter LIKE 'B%';",
        "SELECT number FROM alphabet WHERE id BETWEEN 0 AND 2;",
    };
    for (size_t i = 0; i < sizeof(safeSelects) / sizeof(safeSelects[0]); ++i)
    {
        connection.runQuery(safeSelects[0], &results);
        BOOST_CHECK(results.size() > 0);
    }

    connection.runCommand(
        "INSERT INTO alphabet (letter, number) VALUES ('C', 3), ('C', 3);"
    );
    connection.runQuery("SELECT * FROM alphabet WHERE letter = 'C';", &results);
    BOOST_CHECK(2 == results.size());

    connection.runCommand(
        "UPDATE alphabet SET number = 4, letter = 'D' WHERE id = 4;"
    );
    connection.runQuery("SELECT * FROM alphabet WHERE letter = 'C';", &results);
    BOOST_CHECK(1 == results.size());

    connection.runCommand(
        "INSERT INTO alphabet (letter, number) VALUES ('E', 5)"
    );
    connection.runQuery("SELECT * FROM alphabet WHERE number = 5;", &results);
    BOOST_CHECK(1 == results.size());

    // 5 <= id <= 6, should match only id = 5
    connection.runCommand("DELETE FROM alphabet WHERE id BETWEEN 5 AND 6;");
    connection.runQuery("SELECT * FROM alphabet;", &results);
    BOOST_CHECK(4 == results.size());
}


void testDangerousSelectsAreBlocked()
{
    SqlassieTestConnection connection;

    vector<vector<string> > results;

    const char* dangerousSelects[] = {
        "SELECT a1.* FROM alphabet a1 CROSS JOIN alphabet a2;",
        "SELECT * FROM alphabet WHERE letter = ''"
            " UNION SELECT * FROM alphabet; -- ';",
        "SELECT number FROM alphabet WHERE letter LIKE 'B%'"
            " OR IF((SELECT letter FROM alphabet WHERE id = 1) > 'F',"
            " BENCHMARK(5000000, MD5('')), 0); -- ';",
    };
    for (
        size_t i = 0;
        i < sizeof(dangerousSelects) / sizeof(dangerousSelects[0]);
        ++i
    )
    {
        connection.runQuery(dangerousSelects[i], &results);
        BOOST_CHECK_MESSAGE(
            0 == results.size(),
            '"' << dangerousSelects[i] << "\" should have been blocked but was not"
        );
    }
}


void testDangerousCommandsAreBlocked()
{
    BOOST_CHECK_MESSAGE(false, "Not implemented");
}


void testSemanticallyInvalidCommandsAreBlocked()
{
    BOOST_CHECK_MESSAGE(false, "Not implemented");
}


void testSyntacticallyInvalidCommandsAreBlocked()
{
    BOOST_CHECK_MESSAGE(false, "Not implemented");
}


// -Wformat warns about having a terminal NULL when using execl, which I do,
// but it doesn't look like it because I'm using C++'s nullptr keyword.
#if GCC_VERSION >= 40600
    #pragma GCC diagnostic push
#endif
#pragma GCC diagnostic ignored "-Wformat"
SqlassieTestConnection::SqlassieTestConnection()
    : sqlassiePid_()
    , connection_(mysql_init(nullptr))
{
    if (!createTestData())
    {
        deleteTestData();
        throw DescribedException("Unable to create test data");
    }

    sqlassiePid_ = fork();
    // Failed to fork
    if (-1 == sqlassiePid_)
    {
        mysql_close(connection_);
        throw DescribedException("Unable to fork SQLassie process");
    }
    // Child process
    if (0 == sqlassiePid_)
    {
        // Find the executable path. This probably isn't portable at all, but
        // I don't know how else to do it. Everything else only seems to offer
        // the current working directory.
        string binaryPath(getenv("_"));
        size_t separatorPos(binaryPath.length() - 1);
        while (separatorPos > 0 && '/' != binaryPath.at(separatorPos))
        {
            --separatorPos;
        }
        chdir(binaryPath.substr(0, separatorPos).c_str());
        execl(
            "sqlassie",
            "sqlassie",
            "--connect-port", "3306",
            "--listen-port", "3307",
            "--host", "127.0.0.1",
            "--user", "sqlassie",
            "--quiet",
            static_cast<char*>(nullptr)
        );
        // If execl succeeds, this shouldn't run
        mysql_close(connection_);
        throw DescribedException("Unable to exec SQLassie process");
    }

    if (nullptr == connection_)
    {
        mysql_close(connection_);
        throw DescribedException("Unable to allocate space for MySQL connection");
    }

    MYSQL* success;
    // Try a few times to connect in case it takes a while for SQLassie to start
    for (int i = 0; i < 5; ++i)
    {
        // Give SQLassie some time to start
        sleep(1);

        const char* const host = "127.0.0.1";
        const char* const username = "sqlassie";
        const char* const password = "";
        const char* const database = "sqlassie_test";
        const unsigned int port = 3307;
        const char* const unixSocket = nullptr;
        const unsigned long clientFlag = 0;

        success = mysql_real_connect(
            connection_,
            host,
            username,
            password,
            database,
            port,
            unixSocket,
            clientFlag
        );

        if (nullptr != success)
        {
            break;
        }
    }

    if (nullptr == success)
    {
        kill(sqlassiePid_, SIGCHLD);
        // Wait for SQLassie to actually exit
        waitpid(sqlassiePid_, nullptr, 0);

        DescribedException de(mysql_error(connection_));
        mysql_close(connection_);
        throw de;
    }
}
#if GCC_VERSION >= 40600
    #pragma GCC diagnostic pop
#else
    #pragma GCC diagnostic warning "-Wunused-variable"
#endif


SqlassieTestConnection::~SqlassieTestConnection()
{
    // SIGCHLD is the only signal that Boost Test will ignore (no SIGKILL)
    kill(sqlassiePid_, SIGCHLD);
    // Wait for SQLassie to actually exit
    waitpid(sqlassiePid_, nullptr, 0);

    mysql_close(connection_);
}


void SqlassieTestConnection::runCommand(const char* const command)
{
    if (0 != mysql_query(connection_, command))
    {
        BOOST_FAIL("Unable to run command \"" << command << "\"");
    }

    MYSQL_RES* result = mysql_store_result(connection_);
    // If result is NULL, then the query was a command that doesn't return      
    // any results, e.g. 'USE mysql'
    if (nullptr == result)
    {
        // If there's an error message, the command failed
        const char* const message = mysql_error(connection_);
        if ('\0' != message[0])
        {
            BOOST_FAIL("Unable to run command \"" << command << "\"");
        }
        mysql_free_result(result);
    }
    else
    {
        // Well, it looks like this was a SELECT or something, which is a
        // programming mistake. If this were a library, I'd do something
        // nicer, but because this is just a test, I'll just fail.
        BOOST_FAIL("runCommand called with non-command");
    }
}


void SqlassieTestConnection::runQuery(
    const char* const query,
    vector<vector<string> >* const rows
)
{
    if (0 != mysql_query(connection_, query))
    {
        BOOST_FAIL("Unable to run query \"" << query << "\"");
    }

    MYSQL_RES* result = mysql_store_result(connection_);
    // If result is NULL, then the query was a statement that doesn't return
    // any results, e.g. 'USE mysql'
    if (nullptr == result)
    {
        // Well, it looks like this was an INSERT or something, which is a
        // programming mistake. If this were a library, I'd do something
        // nicer, but because this is just a test, I'll just fail.
        BOOST_FAIL("runQuery called with non-query");
    }


    const size_t numFields = mysql_num_fields(result);
    rows->clear();

    // Parse and save all of the rows
    MYSQL_ROW row = mysql_fetch_row(result);
    while (nullptr != row)
    {
        vector<string> rowVector;
        for (size_t i = 0; i < numFields; ++i)
        {
            if (nullptr == row[i])
            {
                // This isn't perfect because you can't distinguish between
                // the string "NULL" and the value, but we'll check below to
                // make sure we're not using "NULL" strings
                rowVector.push_back("NULL");
            }
            else
            {
                // As noted above, we can't distinguish between the string
                // "NULL" and the value, so let's make sure we're not being
                // stupid and inserting "NULL" strings
                if (0 == strcmp(row[i], "NULL"))
                {
                    BOOST_FAIL("Using \"NULL\" strings is a terrible idea");
                }
                rowVector.push_back(row[i]);
            }
        }
        rows->push_back(rowVector);
        row = mysql_fetch_row(result);
    }

    mysql_free_result(result);
}


bool SqlassieTestConnection::createTestData()
{
    // This can't use the connection through SQLassie because SQLassie doesn't
    // allow schema changing commands

    MYSQL* connection = mysql_init(nullptr);
    if (nullptr == connection)
    {
        throw DescribedException("Unable to create test data");
    }

    // You can create a user with proper permissions by running:
    /*
    CREATE DATABASE sqlassie_test;
    CREATE USER 'sqlassie'@'localhost';
    GRANT SELECT, INSERT, UPDATE, DELETE, CREATE, DROP
        ON sqlassie_test.* TO 'sqlassie'@'localhost';
    FLUSH PRIVILEGES;
    */

    const char* const host = "localhost";
    const char* const username = "sqlassie";
    const char* const password = "";
    const char* const database = "sqlassie_test";
    const unsigned int port = 3306;
    const char* const unixSocket = nullptr;
    const unsigned long clientFlag = 0;

    const MYSQL* const connectionSuccess = mysql_real_connect(
        connection,
        host,
        username,
        password,
        database,
        port,
        unixSocket,
        clientFlag
    );

    if (nullptr == connectionSuccess)
    {
        DescribedException de(mysql_error(connection));
        mysql_close(connection);
        throw de;
    }

    // Use a one-time loop so that we can clean up easily on the first error
    // I prefer this method over gotos because I can guarantee that jumps only
    // come from here
    bool dataCreationSuccess = false;
    do
    {
        if (0 != mysql_query(connection, "DROP TABLE IF EXISTS alphabet;")) break;
        if (0 != mysql_query(connection,
            "CREATE TABLE alphabet ("
            "id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,"
            " letter CHAR(1) NOT NULL,"
            " number INT NOT NULL);"
        )) break;
        if (0 != mysql_query(connection,
            "INSERT INTO alphabet (letter, number) VALUES ('A', 1);"
        )) break;
        if (0 != mysql_query(connection,
            "INSERT INTO alphabet (letter, number) VALUES ('B', 2);"
        )) break;
        dataCreationSuccess = true;
    }
    while (false);

    mysql_close(connection);
    return dataCreationSuccess;
}


void SqlassieTestConnection::deleteTestData()
{
    // This can't use the connection through SQLassie because SQLassie doesn't
    // allow schema changing commands

    MYSQL* connection = mysql_init(nullptr);
    if (nullptr == connection)
    {
        throw DescribedException("Unable to create test data");
    }

    const char* const host = "localhost";
    const char* const username = "sqlassie";
    const char* const password = "";
    const char* const database = "sqlassie_test";
    const unsigned int port = 3306;
    const char* const unixSocket = nullptr;
    const unsigned long clientFlag = 0;

    const MYSQL* const success = mysql_real_connect(
        connection,
        host,
        username,
        password,
        database,
        port,
        unixSocket,
        clientFlag
    );

    if (nullptr == success)
    {
        DescribedException de(mysql_error(connection));
        mysql_close(connection);
        throw de;
    }

    mysql_query(connection, "DROP TABLE alphabet;");
    mysql_close(connection);
}
