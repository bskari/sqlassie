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
#include "MySqlLoginCheck.hpp"
#include "MySqlConstants.hpp"
#include "nullptr.hpp"

#include <boost/regex.hpp>
#include <boost/thread/mutex.hpp>
#include <cassert>
#include <cstring>
#include <map>
#include <mysql/mysql.h>
#include <set>
#include <string>

using std::map;
using std::string;
using std::set;
using boost::lock_guard;
using boost::mutex;
using boost::regex;
using boost::regex_search;


// Static variables
map<string, set<regex> > MySqlLoginCheck::userHostLogins_;
const MySqlLoginCheck* MySqlLoginCheck::instance_ = nullptr;
mutex MySqlLoginCheck::initializationMutex_;


void MySqlLoginCheck::initialize(
    const std::string& username,
    const std::string& password,
    const std::string& host,
    uint16_t port
)
{
    lock_guard<mutex> lg(initializationMutex_);

    if (instance_ == nullptr)
    {
        instance_ = new MySqlLoginCheck(username, password, host, port);
    }
}


void MySqlLoginCheck::initialize(
    const string& username,
    const string& password,
    const string& domainSocket
)
{
    lock_guard<mutex> lg(initializationMutex_);

    if (instance_ == nullptr)
    {
        instance_ = new MySqlLoginCheck(username, password, domainSocket);
    }
}


MySqlLoginCheck::MySqlLoginCheck(
    const string& username,
    const string& password,
    const string& domainSocket
)
{
    MYSQL* conn = mysql_init(nullptr);
    if (nullptr == conn)
    {
        Logger::log(Logger::ERROR)
            << "Unable to connect to MySQL server to access logins";
        return;
    }
    MYSQL* success = mysql_real_connect(
        conn,
        nullptr,
        username.c_str(),
        password.c_str(),
        "mysql",
        0,
        domainSocket.c_str(),
        0
    );
    if (nullptr == success)
    {
        Logger::log(Logger::ERROR)
            << "Unable to login to MySQL server to access logins";
        mysql_close(conn);
        return;
    }

    loadUserHostsFromMySql(conn);

    mysql_close(conn);
}



MySqlLoginCheck::MySqlLoginCheck(
    const std::string& username,
    const std::string& password,
    const std::string& host,
    uint16_t port
)
{
    MYSQL* conn = mysql_init(nullptr);
    if (nullptr == conn)
    {
        Logger::log(Logger::ERROR)
            << "Unable to connect to MySQL server to access logins";
        return;
    }
    MYSQL* success = mysql_real_connect(
        conn,
        host.c_str(),
        username.c_str(),
        password.c_str(),
        "mysql",
        port,
        nullptr,
        0
    );
    if (nullptr == success)
    {
        Logger::log(Logger::ERROR)
            << "Unable to login to MySQL server to access logins";
        mysql_close(conn);
        return;
    }

    loadUserHostsFromMySql(conn);

    mysql_close(conn);
}


bool MySqlLoginCheck::loadUserHostsFromMySql(MYSQL* conn)
{
    // Grab the usernames and hosts
    if (0 != mysql_query(conn, "SELECT User, Host FROM user"))
    {
        Logger::log(Logger::ERROR) << "Unable to access logins from MySQL";
        Logger::log(Logger::DEBUG)
            << "SELECT query failed to run: "
            << mysql_error(conn);
        return false;
    }

    MYSQL_RES* result = mysql_store_result(conn);
    if (nullptr == result)
    {
        Logger::log(Logger::ERROR) << "Unable to access logins from MySQL";
        Logger::log(Logger::DEBUG)
            << "Fetching results failed: "
            << mysql_error(conn);
        return false;
    }

    MYSQL_ROW row = mysql_fetch_row(result);
    int numFields;
    if (nullptr != row)
    {
        numFields = mysql_num_fields(result);
    }
    else
    {
        Logger::log(Logger::ERROR) << "Unable to access logins from MySQL";
        Logger::log(Logger::DEBUG)
            << "Fetching row failed: "
            << mysql_error(conn);
        return false;
    }

    assert(
        2 == numFields
        && "That select query should return exactly 2 fields"
    );
    if (2 != numFields)
    {
        mysql_free_result(result);
        Logger::log(Logger::ERROR) << "Unable to access logins from MySQL";
        Logger::log(Logger::DEBUG)
            << "Expected two fields but received "
            << numFields;
        return false;
    }

    Logger::log(Logger::DEBUG)
        << "Processing "
        << mysql_num_rows(result)
        << " logins";

    while (nullptr != row)
    {
        const string user(row[0]);
        const string host(row[1]);

        regex r(MySqlConstants::mySqlRegexToPerlRegex(host), regex::perl);
        Logger::log(Logger::DEBUG) << "Adding login " << user << '@' << host;
        userHostLogins_[host].insert(r);

        // MySQL treats localhost and 127.0.0.1 differently for whatever
        // reason - if we see 'localhost' then just add '127.0.0.1' and let
        // the MySQL server deal with possibly bad connections
        if (0 == strcmp("localhost", host.c_str()))
        {
            regex localhostRegex(
                MySqlConstants::mySqlRegexToPerlRegex("127.0.0.1"),
                regex::perl
            );
            userHostLogins_[user].insert(localhostRegex);
        }

        // Fetch the next row
        row = mysql_fetch_row(result);
    }

    // Clean up memory
    mysql_free_result(result);

    return true;
}


bool MySqlLoginCheck::validUserHost(const string& user, const string& host)
{
    Logger::log(Logger::DEBUG) << "Checking for " << user << '@' << host;
    // If this wasn't initialized, the user probably didn't enter the settings
    // for it, so just assume it's okay
    if (nullptr == instance_)
    {
        return true;
    }
    // If there are no records, it's probably because we couldn't access the
    // database, so just assumw it's okay
    if (userHostLogins_.empty())
    {
        return true;
    }

    const map<string, set<regex> >::const_iterator u(
        userHostLogins_.find(user)
    );
    if (userHostLogins_.end() == u)
    {
        return false;
    }

    const set<regex>::const_iterator end(u->second.end());
    for (set<regex>::const_iterator i(u->second.begin()); i != end; ++i)
    {
        if (regex_search(host, *i))
        {
            return true;
        }
    }
    return false;
}
