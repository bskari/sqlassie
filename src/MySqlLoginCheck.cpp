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

#include "MySqlLoginCheck.hpp"
#include "MySqlConstants.hpp"
#include "nullptr.hpp"

#include <map>
#include <set>
#include <string>
#include <mysql/mysql.h>
#include <cassert>
#include <cstring>
#include <boost/regex.hpp>

using std::map;
using std::string;
using std::set;
using boost::regex;
using boost::regex_search;


class StaticStringsContainer
{
public:
    std::string hostOrUnixDomain_;
    std::string username_;
    std::string password_;
};


// Static variables
map<string, set<regex> > MySqlLoginCheck::userHostLogins_;
const MySqlLoginCheck* MySqlLoginCheck::instance_ = nullptr;
uint16_t MySqlLoginCheck::port_;
bool MySqlLoginCheck::initialized_ = false;
StaticStringsContainer* MySqlLoginCheck::stringsContainer_;


const MySqlLoginCheck& MySqlLoginCheck::getInstance()
{
    if (nullptr == instance_ || !initialized_)
    {
        delete instance_;
        instance_ = new MySqlLoginCheck();
    }
    return *instance_;
}


bool MySqlLoginCheck::getUserHostsFromMySql()
{
    MYSQL* conn = mysql_init(nullptr);
    if (nullptr == conn)
    {
        return false;
    }

    if (
        stringsContainer_->username_.empty() ||
        stringsContainer_->hostOrUnixDomain_.empty()
    )
    {
        return false;
    }

    MYSQL* success;
    // Domain socket connection
    if (0 == port_)
    {
        success = mysql_real_connect(
            conn,
            nullptr,
            stringsContainer_->username_.c_str(),
            stringsContainer_->password_.c_str(),
            "mysql",
            0,
            stringsContainer_->hostOrUnixDomain_.c_str(),
            0
        );
    }
    // TCP socket connection
    else
    {
        success = mysql_real_connect(
            conn,
            stringsContainer_->hostOrUnixDomain_.c_str(),
            stringsContainer_->username_.c_str(),
            stringsContainer_->password_.c_str(),
            "mysql",
            port_,
            nullptr,
            0
        );
    }

    if (nullptr == success)
    {
        return false;
    }

    // Grab the usernames and hosts
    if (0 != mysql_query(conn, "SELECT User, Host FROM user"))
    {
        return false;
    }

    MYSQL_RES* result = mysql_store_result(conn);
    if (nullptr == result)
    {
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
        return false;
    }

    assert(
        2 == numFields
        && "That select query should return exactly 2 fields"
    );
    if (2 != numFields)
    {
        return false;
    }

    while (nullptr != row)
    {
        regex r(MySqlConstants::mySqlRegexToPerlRegex(row[1]), regex::perl);
        userHostLogins_[row[0]].insert(r);

        // MySQL treats localhost and 127.0.0.1 differently for whatever
        // reason - if we see 'localhost' then just add '127.0.0.1' and let
        // the MySQL server deal with possibly bad connections
        if (0 == strcmp("localhost", row[1]))
        {
            regex localhostRegex(
                MySqlConstants::mySqlRegexToPerlRegex("127.0.0.1"),
                regex::perl
            );
            userHostLogins_[row[0]].insert(localhostRegex);
        }

        // Fetch the next row
        row = mysql_fetch_row(result);
    }

    // Clean up the memory from the result
    mysql_free_result(result);

    mysql_close(conn);

    return true;
}


bool MySqlLoginCheck::validUserHost(
    const string& user, const string& host) const
{
    if (userHostLogins_.empty())
    {
        return true;
    }

    const map<string, set<regex> >::const_iterator u(
        userHostLogins_.find(user));
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


MySqlLoginCheck::MySqlLoginCheck()
{
    if (!initialized_)
    {
        /// @TODO(bskari): Prevent race conditions
        // Prevent other threads from trying to initialize
        initialized_ = true;

        initialized_ = getUserHostsFromMySql();
    }
    stringsContainer_ = new StaticStringsContainer;
}


MySqlLoginCheck::~MySqlLoginCheck()
{
    delete stringsContainer_;
}


void MySqlLoginCheck::setHostAndPort(const string& host, const uint16_t port)
{
    if (initialized_)
    {
        return;
    }
    stringsContainer_->hostOrUnixDomain_ = host;
    port_ = port;
}


void MySqlLoginCheck::setUsername(const string& username)
{
    if (initialized_)
    {
        return;
    }
    stringsContainer_->username_ = username;
}


void MySqlLoginCheck::setPassword(const std::string& password)
{
    if (initialized_)
    {
        return;
    }
    stringsContainer_->password_ = password;
}


void MySqlLoginCheck::setUnixDomain(const string& unixDomain)
{
    if (initialized_)
    {
        return;
    }
    stringsContainer_->hostOrUnixDomain_ = unixDomain;
    port_ = 0;
}
