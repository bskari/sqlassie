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

#ifndef SRC_MYSQLLOGINCHECK_HPP_
#define SRC_MYSQLLOGINCHECK_HPP_

class st_mysql;

#include <boost/cstdint.hpp>
#include <boost/thread/mutex.hpp>
#include <boost/regex.hpp>
#include <map>
#include <set>
#include <string>

/**
 * Helper class to reduce a MySQL remote connection security bypass.
 * SQLassie can present a security risk, because MySQL has a fine-grained
 * security policy that allows different passwords and different database/table
 * permissions depending on where a client is connecting from. It's generally
 * good practice to only allow connections from trusted places, e.g. localhost,
 * 127.0.0.1, or somewhere on the local network. However, when a connection is
 * tunnelled through SQLassie, MySQL thinks that it is being connected to from
 * wherever SQLassie is running. If SQLassie is running on the same server as
 * the database, then connections to SQLassie will bypass these security
 * checks. This class tries to partially remedy this problem by loading the
 * user/host connections from MySQl and then including ways to check if
 * connections would normally be allowed by MySQL. This method isn't perfect
 * because it only checks if a login is allowed and doesn't implement the
 * specific table/database permissions.
 * @author Brandon Skari
 * @date May 5 2011
 */

class MySqlLoginCheck
{
public:
    /**
     * Initialize the singleton class.
     */
    ///@{
    static void initialize(
        const std::string& username,
        const std::string& password,
        const std::string& host,
        uint16_t port
    );
    static void initialize(
        const std::string& username,
        const std::string& password,
        const std::string& domainSocket
    );
    ///@}

    /**
     * Checks to make sure that the connecting user/host has permissions to
     * access MySQL. If the class was unable to connect to MySQL and get the
     * list of users and passwords, then this method defaults to true.
     * @param user The username that the client supplied.
     * @param host The host that the client is connecting from.
     */
    static bool validUserHost(const std::string& user, const std::string& host);

private:
    /**
     * Constructor is private because this is a singleton class.
     */
    ///@{
    MySqlLoginCheck(
        const std::string& username,
        const std::string& password,
        const std::string& host,
        uint16_t port
    );
    MySqlLoginCheck(
        const std::string& username,
        const std::string& password,
        const std::string& domainSocket
    );
    ///@}

    /**
     * Connects to MySQL and constructs a list of the user/host logins. If
     * username is empty or the credentials are invalid, an empty list is
     * returned.
     * @return Successfully connected and built the list.
     */
    bool loadUserHostsFromMySql(st_mysql* conn);

    static std::map<std::string, std::set<boost::regex> > userHostLogins_;
    static const MySqlLoginCheck* instance_;
    static boost::mutex initializationMutex_;

    // Hidden methods
    MySqlLoginCheck& operator=(const MySqlLoginCheck& rhs);
};

#endif  // SRC_MYSQLLOGINCHECK_HPP_
