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

#ifndef SRC_MYSQLLOGGER_HPP_
#define SRC_MYSQLLOGGER_HPP_

#include "ProxyHalf.hpp"

#include <string>
#include <vector>
#include <fstream>
#include <boost/cstdint.hpp>

class Socket;

/**
 * Half of a full proxy that receives MySQL commands and logs them to a file.
 * The chosen filename is a provided base string + a filename that matches the
 * selected database that is sniffed from the connection messages.
 * @author Brandon Skari
 * @date October 25 2010
 */

class MySqlLogger : public ProxyHalf
{
public:
    /**
     * Default constructor.
     * @param socket The socket to listen on.
     */
    MySqlLogger(Socket* incomingConnection, Socket* outgoingConnection,
        const std::string& fileDirectory);

    /**
     * Copy constructor needed for Boost threads. This can't be const because
     * we need to transfer ownership of the auto_ptrs.
     */
    ///@{
    MySqlLogger(MySqlLogger& rhs);
    MySqlLogger(ProxyHalf& rhs);
    ///@}

    /**
     * Destructor.
     */
    virtual ~MySqlLogger();

protected:
    /**
     * Forwards the message to the MySQL connection and logs any queries to a
     * file.
     */
    virtual void handleMessage(std::vector<uint8_t>& rawMessage) const;

private:
    const std::string fileDirectory_;
    mutable std::string database_;
    mutable std::string currentDatabaseFile_;
    mutable std::ofstream logFile_;
    mutable bool firstPacket_;
    mutable uint8_t lastCommandCode_;

    /**
     * Makes sure the given fileDirectory ends in '/'.
     */
    static std::string fixDirectory(std::string fileDirectory);

    // ***** Hidden methods *****
    MySqlLogger& operator=(const MySqlLogger&);
};

#endif  // SRC_MYSQLLOGGER_HPP_
