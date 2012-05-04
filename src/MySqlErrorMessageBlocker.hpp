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

#ifndef MYSQL_ERROR_MESSAGE_BLOCKER_HPP
#define MYSQL_ERROR_MESSAGE_BLOCKER_HPP

#include "ProxyHalf.hpp"
#include "QueryRisk.hpp"
class MySqlSocket;

#include <string>
#include <vector>
#include <fstream>
#include <boost/cstdint.hpp>

/**
 * Half of a full proxy that receives responses from a MySQL database and
 * replaces error messages with generic error messages. MySQL is very verbose
 * with its error messages, both giving up that the server is runnign MySQL
 * and generally prints out half of the query starting where the parsing
 * failed. This prevents that information from leaking out.
 * @author Brandon Skari
 * @date January 18 2011
 */

class MySqlErrorMessageBlocker : public ProxyHalf
{
public:
    /**
     * Default constructor.
     * @param incomingConnection The socket to listen on.
     * @param outgoingConnection The socket to write to.
     * logged.
     */
    MySqlErrorMessageBlocker(MySqlSocket* incomingConnection,
        MySqlSocket* outgoingConnection);

    /**
     * Copy constructor needed for Boost threads. This can't be const because
     * we need to transfer ownership of the auto_ptrs.
     */
    MySqlErrorMessageBlocker(MySqlErrorMessageBlocker& rhs);

    /**
     * Destructor.
     */
    ~MySqlErrorMessageBlocker();

    /**
     * Tell the class what kind of query generated a particular response. This
     * way, the blocker can tailor the error message. For example, INSERT
     * queries can return an 'OK' packet.
     */
    void setQueryType(QueryRisk::QueryType type);

private:
    /**
     * Handles a message from MySQL. Inherited from ProxyHalf.
     */
    void handleMessage(std::vector<uint8_t>& rawMessage) const;

    /**
     * Sends an error packet to the client.
     * @param packetNumber The packet number that should be in the packet.
     * @throw SocketExpcetion
     */
    void sendErrorPacket(uint8_t packetNumber) const;

    QueryRisk::QueryType lastQueryType_;
    mutable bool firstPacket_;

    // ***** Hidden methods *****
    MySqlErrorMessageBlocker& operator=(const MySqlErrorMessageBlocker&);
};

#endif
