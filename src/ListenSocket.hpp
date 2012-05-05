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

#ifndef SRC_LISTENSOCKET_HPP_
#define SRC_LISTENSOCKET_HPP_

class Socket;
class MessageHandlerFactory;

#include <string>
#include <memory>
#include <boost/cstdint.hpp>

/**
 * Socket that listens for connections.
 * @author Brandon Skari
 * @date April 21 2010
 */

class ListenSocket
{
public:
    explicit ListenSocket(const uint16_t port);
    explicit ListenSocket(const std::string& domainSocket);
    virtual ~ListenSocket();

    virtual void acceptClients() const;

    static const int MAX_CONNECTIONS = 5;


protected:
    virtual void handleConnection(std::auto_ptr<Socket> socket) const;

    const int socketFD_;
};

#endif  // SRC_LISTENSOCKET_HPP_
