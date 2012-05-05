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

#ifndef SRC_PROXYLISTENSOCKET_HPP_
#define SRC_PROXYLISTENSOCKET_HPP_

#include "Socket.hpp"
#include "Proxy.hpp"
#include "ProxyHalf.hpp"
#include "ListenSocket.hpp"

#include <string>
#include <memory>
#include <boost/cstdint.hpp>

/**
 * Listens for connections on a given port or domain and then opens a connection
 * to another port or domain and tunnels the connection.
 * @author Brandon Skari
 * @date February 16 2011
 */

class ProxyListenSocket : public ListenSocket
{
public:
    /**
     * Constructor for connecting two ports.
     */
    ProxyListenSocket(uint16_t listenPort, uint16_t serverPort,
        const std::string& connectHost = "127.0.0.1");

    /**
     * Constructor for listening on a domain socket and connecting to a port.
     */
    ProxyListenSocket(const std::string& listenDomain,
        uint16_t  serverPort, const std::string& connectHost = "127.0.0.1");

    /**
     * Constructor for listening on a port and connecting to a domain socket.
     */
    ProxyListenSocket(uint16_t listenPort, const std::string& domain);

    /**
     * Constructor for connecting two domain sockets.
     */
    ProxyListenSocket(const std::string& listenDomain,
        const std::string& connectDomain);

    ~ProxyListenSocket();

    /**
     * Overridden from ListenSocket.
     */
    void handleConnection(std::auto_ptr<Socket> clientConnection) const;

private:
    const uint16_t serverPort_;
    const std::string serverDomainSocket_;
    const std::string connectHost_;
    mutable Proxy* proxy_;
    ProxyListenSocket(const ProxyListenSocket& rhs);
    ProxyListenSocket& operator=(const ProxyListenSocket& rhs);
};

#endif  // SRC_PROXYLISTENSOCKET_HPP_
