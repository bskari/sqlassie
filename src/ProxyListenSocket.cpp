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

#include "MySqlPrinter.hpp"
#include "nullptr.hpp"
#include "Proxy.hpp"
#include "ProxyListenSocket.hpp"

#include <boost/cstdint.hpp>
#include <boost/thread.hpp>
#include <memory>
#include <string>

using std::string;
using std::auto_ptr;
using boost::thread;


// Port <-> port
ProxyListenSocket::ProxyListenSocket(
    const uint16_t listenPort,
    const uint16_t serverPort,
    const string& connectHost
) :
    ListenSocket(listenPort),
    serverPort_(serverPort),
    serverDomainSocket_(),
    connectHost_(connectHost),
    proxy_(nullptr)
{
}


// Port <-> domain
ProxyListenSocket::ProxyListenSocket(
    const uint16_t listenPort,
    const string& connectDomain
) :
    ListenSocket(listenPort),
    serverPort_(0),
    serverDomainSocket_(connectDomain),
    connectHost_(),
    proxy_(nullptr)
{
}


// Domain <-> port
ProxyListenSocket::ProxyListenSocket(
    const string& listenDomain,
    const uint16_t connectPort,
    const string& connectHost
) :
    ListenSocket(listenDomain),
    serverPort_(connectPort),
    serverDomainSocket_(),
    connectHost_(connectHost),
    proxy_(nullptr)
{
}


// Domain <-> domain
ProxyListenSocket::ProxyListenSocket(
    const string& listenDomain,
    const string& connectDomain
) :
    ListenSocket(listenDomain),
    serverPort_(0),
    serverDomainSocket_(connectDomain),
    connectHost_(),
    proxy_(nullptr)
{
}


ProxyListenSocket::~ProxyListenSocket()
{
    delete proxy_;
}


void ProxyListenSocket::handleConnection(
    std::auto_ptr<Socket> clientConnection
) const
{
    Socket* s;
    if (0 != serverPort_)
    {
        s = new Socket(serverPort_, connectHost_);
    }
    else
    {
        s = new Socket(serverDomainSocket_);
    }
    auto_ptr<Socket> serverConnection(s);

    AutoPtrWithOperatorParens<ProxyHalf> client(
        new MySqlPrinter(
            clientConnection.get(),
            serverConnection.get()
        )
    );
    AutoPtrWithOperatorParens<ProxyHalf> server(
        new ProxyHalf(
            serverConnection.get(),
            clientConnection.get()
        )
    );
    Proxy proxy(client, server, clientConnection, serverConnection);

    thread newThread(proxy);
}
