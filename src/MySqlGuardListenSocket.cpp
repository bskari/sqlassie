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

#include "assertCast.hpp"
#include "ListenSocket.hpp"
#include "Logger.hpp"
#include "MySqlErrorMessageBlocker.hpp"
#include "MySqlGuardListenSocket.hpp"
#include "MySqlGuard.hpp"
#include "MySqlLoginCheck.hpp"
#include "MySqlSocket.hpp"
#include "nullptr.hpp"
#include "Proxy.hpp"
#include "Socket.hpp"
#include "SocketException.hpp"

#include <boost/thread.hpp>
#include <memory>
#include <netinet/in.h>
#include <string>
#include <sys/socket.h>

using std::auto_ptr;
using std::string;
using boost::thread;


MySqlGuardListenSocket::MySqlGuardListenSocket(
    const uint16_t listenPort,
    const uint16_t mySqlPort,
    const string mySqlHost
) :
    ListenSocket(listenPort),
    mySqlNetworkSocket_(true),
    mySqlPort_(mySqlPort),
    mySqlHost_(mySqlHost),
    domainSocketFile_()
{
}


MySqlGuardListenSocket::MySqlGuardListenSocket(
    const string& domainSocket,
    const uint16_t mySqlPort,
    const string mySqlHost
) :
    ListenSocket(domainSocket),
    mySqlNetworkSocket_(true),
    mySqlPort_(mySqlPort),
    mySqlHost_(mySqlHost),
    domainSocketFile_()
{
}


MySqlGuardListenSocket::MySqlGuardListenSocket(
    const uint16_t listenPort,
    const string& domainSocket
) :
        ListenSocket(listenPort),
        mySqlNetworkSocket_(false),
        mySqlPort_(0),
        mySqlHost_(),
        domainSocketFile_(domainSocket)
{
}


MySqlGuardListenSocket::MySqlGuardListenSocket(
    const string& listenDomainSocket,
    const string& serverDomainSocket
) :
    ListenSocket(listenDomainSocket),
    mySqlNetworkSocket_(false),
    mySqlPort_(0),
    mySqlHost_(),
    domainSocketFile_(serverDomainSocket)
{
}


MySqlGuardListenSocket::~MySqlGuardListenSocket()
{
}


void MySqlGuardListenSocket::acceptClients() const
{
    while (true)
    {
        socklen_t addressLength = sizeof(sockaddr_in);
        sockaddr_in newAddr;
        int newSocketFD;
        newSocketFD = accept(socketFD_, reinterpret_cast<sockaddr*>(&newAddr),
            reinterpret_cast<socklen_t*>(&addressLength));

        if (newSocketFD < 0)
        {
            throw SocketException("Failed to accept connection");
        }

        handleConnection(auto_ptr<Socket>(new MySqlSocket(newSocketFD)));
    }
}


void MySqlGuardListenSocket::handleConnection(
    auto_ptr<Socket> clientConnection
) const
{
    MySqlSocket* s;
    if (mySqlNetworkSocket_)
    {
        s = new MySqlSocket(mySqlPort_, mySqlHost_);
    }
    else
    {
        s = new MySqlSocket(domainSocketFile_);
    }

    auto_ptr<Socket> serverConnection(s);

    MySqlSocket* const clientPtr = assert_cast<MySqlSocket*>(
        clientConnection.get()
    );

    string clientAddress(clientPtr->getPeerName());

    MySqlErrorMessageBlocker* blocker =
        new MySqlErrorMessageBlocker(s, clientPtr);
    AutoPtrWithOperatorParens<ProxyHalf> server(blocker);
    AutoPtrWithOperatorParens<ProxyHalf> client(
        new MySqlGuard(
            clientPtr,
            s,
            blocker
        )
    );
    // Create a new Proxy thread
    Proxy proxy(client, server, clientConnection, serverConnection);
    thread newThread(proxy);
    Logger::log(Logger::DEBUG)
        << "New client connected from "
        << clientAddress
        << ", spawned thread #"
        << newThread.get_id();
}
