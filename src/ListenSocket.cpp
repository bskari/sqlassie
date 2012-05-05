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
#include "ListenSocket.hpp"
#include "MessageHandler.hpp"
#include "SocketException.hpp"

#include <boost/thread/thread.hpp>
#include <memory>
#include <errno.h>
#include <string.h>
#include <string>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/un.h>
#include <stdio.h>

using boost::thread;
using std::auto_ptr;
using std::string;


ListenSocket::ListenSocket(const uint16_t port) :
    socketFD_(socket(AF_INET, SOCK_STREAM, IPPROTO_IP))
{
    // Check that socket creation succeeded
    if (socketFD_ < 0)
    {
        string error("Unable to create socket: ");
        error += strerror(errno);
        throw SocketException(error);
    }

    sockaddr_in sockAddr;

    // Set details
    memset(&sockAddr, 0, sizeof(sockAddr));
    sockAddr.sin_family = AF_INET;
    sockAddr.sin_addr.s_addr = htonl(INADDR_ANY);
    sockAddr.sin_port = htons(port);

    // Bind to the port
    if (
        bind(
            socketFD_,
            reinterpret_cast<sockaddr*>(&sockAddr),
            sizeof(sockAddr)
        ) < 0
    )
    {
        string error("Unable to bind to port: ");
        error += strerror(errno);
        throw SocketException(error);
    }

    // Start listening
    if (-1 == listen(socketFD_, MAX_CONNECTIONS))
    {
        string error("Unable to listen: ");
        error += strerror(errno);
        throw SocketException(error);
    }
}


ListenSocket::ListenSocket(const string& domainSocket) :
    socketFD_(socket(PF_UNIX, SOCK_STREAM, 0))
{
    // Did socket creation succeed?
    if (socketFD_ < 0)
    {
        string error("Unable to create socket: ");
        error += strerror(errno);
        throw SocketException(error);
    }

    // Remove the file link
    unlink(domainSocket.c_str());

    sockaddr_un sockAddr;
    size_t sockAddrLength;

    sockAddr.sun_family = AF_UNIX;
    if (sizeof(sockAddr.sun_path) < domainSocket.size() - 1)
    {
        throw SocketException("Domain socket filename is too long");
    }
    const int charsPrinted = snprintf(
        sockAddr.sun_path,
        sizeof(sockAddr.sun_path),
        "%s",
        domainSocket.c_str()
    );
    sockAddrLength = sizeof(sockAddr.sun_family) + charsPrinted + 1;
    sockAddr.sun_path[domainSocket.size()] = '\0';

    // Bind to the domain socket
    if (
        bind(
            socketFD_,
            reinterpret_cast<sockaddr*>(&sockAddr),
            sockAddrLength
        ) < 0
    )
    {
        string error("Unable to bind to domain socket: ");
        error += strerror(errno);
        throw SocketException(error);
    }

    // Start listening
    if (-1 == listen(socketFD_, MAX_CONNECTIONS))
    {
        string error("Unable to listen: ");
        error += strerror(errno);
        throw SocketException(error);
    }
}


ListenSocket::~ListenSocket()
{
    close(socketFD_);
}


void ListenSocket::acceptClients() const
{
    while (true)
    {
        socklen_t addressLength = sizeof(sockaddr_in);
        sockaddr_in newAddr;
        int newSocketFD;
        newSocketFD = accept(
            socketFD_,
            reinterpret_cast<sockaddr*>(&newAddr),
            reinterpret_cast<socklen_t*>(&addressLength)
        );

        if (newSocketFD < 0)
        {
            throw SocketException("Failed to accept connection");
        }

        handleConnection(auto_ptr<Socket>(new Socket(newSocketFD)));
    }
}


void ListenSocket::handleConnection(auto_ptr<Socket> s) const
{
    MessageHandler mh(s);
    thread newThread(mh);
    Logger::log(Logger::DEBUG)
        << "New client connected, spawned thread #"
        << newThread.get_id();
}
