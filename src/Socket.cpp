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
#include "nullptr.hpp"
#include "Socket.hpp"
#include "SocketException.hpp"

#include <algorithm>
#include <arpa/inet.h>
#include <fcntl.h>
#include <boost/cstdint.hpp>
#include <boost/lexical_cast.hpp>
#include <cassert>
#include <cstring>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <string>
#include <sys/socket.h>
#include <sys/un.h>
#include <vector>

using std::memset;
using std::vector;
using std::min;
using std::string;
using boost::lexical_cast;

const size_t Socket::MAX_RECEIVE;
const size_t Socket::TIMEOUT_SECONDS;
const size_t Socket::TIMEOUT_MILLISECONDS;


Socket::Socket(const uint16_t port, const string& address, bool blocking) :
    socketFD_(socket(AF_INET, SOCK_STREAM, 0)),
    open_(true),
    buffer_(MAX_RECEIVE, 0),
    peerName_()
{
    // Did socket creation succeed?
    if (socketFD_ < 0)
    {
        string error("Unable to create socket: ");
        error += strerror(errno);
        throw SocketException(error);
    }

    // Turn off blocking if requested
    if (!blocking)
    {
        if (fcntl(socketFD_, F_SETFL, O_NONBLOCK) < 0)
        {
            throw SocketException("Unable to set socket to non-blocking");
        }
    }

    // Look up the host
    addrinfo* serverInfo;
    addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET; // IPv4
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_NUMERICSERV; // Use decmimal port

    string portStr(lexical_cast<string>(port));

    int returnCode = getaddrinfo(
        address.c_str(),
        portStr.c_str(),
        &hints,
        &serverInfo
    );
    if (0 != returnCode)
    {
        freeaddrinfo(serverInfo);
        throw SocketException(string("Unknown host: ") + address
            + ", error was " + gai_strerror(returnCode));
    }

    // Set the timeout so this doesn't wait forever if nobody's listening
    timeval tv;
    tv.tv_sec = TIMEOUT_SECONDS;
    tv.tv_usec = TIMEOUT_MILLISECONDS;
    if (setsockopt(socketFD_, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) < 0)
    {
        freeaddrinfo(serverInfo);
        string error("Unable to set timeout option for Socket connection: ");
        error += strerror(errno);
        throw SocketException(error);
    }

    // Loop through the host results until we succeed in connecting
    bool connected = false;
    for (addrinfo* ptr = serverInfo; nullptr != ptr; ptr = ptr->ai_next)
    {
        // Connect to the remote machine
        int status;
        do
        {
            status = connect(socketFD_, ptr->ai_addr, ptr->ai_addrlen);
        } while(EINTR == errno);

        if (status < 0 && EISCONN != errno)
        {
            // Try the next host
            continue;
        }
        connected = true;
        break;
    }
    // We're done with the server info now, so free it
    freeaddrinfo(serverInfo);

    if (!connected)
    {
        throw SocketException(
            string("Unable to connect to server: ") + strerror(errno));
    }

    // Set the timeout for listens on this socket
    tv.tv_sec = 1;
    tv.tv_usec = 0;
    if (0 != setsockopt(socketFD_, SOL_SOCKET, SO_RCVTIMEO,
        reinterpret_cast<char*>(&tv), sizeof(tv)))
    {
        throw SocketException("Unable to set timeout");
    }

    setPeerName();
}


Socket::Socket(const string& domainSocket, bool blocking) :
    socketFD_(socket(PF_UNIX, SOCK_STREAM, 0)),
    open_(true),
    buffer_(MAX_RECEIVE, 0),
    peerName_()
{
    sockaddr_un sockAddr;
    size_t sockAddrLength;

    // Did socket creation succeed?
    if (socketFD_ < 0)
    {
        string error("Unable to create socket: ");
        error += strerror(errno);
        throw SocketException(error);
    }

    // Turn off blocking if requested
    if (!blocking)
    {
        if (fcntl(socketFD_, F_SETFL, O_NONBLOCK) < 0)
        {
            throw SocketException("Unable to set socket to non-blocking");
        }
    }

    sockAddr.sun_family = AF_UNIX;
    if (sizeof(sockAddr.sun_path) < domainSocket.size() - 1)
    {
        throw SocketException("Domain socket filename is too long");
    }
    sockAddrLength = sizeof(sockAddr.sun_family) + domainSocket.size() + 1;
    memcpy(sockAddr.sun_path, domainSocket.c_str(), domainSocket.size() + 1);

    // Connect to the remote machine
    while (connect(
        socketFD_, reinterpret_cast<sockaddr*>(&sockAddr), sockAddrLength) < 0)
    {
        // Connected isn't an error, ignore it
        if (EISCONN == errno)
        {
            break;
        }
        // Interrupted isn't a problem - just try again
        else if (EINTR == errno)
        {
            continue;
        }

        string error("Unable to connect to server: ");
        error += strerror(errno);

        throw SocketException(error);
    }

    // Set the timeout for listens on this socket
    timeval tv;
    tv.tv_sec = 1;
    tv.tv_usec = 0;
    if (0 != setsockopt(socketFD_, SOL_SOCKET, SO_RCVTIMEO,
        reinterpret_cast<char*>(&tv), sizeof(tv)))
    {
        throw SocketException("Unable to set timeout");
    }

    setPeerName();
}


Socket::Socket(const int fileDescriptor) :
    socketFD_(fileDescriptor),
    open_(true),
    buffer_(MAX_RECEIVE, 0),
    peerName_()
{
    sockaddr_storage sockAddr;

    memset(&sockAddr, 0, sizeof(sockAddr));
    socklen_t n = sizeof(sockAddr);
    if (getsockname(socketFD_, reinterpret_cast<sockaddr*>(&sockAddr), &n) < 0)
    {
        throw SocketException("Invalid file descriptor");
    }

    // Set the timeout for listens on this socket
    timeval tv;
    tv.tv_sec = 5;
    tv.tv_usec = 0;
    if (0 != setsockopt(socketFD_, SOL_SOCKET, SO_RCVTIMEO,
        reinterpret_cast<char*>(&tv), sizeof(tv)))
    {
        throw SocketException("Unable to set timeout");
    }

    setPeerName();
}


Socket::~Socket()
{
    close();
}


void Socket::send(const vector<uint8_t>& message) const
{
    send(message.begin(), message.end());
}


void Socket::send(const vector<uint8_t>::const_iterator& begin,
    const vector<uint8_t>::const_iterator& end) const
{
    // Check to make sure the socket isn't closed before trying to send
    if (!open_)
    {
        throw ClosedException();
    }
    if (::send(socketFD_, &(*begin), end - begin, MSG_NOSIGNAL) < 0)
    {
        if (!open_)
        {
            throw ClosedException();
        }
        string error("Failed to send: ");
        error += strerror(errno);
        throw SocketException(error);
    }
}


void Socket::send(const char* const message) const
{
    send(message, strlen(message));
}


void Socket::send(const uint8_t* const message, const uint16_t length) const
{
    send(reinterpret_cast<const char*>(message), length);
}


void Socket::send(const char* const message, const uint16_t length) const
{
    // Check to make sure the socket isn't closed before trying to send
    if (!open_)
    {
        throw ClosedException();
    }
    if (::send(socketFD_, message, length, MSG_NOSIGNAL) < 0)
    {
        if (!open_)
        {
            throw ClosedException();
        }
        string error("Failed to send: ");
        error += strerror(errno);
        throw SocketException(error);
    }
}


vector<uint8_t> Socket::receive() const
{
    // There are four cases here:
    // Another thread may have closed the socket
    // The entity we connected to closed the socket
    // The socket is still open, we just have to keep waiting for data
    // Some other error occurred
    size_t returnedBytes = 0;
    while (returnedBytes <= 0)
    {
        returnedBytes = ::recv(socketFD_, &buffer_[0], buffer_.size(), 0);

        // Entity performed an orderly close
        if (0 == returnedBytes)
        {
            throw ClosedException();
        }
        else if (returnedBytes < 0)
        {
            // Another thread closed the socket while we were waiting
            if (!open_)
            {
                throw ClosedException();
            }
            // Socket is still open, wait for more data
            else if (ETIMEDOUT == errno || EAGAIN == errno || EINTR == errno)
            {
                continue;
            }
            // Some other error
            else
            {
                string error("Failed to read: ");
                error += strerror(errno);
                throw SocketException(error);
            }
        }
        // Received a message, hooray!
        else
        {
            break;
        }
    }
    return vector<uint8_t>(
        buffer_.begin(),
        buffer_.begin() + min(MAX_RECEIVE, returnedBytes)
    );
}


bool Socket::getBlocking() const
{
    return O_NONBLOCK & fcntl(socketFD_, F_GETFD);
}


void Socket::close()
{
    /// @TODO(bskari) Fix this race condition.
    if (open_)
    {
        open_ = false;
        ::close(socketFD_);
    }
}

#include <iostream>
void Socket::setPeerName()
{
    sockaddr_storage address;
    socklen_t length = sizeof(address);
    if (0 == getpeername(socketFD_, reinterpret_cast<sockaddr*>(&address), &length))
    {
        assert(length <= sizeof(address) &&
            "getpeername used up too much buffer space");
        if (length > sizeof(address))
        {
            Logger::log(Logger::WARN) << "Unable to set peer name";
            return;
        }

        char addressStr[INET6_ADDRSTRLEN];
        if (AF_INET == address.ss_family || AF_INET6 == address.ss_family)
        {
            const char* success = inet_ntop(
                address.ss_family,
                &address,
                addressStr,
                sizeof(addressStr) / sizeof(addressStr[0])
            );
            const bool truncated = (nullptr == success);
            if (truncated)
            {
                Logger::log(Logger::WARN) << "Peer name truncated to "
                    << addressStr;
            }
        }
        else if (AF_UNIX == address.ss_family)
        {
            // Addresses don't make sense with Unix domain sockets
            return;
        }
        else
        {
            assert(false && "Unknown socket address family");
            Logger::log(Logger::WARN) << "Unknown socket address family: "
                << address.ss_family << ", expected IPv4 or IPv6";
            return;
        }

        const_cast<string*>(&peerName_)->operator=(addressStr);
    }
}
