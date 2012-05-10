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

#ifndef SRC_SOCKET_HPP_
#define SRC_SOCKET_HPP_

#include <vector>
#include <string>
#include <boost/cstdint.hpp>

/**
 * Wrapper around Unix C sockets for TCP communication.
 * @author Brandon Skari
 * @date April 22 2010
 */

class Socket
{
public:
    /**
     * Normal constructor to communicate to an address on a given port.
     * @param port The port to communicate on.
     * @param address The computer to connect to.
     */
    Socket(const uint16_t port, const std::string& address,
        bool blocking = true);

    /**
     * Constructor to communicate on the localhost using Unix domain sockets.
     * @param domainSocket The .
     */
    explicit Socket(const std::string& domainSocket, bool blocking = true);

    /**
     * Constructor from a given C file descriptor.
     * @param fileDescriptor The Unix C file descriptor of a socket.
     */
    explicit Socket(const int fileDescriptor);

    /**
     * Destructor.
     */
    virtual ~Socket();

    /**
     * Sends a message out on the socket.
     * @param message The message to send.
     */
    ///@{
    void send(const std::vector<uint8_t>& message) const;
    void send(const std::vector<uint8_t>::const_iterator& begin,
        const std::vector<uint8_t>::const_iterator& end) const;
    void send(const char* message) const;
    void send(const char* message, const uint16_t length) const;
    void send(const uint8_t* message, const uint16_t length) const;
    ///@}

    /**
     * Blocks and receives a message from the socket.
     * @return The message received on the socket.
     */
    std::vector<uint8_t> receive() const;

    /**
     * Returns true if the socket blocks for send and receive.
     */
    bool getBlocking() const;

    /**
     * Close the Socket prior to destruction.
     */
    void close();

    /**
     * Returns true if the Socket hasn't had any errors and hasn't been
     * explicitly closed by the user. Note that unexpected errors such as
     * network drops will not be noticed until a read/write is attempted and
     * fails, so this is not a reliable guarantee that the Socket is still
     * operating; this just indicates that no error has been found yet and
     * the user has not closed it.
     */
    inline bool isOpen() const { return open_; }

    /**
     * Returns the address of the peer connected to this socket.
     * @return Address of the connected peer.
     */
    inline const std::string& getPeerName() const { return peerName_; }

protected:
    static const ssize_t MAX_RECEIVE = 4096;
    static const size_t TIMEOUT_SECONDS = 1;
    static const size_t TIMEOUT_MILLISECONDS = 0;

    const int socketFD_;
    bool open_;
    mutable std::vector<uint8_t> buffer_;
    const std::string peerName_;

private:
    void setPeerName();

    // Hidden methods
    Socket& operator=(const Socket& rhs);
};

#endif  // SRC_SOCKET_HPP_
