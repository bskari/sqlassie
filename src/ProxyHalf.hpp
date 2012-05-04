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

#ifndef PROXY_HALF_HPP
#define PROXY_HALF_HPP

#include <vector>
#include <boost/cstdint.hpp>

class Socket;

/**
 * Half of a full proxy that receives messages from one Socket and does some
 * processing on the messages. Currently, it forwards the messages through
 * another Socket; derived classes can override this behavior.
 * @author Brandon Skari
 * @date October 24 2010
 */

class ProxyHalf
{
public:
    /**
     * Default constructor.
     * @param socket The socket to listen on.
     */
    ProxyHalf(Socket* incomingConnection, Socket* outgoingConnection);

    /**
     * Copy constructor needed for Boost threads. This can't be const because
     * we need to transfer ownership of the auto_ptrs.
     */
    ProxyHalf(ProxyHalf& rhs);

    /**
     * Destructor.
     */
    virtual ~ProxyHalf();

    /**
     * Called when a new thread is created.
     */
    void operator()();

protected:
    /**
     * Handles a message that has just been received from the incoming Socket.
     * In this class, just forward the message.
     */
    virtual void handleMessage(std::vector<uint8_t>& rawMessage) const;

    Socket* const incomingConnection_;
    Socket* const outgoingConnection_;

private:
    // ***** Hidden methods *****
    ProxyHalf& operator=(const ProxyHalf&);
};

#endif
