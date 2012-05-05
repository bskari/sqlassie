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
#include "ProxyHalf.hpp"
#include "SocketException.hpp"
#include "Socket.hpp"

#include <boost/cstdint.hpp>
#include <boost/thread.hpp>
#include <exception>
#include <memory>
#include <vector>

using std::vector;
using std::exception;
using std::auto_ptr;


ProxyHalf::ProxyHalf(Socket* const incomingConnection,
    Socket* const outgoingConnection) :
        incomingConnection_(incomingConnection),
        outgoingConnection_(outgoingConnection)
{
}


ProxyHalf::ProxyHalf(ProxyHalf& rhs) :
    incomingConnection_(rhs.incomingConnection_),
    outgoingConnection_(rhs.outgoingConnection_)
{
}


ProxyHalf::~ProxyHalf()
{
}


void ProxyHalf::operator()()
{
    // Keep reading until the socket closes
    try
    {
        while (true)
        {
            vector<uint8_t> packet(incomingConnection_->receive());

            handleMessage(packet);
        }
    }
    catch (ClosedException& e)
    {
        // All done, so nothing else to do
        incomingConnection_->close();
        outgoingConnection_->close();
    }
    catch (exception& e)
    {
        Logger::log(Logger::ERROR)
            << "ProxyHalf::operator() exited unexpectedly with error: "
            << e.what();

        // Close the remaining connections
        incomingConnection_->close();
        outgoingConnection_->close();
    }
}


void ProxyHalf::handleMessage(vector<uint8_t>& rawMessage) const
{
    outgoingConnection_->send(rawMessage.begin(), rawMessage.end());
}
