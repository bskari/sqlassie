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

#include "SimpleProxy.hpp"
#include "Socket.hpp"
#include "SocketException.hpp"

#include <vector>
#include <memory>
#include <boost/thread.hpp>
#include <exception>
#include <iostream>
#include <boost/cstdint.hpp>

using std::vector;
using std::auto_ptr;
using boost::thread;
using std::exception;
using std::cerr;
using std::endl;


SimpleProxy::SimpleProxy(auto_ptr<Socket> client, auto_ptr<Socket> server) :
    clientConnection_(client),
    serverConnection_(server)
{
    thread(*this);
}


SimpleProxy::SimpleProxy(const SimpleProxy& rhs) :
    clientConnection_(rhs.clientConnection_),
    serverConnection_(rhs.serverConnection_)
{
}


SimpleProxy::~SimpleProxy()
{
}


void SimpleProxy::operator()()
{
    try
    {
        vector<uint8_t> packet;
        // Keep reading until the socket closes
        while (true)
        {
            // Wait for a message from the client
            packet = clientConnection_->receive();

            processClientMessage(packet);

            // Wait for a message from the server
            packet = serverConnection_->receive();

            processServerMessage(packet);
        }
    }
    catch (ClosedException& e)
    {
        // All done, so nothing else to do
    }
    catch (exception& e)
    {
        cerr << "in Thread exited unexpectedly with error: "
            << e.what()
            << endl;
    }
}


void SimpleProxy::processClientMessage(vector<uint8_t>& message)
{
    serverConnection_->send(message);
}

void SimpleProxy::processServerMessage(vector<uint8_t>& message)
{
    clientConnection_->send(message);
}
