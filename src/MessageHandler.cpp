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
#include "MessageHandler.hpp"
#include "Socket.hpp"
#include "SocketException.hpp"

#include <vector>
#include <memory>
#include <iostream>
#include <boost/cstdint.hpp>

using std::vector;
using std::auto_ptr;
using std::cerr;
using std::endl;


MessageHandler::MessageHandler(auto_ptr<Socket>& socket) : _socket(socket)
{
}


void MessageHandler::operator()()
{
    while (true)
    {
        vector<uint8_t> message;
        try
        {
            message = _socket->receive();
        }
        catch (ClosedException& e)
        {
            Logger::log(Logger::DEBUG) << "Socket closed, rethrowing";
            throw;
        }
        catch (SocketException& e)
        {
            Logger::log(Logger::ERROR) << "MessageHandler caught a SocketException: " << e.what();
            break;
        }

        _socket->send(message.begin(), message.end());
    }
}
