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

#ifndef SRC_MESSAGEHANDLER_HPP_
#define SRC_MESSAGEHANDLER_HPP_

#include "Socket.hpp"

#include <memory>

/**
 * Interface for classes that handle messages received from a socket.
 * @author Brandon Skari
 * @date April 22 2010
 */

class MessageHandler
{
    public:
        /**
         * Normal constructor.
         * @param socket The socket to handle messages from.
         */

        explicit MessageHandler(std::auto_ptr<Socket>& socket);

        /**
         * Destructor.
         */

        virtual ~MessageHandler() {}

        /**
         * Starts listening for messages and handling them. Required starting
         * point for using the Boost thread library.
         */
        virtual void operator()();
    protected:
        std::auto_ptr<Socket> _socket;
};

#endif  // SRC_MESSAGEHANDLER_HPP_
