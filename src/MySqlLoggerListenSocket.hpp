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

#ifndef MYSQL_LOGGER_LISTEN_SOCKET_HPP
#define MYSQL_LOGGER_LISTEN_SOCKET_HPP

#include "ListenSocket.hpp"
#include "Socket.hpp"

#include <memory>
#include <string>
#include <boost/cstdint.hpp>

/**
 * Listen socket that intercepts MySQL connections and saves all commands to a
 * file using MySqlLoggers.
 * @author Brandon Skari
 * @date October 25 2010
 */

class MySqlLoggerListenSocket : public ListenSocket
{
public:
    MySqlLoggerListenSocket(uint16_t listenPort,
        uint16_t mySqlPort = 3306,
        std::string mySqlHost = std::string("127.0.0.1"));

    /**
     * Quit listening and close all the sockets and threads.
     */
    void quit();

protected:
    void handleConnection(std::auto_ptr<Socket> clientConnection) const;

private:
    const uint16_t mySqlPort_;
    const std::string mySqlHost_;
};

#endif
