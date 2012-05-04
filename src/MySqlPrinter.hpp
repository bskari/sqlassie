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

#ifndef MY_SQL_PRINTER_HPP
#define MY_SQL_PRINTER_HPP

#include "ProxyHalf.hpp"
class Socket;

#include <vector>
#include <string>
#include <boost/cstdint.hpp>

class MySqlPrinter : public ProxyHalf
{
public:
    MySqlPrinter(Socket* incomingConnection, Socket* outgoingConnection);
    void handleMessage(std::vector<uint8_t>& rawMessage) const;

private:
    mutable uint8_t lastCommandCode_;
    mutable bool firstPacket_;
    mutable std::string database_;
};

#endif
