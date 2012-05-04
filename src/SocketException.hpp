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

#ifndef SOCKET_EXCEPTION_HPP
#define SOCKET_EXCEPTION_HPP

#include "DescribedException.hpp"

/**
 * Exceptions specifically meant to be thrown by the Socket class.
 * @author Brandon Skari
 * @date April 21 2010
 */

class SocketException : public DescribedException
{
public:
    /**
     * Normal constructor.
     */
    SocketException() : DescribedException("Socket exception") {}

    /**
     * Constructor with explicit description.
     * @param description The descritiption to return from what .
     */
    SocketException(const std::string& description) :
        DescribedException("SocketException: " + description) {}
};

class ClosedException : public SocketException
{
public:
    /**
     * Normal constructor.
     */
    ClosedException() : SocketException("ClosedException") {}
};

#endif
