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

#include "ListenSocket.hpp"
#include "Logger.hpp"
#include "MySqlLogger.hpp"
#include "MySqlLoggerListenSocket.hpp"
#include "Proxy.hpp"
#include "Socket.hpp"
#include "SocketException.hpp"

#include <memory>
#include <string>

using std::auto_ptr;
using std::string;


MySqlLoggerListenSocket::MySqlLoggerListenSocket(
	const uint16_t listenPort,
	const uint16_t mySqlPort,
	const string mySqlHost
) :
	ListenSocket(listenPort),
	mySqlPort_(mySqlPort),
	mySqlHost_(mySqlHost)
{
}


void MySqlLoggerListenSocket::handleConnection(
	auto_ptr<Socket> clientConnection
) const
{
	auto_ptr<Socket> serverConnection(new Socket(mySqlPort_, mySqlHost_));
	AutoPtrWithOperatorParens<ProxyHalf> client(
		new MySqlLogger(
			clientConnection.get(),
			serverConnection.get(),
			"./queries/"
		)
	);
	AutoPtrWithOperatorParens<ProxyHalf> server(
		new ProxyHalf(
			serverConnection.get(),
			clientConnection.get()
		)
	);
	Proxy proxy(client, server, clientConnection, serverConnection);
	proxy.runUntilFinished();
}
