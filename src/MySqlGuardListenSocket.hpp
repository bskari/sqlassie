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

#ifndef MYSQL_GUARD_LISTEN_SOCKET_HPP
#define MYSQL_GUARD_LISTEN_SOCKET_HPP

#include "ListenSocket.hpp"
#include "Socket.hpp"
#include "Proxy.hpp"

#include <memory>
#include <string>
#include <boost/cstdint.hpp>

/**
 * Listen socket that intercepts MySQL connections and analyzes them for
 * attacks. If any are found, the query is rejected.
 * @author Brandon Skari
 * @date January 9 2011
 */

class MySqlGuardListenSocket : public ListenSocket
{
public:
	/**
	 * Constructor for using network sockets.
	 * @param listenPort The port to listen to for network connections.
	 * @param mySqlPort The port to connect to where MySQL is running.
	 * @param mySqlHost The host to connect to where MySQL is running.
	 * @param username The username to use when connecting to MySQL to grab the
	 *  list of valid username/host combinations.
	 * @param password The password to use when connecting to MySQL to grab the
	 *  list of valid username/host combinations.
	 * @throw SocketException Unable to bind to listen port.
	 */
	MySqlGuardListenSocket(
		uint16_t listenPort,
		uint16_t mySqlPort = 3306,
		std::string mySqlHost = std::string("127.0.0.1"),
		std::string username = std::string(),
		std::string password = std::string()
	);
	
	/**
	 * Constructor for listening on a Unix domain socket.
	 * @param domainSocket The socket to listen to for network connections.
	 * @param mySqlPort The port number to connect to where MySQL is running.
	 * @param mySqlHost The host to connect to where MySQL is running.
	 * @param username The username to use when connecting to MySQL to grab the
	 *  list of valid username/host combinations.
	 * @param password The password to use when connecting to MySQL to grab the
	 *  list of valid username/host combinations.
	 * @throw SocketException Unable to bind to listen port.
	 */
	MySqlGuardListenSocket(
		const std::string& domainSocket,
		uint16_t mySqlPort = 3306,
		std::string mySqlHost = std::string("127.0.0.1"),
		std::string username = std::string(),
		std::string password = std::string()
	);
	
	/**
	 * Constructor for connecting to a Unix domain socket.
	 * @param listenPort The port to listen to for network connections.
	 * @param domainSocket The domain socket to connect to MySQL.
	 * @param username The username to use when connecting to MySQL to grab the
	 *  list of valid username/host combinations.
	 * @param password The password to use when connecting to MySQL to grab the
	 *  list of valid username/host combinations.
	 * @throw SocketException Unable to bind to listen port.
	 */
	MySqlGuardListenSocket(
		uint16_t listenPort,
		const std::string& domainSocket,
		std::string username = std::string(),
		std::string password = std::string()
	);
	
	/**
	 * Constructor for connecting to 2 Unix domain sockets.
	 * @param listenDomainSocket The domain socket to listen to for connections.
	 * @param serverDomainSocket The domain socket to connect to MySQL.
	 * @param username The username to use when connecting to MySQL to grab the
	 *  list of valid username/host combinations.
	 * @param password The password to use when connecting to MySQL to grab the
	 *  list of valid username/host combinations.
	 * @throw SocketException Unable to bind to listen port.
	 */
	MySqlGuardListenSocket(
		const std::string& listenDomainSocket,
		const std::string& serverDomainSocket,
		std::string username = std::string(),
		std::string password = std::string()
	);
	
	~MySqlGuardListenSocket();
	
	/**
	 * Overridden from ListenSocket so that it can create MySq1Guard sockets.
	 */
	virtual void acceptClients() const;

protected:
	/**
	 * Handles a new network connection.
	 * @param clientConnection The Socket from the client's connection.
	 * @throw SocketException Unable to connect to MySQL server.
	 */
	void handleConnection(std::auto_ptr<Socket> clientConnection) const;
	
private:
	bool mySqlNetworkSocket_;
	const uint16_t mySqlPort_;
	const std::string mySqlHost_;
	const std::string domainSocketFile_;
	
	// ***** Hidden methods *****
	MySqlGuardListenSocket(const MySqlGuardListenSocket& rhs);
	MySqlGuardListenSocket& operator=(const MySqlGuardListenSocket& rhs);
};

#endif
