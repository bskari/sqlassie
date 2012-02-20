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

#ifndef SIMPLE_PROXY_HPP
#define SIMPLEPROXY_HPP

#include <string>
#include <memory>
#include <vector>
#include <boost/cstdint.hpp>

class Socket;

/**
 * Simple proxy that tunnels a connection. Processing is client initiated. This
 * waits for a message from the client, then processs any and all messages that
 * the client may have queued up. Then it waits for a message from the server,
 * and processes any and all messages the server may have queued. This repeats
 * until the socket is closed.
 * @author Brandon Skari
 * @date October 9 2010
 */

class SimpleProxy
{
public:
	/**
	 * Default constructor.
	 * @param socket The socket to listen on.
	 */
	SimpleProxy(std::auto_ptr<Socket> client, std::auto_ptr<Socket> server);
	
	/**
	 * Copy constructor needed for Boost threads.
	 */
	SimpleProxy(const SimpleProxy& rhs);
	
	/**
	 * Destructor.
	 */
	virtual ~SimpleProxy();
	
	/**
	 * Called when a new thread is created.
	 */
	virtual void operator()();
	
protected:
	/**
	 * Processes a message from the client; currently forwards the message
	 * to the server.
	 */
	virtual void processClientMessage(std::vector<uint8_t>& message);

	/**
	 * Process a message from the server; currently forwards the message to
	 * the connected client.
	 */
	virtual void processServerMessage(std::vector<uint8_t>& message);
	
	mutable std::auto_ptr<Socket> clientConnection_;
	mutable std::auto_ptr<Socket> serverConnection_;

private:
	// ***** Hidden methods *****
	SimpleProxy& operator=(const SimpleProxy&);
};

#endif
