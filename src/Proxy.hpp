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

#ifndef PROXY_HPP
#define PROXY_HPP

#include "ProxyHalf.hpp"
#include "Socket.hpp"
#include "AutoPtrWithOperatorParens.hpp"

#include <memory>

/**
 * Simple proxy that tunnels a connection. If this Proxy is given to a Boost
 * thread, it will automatically close the two connections when they finish.
 * Alternatively, a user can call start themselves.
 * @author Brandon Skari
 * @date October 9 2010
 */

class Proxy
{
public:
	/**
	 * Starts threads with both ProxyHalfs.
	 * @param in The first ProxyHalf that listens to a client.
	 * @param out The second ProxyHalf that listens to a server.
	 * @param inSocket The socket from the client to this proxy.
	 * @param outSocket The socket from this proxy to the server.
	 */
	Proxy(AutoPtrWithOperatorParens<ProxyHalf> in, 
		AutoPtrWithOperatorParens<ProxyHalf> out,
		std::auto_ptr<Socket> inSocket, std::auto_ptr<Socket> outSocket);
	
	Proxy(Proxy& rhs);
	
	/**
	 * Default destructor.
	 */
	virtual ~Proxy();
	
	/**
	 * Called by Boost thread; calls start.
	 */
	void operator()();
	
	/**
	 * Starts the threads for the two instances of ProxyHalf and waits for them
	 * to finish.
	 */
	void runUntilFinished();

private:
	AutoPtrWithOperatorParens<ProxyHalf> in_;
	AutoPtrWithOperatorParens<ProxyHalf> out_;
	std::auto_ptr<Socket> inSocket_;
	std::auto_ptr<Socket> outSocket_;

	// ***** Hidden methods *****
	Proxy& operator=(const Proxy&);
};

#endif
