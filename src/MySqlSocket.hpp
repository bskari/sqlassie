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

#ifndef MYSQL_SOCKET_HPP
#define MYSQL_SOCKET_HPP

#include "Socket.hpp"

#include <string>
#include <boost/cstdint.hpp>
#include <vector>

/**
 * Extension to Socket that adds some MySQL specific send commands.
 * @author Brandon Skari
 * @date May 3 2011
 */

class MySqlSocket : public Socket
{
public:
	/**
	 * Normal constructor to communicate to an address on a given port.
	 * @param port The port to communicate on.
	 * @param address The computer to connect to.
	 * @param blocking If the socket should block on reads.
	 */
	MySqlSocket(const uint16_t port, const std::string& address,
		bool blocking = true);
	
	/**
	 * Constructor to communicate on the localhost using Unix domain sockets.
	 * @param domainSocket The Unix domain socket's name.
	 * @param blocking If the socket should block on reads.
	 */
	explicit MySqlSocket(const std::string& domainSocket, bool blocking = true);
	
	/**
	 * Constructor from a given C file descriptor.
	 * @param fileDescriptor The Unix C file descriptor of a socket.
	 */
	explicit MySqlSocket(const int fileDescriptor);

	/**
	 * Destructor.
	 */
	virtual ~MySqlSocket();
	
	/**
	 * Sends an MySQL OK packet.
	 * @param packetNumber The MySQL packet number (this is used as an internal
	 *  state within client/server communications and is used for consistency -
	 *  this should be one higher than the last message sent/received.
	 * @throw SocketException
	 */
	void sendOkPacket(uint8_t packetNumber) const;
	
	/**
	 * Sends a MySQL empty set packet.
	 * @param packetNumber The MySQL packet number (this is used as an internal
	 *  state within client/server communications and is used for consistency -
	 *  this should be one higher than the last message sent/received.
	 * @throw SocketException
	 */
	void sendEmptySetPacket() const;
	
	/**
	 * Sends a MySQL error packet with a given message and error number.
	 * @param packetNumber The MySQL packet number (this is used as an internal
	 *  state within client/server communications and is used for consistency -
	 *  this should be one higher than the last message sent/received.
	 * @param errorNumber The MySQL error code. The default values was taken
	 *  from a Wireshark packet dump.
	 * @param message The error message.
	 */
	void sendErrorPacket(uint8_t packetNumber,
		const uint16_t errorNumber = 0x0428,
		const std::string& message = std::string("Error")) const;

private:
	/** Message buffers. */
	///@{
	mutable std::vector<uint8_t> okPacket_;
	mutable std::vector<uint8_t> emptySetPacket_;
	mutable std::vector<uint8_t> errorPacket_;
	void initializeOkPacket() const;
	void initializeEmptySetPacket() const;
	void initializeErrorPacket() const;
	mutable bool okPacketInitialized_;
	mutable bool emptySetPacketInitialized_;
	mutable bool errorPacketInitialized_;
	static const size_t packetNumberPos;
	static const size_t errorPacketErrorNumberPos;
	static const size_t errorPacketSqlStatePos;
	static const size_t errorPacketMessagePos;
	///@}
	
	// Hidden methods
	MySqlSocket& operator=(const MySqlSocket& rhs);
	MySqlSocket(MySqlSocket& rhs);
};

#endif
