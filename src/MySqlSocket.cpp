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

#include "MySqlSocket.hpp"
#include "MySqlConstants.hpp"
#include "Socket.hpp"

#include <string>
#include <cassert>
#include <cstring>

using std::string;


/*--------------------------------------
MySQL error messages look like this:
Bytes - Description
3 - payload length
1 - packet number
1 - field count, always 0xFF
2 - error number
1 - SQL state marker, always '#'
5 - SQL state (5 characters)
n - message (not null-terminated!)
--------------------------------------*/
// Static members
const size_t MySqlSocket::packetNumberPos = 3;
const size_t MySqlSocket::errorPacketErrorNumberPos = 3 + 1 + 1;
const size_t MySqlSocket::errorPacketSqlStatePos = 3 + 1 + 1 + 2 + 1;
const size_t MySqlSocket::errorPacketMessagePos = 3 + 1 + 1 + 2 + 1 + 5;


MySqlSocket::MySqlSocket(const uint16_t port, const string& address,
	bool blocking) :
		Socket(port, address, blocking),
		okPacket_(),
		emptySetPacket_(),
		errorPacket_(),
		okPacketInitialized_(false),
		emptySetPacketInitialized_(false),
		errorPacketInitialized_(false)
{
}


MySqlSocket::MySqlSocket(const string& domainSocket, bool blocking) :
	Socket(domainSocket, blocking),
	okPacket_(),
	emptySetPacket_(),
	errorPacket_(),
	okPacketInitialized_(false),
	emptySetPacketInitialized_(false),
	errorPacketInitialized_(false)
{
}


MySqlSocket::MySqlSocket(const int fileDescriptor) :
	Socket(fileDescriptor),
	okPacket_(),
	emptySetPacket_(),
	errorPacket_(),
	okPacketInitialized_(false),
	emptySetPacketInitialized_(false),
	errorPacketInitialized_(false)
{
}


MySqlSocket::~MySqlSocket()
{
}


void MySqlSocket::sendOkPacket(const uint8_t packetNumber) const
{
	if (!okPacketInitialized_)
	{
		initializeOkPacket();
	}
	// Insert the packet number
	okPacket_.at(packetNumberPos) = packetNumber;
	
	assert(okPacket_.at(0) == okPacket_.size() - 4
		&& "Incorrect payload length in okMessage packet");
	
	// Send the ok packet
	send(okPacket_);
}


void MySqlSocket::sendEmptySetPacket() const
{
	if (!emptySetPacketInitialized_)
	{
		initializeEmptySetPacket();
	}
	
	// For this message, affected rows will always be 1, insert ID will always
	// be 1, server status will always be auto commit, warning count will be 0,
	// and message will be blank
	
	// Send the empty set packet
	send(emptySetPacket_);
}


void MySqlSocket::sendErrorPacket(const uint8_t packetNumber,
	const uint16_t errorNumber, const string& message) const
{
	if (!errorPacketInitialized_)
	{
		initializeErrorPacket();
	}

	// Insert the packet number
	errorPacket_.at(packetNumberPos) = packetNumber;
	
	// Insert the error number
	const uint8_t* const errorNumberPtr =
		reinterpret_cast<const uint8_t*>(&errorNumber);
	#ifdef LITTLE_ENDIAN
		errorPacket_.at(errorPacketErrorNumberPos) = errorNumberPtr[0];
		errorPacket_.at(errorPacketErrorNumberPos + 1) = errorNumberPtr[1];
	#else
		#ifdef BIG_ENDIAN
			errorPacket_.at(errorPacketErrorNumberPos) = errorNumberPtr[1];
			errorPacket_.at(errorPacketErrorNumberPos + 1) = errorNumberPtr[0];
		#else
			assert(false &&
"Unexpected endian value - if you're on a mixed endian system, you'll have to\
write this yourself; otherwise, recompile and either define LITTLE_ENDIAN or\
BIG_ENDIAN as appropriate");
		#endif
	#endif
	
	// Insert message
	if (errorPacket_.size() < errorPacketMessagePos + message.size())
	{
		errorPacket_.reserve(errorPacketMessagePos + message.size());
	}
	copy(message.begin(), message.end(),
		errorPacket_.begin() + errorPacketMessagePos);
	
	// Now that we know the size, insert the packet length
	const uint32_t packetLength = errorPacketMessagePos + message.size() - 4;
	const uint8_t* const packetPtr =
		reinterpret_cast<const uint8_t*>(&packetLength);
	#ifdef LITTLE_ENDIAN
		errorPacket_.at(0) = packetPtr[0];
		errorPacket_.at(1) = packetPtr[1];
		errorPacket_.at(2) = packetPtr[2];
	#else
		#ifdef BIG_ENDIAN
			errorPacket_.at(0) = packetPtr[3];
			errorPacket_.at(1) = packetPtr[2];
			errorPacket_.at(2) = packetPtr[1];
		#else
			assert(false &&
"Unexpected endian value - if you're on a mixed endian system, you'll have to\
write this yourself; otherwise, recompile and either define LITTLE_ENDIAN or\
BIG_ENDIAN as appropriate");
		#endif
	#endif
	
	// Send the error packet
	send(errorPacket_.begin(),
		errorPacket_.begin() + errorPacketMessagePos + message.size());
}


void MySqlSocket::initializeOkPacket() const
{
	assert(!okPacketInitialized_ &&
		"Ok packet should only be initialized once");
	/*--------------------------------------
	Individual MySQL (sub)packets look like this:
	Bytes - Description
	3 - payload length (excluding header)
	1 - packet number
	n - packet payload
	--------------------------------------*/
	
	/*--------------------------------------
	Ok messages look like this:
	Bytes - Description
	3 - payload length (excluding header)
	1 - packet number
	1 - always 0
	1-9 - length coded binary, affected rows
	1-9 - length coded binary, insert ID
	2 - server status
	2 - warning count
	n - message (not null-terminated!)
	--------------------------------------*/
	
	// For this message, affected rows will always be 1, insert ID will always
	// be 1, server status will always be auto commit, warning count will be 0,
	// and message will be blank
	uint8_t okMessageInitialization[] = {
		0x07, 0x00, 0x00, // payload length
		0x01, // packet number
		0x00, // field 1, always 0
		0x01, // lcb of affected rows
		0x01, // lcb of insert ID
		MySqlConstants::STATUS_AUTO_COMMIT, 0x00, // server status
		0x00, 0x00 // warning count
		// no message
	};
	const int OK_MESSAGE_SIZE =
		sizeof(okMessageInitialization) / sizeof(okMessageInitialization[0]);
	okPacket_.reserve(OK_MESSAGE_SIZE);
	for (int i = 0; i < OK_MESSAGE_SIZE; ++i)
	{
		okPacket_.push_back(okMessageInitialization[i]);
	}
	assert(okPacket_.at(0) == okPacket_.size() - 4
		&& "Incorrect payload length in ok message packet");
	
	okPacketInitialized_ = true;
}


void MySqlSocket::initializeEmptySetPacket() const
{
	assert(!emptySetPacketInitialized_ &&
		"Empty set packet should only be initialized once");
	/*--------------------------------------
	Individual MySQL (sub)packets look like this:
	Bytes - Description
	3 - payload length (excluding header)
	1 - packet number
	n - packet payload
	--------------------------------------*/
	
	/*-----------------------------------------
	Responses look like this:
	Bytes - Description
	++++ Field count packet ++++
	3 - payload length
	1 - packet number
	1-9 - length coded binary, number of fields
	++++ One or more field descriptors ++++
	3 - payload length
	1 - packet number
	1-9 + n - length coded string, catalog (always def)
	1-9 + n - length coded string, database
	1-9 + n - length coded string, table
	1-9 + n - length coded string, original table
	1-9 + n - length coded string, name
	1-9 + n - length coded string, original name
	1 - filler, always 0x0C
	2 - charset (usually 0xC0)
	4 - length
	1 - field type
	2 - field flags
	1 - decimals (usually 0x1F)
	2 - filler, always 0x00
	++++ EOF packet ++++
	3 - payload length
	1 - packet number
	1 - EOF marker, always 0xFE
	2 - warning count
	2 - status flags
	++++ Zero or more row data packets ++++
	3 - payload length
	1 - packet number
	1-9 + n - length coded string, value of row
	++++ EOF packet ++++
	3 - payload length
	1 - packet number
	1 - EOF marker, always 0xFE
	2 - warning count
	2 - status flags
	-----------------------------------------*/

	uint8_t emptySetMessageInitialization[] = {
		// ++++ Field count packet +++++
		0x01, 0x00, 0x00, // payload length
		0x01, // packet number
		0x01, // number of fields
		// ++++ Field descriptor packet ++++
		0x16, 0x00, 0x00, // packet length
		0x02, // packet number
		0x03, 'd', 'e', 'f', // catalog (always def)
		0x00, // database (none)
		0x00, // table (none)
		0x00, // original table
		0x00, // name (none)
		0x00, // original name (none)
		0x0C, // filler
		0xC0, 0x00, // charset number (this value taken from Wireshark)
		0x00, 0x00, 0x00, 0x00, // length
		MySqlConstants::TYPE_VAR_STRING, // field type
		0x00, 0x00, // field flags
		0x1F, // decimals (this value taken from Wireshark)
		0x00, 0x00, // filler, always 0x00
		// ++++ EOF packet ++++
		0x05, 0x00, 0x00, // packet length
		0x03, // packet number
		0xFE, // EOF marker, always 0xFE
		0x00, 0x00, // warning count
		MySqlConstants::STATUS_AUTO_COMMIT, 0x00, // status flags
		// ++++ Row packet ++++
		// (empty)
		// ++++ EOF packet ++++
		0x05, 0x00, 0x00, // payload length
		0x04, // packet number
		0xFE, // EOF marker, always 0xFE
		0x00, 0x00, // warning count
		MySqlConstants::STATUS_AUTO_COMMIT, 0x00 // status flags
	};
	const int EMPTY_SET_MESSAGE_SIZE = sizeof(emptySetMessageInitialization)
		/ sizeof(emptySetMessageInitialization[0]);
	emptySetPacket_.reserve(EMPTY_SET_MESSAGE_SIZE);
	for (int i = 0; i < EMPTY_SET_MESSAGE_SIZE; ++i)
	{
		emptySetPacket_.push_back(emptySetMessageInitialization[i]);
	}
	
	emptySetPacketInitialized_ = true;
}


void MySqlSocket::initializeErrorPacket() const
{
	assert(!errorPacketInitialized_ &&
		"Error packet should only be initialized once");
	/*--------------------------------------
	Individual MySQL (sub)packets look like this:
	Bytes - Description
	3 - payload length (excluding header)
	1 - packet number
	n - packet payload
	--------------------------------------*/
	
	/*--------------------------------------
	MySQL error messages look like this:
	Bytes - Description
	3 - payload length
	1 - packet number
	1 - field count, always 0xFF
	2 - error number
	1 - SQL state marker, always '#'
	5 - SQL state (5 characters)
	n - message (not null-terminated!)
	--------------------------------------*/
	
	uint8_t errorMessageInitialization[] = {
		// ++++ Error message +++++
		0x00, 0x00, 0x00, // payload length
		0x00, // packet number (replaced by parameter)
		0xFF, // field count, always 0xFF
		0x28, 0x04, // Error number, these values taken from Wireshark
		'#', // SQL state marker, always '#'
		'4', '2', '0', '0', '0' // This value taken from Wireshark
	};
	const int ERROR_MESSAGE_SIZE = sizeof(errorMessageInitialization)
		/ sizeof(errorMessageInitialization[0]);
	errorPacket_.reserve(ERROR_MESSAGE_SIZE);
	for (int i = 0; i < ERROR_MESSAGE_SIZE; ++i)
	{
		errorPacket_.push_back(errorMessageInitialization[i]);
	}
	
	errorPacketInitialized_ = true;
}
