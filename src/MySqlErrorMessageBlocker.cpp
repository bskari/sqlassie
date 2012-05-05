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

#include "Logger.hpp"
#include "MySqlConstants.hpp"
#include "MySqlErrorMessageBlocker.hpp"
#include "MySqlSocket.hpp"
#include "nullptr.hpp"
#include "ProxyHalf.hpp"
#include "QueryRisk.hpp"
#include "Socket.hpp"

#include <boost/cstdint.hpp>
#include <cassert>
#include <vector>

using std::vector;

MySqlErrorMessageBlocker::MySqlErrorMessageBlocker(
    MySqlSocket* incomingConnection,
    MySqlSocket* outgoingConnection
) :
    ProxyHalf(incomingConnection, outgoingConnection),
    lastQueryType_(QueryRisk::TYPE_UNKNOWN),
    firstPacket_(true)
{
}


MySqlErrorMessageBlocker::MySqlErrorMessageBlocker(
    MySqlErrorMessageBlocker& rhs
) :
    ProxyHalf(rhs),
    lastQueryType_(rhs.lastQueryType_),
    firstPacket_(rhs.firstPacket_)
{
}


MySqlErrorMessageBlocker::~MySqlErrorMessageBlocker()
{
}


void MySqlErrorMessageBlocker::handleMessage(vector<uint8_t>& rawMessage) const
{
    const uint8_t RESULT_ERROR = 0xFF;

    MySqlSocket* mySqlSocketPtr;
    #ifndef NDEBUG
        mySqlSocketPtr = dynamic_cast<MySqlSocket*>(outgoingConnection_);
        assert(
            nullptr != mySqlSocketPtr &&
            "MySqlErrorMessageBlocker should have MySqlSockets"
        );
    #else
        mySqlSocketPtr = static_cast<MySqlSocket*>(outgoingConnection_);
    #endif

    assert(
        rawMessage.size() >= 5 &&
        "Response message from MySQL is empty"
    );
    if (rawMessage.size() < 5)
    {
        mySqlSocketPtr->sendErrorPacket(0);
        return;
    }

    // First three bytes are the packet length
    // Fourth byte is the packet number
    const uint8_t packetNumber = rawMessage.at(3);

    // The first packet sent from the server is the handshake initialization
    // packet. This includes information about the server's capabilities. Per
    // ticket #11, we don't support compression, so lie to the client and
    // clear that bit so that the client doesn't try to use compression.
    if (firstPacket_)
    {
        firstPacket_ = false;

        // 3: packet length, 1: packet number number,
        // 1: server version, n: null-terminated server version string
        const size_t BEGIN_VERSION_STRING = 3 + 1 + 1;
        size_t i = BEGIN_VERSION_STRING;
        while (i < rawMessage.size() && rawMessage.at(i) != '\0')
        {
            ++i;
        }
        ++i; // One past the version string
        // 4: thread id, 8: password scramble buffer, 1: filler
        const size_t BEGIN_SERVER_CAPABILITIES = i + 4 + 8 + 1;

        if (BEGIN_SERVER_CAPABILITIES >= rawMessage.size())
        {
            Logger::log(Logger::ERROR) << "Unable to unset client compression";
        }
        else
        {
            // Flip off the compression bit
            rawMessage.at(BEGIN_SERVER_CAPABILITIES) =
                rawMessage.at(BEGIN_SERVER_CAPABILITIES) &
                ~(static_cast<uint8_t>(MySqlConstants::CLIENT_COMPRESS));
        }

        ProxyHalf::handleMessage(rawMessage);
        return;
    }

    // First byte of the payload is the result type
    const uint8_t resultType = rawMessage.at(4);

    if (RESULT_ERROR == resultType)
    {
        // 3: packet length, 1: packet number number,
        // 1: result type, 2: errno, 6: error code
        const int BEGIN_MESSAGE = 3 + 1 + 1 + 2 + 6;
        // Pretend the message is a C-style string for printing
        rawMessage.push_back('\0');
        Logger::log(Logger::WARN)
            << "Blocked MySQL error message: "
            << reinterpret_cast<char*>(&rawMessage[BEGIN_MESSAGE]);

        switch (lastQueryType_)
        {
            // Commands that generate results
            case QueryRisk::TYPE_SELECT:
            case QueryRisk::TYPE_DESCRIBE:
            case QueryRisk::TYPE_EXPLAIN:
            case QueryRisk::TYPE_SHOW:
                mySqlSocketPtr->sendEmptySetPacket();
                break;

            // Commands that just get an acknowledgement back
            case QueryRisk::TYPE_INSERT:
            case QueryRisk::TYPE_UPDATE:
            case QueryRisk::TYPE_DELETE:
            case QueryRisk::TYPE_SET:
            case QueryRisk::TYPE_TRANSACTION:
                mySqlSocketPtr->sendOkPacket(packetNumber);
                break;

            // Invalid queries, things like "DANCE FOR ME MYSQL"
            case QueryRisk::TYPE_UNKNOWN:
                mySqlSocketPtr->sendErrorPacket(packetNumber);
                break;

            default:
                Logger::log(Logger::ERROR)
                    << "Unexpected case for last query type "
                    << "in MySqlErrorMessageBlocker "
                    << lastQueryType_;
                assert(false);
                mySqlSocketPtr->sendErrorPacket(packetNumber);
        }
    }
    else // Forward everything except errors
    {
        ProxyHalf::handleMessage(rawMessage);
    }
}


void MySqlErrorMessageBlocker::setQueryType(const QueryRisk::QueryType type)
{
    lastQueryType_ = type;
}
