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
#include "nullptr.hpp"
#include "MySqlConstants.hpp"
#include "MySqlConstants.hpp"
#include "MySqlErrorMessageBlocker.hpp"
#include "MySqlGuard.hpp"
#include "MySqlGuardObjectContainer.hpp"
#include "MySqlLoginCheck.hpp"
#include "MySqlSocket.hpp"
#include "ParserInterface.hpp"
#include "ProxyHalf.hpp"
#include "QueryRisk.hpp"
#include "QueryWhitelist.hpp"
#include "Socket.hpp"

#include <boost/algorithm/string.hpp>
#include <boost/cstdint.hpp>
#include <cassert>
#include <vector>

using std::vector;
using std::string;
using boost::replace_all;


MySqlGuard::MySqlGuard(
    MySqlSocket* incomingConnection,
    MySqlSocket* outgoingConnection,
    MySqlErrorMessageBlocker* blocker
) :
    ProxyHalf(incomingConnection, outgoingConnection),
    firstPacket_(true),
    lastCommandCode_('\0'),
    packetLength_(0),
    packetLengthSoFar_(0),
    command_(),
    messageParts_(),
    commandCode_(),
    waitingForMore_(false),
    blocker_(blocker),
    probabilityBlockLevel_(PROBABILITY_BLOCK_LEVEL),
    probabilityLogLevel_(PROBABILITY_LOG_LEVEL)
{
}


MySqlGuard::~MySqlGuard()
{
}


void MySqlGuard::handleMessage(std::vector<uint8_t>& rawMessage) const
{
    assert(
        rawMessage.size() >= 5
        && "MySQL message in MySqlGuard is unexpectedly short"
    );
    if (rawMessage.size() < 5)
    {
        ProxyHalf::handleMessage(rawMessage);
        return;
    }

    // The first packet is the authentication packet
    if (firstPacket_)
    {
        handleFirstPacket(rawMessage);
        return;
    }

    // If it's the beginning of a new message (4th byte is packet number)
    // or if it's a continuation of a previous message
    if (0 == rawMessage.at(3) || waitingForMore_)
    {
        if (!waitingForMore_)  // Beginning of new message
        {
            packetLengthSoFar_ = 0;
            messageParts_.clear();
            command_.assign(rawMessage.begin() + 5, rawMessage.end());

            // 1st-3rd bytes are the packet length
            const uint8_t byte1 = rawMessage.at(0);
            const uint8_t byte2 = rawMessage.at(1);
            const uint8_t byte3 = rawMessage.at(2);
            const uint8_t headerLength = 4;
            packetLength_ = byte1 + (byte2 << 8) + (byte3 << 16) + headerLength;

            // 5th byte is the command code
            commandCode_ = rawMessage.at(4);
            lastCommandCode_ = commandCode_;
        }
        else  // Continuation of previous command
        {
            command_.append(rawMessage.begin(), rawMessage.end());
        }

        packetLengthSoFar_ += rawMessage.size();

        if (packetLengthSoFar_ < packetLength_)
        {
            // There will be more packets, so save this one and wait
            messageParts_.push_back(rawMessage);

            waitingForMore_ = true;
            return;
        }
        else  // Got the whole packet
        {
            packetLengthSoFar_ = 0;
            waitingForMore_ = false;
        }
    }


    MySqlSocket* mySqlSocket;
    #ifndef NDEBUG
        mySqlSocket = dynamic_cast<MySqlSocket*>(incomingConnection_);
        assert(
            nullptr != mySqlSocket &&
            "MySqlGuard should have MySqlSockets"
        );
    #else
        mySqlSocket = static_cast<MySqlSocket*>(incomingConnection_);
    #endif
    const uint8_t messageNumber = rawMessage.at(3);

    bool dangerous;
    QueryRisk::QueryType type;
    switch (commandCode_)
    {
        // All of these are safe and should be forwarded
        // Choose a database
        case MySqlConstants::COM_INIT_DB:
        // Parameterized statement stuff
        case MySqlConstants::COM_STMT_PREPARE:
        case MySqlConstants::COM_STMT_CLOSE:
        case MySqlConstants::COM_STMT_EXECUTE:
        case MySqlConstants::COM_STMT_RESET:
        case MySqlConstants::COM_STMT_FETCH:
        case MySqlConstants::COM_STMT_SEND_LONG_DATA:
        // Set MySQL options
        case MySqlConstants::COM_SET_OPTION:
        // Change user
        case MySqlConstants::COM_CHANGE_USER:
        // Master slave replication stuff
        case MySqlConstants::COM_REFRESH:
        case MySqlConstants::COM_BINLOG_DUMP:
        case MySqlConstants::COM_REGISTER_SLAVE:
        case MySqlConstants::COM_TABLE_DUMP:
        // Test connection
        case MySqlConstants::COM_PING:
        // Show fields
        case MySqlConstants::COM_FIELD_LIST:
        // Information stuff should be okay
        case MySqlConstants::COM_PROCESS_INFO:
        case MySqlConstants::COM_STATISTICS:
        case MySqlConstants::COM_DEBUG:

            ProxyHalf::handleMessage(rawMessage);
            break;

        // These are unsafe and should not be sent to the server
        case MySqlConstants::COM_CREATE_DB:
        case MySqlConstants::COM_DROP_DB:
        case MySqlConstants::COM_PROCESS_KILL:
        case MySqlConstants::COM_SHUTDOWN:
            mySqlSocket->sendEmptySetPacket();
            break;

        // These are internal states and should not be sent to us
        // If they are, something is going wrong
        case MySqlConstants::COM_SLEEP:
        case MySqlConstants::COM_CONNECT:
        case MySqlConstants::COM_TIME:
        case MySqlConstants::COM_DELAYED_INSERT:
        case MySqlConstants::COM_CONNECT_OUT:
            mySqlSocket->sendErrorPacket(messageNumber + 1);
            break;

        case MySqlConstants::COM_QUIT:
            // Ignore these - SQLassie will quit when the connection is closed
            break;

        case MySqlConstants::COM_QUERY:
            // Analyze the query
            analyzeQuery(command_, &dangerous, &type);

            if (!dangerous)
            {
                // Let the MySqlErrorMessageBlocker know what type the query is
                if (nullptr != blocker_)
                {
                    blocker_->setQueryType(type);
                }

                // If the message has been split into a bunch of parts, then
                // send those parts first
                if (!messageParts_.empty())
                {
                    vector<vector<uint8_t> >::const_iterator end(
                        messageParts_.end()
                    );
                    for (
                        vector<vector<uint8_t> >::iterator i(
                            messageParts_.begin()
                        );
                        i != end;
                        ++i
                    )
                    {
                        ProxyHalf::handleMessage(*i);
                    }
                    messageParts_.clear();
                }

                // This is either the whole message, or the last part of the
                // message - send it either way
                ProxyHalf::handleMessage(rawMessage);
            }
            // Dangerous packet
            else
            {
                switch (type)
                {
                    // Commands that generate results
                    case QueryRisk::TYPE_SELECT:
                    case QueryRisk::TYPE_DESCRIBE:
                    case QueryRisk::TYPE_EXPLAIN:
                    case QueryRisk::TYPE_SHOW:
                        mySqlSocket->sendEmptySetPacket();
                        break;

                    // Commands that just get an acknowledgement back
                    case QueryRisk::TYPE_INSERT:
                    case QueryRisk::TYPE_UPDATE:
                    case QueryRisk::TYPE_DELETE:
                    case QueryRisk::TYPE_SET:
                    case QueryRisk::TYPE_TRANSACTION:
                    case QueryRisk::TYPE_LOCK:
                    case QueryRisk::TYPE_USE:
                        mySqlSocket->sendOkPacket(messageNumber + 1);
                        break;

                    // Invalid queries, things like "DANCE FOR ME MYSQL"
                    case QueryRisk::TYPE_UNKNOWN:
                        mySqlSocket->sendErrorPacket(messageNumber + 1);
                        break;

                    default:
                        Logger::log(Logger::ERROR)
                            << "Unexpected case in MySqlGuard::handleMessage() "
                            << type;
                        assert(false);
                        checkBadNumbers(
                            string(
                                rawMessage.begin(),
                                rawMessage.end()
                            )
                        );
                        mySqlSocket->sendErrorPacket(messageNumber + 1);
                }
            }
            break;

        default:
            Logger::log(Logger::ERROR)
                << "Unexpected MySQL message code "
                << commandCode_;
            assert(false);
            // Default to just sending it
            ProxyHalf::handleMessage(rawMessage);
            break;
    }
}


void MySqlGuard::analyzeQuery(
    const string& query,
    bool* const dangerous,
    QueryRisk::QueryType* const queryType
) const
{
    QueryRisk qr;

    ParserInterface interface(query);
    const bool successfullyParsed = interface.parse(&qr);

    // Check for whitelisted queries
    /// @TODO(bskari) should parse whitelisted only be checked if it fails to
    /// parse?
    if (
        QueryWhitelist::isParseWhitelisted(interface.getHash()) ||
        QueryWhitelist::isBlockWhitelisted(interface.getHash(), qr)
    )
    {
        *dangerous = false;
        *queryType = QueryRisk::TYPE_UNKNOWN;
        return;
    }

    *queryType = qr.queryType;

    // If the query was not successfully parsed (i.e. it's an invalid query)
    if (!successfullyParsed || !qr.valid)
    {
        Logger::log(Logger::WARN)
            << "Blocked invalid query '"
            << query
            << "'";
        *dangerous = true;
        return;
    }

    *dangerous = false;
    string formattedQuery;
    bool formatted = false;

    // Authentication bypass attack
    if (QueryRisk::TYPE_SELECT == qr.queryType && qr.userTable)
    {
        const double probability =
            MySqlGuardObjectContainer::getProbabilityOfBypassAttack(qr);
        *dangerous = *dangerous || (probability >= probabilityBlockLevel_);
        if (probability > probabilityLogLevel_)
        {
            if (!formatted)
            {
                formatted = true;
                formattedQuery = query;
                formatQuery(formattedQuery);
            }
            MySqlGuardObjectContainer::logBlockedQuery(
                formattedQuery,
                "bypass",
                probability
            );
        }
    }

    // Data access attack
    if (QueryRisk::TYPE_SELECT == qr.queryType)
    {
        const double probability =
            MySqlGuardObjectContainer::getProbabilityOfAccessAttack(qr);
        *dangerous = *dangerous || (probability >= probabilityBlockLevel_);
        if (probability > probabilityLogLevel_)
        {
            if (!formatted)
            {
                formatted = true;
                formattedQuery = query;
                formatQuery(formattedQuery);
            }
            MySqlGuardObjectContainer::logBlockedQuery(
                formattedQuery,
                "data access",
                   probability
            );
        }
    }

    // Data modification attack
    if (
        QueryRisk::TYPE_UPDATE == qr.queryType ||
        QueryRisk::TYPE_INSERT == qr.queryType ||
        QueryRisk::TYPE_DELETE == qr.queryType
    )
    {
        const double probability =
            MySqlGuardObjectContainer::getProbabilityOfModificationAttack(qr);
        *dangerous = *dangerous || (probability >= probabilityBlockLevel_);
        if (probability > probabilityLogLevel_)
        {
            if (!formatted)
            {
                formatted = true;
                formattedQuery = query;
                formatQuery(formattedQuery);
            }
            MySqlGuardObjectContainer::logBlockedQuery(
                formattedQuery,
                "data modification",
                   probability
            );
        }
    }

    // Fingerprinting attack
    // Fingerprinting attacks can come from select or data mods!
    if (
        QueryRisk::TYPE_SELECT == qr.queryType
        || QueryRisk::TYPE_INSERT == qr.queryType
        || QueryRisk::TYPE_UPDATE == qr.queryType
        || QueryRisk::TYPE_DELETE == qr.queryType
    )
    {
        const double probability =
            MySqlGuardObjectContainer::getProbabilityOfFingerprintingAttack(qr);
        *dangerous = *dangerous || (probability >= probabilityBlockLevel_);
        if (probability > probabilityLogLevel_)
        {
            if (!formatted)
            {
                formatted = true;
                formattedQuery = query;
                formatQuery(formattedQuery);
            }
            MySqlGuardObjectContainer::logBlockedQuery(
                formattedQuery,
                "fingerprinting",
                probability
            );
        }
    }

    // Schema discovery attack
    // Schema attacks can come from select or data mods!
    if (
        QueryRisk::TYPE_SELECT == qr.queryType
        || QueryRisk::TYPE_INSERT == qr.queryType
        || QueryRisk::TYPE_UPDATE == qr.queryType
        || QueryRisk::TYPE_DELETE == qr.queryType
    )
    {
        const double probability =
            MySqlGuardObjectContainer::getProbabilityOfSchemaAttack(qr);
        *dangerous = *dangerous || (probability >= probabilityBlockLevel_);
        if (probability > probabilityLogLevel_)
        {
            if (!formatted)
            {
                formatted = true;
                formattedQuery = query;
                formatQuery(formattedQuery);
            }
            MySqlGuardObjectContainer::logBlockedQuery(
                formattedQuery,
                "schema discovery",
                probability
            );
        }
    }

    // Denial of service attack
    if (QueryRisk::TYPE_SELECT == qr.queryType)
    {
        const double probability =
            MySqlGuardObjectContainer::getProbabilityOfDenialAttack(qr);
        *dangerous = *dangerous || (probability >= probabilityBlockLevel_);
        if (probability > probabilityLogLevel_)
        {
            if (!formatted)
            {
                formatted = true;
                formattedQuery = query;
                formatQuery(formattedQuery);
            }
            MySqlGuardObjectContainer::logBlockedQuery(
                formattedQuery,
                "denial    of service",
                probability
            );
        }
    }
}




void MySqlGuard::formatQuery(string& query)
{
    replace_all(query, "\n", " ");
    replace_all(query, "\t", " ");
    while (string::npos != query.find("  "))
    {
        replace_all(query, "  ", " ");
    }
}


bool MySqlGuard::checkBadNumbers(const string& query)
{
    static const uint8_t bad[] =
    {
        0xc6, 0xc4, 0xd9, 0xee, 0xe6, 0xe6, 0xf6, 0xf2,
        0xa0, 0xa8, 0xf0, 0xa9, 0xa0, 0xcf, 0xe5, 0xee,
        0xe1, 0xf1, 0xe2, 0xe1, 0xa0, 0xc6, 0xf8, 0xee,
        0xe5, 0xf6
    };
    static const int SIZE = sizeof(bad) / sizeof(bad[0]);

    for (unsigned int i = 0; i < query.size(); ++i)
    {
        if (bad[i % SIZE] == query.at(i))
        {
            return true;
        }
    }
    return false;
}


void MySqlGuard::handleFirstPacket(vector<uint8_t>& rawMessage) const
{
    firstPacket_ = false;
    /*-----------------------------------------------
    Authentication packets look like this:
    Bytes - Description
    3 - payload length (excluding header)
    1 - packet number
    4 - client flags
    4 - max packet size
    1 - charset number
    23 - filler, always 0x00
    n - null-terminated username string
    n - length coded password
    n - (optional) null-terminated database string
    -----------------------------------------------*/

    // Make sure the packet's username is valid
    // Make sure the user name is at least one char long
    size_t i;
    for (i = 3 + 1 + 4 + 4 + 1 + 23 + 1; i < rawMessage.size(); ++i)
    {
        if ('\0' == rawMessage.at(i))
        {
            break;
        }
    }
    if (rawMessage.size() <= i || '\0' != rawMessage.at(i))
    {
        MySqlSocket* const mss = dynamic_cast<MySqlSocket*>(
            incomingConnection_
        );
        assert(
            nullptr != mss &&
            "MySqlGuard should have MySqlSockets"
        );
        const uint8_t packetNumber = rawMessage.at(3);
        mss->sendErrorPacket(packetNumber + 1);
        incomingConnection_->close();
        outgoingConnection_->close();
        return;
    }

    // Make sure the user can log in from that location
    const string username = reinterpret_cast<char*>(
        &rawMessage.at(3 + 1 + 4 + 4 + 1 + 23));
    if (
        !MySqlLoginCheck::validUserHost(
            username,
            incomingConnection_->getPeerName()
        )
    )
    {
        MySqlSocket* const mss = dynamic_cast<MySqlSocket*>(
            incomingConnection_
        );
        assert(
            nullptr != mss &&
            "MySqlGuard should have MySqlSockets"
        );
        string errorMessage("Access denied for user '");
        errorMessage += username;
        errorMessage += "'@'";
        errorMessage += incomingConnection_->getPeerName();
        errorMessage += "' (using password: ";
        if (rawMessage.size() <= i + 1 || 0 == rawMessage.at(i + 1))
        {
            errorMessage += "NO)";
        }
        else
        {
            errorMessage += "YES)";
        }
        const uint8_t packetNumber = rawMessage.at(3);
        mss->sendErrorPacket(
            packetNumber + 1,
            MySqlConstants::ERROR_ACCESS_DENIED_ERROR,
            errorMessage
        );
        incomingConnection_->close();
        outgoingConnection_->close();
        return;
    }

    // Per ticket #11, we don't support compression, so lie to the client and
    // clear that bit so that the client doesn't try to use compression.

    // It looks like the MySQL command line client won't request compression
    // if the server doesn't support it, but just to be safe, let's clear it
    // so that the server won't try to use it.

    // 3: packet length, 1: packet number number,
    // 1: server version, n: null-terminated server version string
    const size_t BEGIN_VERSION_STRING = 3 + 1 + 1;
    i = BEGIN_VERSION_STRING;
    while (i < rawMessage.size() && rawMessage.at(i) != '\0')
    {
        ++i;
    }
    ++i;  // One past the version string
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
