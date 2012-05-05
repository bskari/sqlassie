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
#include "MySqlLogger.hpp"
#include "ProxyHalf.hpp"

#include <boost/cstdint.hpp>
#include <cassert>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <string>
#include <vector>

using std::string;
using std::vector;
using std::ofstream;
using std::ios;
using std::cout;
using std::endl;
using std::hex;
using std::dec;
using std::setfill;
using std::setw;


MySqlLogger::MySqlLogger(Socket* const incomingConnection,
    Socket* const outgoingConnection, const string& fileDirectory) :
        ProxyHalf(incomingConnection, outgoingConnection),
        fileDirectory_(fixDirectory(fileDirectory)),
        database_(),
        currentDatabaseFile_(),
        logFile_(),
        firstPacket_(true),
        lastCommandCode_(0xFF) // This is an invalid command code
{
}


MySqlLogger::MySqlLogger(MySqlLogger& rhs) :
    ProxyHalf(rhs),
    fileDirectory_(rhs.fileDirectory_),
    database_(rhs.database_),
    currentDatabaseFile_(),
    logFile_(),
    firstPacket_(rhs.firstPacket_),
    lastCommandCode_(rhs.lastCommandCode_)
{
}


MySqlLogger::~MySqlLogger()
{
}


void MySqlLogger::handleMessage(std::vector<uint8_t>& rawMessage) const
{
    assert(rawMessage.size() >= 5 &&
        "MySQL message in MySqlLogger is unexpectedly short");
    if (rawMessage.size() < 5)
    {
        // Just forward it
        ProxyHalf::handleMessage(rawMessage);
        return;
    }

    // The first packet is the authentication packet, so don't log it
    if (firstPacket_)
    {
        firstPacket_ = false;
        ProxyHalf::handleMessage(rawMessage);
        return;
    }

    // First 3 bytes are length-coded binary length of the message
    // The 4th byte is the packet #

    // If it's the beginning of a new message, then the 5th byte will be the
    // command code
    uint8_t commandCode;
    if (0 == rawMessage.at(3))
    {
        commandCode = rawMessage.at(4);
        lastCommandCode_ = commandCode;
    }
    else if (MySqlConstants::COM_QUERY == lastCommandCode_)
    {
        // If it's the continuation of a query, then log it
        logFile_.write(
            reinterpret_cast<char*>(&rawMessage.at(0)), rawMessage.size());
        ProxyHalf::handleMessage(rawMessage);
        return;
    }
    else
    {
        // No idea what is going on with this message... default to forwarding
        #ifndef NDEBUG
        const vector<uint8_t>::const_iterator end(rawMessage.end());
        for (vector<uint8_t>::const_iterator i(rawMessage.begin());
            i != end;
            ++i)
        {
            cout << hex << *i << ' ';
        }
        cout << endl;
        #endif
        Logger::log(Logger::ERROR) << "Unexpected message structure " << commandCode;
        assert(false);
        ProxyHalf::handleMessage(rawMessage);
        return;
    }

    /*
    cout << "MySqlLogger::handleMessage(), messageCode = "
        << "0x" << hex << setfill('0') << setw(2) << (int)commandCode << dec
        << " message = '" << string(rawMessage.begin() + 5, rawMessage.end()) << '\'' << endl;
    */

    switch (commandCode)
    {
        case MySqlConstants::COM_INIT_DB:
            // Grab the database name and open that file
            database_ = string(rawMessage.begin() + 5, rawMessage.end());
            // Only reopen the file if the database has changed
            if (currentDatabaseFile_ != database_)
            {
                if (logFile_.is_open())
                {
                    logFile_.close();
                }
                logFile_.open((fileDirectory_ + database_).c_str(), ios::app);
                currentDatabaseFile_ = database_;
            }
            break;

        case MySqlConstants::COM_QUERY:
            // Log the query
            if (logFile_.is_open())
            {
                // Only print the separator if it's a new query
                // New queries have packet #'s starting at 0
                // The packet # is stored as the 4th byte of the raw message
                if (0 == rawMessage.at(3))
                {
                    logFile_ << "\n######################" << endl;
                }
                logFile_.write(reinterpret_cast<char*>(&rawMessage.at(5)),
                    rawMessage.size() - 5);
            }
            break;

        case MySqlConstants::COM_FIELD_LIST:
        case MySqlConstants::COM_QUIT:
            // Ignore these
            break;

        default:
            Logger::log(Logger::WARN) << "Unexpected messageCode = "
                << "0x"
                << hex
                << setfill('0')
                << setw(2)
                << static_cast<int>(commandCode)
                << dec
                << " message = '"
                << string(rawMessage.begin() + 5, rawMessage.end())
                << '\'';
            break;
    }

    // Send the message
    ProxyHalf::handleMessage(rawMessage);
}


string MySqlLogger::fixDirectory(string fileDirectory)
{
    if ('/' == fileDirectory.at(fileDirectory.length() - 1))
        return fileDirectory;
    else
        return fileDirectory + '/';
}
