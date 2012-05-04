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
#include "MySqlPrinter.hpp"
#include "ProxyHalf.hpp"

#include <boost/algorithm/string.hpp>
#include <boost/cstdint.hpp>
#include <cassert>
#include <iomanip>
#include <iostream>
#include <vector>

using std::cout;
using std::cerr;
using std::endl;
using std::flush;
using std::vector;
using std::string;
using std::hex;
using std::dec;
using std::setw;
using std::setfill;
using boost::replace_all;


MySqlPrinter::MySqlPrinter(Socket* incomingConnection, Socket* outgoingConnection) :
    ProxyHalf(incomingConnection, outgoingConnection),
    lastCommandCode_('\0'),
    firstPacket_(true),
    database_()
{
}


void MySqlPrinter::handleMessage(std::vector<uint8_t>& rawMessage) const
{
    assert(rawMessage.size() >= 5 &&
        "MySQL message in MySqlPrinter is unexpectedly short");

    // The first packet is the authentication packet, so don't print it
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
    char commandCode;
    if (0 == rawMessage.at(3))
    {
        commandCode = rawMessage.at(4);
        lastCommandCode_ = commandCode;
    }
    else if (MySqlConstants::COM_QUERY == lastCommandCode_)
    {
        // If it's the continuation of a query, then log it
        cout.write(reinterpret_cast<const char*>(&rawMessage.at(0)), rawMessage.size());
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
        Logger::log(Logger::ERROR) << "Unexpected message structure " << lastCommandCode_;
        assert(false);
        ProxyHalf::handleMessage(rawMessage);
        return;
    }

    string command;
    switch (commandCode)
    {
        case MySqlConstants::COM_INIT_DB:
            // Grab the database name and open that file
            database_ = string(rawMessage.begin() + 5, rawMessage.end());
            cout << "database = " << database_ << endl;
            break;

        case MySqlConstants::COM_QUERY:
            // Print the query

            // Only print the separator if it's a new query
            // New queries have packet #'s starting at 0
            // The packet # is stored as the 4th byte of the raw message
            if (0 == rawMessage.at(3))
            {
                cout << "\n######################" << endl;
            }

            command = string(rawMessage.begin() + 5, rawMessage.end());
            replace_all(command, "\n", " ");
            replace_all(command, "\t", " ");
            while (string::npos != command.find("  "))
            {
                replace_all(command, "  ", " ");
            }
            cout << command << flush;
            break;

        case MySqlConstants::COM_FIELD_LIST:
        case MySqlConstants::COM_QUIT:
            // Ignore these
            break;

        default:
            Logger::log(Logger::WARN) << "Unexpected messageCode = "
                << "0x" << hex << setfill('0') << setw(2) << (int)commandCode << dec
                << " message = '" << string(rawMessage.begin() + 5, rawMessage.end()) << '\'';
            break;
    }

    // Send the message
    ProxyHalf::handleMessage(rawMessage);
}

