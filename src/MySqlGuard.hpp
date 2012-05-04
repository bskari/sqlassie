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

#ifndef MYSQL_GUARD_HPP
#define MYSQL_GUARD_HPP

class MySqlSocket;
class MySqlGuardObjectContainer;
class MySqlErrorMessageBlocker;
#include "nullptr.hpp"
#include "ProxyHalf.hpp"
#include "QueryRisk.hpp"

#include <string>
#include <vector>
#include <fstream>
#include <boost/thread.hpp>
#include <boost/cstdint.hpp>

/**
 * Half of a full proxy that receives MySQL commands, analyzes them for
 * probability of SQL injection attacks, and logs suspicious commands and if
 * the probability is particularly high, blocks the query.
 * @author Brandon Skari
 * @date January 9 2011
 */

class MySqlGuard : public ProxyHalf
{
public:
    /**
     * Default constructor.
     * @param incomingConnection The socket to listen on.
     * @param outgoingConnection The socket to write to.
     * @param blocker Optional link to the blocker so that it can be told what
     *  kind of command the query had and tailor any error messages to things
     *     like 'OK' for insert and update queries.
     */
    MySqlGuard(
        MySqlSocket* incomingConnection,
        MySqlSocket* outgoingConnection,
        MySqlErrorMessageBlocker* blocker = nullptr
    );

    /**
     * Copy constructor needed for Boost threads. This can't be const because
     * we need to transfer ownership of the auto_ptrs.
     */
    MySqlGuard(MySqlGuard& rhs);

    /**
     * Destructor.
     */
    ~MySqlGuard();

private:
    /**
     * Analyzes a message and determines probability of SQL injection attacks.
     * Suspicious queries are logged and extremely suspect queries are blocked.
     * @param rawMessage The message that was received from the client that
     *  needs to be inspected for injection attacks.
     */
    void handleMessage(std::vector<uint8_t>& rawMessage) const;

    /**
     * Analyzes a query and determines if it's dangerous or not; if it is,
     * the query is logged.
     * @param query The query to analyze.
     * @param dangerous In out variable that is set if the query is dangerous.
     * @param queryType In out variable that is set to the type of the query.
     */
    void analyzeQuery(
        const std::string& query,
        bool* const dangerous,
        QueryRisk::QueryType* const queryType
    ) const;

    /**
     * All of these objects are only used in handleMessage. I need them to keep
     * their values between subsequent calls to handleMessage, but I can't
     * declare them as static in there because then all instances of the class
     * will share them, which is bad for multi-threading. That is why they are
     * declared mutable here.
     */
    ///@{
    mutable bool firstPacket_;
    mutable uint8_t lastCommandCode_;
    mutable uint_least32_t packetLength_;
    mutable uint_least32_t packetLengthSoFar_;
    mutable std::string command_;
    mutable std::vector<std::vector<uint8_t> > messageParts_;
    mutable uint8_t commandCode_;
    mutable bool waitingForMore_;
    ///@}

    MySqlErrorMessageBlocker* const blocker_;

    const double probabilityBlockLevel_;
    const double probabilityLogLevel_;

    /**
     * Formats a query for logging. Removes newlines, tabs, and excessive
     * spaces.
     */
    static void formatQuery(std::string& query);

    /**
     * Checks for badly formatted numbers.
     */
    static bool checkBadNumbers(const std::string& query);

    void handleFirstPacket(std::vector<uint8_t>& rawMessage) const;

    // ***** Hidden methods *****
    MySqlGuard& operator=(const MySqlGuard&);
};

const static double PROBABILITY_BLOCK_LEVEL = 0.75;
const static double PROBABILITY_LOG_LEVEL = 0.5;

#endif
