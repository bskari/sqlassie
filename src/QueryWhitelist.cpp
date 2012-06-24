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
 * but WITHOUT ANY WARRANTY; without even the implied wstrArranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with SQLassie. If not, see <http://www.gnu.org/licenses/>.
 */

#include "DescribedException.hpp"
#include "Logger.hpp"
#include "nullptr.hpp"
#include "ParserInterface.hpp"
#include "QueryWhitelist.hpp"

#include <boost/thread/mutex.hpp>
#include <boost/unordered_set.hpp>
#include <cassert>
#include <fstream>
#include <string>
#include <utility>
#include <vector>

using boost::lock_guard;
using boost::mutex;
using boost::unordered_set;
using std::ifstream;
using std::pair;
using std::string;
using std::vector;


// Static variables
QueryWhitelist* QueryWhitelist::instance_ = nullptr;


void QueryWhitelist::initialize(
    const string* const failToParseFilename,
    const string* const allowedFilename
)
{
    // Prevent race conditions between threads
    mutex m;
    lock_guard<mutex> lg(m);

    if (nullptr == instance_)
    {
        instance_ = new QueryWhitelist(failToParseFilename, allowedFilename);
    }
}


QueryWhitelist::QueryWhitelist(
    const string* const failToParseFilename,
    const string* const allowedFilename
) :
    failToParseFilename_(
        nullptr != failToParseFilename
        ? *failToParseFilename
        : ""
    ),
    allowedFilename_(nullptr != allowedFilename ? *allowedFilename : ""),
    failToParseList_(),
    allowedList_()
{
    if (nullptr != failToParseFilename)
    {
        readFailToParseQueriesFile(*failToParseFilename);
    }

    if (nullptr != allowedFilename)
    {
        readAllowedQueriesFile(*allowedFilename);
    }
}



bool QueryWhitelist::isParseWhitelisted(
    const ParserInterface::QueryHash& hash
)
{
    assert(
        nullptr != instance_ &&
        "QueryWhitelist functions called without calling initalize first"
    );

    if (
        instance_->failToParseList_.end() ==
        instance_->failToParseList_.find(hash)
    )
    {
        return false;
    }
    else
    {
        return true;
    }
}


bool QueryWhitelist::isBlockWhitelisted(
    const ParserInterface::QueryHash& hash,
    const QueryRisk& qr
)
{
    assert(nullptr != instance_);

    if (
        instance_->allowedList_.end() ==
        instance_->allowedList_.find(
            pair<ParserInterface::QueryHash, QueryRisk>(hash, qr)
        )
    )
    {
        return false;
    }
    else
    {
        return true;
    }
}


void QueryWhitelist::readFailToParseQueriesFile(const string& filename)
{
    queryList queries(readQueriesFromFile(filename));
    queryList::const_iterator end(queries.end());
    for (queryList::const_iterator i(queries.begin()); i != end; ++i)
    {
        ParserInterface pi(i->first);
        QueryRisk qr;
        const bool successfullyParsed = pi.parse(&qr);
        if (successfullyParsed)
        {
            Logger::log(Logger::WARN)
                << "Query in fail-to-parse whitelist file "
                << filename
                << " on line "
                << i->second
                << " was successfully parsed";
        }
        failToParseList_.insert(pi.getHash());
    }
}


void QueryWhitelist::readAllowedQueriesFile(const string& filename)
{
    queryList queries(readQueriesFromFile(filename));
    queryList::const_iterator end(queries.end());
    for (queryList::const_iterator i(queries.begin()); i != end; ++i)
    {
        ParserInterface pi(i->first);
        QueryRisk qr;
        const int status = pi.parse(&qr);
        if (0 != status)
        {
            Logger::log(Logger::WARN)
                << "Query in allowed whitelist file "
                << filename
                << " on line "
                << i->second
                << " could not be parsed";
            continue;
        }
        allowedList_.insert(
            pair<ParserInterface::QueryHash, QueryRisk>(pi.getHash(), qr)
        );
    }
}


QueryWhitelist::queryList QueryWhitelist::readQueriesFromFile(
    const string& filename
)
{
    /// @TODO(bskari) This should watch this file for changes and reload the
    /// whitelist when the files change.
    ifstream fin(filename.c_str());
    if (!fin)
    {
        throw DescribedException(
            "Unable to open whitelist file \"" + filename + "\""
        );
    }
    queryList queries;
    string query;
    size_t line = 0;
    while (getline(fin, query))
    {
        ++line;
        // Skip empty lines and comments
        if (0 == query.size() || '#' == query.at(0))
        {
            continue;
        }
        queries.push_back(pair<string, size_t>(query, line));
    }
    fin.close();
    return queries;
}
