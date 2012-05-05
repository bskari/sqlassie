
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

#ifndef SRC_QUERYWHITELIST_HPP_
#define SRC_QUERYWHITELIST_HPP_

/**
 * Singleton interface to store and access whitelisted queries.
 * @author Brandon Skari
 * @date January 22 2012
 */

#include "ParserInterface.hpp"
#include "QueryRisk.hpp"

#include <boost/unordered_set.hpp>
#include <string>
#include <utility>
#include <vector>

class QueryWhitelist
{
public:
    /**
     * Initializes this singleton instance.
     * @param failedToParseFile Name of file with queries that failed to
     * parse. If the pointer is null, then no file is parsed.
     * @param allowedFile Name of file with queries that should be allowed. If
     * the pointer is null, then no file is parsed.
     */
    static void initialize(
        const std::string* const failedToParseFile,
        const std::string* const allowedFile
    );

    /**
     * Determines if a query (as represented by the hash) is whitelisted as
     * being safe even if it faileds to parse. SQLassie's parser isn't perfect
     * (see bug #12), so this is a workaround until that's resolved.
     * @param hash The hash of the query to be checked.
     */
    static bool isParseWhitelisted(const ParserInterface::QueryHash& hash);

    /**
     * Determines if a query (as represented by the hash and associated risk)
     * are safe, even if it exceeds the unsafe threshold.
     * @param hash The hash of the query to be checked.
     * @param qr The risk associated with the query.
     */
    static bool isBlockWhitelisted(
        const ParserInterface::QueryHash& hash,
        const QueryRisk& qr
    );

private:
    /**
     * Default constructor.
     * @param failedToParseFile Name of file with queries that failed to parse. If
     * the pointer is null, then no file is parsed.
     * @param allowedFile Name of file with queries that are allowed. If the
     * pointer is null, then no file is parsed.
     */
    QueryWhitelist(
        const std::string* const failedToParseFilename,
        const std::string* const allowedFilename
    );

    void readFailToParseQueriesFile(const std::string& failToParseFilename);
    void readAllowedQueriesFile(const std::string& allowedFilename);

    typedef std::vector<std::pair<std::string, size_t> > queryList;
    queryList readQueriesFromFile(const std::string& filename);

    const std::string failToParseFilename_;
    const std::string allowedFilename_;
    boost::unordered_set<ParserInterface::QueryHash> failToParseList_;
    boost::unordered_set<
        std::pair<
            ParserInterface::QueryHash,
            QueryRisk
        >
    > allowedList_;

    static QueryWhitelist* instance_;

    // Hidden methods
    QueryWhitelist(const QueryWhitelist&);
};

#endif  // SRC_QUERYWHITELIST_HPP_
