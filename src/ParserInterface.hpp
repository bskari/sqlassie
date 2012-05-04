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

#ifndef PARSER_INTERFACE_HPP
#define PARSER_INTERFACE_HPP

#include "AstNode.hpp"
class ParserInterfaceScannerMembers;
#include "QueryRisk.hpp"
#include "ScannerContext.hpp"

#include <boost/cstdint.hpp>
#include <boost/thread/mutex.hpp>
#include <vector>

/**
 * Interface to the Bison parser so I don't have to keep allocating
 * YY_BUFFER_STATESs and stuff all over in my code.
 * @author Brandon Skari
 * @date January 12 2011
 */

class ParserInterface
{
public:
    /**
     * Default constructor.
     * @param buffer The buffer to read tokens from (i.e. the query to be
     * parsed).
     */
    explicit ParserInterface(const std::string& buffer);

    ~ParserInterface();

    /**
     * Parses the provided buffer.
     * @param qr The QueryRisk attributes of the parsed query.
     * @return The status code from the Bison parser.
     */
    int parse(QueryRisk* const qr) WARN_UNUSED_RESULT;

    typedef uint64_t hashType;
    struct QueryHash
    {
        hashType hash;
        int tokensCount;
        QueryHash();
        friend bool operator==(const QueryHash& q1, const QueryHash& q2);
    };
    QueryHash getHash() const;

    ScannerContext scannerContext_;

    /**
     * @TODO Declare yylex as a friend so that I can make these private. I
     * tried to do it here, but yylex takes a YYSTYPE* parameter, which
     * means I have to include parser.tab.hpp for the definition, but
     * parser.tab.hpp includes this file, which creates a circular dependency.
     */
    //@{
    ParserInterfaceScannerMembers* scannerPimpl_;
    // Used to tokenize the string before parsing, so that I can do things
    // like whitelist queries that fail to parse until I fix the parser.
    QueryHash tokensHash_;
    //@}

private:
    bool parsed_;
    QueryRisk qr_;
    int parserStatus_;
    const int bufferLen_;

    static boost::mutex parserMutex_;

    // Hidden methods
    ParserInterface(const ParserInterface& rhs);
    ParserInterface& operator=(const ParserInterface& rhs);
};


/**
 * Functions needed for Boost::hash of ParserInterface::QueryHash.
 */
/// @{
bool operator==(
    const ParserInterface::QueryHash& hash1,
    const ParserInterface::QueryHash& hash2
);

std::size_t hash_value(const ParserInterface::QueryHash& qh);
/// @}

#endif
