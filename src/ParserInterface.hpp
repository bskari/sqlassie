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

#ifndef SRC_PARSERINTERFACE_HPP_
#define SRC_PARSERINTERFACE_HPP_

#include "AstNode.hpp"
class ParserInterfaceScannerMembers;
#include "QueryRisk.hpp"
#include "ScannerContext.hpp"

#include <boost/cstdint.hpp>
#include <boost/thread/mutex.hpp>
#include <vector>

/**
 * Interface to the Lemon parser so I don't have to keep allocating
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
     * @return If the string was successfully parsed.
     */
    bool parse(QueryRisk* const qr) WARN_UNUSED_RESULT;

    typedef size_t hashType;
    struct QueryHash
    {
        hashType hash;
        int tokensCount;
        QueryHash();
        friend bool operator==(const QueryHash& qh1, const QueryHash& qh2);
    };
    QueryHash getHash() const;

private:
    // The below ScannerContext needs to hold a pointer to this value, so
    // declare it here so that variable initialization order makes sense
    QueryRisk qr_;
public:
    ScannerContext scannerContext_;

    /**
     * @TODO(bskari) Declare yylex as a friend so that I can make these
     * private. I tried to do it here, but yylex takes a YYSTYPE* parameter,
     * which means I have to include parser.tab.hpp for the definition, but
     * parser.tab.hpp includes this file, which creates a circular dependency.
     */
    //@{
    ParserInterfaceScannerMembers* scannerPimpl_;
    // Used to tokenize the string before parsing, so that I can do things
    // like whitelist queries that fail to parse until I fix the parser.
    QueryHash tokensHash_;
    //@}

private:
    int getLexValue();

    bool parsed_;
    bool successfullyParsed_;
    const int bufferLen_;
    void* lemonParser_;

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

#endif  // SRC_PARSERINTERFACE_HPP_
