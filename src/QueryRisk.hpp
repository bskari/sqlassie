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

#ifndef SRC_QUERYRISK_HPP_
#define SRC_QUERYRISK_HPP_

#include <boost/regex.hpp>
#include <iosfwd>

/**
 * Stores information about potentionally dangers commands that are found in a
 * parsed query.
 * @author Brandon Skari
 * @date December 6 2010
 */

class QueryRisk
{
public:
    /**
     * Default constructor.
     * @TODO(bskari) This should read configuration from a configuration file.
     */
    QueryRisk();

    QueryRisk(const QueryRisk& rhs);

    enum QueryType
    {
        TYPE_UNKNOWN,
        TYPE_SELECT,
        TYPE_INSERT,
        TYPE_UPDATE,
        TYPE_DELETE,
        TYPE_TRANSACTION,
        TYPE_SET,
        TYPE_EXPLAIN,
        TYPE_SHOW,
        TYPE_DESCRIBE,
        TYPE_LOCK,
        TYPE_USE
    };

    enum EmptyPassword
    {
        PASSWORD_NOT_EMPTY = 0,
        PASSWORD_EMPTY = 1,
        PASSWORD_NOT_USED = -1
    };


    // In general, I try to do as much of this work as possible in the parser
    // because some keywords can be also be used as identifiers, and the
    // scanner can't tell the difference. To be consistent, if a rule could be
    // handled in either place, I do it in the parser.

    // Each risk has a corresponding test in testQueryRisk.hpp, so as long as
    // the tests pass, these should be properly accounted for by the parser.

    /**
     * Risk factors.
     */
    ///@{
    QueryType queryType;
    size_t multiLineComments;
    size_t hashComments;
    size_t dashDashComments;
    size_t mySqlComments;
    size_t mySqlVersionedComments;
    size_t sensitiveTables;
    size_t orStatements;
    size_t unionStatements;
    size_t unionAllStatements;
    size_t bruteForceCommands;
    size_t ifStatements;
    size_t hexStrings;
    size_t benchmarkStatements;
    size_t userStatements;
    size_t fingerprintingStatements;
    size_t mySqlStringConcat;
    size_t stringManipulationStatements;
    size_t alwaysTrueConditionals;
    size_t commentedConditionals;
    size_t commentedQuotes;
    size_t globalVariables;
    size_t joinStatements;
    size_t crossJoinStatements;
    size_t regexLength;
    size_t slowRegexes;
    EmptyPassword emptyPassword;
    bool multipleQueries;
    bool orderByNumber;
    bool alwaysTrue;
    bool informationSchema;
    bool valid;
    bool userTable;
    ///@}

    /**
     * Checks an identifier for a risky identifier and if it is risky, it
     * increments the respective variable.
     */
    ///@{
    void checkTable(const std::string& table);
    void checkFunction(const std::string& function);
    void checkDatabase(const std::string& database);
    void checkPasswordComparison(
        const std::string& field,
        const std::string& compareString
    );
    ///@}

    /**
     * Checks if a regular expression for denial of service attacks.
     */
    void checkRegex(const std::string& regex);

    friend std::ostream& operator<<(std::ostream& out, const QueryRisk& rhs);
    friend std::ostream& operator<<(std::ostream& out, const QueryType qt);

private:
    static boost::regex sensitiveTablesRegex;
    static boost::regex bruteForceCommandsRegex;
    static boost::regex userStatementsRegex;
    static boost::regex ifRegex;
    static boost::regex benchmarkRegex;
    static boost::regex fingerprintingRegex;
    static boost::regex informationSchemaRegex;
    static boost::regex stringManipulationRegex;
    static const boost::regex userTableRegex;
};


/**
 * Functions needed for boost::hash of ParserInterface::QueryRisk.
 */
/// @{
bool operator==(const QueryRisk& qr1, const QueryRisk& qr2);
size_t hash_value(const QueryRisk& qr);
/// @}

#endif  // SRC_QUERYRISK_HPP_
