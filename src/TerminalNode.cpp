/*
 * SQLassie - database firewall
 * Copyright (C) 2012 Brandon Skari <brandon.skari@gmail.com>
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

#include "AstNode.hpp"
#include "ExpressionNode.hpp"
#include "Logger.hpp"
#include "sqlParser.h"
#include "TerminalNode.hpp"

#include <boost/cstdint.hpp>
#include <boost/lexical_cast.hpp>
#include <ostream>
#include <string>

using boost::bad_lexical_cast;
using boost::lexical_cast;
using std::string;

static bool stringIsNumber(const string& s);


TerminalNode::TerminalNode(const string& value, const int type)
    : ExpressionNode("Terminal")
    , value_(value)
    , type_(type)
{
    assert(
        HEX_NUMBER == type
        || INTEGER == type
        || STRING == type
        || ID == type
        || FLOAT == type
        || GLOBAL_VARIABLE == type
        || VARIABLE == type
    );
}


TerminalNode* TerminalNode::createDummyIdentifierTerminalNode()
{
    return new TerminalNode("dummy_terminal_node", ID);
}


TerminalNode* TerminalNode::createStringTerminalNode(const string& str)
{
    return new TerminalNode(str, STRING);
}


TerminalNode* TerminalNode::createNumberTerminalNode(const string& str)
{
    return new TerminalNode(str, FLOAT);
}


TerminalNode::~TerminalNode()
{
}


bool TerminalNode::isAlwaysTrueOrFalse() const
{
    switch (type_)
    {
        case ID:
            return false;
        case INTEGER:
        case HEX_NUMBER:
        case STRING:
            return true;
        default:
            Logger::log(Logger::WARN)
                << "Unexpected case " << type_ << " in TerminalNode::isAlwaysTrueOrFalse";
            assert(false);
            return false;
    }
}


#if __GNUC__ >= 4 && __GNUC_MINOR__ >= 6
#pragma GCC diagnostic push
#endif
#pragma GCC diagnostic ignored "-Wfloat-equal"
bool TerminalNode::isAlwaysTrue() const
{
    switch (type_)
    {
    case INTEGER:
        /// @TODO(bskari|2012-07-27) Doing a full conversion here seems
        /// unnecessary when all we care about is if it's 0
        return lexical_cast<int64_t>(value_) != static_cast<int64_t>(0);
    case HEX_NUMBER:
        /// @TODO(bskari|2012-07-27) Convert the hex value to an integer and
        /// see if it's 0
        return 0;
    case STRING:
        // MySQL converts plain strings into floating point values, and then
        // checks if they are 0
        try
        {
            return 0.0 == lexical_cast<double>(value_);
        }
        catch (bad_lexical_cast&)
        {
            return false;
        }
    case ID:
        // Identifiers may or may not result in true, so they are not
        // necessarily always true
        return false;
    default:
        Logger::log(Logger::WARN)
            << "Unexpected case " << type_ << " in TerminalNode::isAlwaysTrue";
        assert(false);
        return false;
    }
}
#if __GNUC__ >= 4 && __GNUC_MINOR__ >= 6
#pragma GCC diagnostic pop
#endif


bool TerminalNode::anyIsAlwaysTrue() const
{
    return isAlwaysTrue();
}


QueryRisk::EmptyPassword TerminalNode::emptyPassword() const
{
    return QueryRisk::PASSWORD_NOT_USED;
}


bool TerminalNode::resultsInValue() const
{
    if (isNumber())
    {
        return true;
    }
    // MySQL interprets strings as numbers if it can
    if (isString() && stringIsNumber(getValue()))
    {
        return true;
    }
    return false;
}

bool TerminalNode::resultsInString() const
{
    return isString();
}

string TerminalNode::getValue() const
{
    return value_;
}


bool TerminalNode::isNumber() const
{
    return HEX_NUMBER == type_ || INTEGER == type_ || FLOAT== type_;
}


bool TerminalNode::isIdentifier() const
{
    return ID == type_;
}


bool TerminalNode::isString() const
{
    return STRING == type_;
}


static bool stringIsNumber(const string& s)
{
    // I used to do this with a regex, but it was very slow... rewriting it by
    // hand increased total performance by around 8%

    const string::const_iterator end(s.end());

    string::const_iterator i(s.begin());
    while (i != end && (' ' == *i || '\t' == *i))
    {
        ++i;
    }
    if (end == i)
    {
        return false;
    }

    // Check for hex
    if ('0' == *i && end != (i + 1) && ('x' == *(i + 1) || 'X' == *(i + 1)))
    {
        i += 2;
        size_t hexDigits = 0;
        // Parse the hex digits
        while (
            end != i &&
            ((*i >= '0' && *i <= '9')
            || (*i >= 'a' && *i <= 'f')
            || (*i >= 'A' && *i <= 'F'))
        )
        {
            ++hexDigits;
            ++i;
        }

        if (hexDigits < 1)
        {
            return false;
        }
    }
    // Check for integers/floating point
    else
    {
        while (end != i && (*i >= '0' && *i <= '9'))
        {
            ++i;
        }
        // Floating point part
        if (end != i && '.' == *i)
        {
            ++i;
            while (end != i && (*i >= '0' && *i <= '9'))
            {
                ++i;
            }
        }
    }

    // Skip trailing white space
    while (end != i && (' ' == *i || '\t' == *i))
    {
        ++i;
    }

    return end == i;
}
