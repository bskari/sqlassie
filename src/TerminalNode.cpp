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
#include <iomanip>
#include <ostream>
#include <sstream>
#include <string>

using boost::bad_lexical_cast;
using boost::lexical_cast;
using std::hex;
using std::istringstream;
using std::ostringstream;
using std::string;
using std::ostream;

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
    case FLOAT:
        /// @TODO(bskari|2012-08-30) Doing a full conversion here seems
        /// unnecessary when all we care about is if it's 0
        return lexical_cast<double>(value_) != static_cast<double>(0.0);
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


bool TerminalNode::isField() const
{
    return isIdentifier();
}


string TerminalNode::getValue() const
{
    /// @TODO(bskari|2012-09-23) Write a function instead of using streams
    if (HEX_NUMBER == type_)
    {
        istringstream is(value_.substr(2)); // Skip the 0x
        int64_t number;
        is >> hex >> number;
        ostringstream os;
        os << number;
        return os.str();
    }
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


void TerminalNode::print(
    ostream& out,
    const int depth,
    const char indent
) const
{
    for (int i = 0; i < depth; ++i)
    {
        out << indent;
    }
    out << name_ << ' ';
    switch (type_)
    {
        case HEX_NUMBER:
            out << "HEX_NUMBER ";
            break;
        case INTEGER:
            out << "INTEGER ";
            break;
        case STRING:
            out << "STRING ";
            break;
        case ID:
            out << "ID ";
            break;
        case FLOAT:
            out << "FLOAT ";
            break;
        case GLOBAL_VARIABLE:
            out << "GLOBAL_VARIABLE ";
            break;
        case VARIABLE:
            out << "VARIABLE ";
            break;
        default:
            out << "Unknown type ";
            break;
    }
    out << value_ << '\n';
    printChildren(out, depth + 1, indent);
}
