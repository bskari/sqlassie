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

#include "AstNode.hpp"
#include "ExpressionNode.hpp"

#include <boost/algorithm/string/predicate.hpp>
#include <boost/lexical_cast.hpp>
#include <iomanip>
#include <ostream>
#include <sstream>
#include <string>

using boost::lexical_cast;
using boost::starts_with;
using std::hex;
using std::ostream;
using std::string;
using std::stringstream;


ExpressionNode::ExpressionNode(const std::string& str) :
    AstNode(str + "-Expression")
{
}


ExpressionNode::~ExpressionNode()
{
}


bool ExpressionNode::resultsInString() const
{
    return false;
}


bool ExpressionNode::isField() const
{
    return false;
}


bool ExpressionNode::isAlwaysFalse() const
{
    if (isAlwaysTrueOrFalse())
    {
        return !isAlwaysTrue();
    }
    return false;
}


ExpressionNode::SQL_FLOAT ExpressionNode::convertFloatOrHexString(
    const string& str
)
{
    ExpressionNode::SQL_FLOAT returnValue;
    if (starts_with(str, "0x"))
    {
        stringstream s;
        s << str;
        s >> hex >> returnValue;
        return returnValue;
    }
    else
    {
        return lexical_cast<ExpressionNode::SQL_FLOAT>(str);
    }
}


void ExpressionNode::print(
    ostream& out,
    const int depth,
    const char indent
) const
{
    for (int i = 0; i < depth; ++i)
    {
        out << indent;
    }
    out << name_;
    if (resultsInValue() || resultsInString())
    {
        out << " (" << getValue() << ')';
    }
    out << '\n';
    printChildren(out, depth + 1, indent);
}
