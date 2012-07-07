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

#include "AlwaysSomethingNode.hpp"
#include "ComparisonNode.hpp"
#include "sqlParser.h"

#include <string>
#include <boost/regex.hpp>
using std::string;
using boost::regex;
using boost::regex_match;

AlwaysSomethingNode::AlwaysSomethingNode(
    const bool always,
    const int compareType
)
    : ComparisonNode(compareType)
    , always_(always)
{
}


AlwaysSomethingNode::AlwaysSomethingNode(
    const bool always
)
    : ComparisonNode(EQ)  // This type is a lie, but doesn't matter anyway
    , always_(always)
{
}


AlwaysSomethingNode::~AlwaysSomethingNode()
{
}


AstNode* AlwaysSomethingNode::copy() const
{
    AlwaysSomethingNode* const temp =
        new AlwaysSomethingNode(always_, compareType_);
    AstNode::addCopyOfChildren(temp);
    return temp;
}


bool AlwaysSomethingNode::isAlwaysTrue() const
{
    return always_;
}


bool AlwaysSomethingNode::anyIsAlwaysTrue() const
{
    return AlwaysSomethingNode::isAlwaysTrue();
}
