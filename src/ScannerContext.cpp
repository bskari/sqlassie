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

#include "QueryRisk.hpp"
#include "ScannerContext.hpp"

#include <stack>
#include <string>
#include <utility>

#include <iostream>

using std::pair;


ScannerContext::ScannerContext(QueryRisk* const qrToModify)
    : quotedString()
    , qrPtr(qrToModify)
    , nodes_()
    , selectDepth_()
{
}


ScannerContext::~ScannerContext()
{
    while (!nodes_.empty())
    {
        delete nodes_.top().first;
        nodes_.pop();
    }
}


void ScannerContext::pushNode(AstNode* const node)
{
    nodes_.push(pair<AstNode*, size_t>(node, selectDepth_));
}


AstNode* ScannerContext::getTopNode() const
{
    assert(!nodes_.empty());
    return nodes_.top().first;
}


void ScannerContext::popNode()
{
    nodes_.pop();
}


void ScannerContext::removeTopSelectDepthNodes()
{
    while (!nodes_.empty() && nodes_.top().second == selectDepth_)
    {
        nodes_.pop();
    }
    --selectDepth_;
}


void ScannerContext::increaseSelectDepth()
{
    ++selectDepth_;
}
