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

#ifndef NDEBUG
#include <iostream>
#endif

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
    // All of the nodes should have been removed if parsing was successful
#ifndef NDEBUG
    if (qrPtr->valid && !nodes_.empty())
    {
        std::cerr << "The following nodes are still on the stack:\n";
        while (!nodes_.empty())
        {
            std::cerr << *nodes_.top().first;
            nodes_.pop();
        }
        std::cerr << std::flush;
        assert(
            false
            && "All nodes should be deleted when parsing is successful"
        );
    }
#endif

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


bool ScannerContext::isTopNodeFromCurrentDepth()
{
    if (nodes_.empty())
    {
        return false;
    }
    return nodes_.top().second == selectDepth_;
}


void ScannerContext::decreaseNodeDepth()
{
    assert(selectDepth_ > 0);
    --selectDepth_;
}


void ScannerContext::increaseNodeDepth()
{
    ++selectDepth_;
}
