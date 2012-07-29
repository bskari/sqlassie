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

#include "testNode.hpp"
#include "../AlwaysSomethingNode.hpp"
#include "../AstNode.hpp"
#include "../BinaryOperatorNode.hpp"
#include "../ComparisonNode.hpp"
#include "../InValuesListNode.hpp"
#include "../NegationNode.hpp"
#include "../TerminalNode.hpp"
#include "../sqlParser.h"

#include <boost/test/unit_test.hpp>
#include <string>

using std::string;

void testAstNode()
{
    const string name("SomeName");
    AstNode an(name);
    BOOST_CHECK_EQUAL(name, an.getName());
}


void testAlwaysSomethingNode()
{
    bool values[] = {true, false};
    for (unsigned int i = 0; i < sizeof(values) / sizeof(values[0]); ++i)
    {
        const bool value = values[i];
        AlwaysSomethingNode asn(value);
        BOOST_CHECK_EQUAL(value, asn.isAlwaysTrue());
        BOOST_CHECK_EQUAL(value, asn.anyIsAlwaysTrue());
    }
}


void testComparisonNode()
{
    BinaryOperatorNode* bonAdd;
    BinaryOperatorNode* bonSubtract;
    BinaryOperatorNode* bonMultiply;

    ComparisonNode* cn;
    NegationNode* nn;

    cn = new ComparisonNode(
        new TerminalNode("1", INTEGER),
        EQ,
        new TerminalNode("2", INTEGER)
    );
    BOOST_CHECK(!cn->isAlwaysTrue());
    BOOST_CHECK_EQUAL(QueryRisk::PASSWORD_NOT_USED, cn->emptyPassword());
    delete cn;

    cn = new ComparisonNode(
        new TerminalNode("1", INTEGER),
        NE,
        new TerminalNode("1", INTEGER)
    );
    BOOST_CHECK(cn->isAlwaysTrue());
    BOOST_CHECK_EQUAL(QueryRisk::PASSWORD_NOT_USED, cn->emptyPassword());
    delete cn;

    // (1 + 2) * -3 == (-4 - 5)
    bonAdd = new BinaryOperatorNode(
        new TerminalNode("1", INTEGER),
        PLUS,
        new TerminalNode("2", INTEGER)
    );
    bonMultiply = new BinaryOperatorNode(
        bonAdd,
        STAR,
        new TerminalNode("-3", INTEGER)
    );
    bonSubtract = new BinaryOperatorNode(
        new TerminalNode("-4", INTEGER),
        MINUS,
        new TerminalNode("5", INTEGER)
    );
    cn = new ComparisonNode(
        bonMultiply,
        EQ,
        bonSubtract
    );
    BOOST_CHECK(cn->isAlwaysTrue());
    delete cn;

    cn = new ComparisonNode(
        new TerminalNode("skari", STRING),
        LIKE_KW,
        new TerminalNode("%", STRING)
    );
    BOOST_CHECK(cn->isAlwaysTrue());
    delete cn;

    cn = new ComparisonNode(
        new TerminalNode("skari", STRING),
        LIKE_KW,
        new TerminalNode("s%i", STRING)
    );
    BOOST_CHECK(cn->isAlwaysTrue());
    delete cn;

    cn = new ComparisonNode(
        new TerminalNode("skari", false),
        LIKE_KW,
        new TerminalNode("___r_", false)
    );
    BOOST_CHECK(cn->isAlwaysTrue());
    delete cn;

    cn = new ComparisonNode(
        new TerminalNode("skari", false),
        LIKE_KW,
        new TerminalNode("___", false)
    );
    BOOST_CHECK(!cn->isAlwaysTrue());
    delete cn;

    cn = new ComparisonNode(
        new TerminalNode("brandon", false),
        LIKE_KW,
        new TerminalNode("skari", false)
    );
    nn = new NegationNode(cn);
    BOOST_CHECK(nn->isAlwaysTrue());
    delete nn;

    cn = new ComparisonNode(
        new TerminalNode("brandon", false),
        LIKE_KW,
        new TerminalNode("s%", false)
    );
    nn = new NegationNode(cn);
    BOOST_CHECK(nn->isAlwaysTrue());
    delete nn;

    cn = new ComparisonNode(
        new TerminalNode("skari", false),
        LIKE_KW,
        new TerminalNode("__b__", false)
    );
    nn = new NegationNode(cn);
    BOOST_CHECK(nn->isAlwaysTrue());
    delete nn;

    cn = new ComparisonNode(
        new TerminalNode("skari", false),
        LIKE_KW,
        new TerminalNode("______", false)
    );
    nn = new NegationNode(cn);
    BOOST_CHECK(nn->isAlwaysTrue());
    delete nn;
}
