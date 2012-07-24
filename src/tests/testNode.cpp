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
#include "../ComparisonNode.hpp"
#include "../ConditionalListNode.hpp"
#include "../ConditionalNode.hpp"
#include "../ExpressionNode.hpp"
#include "../InValuesListNode.hpp"
#include "../NegationNode.hpp"
#include "../OperatorNode.hpp"
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
        AlwaysSomethingNode asn(value, EQ);
        BOOST_CHECK_EQUAL(value, asn.isAlwaysTrue());
        BOOST_CHECK_EQUAL(value, asn.anyIsAlwaysTrue());
    }
}


void testComparisonNode()
{
    ExpressionNode* enAdd;
    ExpressionNode* enSubtract;
    ExpressionNode* enMultiply;

    ComparisonNode* cn;
    NegationNode* nn;

    cn = new ComparisonNode(EQ);
    cn->addChild(new ExpressionNode("1", false));
    cn->addChild(new ExpressionNode("2", false));
    BOOST_CHECK(!cn->isAlwaysTrue());
    BOOST_CHECK_EQUAL(QueryRisk::PASSWORD_NOT_USED, cn->emptyPassword());
    delete cn;

    cn = new ComparisonNode(NE);
    cn->addChild(new ExpressionNode("1", false));
    cn->addChild(new ExpressionNode("2", false));
    BOOST_CHECK(cn->isAlwaysTrue());
    BOOST_CHECK_EQUAL(QueryRisk::PASSWORD_NOT_USED, cn->emptyPassword());
    delete cn;

    // (1 + 2) * 3 == (-4 - 5)
    enAdd = new ExpressionNode();
    enAdd->addChild(new ExpressionNode("1", false));
    enAdd->addChild(new OperatorNode(PLUS));
    enAdd->addChild(new ExpressionNode("2", false));
    enMultiply = new ExpressionNode();
    enMultiply->addChild(enAdd);
    enMultiply->addChild(new OperatorNode(STAR));
    enMultiply->addChild(new ExpressionNode("-3", false));
    enSubtract = new ExpressionNode();
    enSubtract->addChild(new ExpressionNode("-4", false));
    enSubtract->addChild(new OperatorNode(MINUS));
    enSubtract->addChild(new ExpressionNode("5", false));
    cn = new ComparisonNode(EQ);
    cn->addChild(enMultiply);
    cn->addChild(enSubtract);
    BOOST_CHECK(cn->isAlwaysTrue());
    delete cn;

    cn = new ComparisonNode(LIKE_KW);
    cn->addChild(new ExpressionNode("skari", false));
    cn->addChild(new ExpressionNode("%", false));
    BOOST_CHECK(cn->isAlwaysTrue());
    delete cn;

    cn = new ComparisonNode(LIKE_KW);
    cn->addChild(new ExpressionNode("skari", false));
    cn->addChild(new ExpressionNode("s%i", false));
    BOOST_CHECK(cn->isAlwaysTrue());
    delete cn;

    cn = new ComparisonNode(LIKE_KW);
    cn->addChild(new ExpressionNode("skari", false));
    cn->addChild(new ExpressionNode("___r_", false));
    BOOST_CHECK(cn->isAlwaysTrue());
    delete cn;

    cn = new ComparisonNode(LIKE_KW);
    cn->addChild(new ExpressionNode("skari", false));
    cn->addChild(new ExpressionNode("___", false));
    BOOST_CHECK(!cn->isAlwaysTrue());
    delete cn;

    nn = new NegationNode;
    cn = new ComparisonNode(LIKE_KW);
    cn->addChild(new ExpressionNode("brandon", false));
    cn->addChild(new ExpressionNode("skari", false));
    nn->addChild(cn);
    BOOST_CHECK(nn->isAlwaysTrue());
    delete nn;

    nn = new NegationNode;
    cn = new ComparisonNode(LIKE_KW);
    cn->addChild(new ExpressionNode("brandon", false));
    cn->addChild(new ExpressionNode("s%", false));
    nn->addChild(cn);
    BOOST_CHECK(nn->isAlwaysTrue());
    delete nn;

    nn = new NegationNode;
    cn = new ComparisonNode(LIKE_KW);
    cn->addChild(new ExpressionNode("skari", false));
    cn->addChild(new ExpressionNode("__b__", false));
    nn->addChild(cn);
    BOOST_CHECK(nn->isAlwaysTrue());
    delete nn;

    nn = new NegationNode;
    cn = new ComparisonNode(LIKE_KW);
    cn->addChild(new ExpressionNode("skari", false));
    cn->addChild(new ExpressionNode("______", false));
    nn->addChild(cn);
    BOOST_CHECK(nn->isAlwaysTrue());
    delete nn;
}
