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

#include <boost/lexical_cast.hpp>
#include <boost/test/unit_test.hpp>
#include <string>

using boost::lexical_cast;
using std::string;

static bool approximatelyEqual(const float a, const float b);


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
    }
}


void testComparisonNode()
{
    BinaryOperatorNode* bonAdd;
    BinaryOperatorNode* bonSubtract;
    BinaryOperatorNode* bonMultiply;

    ComparisonNode* cn;
    NegationNode* nn;

    // 1 = 2
    cn = new ComparisonNode(
        new TerminalNode("1", INTEGER),
        EQ,
        new TerminalNode("2", INTEGER)
    );
    BOOST_CHECK(!cn->isAlwaysTrue());
    BOOST_CHECK_EQUAL(QueryRisk::PASSWORD_NOT_USED, cn->emptyPassword());
    delete cn;

    // 1 != 1
    cn = new ComparisonNode(
        new TerminalNode("1", INTEGER),
        NE,
        new TerminalNode("1", INTEGER)
    );
    BOOST_CHECK(!cn->isAlwaysTrue());
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
        new TerminalNode("skari", STRING),
        LIKE_KW,
        new TerminalNode("___r_", STRING)
    );
    BOOST_CHECK(cn->isAlwaysTrue());
    delete cn;

    cn = new ComparisonNode(
        new TerminalNode("skari", STRING),
        LIKE_KW,
        new TerminalNode("___", STRING)
    );
    BOOST_CHECK(!cn->isAlwaysTrue());
    delete cn;

    cn = new ComparisonNode(
        new TerminalNode("brandon", STRING),
        LIKE_KW,
        new TerminalNode("skari", STRING)
    );
    nn = new NegationNode(cn);
    BOOST_CHECK(nn->isAlwaysTrue());
    delete nn;

    cn = new ComparisonNode(
        new TerminalNode("brandon", STRING),
        LIKE_KW,
        new TerminalNode("s%", STRING)
    );
    nn = new NegationNode(cn);
    BOOST_CHECK(nn->isAlwaysTrue());
    delete nn;

    cn = new ComparisonNode(
        new TerminalNode("skari", STRING),
        LIKE_KW,
        new TerminalNode("__b__", STRING)
    );
    nn = new NegationNode(cn);
    BOOST_CHECK(nn->isAlwaysTrue());
    delete nn;

    cn = new ComparisonNode(
        new TerminalNode("skari", STRING),
        LIKE_KW,
        new TerminalNode("______", STRING)
    );
    nn = new NegationNode(cn);
    BOOST_CHECK(nn->isAlwaysTrue());
    delete nn;
}


void testNegationNode()
{
    NegationNode* nn;

    nn = new NegationNode(new AlwaysSomethingNode(true));
    BOOST_CHECK(nn->isAlwaysTrueOrFalse());
    BOOST_CHECK(!nn->isAlwaysTrue());
    BOOST_CHECK(nn->isAlwaysFalse());
    delete nn;

    nn = new NegationNode(new NegationNode(new AlwaysSomethingNode(true)));
    BOOST_CHECK(nn->isAlwaysTrueOrFalse());
    BOOST_CHECK(nn->isAlwaysTrue());
    BOOST_CHECK(!nn->isAlwaysFalse());
    delete nn;

    // Identifier comparisons should neither be always true or always false
    nn = new NegationNode(
        new ComparisonNode(
            new TerminalNode("x", ID),
            EQ,
            new TerminalNode("5", INTEGER)
        )
    );
    BOOST_CHECK(!nn->isAlwaysTrueOrFalse());
    BOOST_CHECK(!nn->isAlwaysTrue());
    BOOST_CHECK(!nn->isAlwaysFalse());
    delete nn;
}


void testInValuesListNode()
{
    InValuesListNode* ivln;

    // 1 IN ()
    ivln = new InValuesListNode(new TerminalNode("1", INTEGER));
    BOOST_CHECK(ivln->resultsInValue());
    BOOST_CHECK(ivln->isAlwaysTrueOrFalse());
    BOOST_CHECK(!ivln->isAlwaysTrue());
    BOOST_CHECK(ivln->isAlwaysFalse());
    delete ivln;

    // 1 IN (1)
    ivln = new InValuesListNode(new TerminalNode("1", INTEGER));
    ivln->addChild(new TerminalNode("1", INTEGER));
    BOOST_CHECK(ivln->resultsInValue());
    BOOST_CHECK(ivln->isAlwaysTrueOrFalse());
    BOOST_CHECK(ivln->isAlwaysTrue());
    BOOST_CHECK(!ivln->isAlwaysFalse());
    delete ivln;

    // 1 IN (0, 2, 3)
    ivln = new InValuesListNode(new TerminalNode("1", INTEGER));
    ivln->addChild(new TerminalNode("0", INTEGER));
    ivln->addChild(new TerminalNode("2", INTEGER));
    ivln->addChild(new TerminalNode("3", INTEGER));
    BOOST_CHECK(ivln->resultsInValue());
    BOOST_CHECK(ivln->isAlwaysTrueOrFalse());
    BOOST_CHECK(!ivln->isAlwaysTrue());
    BOOST_CHECK(ivln->isAlwaysFalse());
    delete ivln;

    // 1 IN (2 - 1)
    ivln = new InValuesListNode(new TerminalNode("1", INTEGER));
    ivln->addChild(
        new BinaryOperatorNode(
            new TerminalNode("2", INTEGER),
            MINUS,
            new TerminalNode("1", INTEGER)
        )
    );
    BOOST_CHECK(ivln->resultsInValue());
    BOOST_CHECK(ivln->isAlwaysTrueOrFalse());
    BOOST_CHECK(ivln->isAlwaysTrue());
    BOOST_CHECK(!ivln->isAlwaysFalse());
    delete ivln;

    // 1 IN (0, 2, 2 - 1)
    ivln = new InValuesListNode(new TerminalNode("1", INTEGER));
    ivln->addChild(new TerminalNode("0", INTEGER));
    ivln->addChild(new TerminalNode("2", INTEGER));
    ivln->addChild(
        new BinaryOperatorNode(
            new TerminalNode("2", INTEGER),
            MINUS,
            new TerminalNode("1", INTEGER)
        )
    );
    BOOST_CHECK(ivln->resultsInValue());
    BOOST_CHECK(ivln->isAlwaysTrueOrFalse());
    BOOST_CHECK(ivln->isAlwaysTrue());
    BOOST_CHECK(!ivln->isAlwaysFalse());
    delete ivln;

    // 1 IN (age, 1)
    ivln = new InValuesListNode(new TerminalNode("1", INTEGER));
    ivln->addChild(new TerminalNode("age", ID));
    ivln->addChild(
        new BinaryOperatorNode(
            new TerminalNode("2", INTEGER),
            MINUS,
            new TerminalNode("1", INTEGER)
        )
    );
    BOOST_CHECK(ivln->resultsInValue());
    BOOST_CHECK(ivln->isAlwaysTrueOrFalse());
    BOOST_CHECK(ivln->isAlwaysTrue());
    BOOST_CHECK(!ivln->isAlwaysFalse());
    delete ivln;

    // 1 IN (3, (SELECT 2), 1)
    ivln = new InValuesListNode(new TerminalNode("1", INTEGER));
    ivln->addChild(new TerminalNode("age", ID));
    ivln->addChild(
        new BinaryOperatorNode(
            new TerminalNode("2", INTEGER),
            MINUS,
            new TerminalNode("1", INTEGER)
        )
    );
    BOOST_CHECK(ivln->resultsInValue());
    BOOST_CHECK(ivln->isAlwaysTrueOrFalse());
    BOOST_CHECK(ivln->isAlwaysTrue());
    BOOST_CHECK(!ivln->isAlwaysFalse());
    delete ivln;
}


void testBinaryOperatorNode()
{
    // This function should test:
    // + - * / DIV & | << >>
    const BinaryOperatorNode* bon;

    bon = new BinaryOperatorNode(
        new TerminalNode("-3", INTEGER),
        PLUS,
        new TerminalNode("5", INTEGER)
    );
    BOOST_CHECK("2" == bon->getValue());
    delete bon;

    bon = new BinaryOperatorNode(
        new TerminalNode("-3", INTEGER),
        MINUS,
        new TerminalNode("5", INTEGER)
    );
    BOOST_CHECK("-8" == bon->getValue());
    delete bon;

    bon = new BinaryOperatorNode(
        new TerminalNode("-3", INTEGER),
        STAR,
        new TerminalNode("5", INTEGER)
    );
    BOOST_CHECK("-15" == bon->getValue());
    delete bon;

    bon = new BinaryOperatorNode(
        new TerminalNode("-3", INTEGER),
        SLASH,
        new TerminalNode("5", INTEGER)
    );
    BOOST_CHECK(approximatelyEqual(lexical_cast<float>(bon->getValue()), -0.6));
    delete bon;

    bon = new BinaryOperatorNode(
        new TerminalNode("-3", INTEGER),
        INTEGER_DIVIDE,
        new TerminalNode("5", INTEGER)
    );
    BOOST_CHECK("0" == bon->getValue());
    delete bon;

    bon = new BinaryOperatorNode(
        new TerminalNode("3", INTEGER),
        BITAND,
        new TerminalNode("5", INTEGER)
    );
    BOOST_CHECK("1" == bon->getValue());
    delete bon;

    bon = new BinaryOperatorNode(
        new TerminalNode("-3", INTEGER),
        BITAND,
        new TerminalNode("5", INTEGER)
    );
    BOOST_CHECK("5" == bon->getValue());
    delete bon;

    bon = new BinaryOperatorNode(
        new TerminalNode("3", INTEGER),
        BITOR,
        new TerminalNode("5", INTEGER)
    );
    BOOST_CHECK("7" == bon->getValue());
    delete bon;

    bon = new BinaryOperatorNode(
        new TerminalNode("-3", INTEGER),
        BITOR,
        new TerminalNode("5", INTEGER)
    );
    BOOST_CHECK("18446744073709551613" == bon->getValue());
    delete bon;

    bon = new BinaryOperatorNode(
        new TerminalNode("-3", INTEGER),
        LSHIFT,
        new TerminalNode("5", INTEGER)
    );
    BOOST_CHECK("18446744073709551520" == bon->getValue());
    delete bon;

    bon = new BinaryOperatorNode(
        new TerminalNode("3", INTEGER),
        LSHIFT,
        new TerminalNode("5", INTEGER)
    );
    BOOST_CHECK("96" == bon->getValue());
    delete bon;

    bon = new BinaryOperatorNode(
        new TerminalNode("-3", INTEGER),
        RSHIFT,
        new TerminalNode("5", INTEGER)
    );
    BOOST_CHECK("576460752303423487" == bon->getValue());
    delete bon;

    bon = new BinaryOperatorNode(
        new TerminalNode("3", INTEGER),
        RSHIFT,
        new TerminalNode("5", INTEGER)
    );
    BOOST_CHECK("0" == bon->getValue());
    delete bon;

    bon = new BinaryOperatorNode(
        new TerminalNode("243", INTEGER),
        RSHIFT,
        new TerminalNode("4", INTEGER)
    );
    BOOST_CHECK("15" == bon->getValue());
    delete bon;
}


bool approximatelyEqual(const float a, const float b)
{
    // I know this isn't perfect for a lot of reasons, such as small values
    // will always be deemed as approximately equal, but for the purposes of
    // tests here, that's fine. Do not use this function outside of
    // tests/testNode.cpp!
    return abs(a - b) < 0.001;
}
