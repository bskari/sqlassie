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

#ifndef BAYES_EXCEPTION_HPP
#define BAYES_EXCEPTION_HPP

#include "DescribedException.hpp"
#include <string>

/**
 * Exception that's meant to be thrown by the AttackProbabilities class.
 * @author Brandon Skari
 * @date January 5 2010
 */

class BayesException : public DescribedException
{
public:
    /**
     * Normal constructor.
     */
    BayesException() : DescribedException("BayesException") {}

    /**
     * Constructor with explicit description.
     * @param description The description to return from what.
     */
    explicit BayesException(const std::string& description) :
        DescribedException("BayesException: " + description)
    {
    }
};

#endif
