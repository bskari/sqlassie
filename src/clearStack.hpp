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

#ifndef SRC_CLEARSTACK_HPP_
#define SRC_CLEARSTACK_HPP_

#include "nullptr.hpp"

#include <cassert>
#include <queue>
#include <stack>

template <typename T>
void clearStack(std::stack<T>* aStack)
{
    assert(nullptr != aStack);
    while (!aStack->empty())
    {
        aStack->pop();
    }
}


template <typename T>
void clearQueue(std::queue<T>* aQueue)
{
    assert(nullptr != aQueue);
    while (!aQueue->empty())
    {
        aQueue->pop();
    }
}

#endif  // SRC_CLEARSTACK_HPP_
