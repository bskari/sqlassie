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

#ifndef SRC_ASSERTCAST_HPP_
#define SRC_ASSERTCAST_HPP_

#include "nullptr.hpp"
#include "warnUnusedResult.h"

#ifndef NDEBUG
// This is only needed when debugging is on, to catch std::bad_cast
#include <typeinfo>
#endif

#include <cassert>

/**
 * Assert safe static and dynamic typecasts.
 *
 * If assertions are enabled, does a dynamic cast on the pointer and asserts
 * that the result is not nullptr, i.e. that the pointer is an instance of the
 * casted to type. If assertions are not enabled, just does a static_cast.
 *
 * @author Brandon Skari
 * @date July 4 2012
 */

/**
 * Type-safe if assert-is-enabled conversion for pointers.
 */
template <typename ResultPtr, typename Source>
inline ResultPtr assert_cast(Source* source) WARN_UNUSED_RESULT;

/**
 * Type-safe if assert-is-enabled conversion for references.
 */
template <typename ResultRef, typename Source>
inline ResultRef assert_cast(Source& source) WARN_UNUSED_RESULT;


template <typename ResultPtr, typename Source>
inline ResultPtr assert_cast(Source* source)
{
#ifndef NDEBUG
    ResultPtr const p = dynamic_cast<ResultPtr>(source);
    assert(nullptr != p);
    return p;
#else
    return static_cast<ResultPtr>(src);
#endif
}


template <typename ResultRef, typename Source>
inline ResultRef assert_cast(Source& source)
{
#ifndef NDEBUG
    try
    {
        return dynamic_cast<ResultRef>(source);
    }
    catch (std::bad_cast& bc)
    {
        assert(false);
        // Silence warnings
        return static_cast<ResultRef>(source);
    }
#else
    return static_cast<ResultRef>(source);
#endif
}

#endif  // SRC_ASSERTCAST_HPP_
