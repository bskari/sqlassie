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

// GCC gives a warning about defining a future keyword (which is exactly what
// we are doing). Unfortunately, GCC ignores this pragma. See
// http://gcc.gnu.org/bugzilla/show_bug.cgi?id=48914 for a full bug report.
#pragma GCC diagnostic ignored "-Wc++0x-compat"

#ifndef SRC_NULLPTR_HPP_
#define SRC_NULLPTR_HPP_

#define NEED_TO_DEFINE_NULLPTR 1
// GNU g++ didn't support the __cplusplus macro until version 4.7
#if (__GNUC__ && __GNUC_VERSION__ >= 40700 && __cplusplus > 199711L) \
    || (__GNUC__ && __GXX_EXPERIMENTAL_CXX0X__)
        #undef NEED_TO_DEFINE_NULLPTR
#endif

// Versions of GCC prior to 4.6 have problems with this workaround
#if (__GNUC__ <= 3 || (__GNUC__ == 4 && __GNUC_MINOR__ < 6))
    #undef NEED_TO_DEFINE_NULLPTR
    #define NEED_TO_DEFINE_NULLPTR 0
    #define nullptr 0
#endif

#if NEED_TO_DEFINE_NULLPTR

/**
 * Forward compatible definition of nullptr. Taken from the official
 * proposal's workaround.
 * @author Brandon Skari
 * @date January 14 2012
 */

const                            // this is a const object...
class {
public:
    template<class T>            // convertible to any type
    operator T*() const            // of null non-member
        { return 0; }            // pointer...
    template<class C, class T>    // or any type of null
    operator T C::*() const        // member pointer...
        { return 0; }
private:
    // Break the line between 'operator' and '&()' so that cppcheck doesn't
    // produce a false positive
    void operator
        &() const;        // whose address can't be taken
} nullptr = {};                    // and whose name is nullptr

#endif  // #if NEED_TO_DEFINE_NULLPTR
#endif  // SRC_NULLPTR_HPP_
