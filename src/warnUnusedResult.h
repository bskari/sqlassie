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

#ifndef WARN_UNUSED_RESULT_H
#define WARN_UNUSED_RESULT_H

/**
 * Defines a macro WARN_IF_UNUSED that can be applied as a function attribute
 * that will issue a warning if the return value of that function is ignored.
 * This must be applied at the declaration of the function.
 *
 * Example:
 * int run_some_tests() WARN_UNUSED_RESULT;
 *
 * You can ignore these checks by using the -Wno-unused-result compiler flag.
 * @author Brandon Skari
 * @date June 30 2011
 */

#ifdef WARN_UNUSED_RESULT
    #undef WARN_UNUSED_RESULT
#endif

#ifdef __GNUC__
    #define WARN_UNUSED_RESULT __attribute__ ((warn_unused_result))
#else
    #define WARN_UNUSED_RESULT
#endif

#endif
