/*
 * SQLassie - database firewall
 * Copyright (C) 2012 Brandon Skari <brandon.skari@gmail.com>
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

/**
 * Input stream with history, editing, up arrow completion, etc. Frontend to
 * GNU readline.
 * @author Brandon Skari
 * @date July 22 2012
 */

#ifndef SRC_READLINESTREAM_HPP_
#define SRC_READLINESTREAM_HPP_

#include <boost/iostreams/stream.hpp>
#include <string>

#include "nullptr.hpp"


class ReadlineSource
{
public:
    ReadlineSource(const std::string& prompt);
    ReadlineSource(const ReadlineSource& rhs);
    virtual ~ReadlineSource();

    typedef char char_type;
    typedef boost::iostreams::source_tag category;  // Only support reading

    /**
     * Reads up to n characters from the readline interface into the buffer s,
     * returning the number of characters read; return -1 to indicate EOF.
     */
    std::streamsize read(char_type* s, const std::streamsize n);

    static const std::streamsize EOF_ = -1;

private:
    std::string prompt_;
    char_type* input_;
    char_type* currentInput_;
    bool needToReturnNewline_;
    
    // Hidden methods
    ReadlineSource& operator=(const ReadlineSource&);
};

typedef boost::iostreams::stream<ReadlineSource> ReadlineStream;

#endif  // SRC_READLINESTREAM_HPP_
