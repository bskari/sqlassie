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

#ifndef DESCRIBED_EXCEPTION_HPP
#define DESCRIBED_EXCEPTION_HPP

#include <string>
#include <exception>

/**
 * Exception class that allows the description to be entered at
 * construction.
 * @author Brandon Skari
 * @date January 11 2011
 */

class DescribedException : public std::exception
{
public:
	/**
	 * Constructor with explicit description.
	 * @param description The description to return from what .
	 */
	explicit DescribedException(const std::string& description) :
		_description(description) {}
	
	/**
	 * Constructor with explicit description.
	 * @param description The description to return from what .
	 */
	//DescribedException(explicit const char* const description) :
	//	_description(description) {}
	
	/**
	 * Destructor.
	 */
	~DescribedException() throw() {}

	/**
	 * Returns a description of the exception. Overridden from
	 * std::exception.
	 * @return A description of the exception.
	 */
	virtual const char* what() const throw()
	{
		return _description.c_str();
	}
	
private:
	const std::string _description;
};

#endif
