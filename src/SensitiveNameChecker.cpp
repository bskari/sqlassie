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

#include "nullptr.hpp"
#include "SensitiveNameChecker.hpp"

#include <boost/regex.hpp>
#include <boost/algorithm/string/find.hpp>
#include <string>

using boost::find_first;
using boost::regex;
using boost::regex_match;
using std::string;


SensitiveNameChecker* SensitiveNameChecker::instance_;


SensitiveNameChecker::SensitiveNameChecker() :
    passwordRegex_(),
    passwordSubstring_(),
    userRegex_(),
    userSubstring_()
{
}


void SensitiveNameChecker::initialize()
{
    instance_ = new SensitiveNameChecker;
}


void SensitiveNameChecker::setPasswordRegex(const string& passwordRegex)
{
    assert(nullptr != instance_);
    instance_->passwordRegex_ =
        regex(passwordRegex, regex::perl | regex::icase);
}


void SensitiveNameChecker::setPasswordSubstring(const string& passwordSubstring)
{
    assert(nullptr != instance_);
    instance_->passwordSubstring_ = passwordSubstring;
}


void SensitiveNameChecker::setUserRegex(const string& userRegex)
{
    assert(nullptr != instance_);
    instance_->userRegex_ = regex(userRegex, regex::perl | regex::icase);
}


void SensitiveNameChecker::setUserSubstring(const string& userSubstring)
{
    assert(nullptr != instance_);
    instance_->userSubstring_ = userSubstring;
}


bool SensitiveNameChecker::isPasswordField(const std::string& field)
{
    assert(nullptr != instance_);
    return SensitiveNameChecker::isMatch(
        instance_->passwordRegex_,
        instance_->passwordSubstring_,
        field
    );
}


bool SensitiveNameChecker::isUserTable(const std::string& field)
{
    assert(nullptr != instance_);
    return SensitiveNameChecker::isMatch(
        instance_->userRegex_,
        instance_->userSubstring_,
        field
    );
}


bool SensitiveNameChecker::isMatch(
    const boost::regex& re,
    const std::string& substring,
    const std::string& field
)
{
    assert(
        (
            (re.empty() && !substring.empty())
            || (!re.empty() && substring.empty())
        )
        && "Either substring or regex needs to be set"
    );

    if (!substring.empty())
    {
        return find_first(field, substring);
    }
    else
    {
        return regex_search(field, re);
    }
}
