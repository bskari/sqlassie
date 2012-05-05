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

#ifndef SRC_SENSITIVENAMECHECKER_HPP_
#define SRC_SENSITIVENAMECHECKER_HPP_

/**
 * Singleton class that defines methods to check identify sensitive fields and
 * tables, such as 'user' table or 'password' field.
 * @author Brandon Skari
 * @date April 6 2012
 */

#include <boost/regex.hpp>
#include <string>

class SensitiveNameChecker
{
public:
    /**
     * Singleton accessor.
     */
    static SensitiveNameChecker& get();

    /**
     * Creates the singleton instance.
     */
    static void initialize();

    /**
     * Checks for various fields,
     */
    ///@{
    bool isPasswordField(const std::string& field) const;
    bool isUserTable(const std::string& table) const;
    ///@}

    /**
     * Set how the fields are checked.
     */
    ///@{
    void setPasswordRegex(const std::string& pwRegex);
    void setPasswordSubstring(const std::string& pwSubstr);
    void setUserRegex(const std::string& userRegex);
    void setUserSubstring(const std::string& userSubstr);
    ///@}

private:
    SensitiveNameChecker();
    ~SensitiveNameChecker();
    static bool isMatch(
        const boost::regex& re,
        const std::string& substring,
        const std::string& name
    );

    static SensitiveNameChecker* instance_;

    boost::regex passwordRegex_;
    std::string passwordSubstring_;

    boost::regex userRegex_;
    std::string userSubstring_;
};

#endif  // SRC_SENSITIVENAMECHECKER_HPP_
