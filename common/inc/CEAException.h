/*************************************************************************
 *   This program is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, either version 3 of the License, or
 *   any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program.  If not, see <https://www.gnu.org/licenses/>.
************************************************************************/
#ifndef _CEAEXCEPTION_H_
#define _CEAEXCEPTION_H_

#include <stdexcept>

class FormatException : public std::logic_error
{
    public:
        using std::logic_error::logic_error;
};

class SystemException : public std::logic_error
{
    public:
        using std::logic_error::logic_error;
};

class NetworkException : public std::logic_error
{
    public:
        using std::logic_error::logic_error;
};

class ConfigfileException : public std::logic_error
{
    public:
        using std::logic_error::logic_error;
};

#endif
