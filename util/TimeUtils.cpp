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
#include "TimeUtils.h"

#ifndef SGX_TRUSTED
#include <sstream>
#include <iomanip>
#include <regex>
#include <chrono>
#endif

time_t getEpochTimeFromString(const std::string& date)
{
    struct tm date_c{};
    std::istringstream input(date);
    input.imbue (std::locale(setlocale(LC_ALL, "")));
    input >> std::get_time(&date_c, "%Y-%m-%dT%H:%M:%SZ");

    return std::mktime(&date_c);
}

bool isValidTimeString(const std::string& timeString)
{
    // to make sure that this doesn't happen on windows:
    // https://developercommunity.visualstudio.com/content/problem/18311/stdget-time-asserts-with-istreambuf-iterator-is-no.html
    // first check with regex
    std::regex timeRegex("[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z");
    if (!std::regex_match(timeString, timeRegex))
    {
        return false;
    }
    std::tm time{};
    std::istringstream input(timeString);
    input.imbue (std::locale(setlocale(LC_ALL, nullptr)));
    input >> std::get_time(&time, "%Y-%m-%dT%H:%M:%SZ");
    return !input.fail();
}



