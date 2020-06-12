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
#ifndef _TIME_UTILS_H_
#define _TIME_UTILS_H_

#include <ctime>
#include <string>

//struct tm * gmtime(const time_t * timep);
//time_t mktime(struct tm * tmp);
#ifdef __cplusplus
extern "C" {
#endif
//time_t getCurrentTime(const time_t * timp);
//struct tm getTimeFromString(const std::string & date);
time_t getEpochTimeFromString(const std::string & date);
bool isValidTimeString(const std::string & timeString);

#ifndef SGX_TRUSTED
namespace standard {
    //struct tm * gmtime(const time_t * timep);
    //time_t mktime(struct tm * tmp);
    //time_t getCurrentTime(const time_t * timp);
    //struct tm getTimeFromString(const std::string & date);
    //time_t getEpochTimeFromString(const std::string & date);
    //bool isValidTimeString(const std::string & timeString);
}
#endif

#ifdef __cplusplus
}
#endif
#endif
