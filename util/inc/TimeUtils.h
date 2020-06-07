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
