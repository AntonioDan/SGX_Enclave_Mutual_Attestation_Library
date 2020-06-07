#include "TimeUtils.h"

#ifndef SGX_TRUSTED
#include <sstream>
#include <iomanip>
#include <regex>
#include <chrono>
#endif

#if 0
struct tm * gmtime(const time_t * timep)
{
#ifdef SGX_TRUSTED
    return enclave::gmtime(timep);
#else // SGX_TRUSTED
    return standard::gmtime(timep);
#endif
}

time_t mktime(struct tm* tmp)
{
#ifdef SGX_TRUSTED
    return enclave::mktime(tmp);
#else // SGX_TRUSTED
    return standard::mktime(tmp);
#endif
}

time_t getCurrentTime(const time_t *in_time)
{
#ifdef SGX_TRUSTED
    return enclave::getCurrentTime(in_time);
#else // SGX_TRUSTED
    return standard::getCurrentTime(in_time);
#endif
}
struct tm getTimeFromString(const std::string& date)
{
#ifdef SGX_TRUSTED
    return enclave::getTimeFromString(date);
#else // SGX_TRUSTED
    return standard::getTimeFromString(date);
#endif
}
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

#ifndef SGX_TRUSTED
namespace standard
{
#if 0
    struct tm * gmtime(const time_t * timep)
    {
        return std::gmtime(timep);
    }
    time_t mktime(struct tm* tmp)
    {
        return std::mktime(tmp);
    }
    time_t getCurrentTime(const time_t *in_time)
    {
        if(in_time == nullptr)
        {
            return std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
        }

        return (*in_time);
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
    struct tm getTimeFromString(const std::string& date)
    {
        struct tm date_c{};
        std::istringstream input(date);
        input.imbue (std::locale(setlocale(LC_ALL, "")));
        input >> std::get_time(&date_c, "%Y-%m-%dT%H:%M:%SZ");
        return date_c;
    }
#endif
} // namespace standard
#endif // SGX_TRUSTED


