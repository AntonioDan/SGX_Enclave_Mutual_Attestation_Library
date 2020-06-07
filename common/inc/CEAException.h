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
