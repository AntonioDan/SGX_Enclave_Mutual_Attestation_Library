#ifndef _BYTES_H_
#define _BYTES_H_

#include <vector>
#include <string>
#include <stdexcept>
#include <ctype.h>

using Bytes = std::vector<uint8_t>;

namespace detail {
inline uint8_t asciiToValue(const char in)
{
    if (::isxdigit(static_cast<unsigned char>(in)))
    {
        if (in >= '0' && in <= '9')
        {
            return static_cast<uint8_t>(in - '0');
        }

        if (in >= 'A' && in <= 'F')
        {
            return static_cast<uint8_t>(in - 'A' + 10);
        }

        if (in >= 'a' && in <= 'f')
        {
            return static_cast<uint8_t> (in - 'a' + 10);
        }
    }

    throw std::invalid_argument("Invalid hex character");
}
}

inline Bytes hexStringToBytes(const std::string& hexEncoded)
{
    try 
    {
        //auto pos = hexEncoded.cbegin();

        Bytes outbuffer;
        outbuffer.reserve(hexEncoded.length() / 2);

        /*
        while (pos < hexEncoded.cend())
        {
            outbuffer.push_back(static_cast<uint8_t>(detail::asciiToValue(*(pos + 1))) + static_cast<uint8_t>((detail::asciiToValue(*pos)) << 4));
            pos = std::next(pos + 2);
        }*/

        unsigned int i = 0;
        while (i < hexEncoded.length())
        {
            outbuffer.push_back(static_cast<uint8_t>(detail::asciiToValue(hexEncoded[i + 1]) + (detail::asciiToValue(hexEncoded[i]) << 4)));
            i += 2;
        }


        return outbuffer;
    } catch (const std::invalid_argument&) 
    {
        return {};
    }
}

inline Bytes operator+(const Bytes & lhs, const Bytes & rhs)
{
    Bytes retVal{lhs};

    retVal.insert(retVal.cend(), rhs.cbegin(), rhs.cend());
    
    return retVal;
}
#endif
