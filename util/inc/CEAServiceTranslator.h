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
#ifndef _CEASERVICETRANSLATOR_H_
#define _CEASERVICETRANSLATOR_H_

#include <stdint.h>
#include "sgx_ea.h"

class CEAServiceTranslator {
    public:
        virtual ~CEAServiceTranslator(){}
    public:
        virtual void init() = 0;
        virtual size_t sendMessage(uint8_t * message, size_t size) = 0;
        virtual uint8_t* recvMessage() = 0;
        virtual uint8_t* sendandrecv(uint8_t * message, size_t size) = 0;
};

#endif
