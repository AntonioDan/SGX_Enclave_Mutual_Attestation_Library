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
#ifndef _CEASERVICEPROVIDER_H_
#define _CEASERVICEPROVIDER_H_

#include <string>
#include "CEAServiceTranslator.h"

class CEAServiceProvider
{
    public:
        //static CEAService * GetServiceProvider(int mode);
        static CEAServiceTranslator * GetServiceProvider(std::string server, short port);
        static CEAServiceTranslator * GetServiceProvider(std::string filesocket);

    private:
        static CEAServiceTranslator * m_ea_service_imp;

    private:
        CEAServiceProvider();
        CEAServiceProvider(const CEAServiceProvider&);
        CEAServiceProvider& operator=(const CEAServiceProvider&);
};
#endif
