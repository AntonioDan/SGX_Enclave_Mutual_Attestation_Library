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
