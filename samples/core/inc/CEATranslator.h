#ifndef _CEATRANSLATOR_H_
#define _CEATRANSLATOR_H_

#include "ITransportor.h"
#include "IEARequest.h"

class CEATranslator : public ITransportor {
    public:
        IEARequest* receiveRequest(ICommunicationSocket* sock);
    private:

};

#endif
