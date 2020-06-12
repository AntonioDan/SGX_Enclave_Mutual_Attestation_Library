#ifndef _CMSG_HANDLE_H_
#define _CMSG_HANDLE_H_

#include "sgx_urts.h"

#include "sgx_ea.h"
#include "sgx_ea_error.h"
#include "CEAServerMsg.h"

class CEAMsgHandler {
    friend class CEAMsgHandlerProvider;

    public:
        virtual sgx_ea_status_t init();
        virtual int procmsg(EAServerMsg * request);

    private:    
        sgx_ea_status_t procmsg0(ICommunicationSocket * socket);
        sgx_ea_status_t sendmsg1(ICommunicationSocket * socket, sgx_uea_msg1_req_t*);
        sgx_ea_status_t procmsg2(ICommunicationSocket * socket, sgx_uea_msg2_t *msg2);
        sgx_ea_status_t proc_sec_msg(ICommunicationSocket * socket, sgx_ea_msg_sec_t *p_sec_msg);
#ifdef DEBUG
        sgx_ea_status_t get_mk_by_sessionid(sgx_ea_session_id_t sessionid);
#endif
		sgx_ea_status_t proc_close_msg(sgx_ea_session_id_t sid);

    private:
        //sgx_enclave_id_t m_enclave_id;

    private:
        CEAMsgHandler();
        virtual ~CEAMsgHandler(){}
};

class CEAMsgHandlerProvider {
    public:
        static CEAMsgHandler * GetInstance();

    private:
        static CEAMsgHandler * m_handler;

    private:
        CEAMsgHandlerProvider();
        CEAMsgHandlerProvider(const CEAMsgHandlerProvider &);
        CEAMsgHandlerProvider& operator=(const CEAMsgHandlerProvider &);
};

#endif
