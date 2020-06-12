#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <memory>
#include <string.h>

#include "se_trace.h"

#include "CEAServiceNetwork.h"
#include "parseconfig.h"
#include "sgx_uea_key_exchange_initiator.h"

#define UEA_KEY_EXCHANGE_LIB_HANDLE "libsgx_uea_key_exchange_initiator.so"
#define QEIDENTITY_FILENAME "qeidentity.json"

class CEAServiceNetwork;

typedef sgx_ea_status_t (*f_create_ea_session)();
typedef sgx_ea_status_t (*f_initiator_get_session_key)(sgx_aes_gcm_128bit_key_t * key);
typedef sgx_ea_status_t (*f_initiator_query_server_session_key)();
typedef sgx_ea_status_t (*f_initiator_set_qeidentity)(const char * qeidentityfilename);
typedef sgx_ea_status_t (*f_uea_init_initiator_adv)(std::shared_ptr<CEAServiceTranslator> tanslator);
typedef sgx_ea_status_t (*f_uea_initiator_sendmsg)(const uint8_t * p_sentmsg, uint32_t sentmsgsize);
typedef sgx_ea_status_t (*f_uea_initiator_recvmsg)(uint8_t **pp_msg, uint32_t *p_msgsize);
typedef sgx_ea_status_t (*f_uea_initiator_close_ea_session)();

int main(int argc, char * argv[])
{
    sgx_ea_status_t earetval;
    sgx_ea_server_t server;

    std::shared_ptr<CEAServiceTranslator> p_translator;

    (void)argc;
    (void)argv;

    try
    {
        parseconfig(server);
        
        p_translator = std::make_shared<CEAServiceNetwork>(server.m_server, server.m_port);
    } catch (std::bad_alloc())
    {
        return SGX_EA_ERROR_OUT_OF_MEMORY;
    } catch (...)
    {
        return SGX_EA_ERROR_UNEXPECTED;
    }

    void * uea_handler = NULL;
    f_uea_init_initiator_adv pfinit = NULL;
    f_create_ea_session pfcreateasession = NULL;
#ifdef DEBUG
    f_initiator_get_session_key pfgetsessionkey = NULL;
    f_initiator_query_server_session_key pfquerysessionkey = NULL;
#endif
    f_initiator_set_qeidentity pfsetqeidentity = NULL;
    f_uea_initiator_sendmsg pfsendmsg = NULL;
    f_uea_initiator_recvmsg pfrecvmsg = NULL;
	f_uea_initiator_close_ea_session pfclosesession = NULL;

    uea_handler = dlopen(UEA_KEY_EXCHANGE_LIB_HANDLE, RTLD_LAZY);
    if (!uea_handler) {
        SE_TRACE_ERROR("failed to load uea_key_exchange library, %s\n", dlerror());
        exit(0);
    }

    pfinit = (f_uea_init_initiator_adv)dlsym(uea_handler, "sgx_uea_init_initiator_adv");
    pfcreateasession = (f_create_ea_session)dlsym(uea_handler, "sgx_uea_initiator_create_ea_session");
#ifdef DEBUG
    pfgetsessionkey = (f_initiator_get_session_key)dlsym(uea_handler, "sgx_uea_initiator_get_session_key");
    pfquerysessionkey = (f_initiator_query_server_session_key)dlsym(uea_handler, "sgx_uea_initiator_query_server_session_key");
#endif
    pfsetqeidentity = (f_initiator_set_qeidentity)dlsym(uea_handler, "sgx_uea_initiator_set_qeidentity");
    pfsendmsg = (f_uea_initiator_sendmsg)dlsym(uea_handler, "sgx_uea_initiator_sendmsg");
    pfrecvmsg = (f_uea_initiator_recvmsg)dlsym(uea_handler, "sgx_uea_initiator_recvmsg");
	pfclosesession = (f_uea_initiator_close_ea_session)dlsym(uea_handler, "sgx_uea_initiator_close_ea_session");

    if ((pfinit == NULL) || (pfcreateasession == NULL) 
         || (pfsetqeidentity == NULL) || (pfsendmsg == NULL) || (pfrecvmsg == NULL) || (pfclosesession == NULL)) {
        SE_TRACE_ERROR("failed to get function interface from uea key exchange library.");
        dlclose(uea_handler);
        exit(0);
    }

#ifdef DEBUG
	if (()pfgetsessionkey == NULL) || (pfquerysessionkey == NULL) {
        SE_TRACE_ERROR("failed to get function interface from uea key exchange library.");
        dlclose(uea_handler);
        exit(0);
	}
#endif

    earetval = pfinit(p_translator);
    if (earetval != SGX_EA_SUCCESS) {
        SE_TRACE_ERROR("fail to call init(), return code is 0x%x.\n", earetval);
        dlclose(uea_handler);
        return -1;
    }

    earetval = pfsetqeidentity(QEIDENTITY_FILENAME);
    if (earetval != SGX_EA_SUCCESS) {
        SE_TRACE_ERROR("fail to set QE Identity, return code is 0x%x.\n", earetval);
        dlclose(uea_handler);
        return -1;
    }

    earetval = pfcreateasession();
    if (earetval != SGX_EA_SUCCESS) {
        printf("fail to call create_session(), return code is 0x%x.\n", earetval);
        dlclose(uea_handler);
        return -1;
    }

    SE_TRACE_NOTICE("succeed to create session.\n");

#ifdef DEBUG
    sgx_aes_gcm_128bit_key_t key;

    earetval = pfgetsessionkey(&key);
    if (earetval != SGX_EA_SUCCESS) {
        printf("fail to get session key, return code is 0x%x.\n", earetval);
        dlclose(uea_handler);
        return -1;
    }
    
    {
        uint8_t * pmk;

        printf("mk:\n");
        pmk = (uint8_t *)&key;
        for (int i = 0; i < (int)sizeof(key); i++, pmk++) {
            printf("0x%02x ", *pmk);
        }

        printf("\n");
    }
   
    pfquerysessionkey();
#endif

	const char * message = "Hello, this is SGX Mutual Enclave Attestation library!";
    
    earetval = pfsendmsg((uint8_t *)message, (uint32_t)strlen(message));
    if (earetval != SGX_EA_SUCCESS) {
        printf("failed to send message, return code is 0x%04x.\n", earetval);
        dlclose(uea_handler);
        return -1;
    }

	printf("Message sent to responder.\n");
    uint8_t *p_recvmsg;
    uint32_t recvmsgsize;

    earetval = pfrecvmsg(&p_recvmsg, &recvmsgsize);
    if (earetval != SGX_EA_SUCCESS) {
        printf("failed to receive message, return code 0x%04x.\n", earetval);
        dlclose(uea_handler);
        return -1;
    }

    if ((recvmsgsize != (uint32_t)strlen(message)) 
        || (memcmp(p_recvmsg, message, (uint32_t)strlen(message)) != 0)) {
        printf("received message doesn't match with sent message.\n");
    } else
    {
        printf("received message match with sent message.\n");
    }
    
    delete[] p_recvmsg;   

	earetval = pfclosesession();
	if (earetval != SGX_EA_SUCCESS) {
		printf("failed to close secure session, return code 0x%04x.\n", earetval);
		dlclose(uea_handler);
		return -1;		
	}

	printf("session closed.\n");
    dlclose(uea_handler);

    return 0;
}
