Intel(R) SGX Enclave Mutual Attestation Library for confidential computing in distributed environment.
=====================================================================
This library aims to provide a reference design in which two enclaves running in different physical machines can mutually attest each other and establish secure channel. In distributed environment, users are more and more interested with how to guarantee data confidentiality and privacy when they leverages cloud computing infra. E.g., an organization who owns confidential data would like to use a commercial cloud computing provider while they have concern to leak their data, internet users don't like their browse records are recorded or analyzed by some third-party orgnazation, who are interested to deduce user behaviour and make money for this. Some technology have been provided to address such problems, e.g. classical SSL/TLS protocal can be used to establish secure session between client browser and service provider. However, there are some known limitations, mainly because there is no trusted execution environment (TEE) which can protect data in use. 
Intel(R) SGX provides a good TEE solution with remote attestation support, it can be used to establish secure session without leaking any user identity and provides isoloated execution environment to process user's data. Intel(R) SGX SDK and DCAP SW stack provides remote attesation primitive, it also provides key exchange library based on SGX Quote verification. However, Intel(R) SGX SDK's key exchange library doesn't provides full reference for peer-to-peer key exchange. E.g., it only provides library for initiator use, it doesn't provides library for responder user; Intel(R) SGX key exchange library doesn't provide reference how to verify quote. Intel(R) SGX SDK provides a remote attesation sample project, it includes service provider simulation which looks too simple to provide value reference.
This library aims to provide a turn-key reference to establish secure channel between two SGX applications running in diffent host machines in internet. We consider below principle when design this library:
a. This solution guaratees CIA (Confidentiality/Integrity/Authentity) in secure channel. This is achieved by:
    (1) Designed a key exchange protocal based on ECDH algorithm, the EC key pairs are generated inside enclave with SGXSSL; in untrusted part, the public are integrity protected;
    (2) SGX ECDSA Quote and Quote verification library (QVL) are used to verify Quote.
    Note: 
    a. Intel SGX Quote attestation provides a way to verify the peer is running in an SGX enclave instance. ISV may still needs to do further verification about peer enclave's attributes, e.g. checking the enclave eversion, checking the enclave's identity with enclave.MRENCLAVE, etc. We demontrate how to do this and user can easily modify the code to implement their own verification logic.
    b. We provides reference how to verify Intel(R) SGX Quote enclave (QE) and SGX Quote verification enclave (QVE)'s identity. Intel would release new version QE and QvE for new feature update or bug fix, with ISVSVN bumped up. Intel publish qeidentity.json and qveidentity.json in Intel(R) Platform Certificate Server (PCS) which corresponds to latest QE and QvE's identity, user can download and use it to verify QE and QvE so they can decide to trust QE generated Quote (and QvE generated verification report) or not. For more details, you can refer to Intel(R) SGX SDK and DCAP documents. 
b. This library aims to wrap implemenation details like secure session establishment and provides user friendly interface. So user just needs to do verfy few lines of code to leverage our implementation in their product.        


Build Instruction
-------
Hardware Pre-requirements:
* SGX capable hardware platform with Intel(R) SGX Flexible Launch Control support. SGX is enabled in BIOS.

Software Pre-requirements:
* To build the project from source code, you need to install Intel(R) SGX SDK, SGX DCAP developer .deb installer (e.g. libsgx-dcap-ql-dev_<version>-bionic1_amd64.deb)
* To execute the demo. application, you need to
*   a. install Intel(R) SGX driver, platform software and Data Center Attestation Primitive (DCAP) SW stack. 
*   b. install and configure SGX PCCS (platform cert caching service).
* Please refer to related SGX documents to know how to do this.

Supported Operation systems:
* Ubuntu 16.04 LTS Desktop 64bits
* Ubuntu 18.04 LTS Desktop 64bits

Build steps:
------
1. in source code root directory, run "make"
2. when build complete, it would generate two output folders:
   "bin" subfolder - includes demo. application 
   "lib" subfolder - include trusted run time library to establish secure session.

Execution steps:
------
You can run demo. application with below stpes:
   a. in "bin" sub-folder, execute "./enclavereresponder"
   b. open a new concole, execute "./enclaveinitiator"

Trusted SGX Enclave Mutual Attestation library
=============================
General Design:
-----
   We provide three trusted runtime library to establish secure channel.
   a. libsgx_tqvl.a
   This is trusted library to verify Intel(R) SGX DCAP Quote Enclave (QE) and Quote Verification Enclave(QvE) identity. The assumption is, enclave attestation initiator and responder needs to generate SGX ECDSA Quote to attest its identity, user enclave needs to verify Intel(R) SGX QE and QvE's identity to protect from attack e.g. hacker roll back QE or QvE to an old version which has security issue.
   b. libsgx_tea_key_exchange_initiator.a
   This is trusted library to establish secure session as attestation initiator role.
   c. libsgx_tea_key_exchange_responder.a
   This is trusted library to establish secure session as attesattion responder role.

Demo application description:
=============================
General Design:
------
   This applicatin demos the library usage. It shows two enclaves running in different physcial machine can create secure session with our provided library. The two enclaves runs classical ECDH algorithm to negociate shared key in runtime. In this process, the two enclave uses Intel(R) SGX ECDSA Quote to attest its identity to peer, it also uses quote to verify peer's identity. These operations are executed in Intel(R) SGX enclave, which provides trusted execution environment to protect the confidentital data like session key. 

Binary Description:
------
Once build is completed, you can find output binary in "bin" subfolder, which includes below files:
   a. enclaveattest_responder
      This application runs as attestation responder, it creates ECDH secure session with one or mulitple initiators. During secure session establishment, it would generate Intel(R) SGX ECDSA Quote with SGX DCAP software stack and send to initiator, so initiator can attest responder's identity; responder would also verify initiator's identity by verifying initiator's SGX ECDSA Quote. This application supports to create multiple secure sessions with different initiators. This application launches an SGX enclave libsgx_uea_key_exchange_responder.so to perform all needed confidential operation, e.g. in ECDH algorim, private key generation and shared key derivation are computed inside enclave.
   b. enclaveattest_initiator
      This application runs as attestation initiator, it creates ECDH secure sesion with responder. It would load an SGX enclave libsgx_uea_key_exchange_initiator.so to perform all needed confidential operation.
   c. easerver.json
      This is configuration of responder's address. In this demo. application, enclave attesation responder and initiator communicates with TCP/IP socket. This configuration is for initiator to specify where is attestation responder, which is specified with "server_ip" and "server_port" field.
   d. qeidentity.json
      This is Intel provided SGX Quote Enclave(QE) identity file, you can download it from Intel(R) Platform Certificate Service (https://api.trustedservices.intel.com/sgx/certification/v2/). During enclave mutual attestation, both initiator and responder would generate Intel(R) SGX ECDSA Quote with SGX DCAP software, it would verify SGX QE's identity against this qeidentity.
      Note: Intel would update this file in PCS server when there is new version QE release, so it's recommended to download latest QEIdentity.json from Intel Server.
   e. qveidentity.json
      This is Intel provided SGX Quote Verification Enclave(QVE) identity file, you can download it Intel(R) PCS server. During enclave mutual attestation, both initiator and responder would generate Intel(R) SGX ECDSA Quote with SGX DCAP software and send to peer, which would use the quote to verify initiator/responder's identity.
   f. libsgx_uea_key_exchange_initiator.so
      This is enclave mutual attestion untrusted runtime library for initiator role. It loads libenclaveinitiator.signed.so, wrapps the ECALL interface and provides interfaces for ISV application (enclaveattest_initiator in this demo application) to create secure session with responder.
   g. libsgx_uea_key_exchange_responder.so
      This is enclave mutual attestation untrusted runtime library for responder role. It loads libenclaveresponder.signed.so, wrapps the ECALL interface and provides interfaces for ISV application (ecnlaveattest_responder in this demo application) to create secure session with initiator.

Runtime Logic Description:
------
The enclave attesation responder application (enclaveattest_responder) would load enclave (libenclaveresponder.so) to act as attesation responder, it lists on a TCP socket for initiator's request and process according to ECDH algorithm; the enclave attestation initiator application (enclaveattest_initiator) would load enclave (libenclaveinitiator.so) to act as attestation initiator. After secure session is established, initiator application sends a message to responder through secure session, reponder received it and decrypt it through secure session. For demonostration purpose, the responder application prints the plaintext so user can see the message are correctly sent to peer.

Contract:
------
If you have any questions or comments, you can send mail to antoniodanhu@gmail.com.