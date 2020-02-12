---
title: Ephemeral Diffie-Hellman Over COSE (EDHOC)
docname: draft-selander-lake-edhoc-latest

ipr: trust200902
cat: std

coding: utf-8
pi: # can use array (if all yes) or hash here
  toc: yes
  sortrefs: yes
  symrefs: yes
  tocdepth: 2

author:
      -
        ins: G. Selander
        name: Göran Selander
        org: Ericsson AB
        email: goran.selander@ericsson.com
      -
        ins: J. Mattsson
        name: John Preuß Mattsson
        org: Ericsson AB
        email: john.mattsson@ericsson.com
      -
        ins: F. Palombini
        name: Francesca Palombini
        org: Ericsson AB
        email: francesca.palombini@ericsson.com

        
normative:

  I-D.ietf-cbor-sequence:
  I-D.ietf-cose-x509:
  I-D.ietf-core-echo-request-tag:
  
  RFC2119:
  RFC5116:
  RFC5869:
  RFC6090:
  RFC6979:
  RFC7252:
  RFC7748:
  RFC7049:
  RFC7959:
  RFC8152:
  RFC8174:
  RFC8610:
  RFC8613:

  SP-800-56A:
    target: https://doi.org/10.6028/NIST.SP.800-56Ar3
    title: Recommendation for Pair-Wise Key-Establishment Schemes Using Discrete Logarithm Cryptography
    seriesinfo:
      "NIST": "Special Publication 800-56A Revision 3"
    author:
      -
        ins: E. Barker
      -
        ins: L. Chen
      -
        ins: A. Roginsky
      -
        ins: A. Vassilev
      -
        ins: R. Davis
    date: April 2018
 
  SIGMA:
    target: http://webee.technion.ac.il/~hugo/sigma-pdf.pdf
    title: SIGMA - The 'SIGn-and-MAc' Approach to Authenticated Diffie-Hellman and Its Use in the IKE-Protocols (Long version)
    author:
      -
        ins: H. Krawczyk
    date: June 2003

informative:

  I-D.hartke-core-e2e-security-reqs:
  I-D.ietf-6tisch-dtsecurity-zerotouch-join:
  I-D.ietf-ace-oauth-authz:
  I-D.ietf-ace-oscore-profile:
  I-D.ietf-core-resource-directory:
  I-D.ietf-lwig-security-protocol-comparison:
  I-D.ietf-tls-dtls13:
  I-D.selander-ace-ake-authz:

  RFC7228:
  RFC7258:
  RFC8446:

  OPTLS:
    target: https://eprint.iacr.org/2015/978.pdf
    title: The OPTLS Protocol and TLS 1.3
    author:
      -
        ins: H. Krawczyk
      -
        ins: H. Wee
    date: October 2015

  LoRa1:
    target: https://www.ncbi.nlm.nih.gov/pmc/articles/PMC6021899/pdf/sensors-18-01833.pdf
    title: Enhancing LoRaWAN Security through a Lightweight and Authenticated Key Management Approach
    author:
      -
        ins: R. Sanchez-Iborra
      -
        ins: J. Sánchez-Gómez
      -
        ins: S. Pérez
      -
        ins: P.J. Fernández
      -
        ins: J. Santa
      -
        ins: J.L. Hernández-Ramos
      -
        ins: A.F. Skarmeta
    date: June 2018

  LoRa2:
    target: https://ants.inf.um.es/~josesanta/doc/GIoTS1.pdf
    title: Internet Access for LoRaWAN Devices Considering Security Issues
    author:
      -
        ins: R. Sanchez-Iborra
      -
        ins: J. Sánchez-Gómez
      -
        ins: S. Pérez
      -
        ins: P.J. Fernández
      -
        ins: J. Santa
      -
        ins: J.L. Hernández-Ramos
      -
        ins: A.F. Skarmeta
    date: June 2018

  Kron18:
    target: https://www.nada.kth.se/~ann/exjobb/alexandros_krontiris.pdf
    title: Evaluation of Certificate Enrollment over Application Layer Security
    author:
      -
        ins: A. Krontiris
    date: May 2018

  SSR18:
    target: https://www.springerprofessional.de/en/formal-verification-of-ephemeral-diffie-hellman-over-cose-edhoc/16284348
    title: Formal Verification of Ephemeral Diffie-Hellman Over COSE (EDHOC)
    author:
      -
        ins: A. Bruni
      -
        ins: T. Sahl Jørgensen
      -
        ins: T. Grønbech Petersen
      -
        ins: C. Schürmann
    date: November 2018

  Perez18:
    target: http://www.anastacia-h2020.eu/publications/Architecture_of_security_association_establishment_based_on_bootstrapping_technologies_for_enabling_critical_IoT_infrastructures.pdf
    title: Architecture of security association establishment based on bootstrapping technologies for enabling critical IoT infrastructures
    author:
      -
        ins: S. Pérez
      -
        ins: D. Garcia-Carrillo
      -
        ins: R. Marín-López
      -
        ins: J. Hernández-Ramos
      -
        ins: R. Marín-Pérez
      -
        ins: A. Skarmeta
    date: October 2018
    
  CborMe:
    target: http://cbor.me/
    title: CBOR Playground
    author:
      -
        ins: C. Bormann
    date: May 2018

--- abstract

This document specifies Ephemeral Diffie-Hellman Over COSE (EDHOC), a very compact, and lightweight authenticated Diffie-Hellman key exchange with ephemeral keys.  EDHOC provides mutual authentication, perfect forward secrecy, and identity protection. EDHOC is intended for usage in constrained scenarios and a main use case is to establish an OSCORE security context. By reusing COSE for cryptography, CBOR for encoding, and CoAP for transport, the additional code footprint can be kept very low.

--- middle

# Introduction

Security at the application layer provides an attractive option for protecting Internet of Things (IoT) deployments, for example where transport layer security is not sufficient {{I-D.hartke-core-e2e-security-reqs}} or where the protection needs to work over a variety of underlying protocols. IoT devices may be constrained in various ways, including memory, storage, processing capacity, and energy {{RFC7228}}. A method for protecting individual messages at the application layer suitable for constrained devices, is provided by CBOR Object Signing and Encryption (COSE) {{RFC8152}}), which builds on the Concise Binary Object Representation (CBOR) {{RFC7049}}. Object Security for Constrained RESTful Environments (OSCORE) {{RFC8613}} is a method for application-layer protection of the Constrained Application Protocol (CoAP), using COSE. 

In order for a communication session to provide forward secrecy, the communicating parties can run an Elliptic Curve Diffie-Hellman (ECDH) key exchange protocol with ephemeral keys, from which shared key material can be derived. This document specifies Ephemeral Diffie-Hellman Over COSE (EDHOC), a lightweight key exchange protocol providing perfect forward secrecy and identity protection. Authentication is based on credentials established out of band, e.g. from a trusted third party, such as an Authorization Server as specified by {{I-D.ietf-ace-oauth-authz}}. EDHOC supports authentication using pre-shared keys (PSK), raw public keys (RPK), and public key certificates. After successful completion of the EDHOC protocol, application keys and other application specific data can be derived using the EDHOC-Exporter interface. A main use case for EDHOC is to establish an OSCORE security context. EDHOC uses COSE for cryptography, CBOR for encoding, and CoAP for transport. By reusing existing libraries, the additional code footprint can be kept very low. Note that this document focuses on authentication and key establishment: for integration with authorization of resource access, refer to {{I-D.ietf-ace-oscore-profile}}.

EDHOC is designed to work in highly constrained scenarios making it especially suitable for network technologies such as Cellular IoT, 6TiSCH {{I-D.ietf-6tisch-dtsecurity-zerotouch-join}}, and LoRaWAN {{LoRa1}}{{LoRa2}}. These network technologies are characterized by their low throughput, low power consumption, and small frame sizes. Compared to the DTLS 1.3 handshake {{I-D.ietf-tls-dtls13}} with ECDH and connection ID, the number of bytes in EDHOC + CoAP is around 1/4 when PSK authentication is used and around 1/6 when RPK authentication is used, see {{I-D.ietf-lwig-security-protocol-comparison}}. Typical message sizes for EDHOC with pre-shared keys, raw public keys with static Diffie-Hellman keyss, and two different way to identify X.509 certificates with signature keys are shown in {{fig-sizes}}. 

~~~~~~~~~~~~~~~~~~~~~~~
=====================================================================
               PSK       RPK       x5t     x5chain                  
---------------------------------------------------------------------
message_1       40        38        38        38                     
message_2       45        48       118       108 + Certificate chain 
message_3       11        22        91        81 + Certificate chain 
---------------------------------------------------------------------
Total           96       108       247       227 + Certificate chains
=====================================================================
~~~~~~~~~~~~~~~~~~~~~~~
{: #fig-sizes title="Typical message sizes in bytes" artwork-align="center"}

The ECDH exchange and the key derivation follow {{SIGMA}}, NIST SP-800-56A {{SP-800-56A}}, and HKDF {{RFC5869}}. CBOR {{RFC7049}} and COSE {{RFC8152}} are used to implement these standards. The use of COSE provides crypto agility and enables use of future algorithms and headers designed for constrained IoT.

This document is organized as follows: {{background}} describes how EDHOC builds on SIGMA-I, {{overview}} specifies general properties of EDHOC, including message flow, formatting of the ephemeral public keys, and key derivation, {{asym}} specifies EDHOC with signature key and static Diffie-Hellman key authentication, {{sym}} specifies EDHOC with symmetric key authentication, {{error}} specifies the EDHOC error message, and {{transfer}} describes how EDHOC can be transferred in CoAP and used to establish an OSCORE security context.

## Rationale for EDHOC
 
Many constrained IoT systems today do not use any security at all, and when they do, they often do not follow best practices. One reason is that many current security protocols are not designed with constrained IoT in mind. Constrained IoT systems often deal with personal information, valuable business data, and actuators interacting with the physical world. Not only do such systems need security and privacy, they often need end-to-end protection with source authentication and perfect forward secrecy. EDHOC and OSCORE {{RFC8613}} enables security following current best practices to devices and systems where current security protocols are impractical. 

EDHOC is optimized for small message sizes and can therefore be sent over a small number of radio frames. The message size of a key exchange protocol may have a large impact on the performance of an IoT deployment, especially in constrained environments. For example, in a network bootstrapping setting a large number of devices turned on in a short period of time may result in large latencies caused by parallel key exchanges. Requirements on network formation time in constrained environments can be translated into key exchange overhead. In network technologies with duty cycle, each additional frame significantly increases the latency even if no other devices are transmitting.

Power consumption for wireless devices is highly dependent on message transmission, listening, and reception. For devices that only send a few bytes occasionally, the battery lifetime may be impacted by a heavy key exchange protocol. A key exchange may need to be executed more than once, e.g. due to a device rebooting or for security reasons such as perfect forward secrecy.

EDHOC is adapted to primitives and protocols designed for the Internet of Things: EDHOC is built on CBOR and COSE which enables small message overhead and efficient parsing in constrained devices. EDHOC is not bound to a particular transport layer, but it is recommended to transport the EDHOC message in CoAP payloads. EDHOC is not bound to a particular communication security protocol but works off-the-shelf with OSCORE {{RFC8613}} providing the necessary input parameters with required properties. Maximum code complexity (ROM/Flash) is often a constraint in many devices and by reusing already existing libraries, the additional code footprint for EDHOC + OSCORE can be kept very low.

## Terminology and Requirements Language

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 {{RFC2119}} {{RFC8174}} when, and only when, they appear in all capitals, as shown here.

Readers are expected to be familiar with the terms and concepts described in CBOR {{RFC7049}} {{I-D.ietf-cbor-sequence}}, COSE {{RFC8152}}, and CDDL {{RFC8610}}. The Concise Data Definition Language (CDDL) is used to express CBOR data structures {{RFC7049}}. Examples of CBOR and CDDL are provided in {{CBOR}}.

# Background {#background}

SIGMA (SIGn-and-MAc) is a family of theoretical protocols with a large number of variants {{SIGMA}}. Like IKEv2 and (D)TLS 1.3 {{RFC8446}}, EDHOC is built on a variant of the SIGMA protocol which provide identity protection of the initiator (SIGMA-I), and like (D)TLS 1.3, EDHOC implements the SIGMA-I variant as Sign-then-MAC. The SIGMA-I protocol using an authenticated encryption algorithm is shown in {{fig-sigma}}.

~~~~~~~~~~~
Initiator                                               Responder
   |                          G_X                            |
   +-------------------------------------------------------->|
   |                                                         |
   |  G_Y, AEAD( K_2; ID_CRED_R, Sig(R; CRED_R, G_X, G_Y) )  |
   |<--------------------------------------------------------+
   |                                                         |
   |     AEAD( K_3; ID_CRED_I, Sig(I; CRED_I, G_Y, G_X) )    |
   +-------------------------------------------------------->|
   |                                                         |
~~~~~~~~~~~
{: #fig-sigma title="Authenticated encryption variant of the SIGMA-I protocol."}
{: artwork-align="center"}

The parties exchanging messages are called Initiator (I) and Responder (R). They exchange ephemeral public keys, compute the shared secret, and derive symmetric application keys. 

* G_X and G_Y are the ECDH ephemeral public keys of I and R, respectively.

* CRED_I and CRED_R are the credentials containing the public authentication keys of I and R, respectively.

* ID_CRED_I and ID_CRED_R are data enabling the recipient party to retrieve the credential of I and R, respectively.

* Sig(I; . ) and S(R; . ) denote signatures made with the private authentication key of I and R, respectively.

* AEAD(K; . ) denotes authenticated encryption with additional data using a key K derived from the shared secret.

In order to create a "full-fledged" protocol some additional protocol elements are needed. EDHOC adds:

* Explicit connection identifiers C_I, C_R chosen by I and R, respectively, enabling the recipient to find the protocol state.

* Transcript hashes (hashes of message data) TH_2, TH_3, TH_4 used for key derivation and as additional authenticated data.

* Computationally independent keys derived from the ECDH shared secret and used for authenticated encryption of different messages.

* Verification of a common preferred cipher suite:

   * The Initiator lists supported cipher suites in order of preference
   
   * The Responder verifies that the selected cipher suite is the first supported cipher suite

* Method types and error handling.

* Transport of opaque auxiliary data.

EDHOC is designed to encrypt and integrity protect as much information as possible, and all symmetric keys are derived using as much previous information as possible. EDHOC is furthermore designed to be as compact and lightweight as possible, in terms of message sizes, processing, and the ability to reuse already existing CBOR, COSE, and CoAP libraries.

To simplify for implementors, the use of CBOR in EDHOC is summarized in {{CBORandCOSE}} and test vectors including CBOR diagnostic notation are given in {{vectors}}.

# EDHOC Overview {#overview}

EDHOC consists of three messages (message_1, message_2, message_3) that maps directly to the three messages in SIGMA-I, plus an EDHOC error message. EDHOC messages are CBOR Sequences {{I-D.ietf-cbor-sequence}}, where the first data item (METHOD_CORR) of message_1 is an int specifying the method and the correlation properties of the transport used, see {{transport}}. The method specifies the authentication methods used (signature, static DH, symmetric), see {{method-types}}. An implementation may support only Initiator or Responder. An implementation may support only a single method. The Initiator and the Responder need to have agreed on a single method to be used for EDHOC.

While EDHOC uses the COSE_Key, COSE_Sign1, and COSE_Encrypt0 structures, only a subset of the parameters is included in the EDHOC messages. The unprotected COSE header in COSE_Sign1, and COSE_Encrypt0 (not included in the EDHOC message) MAY contain parameters (e.g. 'alg'). After creating EDHOC message_3, the Initiator can derive symmetric application keys, and application protected data can therefore be sent in parallel with EDHOC message_3. The application may protect data using the algorithms (AEAD, HMAC, etc.) in the selected cipher suite  and the connection identifiers (C_I, C_R). EDHOC may be used with the media type application/edhoc defined in {{iana}}.

~~~~~~~~~~~
Initiator                                             Responder
   |                                                       |
   | ------------------ EDHOC message_1 -----------------> |
   |                                                       |
   | <----------------- EDHOC message_2 ------------------ |
   |                                                       |
   | ------------------ EDHOC message_3 -----------------> |
   |                                                       |
   | <----------- Application Protected Data ------------> |
   |                                                       |
~~~~~~~~~~~
{: #fig-flow title="EDHOC message flow"}
{: artwork-align="center"}

## Transport and Message Correlation {#transport}

Cryptographically, EDHOC does not put requirements on the lower layers. EDHOC is not bound to a particular transport layer, and can be used in environments without IP. The transport is responsible to handle message loss, reordering, message duplication, fragmentation, and denial of service protection, where necessary. The Initiator and the Responder need to have agreed on a transport to be used for EDHOC. It is recommended to transport EDHOC in CoAP payloads, see {{transfer}}.

EDHOC includes connection identifiers (C_I, C_R) to correlate messages. The connection identifiers C_I and C_R do not have any cryptographic purpose in EDHOC. They contain information facilitating retrieval of the protocol state and may therefore be very short. The connection identifier MAY be used with an application protocol (e.g. OSCORE) for which EDHOC establishes keys, in which case the connection identifiers SHALL adhere to the requirements for that protocol. Each party choses a connection identifier it desires the other party to use in outgoing messages.

If the transport provides a mechanism for correlating messages, some of the connection identifiers may be omitted. There are four cases:

   * corr = 0, the transport does not provide a correlation mechanism.

   * corr = 1, the transport provides a correlation mechanism that enables the Responder to correlate message_2 and message_1.

   * corr = 2, the transport provides a correlation mechanism that enables the Initiator to correlate message_3 and message_2.

   * corr = 3, the transport provides a correlation mechanism that enables both parties to correlate all three messages.

For example, if the key exchange is transported over CoAP, the CoAP Token can be used to correlate messages, see {{coap}}.

## Authentication Keys and Identities

The EDHOC message exchange may be authenticated using pre-shared keys (PSK), raw public keys (RPK), or public key certificates. The certificates and RPKs can contain signature keys or static Diffie-Hellman keys. EDHOC assumes the existence of mechanisms (certification authority, trusted third party, manual distribution, etc.) for distributing authentication keys (public or pre-shared) and identities. Policies are set based on the identity of the other party, and parties typically only allow connections from a small restricted set of identities.

* When a Public Key Infrastructure (PKI) is used, the trust anchor is a Certification Authority (CA) certificate, and the identity is the subject whose unique name (e.g. a domain name, NAI, or EUI) is included in the other party's certificate. Before running EDHOC each party needs at least one CA public key certificate, or just the public key, and a set of identities it is allowed to communicate with. Any validated public-key certificate with an allowed subject name is accepted. EDHOC provides proof that the other party possesses the private authentication key corresponding to the public authentication key in its certificate. The certification path provides proof that the subject of the certificate owns the public key in the certificate.

* When public keys are used but not with a PKI (RPK, self-signed certificate), the trust anchor is the public authentication key of the other party. In this case, the identity is typically directly associated to the public authentication key of the other party. For example, the name of the subject may be a canonical representation of the public key. Alternatively, if identities can be expressed in the form of unique subject names assigned to public keys, then a binding to identity can be achieved by including both public key and associated subject name in the protocol message computation: CRED_I or CRED_R may be a self-signed certificate or COSE_Key containing the public authentication key and the subject name, see {{fig-sigma}}. Before running EDHOC, each party need a set of public authentication keys/unique associated subject names it is allowed to communicate with.  EDHOC provides proof that the other party possesses the private authentication key corresponding to the public authentication key. 


* TODO: PSK

## Identifiers

One byte connection and credential identifiers are realistic in many scenarios as most constrained devices only have a few keys and connections. In cases where a node only has one connection or key, the identifiers may even be the empty byte string. 

## Cipher Suites {#cs}

EDHOC cipher suites consist of an ordered set of COSE algorithms: an EDHOC AEAD algorithm, an EDHOC HMAC algorithm, an EDHOC ECDH curve, an EDHOC signature algorithm, an EDHOC signature algorithm curve, an application AEAD algorithm, and an application HMAC algorithm from the COSE Algorithms and Elliptic Curves registries. Each cipher suite is identified with a pre-defined int label. This document specifies four pre-defined cipher suites.

~~~~~~~~~~~
   0. ( 10, 5, 4, -8, 6, 10, 5 )
      (AES-CCM-16-64-128, HMAC 256/256, X25519, EdDSA, Ed25519,
       AES-CCM-16-64-128, HMAC 256/256)

   1. ( 30, 5, 4, -8, 6, 10, 5 )
      (AES-CCM-16-128-128, HMAC 256/256, X25519, EdDSA, Ed25519,
       AES-CCM-16-64-128, HMAC 256/256)

   2. ( 10, 5, 1, -7, 1, 10, 5 )
      (AES-CCM-16-64-128, HMAC 256/256, P-256, ES256, P-256,
       AES-CCM-16-64-128, HMAC 256/256)

   3. ( 30, 5, 1, -7, 1, 10, 5 )
      (AES-CCM-16-128-128, HMAC 256/256, P-256, ES256, P-256,
       AES-CCM-16-64-128, HMAC 256/256)
~~~~~~~~~~~

The different methods use the same cipher suites, but some algorithms are not used in some methods. The EDHOC signature algorithm and the EDHOC signature algorithm curve are not used is methods without signature authentication.

The Initiator need to have a list of cipher suites it supports in order of decreasing preference. The Responder need to have a list of cipher suites it supports.

## Communication/Negotiation of Protocol Features

EDHOC allows the communication or negotiation of various protocol features during the execution of the protocol.

* The Initiator proposes a cipher suite (see {{cs}}), and the Responder either accepts or rejects, and may make a counter proposal. 

* The Initiator decides on the correlation parameter corr (see {{transport}}). This is typically given by the transport which the Initiator and the Responder have agreed on beforehand. The Responder either accepts or rejects.

* The Initiator decides on the method parameter, see {{method-types}}. The Responder either accepts or rejects.

TODO: Do we want to enable parties negotiating public key method?

* The Initiator and the Responder decide on the representation of the identifier of their respective credentials, ID_CRED_I and ID_CRED_R. The decision is reflected by the label used in the CBOR map, see for example {{asym-overview}}.

TODO: Do we want to enable parties to communicate that they already have or have not access to key or certificate of the other? 

## Auxiliary Data

In order to reduce round trips and number of messages, and in some cases also streamline processing, certain security applications may be integrated into EDHOC by transporting auxiliary data together with the messages. One example is the transport of third-party authorization information protected outside of EDHOC {{I-D.selander-ace-ake-authz}}. Another example is the embedding of a certificate enrolment request or a newly issued certificate.

EDHOC allows opaque auxiliary data (AD) to be sent in the EDHOC messages. Unprotected Auxiliary Data (AD_1, AD_2) may be sent in message_1 and message_2, respectively. Protected Auxiliary Data (AD_3) may be sent in message_3.

Since data carried in AD1 and AD2 may not be protected, and the content of AD3 is available to both the Initiator and the Responder, special considerations need to be made such that the availability of the data a) does not violate security and privacy requirements of the service which uses this data, and b) does not violate the security properties of EDHOC.

## Ephemeral Public Keys {#cose_key}
   
The ECDH ephemeral public keys are formatted as a COSE_Key of type EC2 or OKP according to Sections 13.1 and 13.2 of {{RFC8152}}, but only the 'x' parameter is included in the EDHOC messages. For Elliptic Curve Keys of type EC2, compact representation as per {{RFC6090}} MAY be used also in the COSE_Key. If the COSE implementation requires an 'y' parameter, any of the possible values of the y-coordinate can be used, see Appendix C of {{RFC6090}}. COSE {{RFC8152}} always use compact output for Elliptic Curve Keys of type EC2.

## Key Derivation {#key-der}

Derivation of key and IV used with the AEAD functions SHALL be performed with HKDF {{RFC5869}} following the specification in Section 11 of {{RFC8152}} using a pseudorandom key (PRK) and the HMAC algorithm in the selected cipher suite. The PRKs are derived using HKDF-Extract {{RFC5869}}.

~~~~~~~~~~~~~~~~~~~~~~~
   PRK = HKDF-Extract( salt, IKM )
~~~~~~~~~~~~~~~~~~~~~~~

PRK_2 and PRK_3 are used to derive keys and IVs for message_2 and message_3 respectively. PRK_4 is used to derive application specific data. PRK_I and PRK_R are used to derive additional keys and IVs in case of static Diffie-Hellmann authentication of Initator and Responder respectively.

PRK_2 is derived with the following input:

* The salt SHALL be the PSK when EDHOC is authenticated with symmetric keys, and the empty byte string when EDHOC is authenticated with asymmetric keys (signature or static DH). The PSK is used as 'salt' to simplify implementation. Note that {{RFC5869}} specifies that if the salt is not provided, it is set to a string of zeros (see Section 2.2 of {{RFC5869}}). For implementation purposes, not providing the salt is the same as setting the salt to the empty byte string. 

* The input keying material (IKM) SHALL be the ECDH shared secret G_XY (calculated from G_X and Y or G_Y and X) as defined in Section 12.4.1 of {{RFC8152}}.

Example: Assuming the use of HMAC 256/256 the extract phase of HKDF produces PRK_2 as follows:

~~~~~~~~~~~~~~~~~~~~~~~
   PRK_2 = HMAC-SHA-256( salt, G_XY )
~~~~~~~~~~~~~~~~~~~~~~~

where salt = 0x (the empty byte string) in the asymmetric case and salt = PSK in the symmetric case.

The pseudorandom keys PRK_R, PRK_3, PRK_I, and PRK_4 are defined as follow:

* PRK_R is derived as PRK_R = HKDF-Extract( PRK_2, G_RX ), where G_RX is the ECDH shared secret calculated from G_R and X, or G_X and R.

* If PRK_R has been derived, i.e. static DH authentication of the Responder, then PRK_3 = PRK_R, else PRK_3 = PRK_2

* PRK_I is derived as PRK_I = HKDF-Extract( PRK_3, G_IY ), where G_IY is the ECDH shared secret calculated from G_I and Y, or G_Y and I.

* If PRK_I has been derived, i.e. static DH authentication of the Responder, then PRK_4 = PRK_I, else PRK_4 = PRK_3

This construction allows a common definition of PRKs also in the case of static DH methods, which requires additional keys and IVs.

Example: Assuming the use of curve25519, the ECDH shared secrets G_XY, G_RX, and G_IY are the outputs of the X25519 function {{RFC7748}}:

~~~~~~~~~~~~~~~~~~~~~~~
   G_XY = X25519( Y, G_X ) = X25519( X, G_Y )
~~~~~~~~~~~~~~~~~~~~~~~

The keys and IVs used in EDHOC are derived from PRK using HKDF-Expand {{RFC5869}}

~~~~~~~~~~~~~~~~~~~~~~~
   OKM = HKDF-Expand( PRK, info, L )
~~~~~~~~~~~~~~~~~~~~~~~

where L is the length of output keying material (OKM) in bytes and info is the CBOR encoding of a COSE_KDF_Context

~~~~~~~~~~~~~~~~~~~~~~~
info = [
  AlgorithmID,
  [ null, null, null ],
  [ null, null, null ],
  [ keyDataLength, h'', other ]
]
~~~~~~~~~~~~~~~~~~~~~~~

where 

  + AlgorithmID is an int or tstr, see below
  
  + keyDataLength is a uint set to the length of output keying material in bits, see below

  + other is a bstr set to one of the transcript hashes TH_2, TH_3, or TH_4 as defined in Sections {{asym-msg2-form}}{: format="counter"}, {{asym-msg3-form}}{: format="counter"}, and {{exporter}}{: format="counter"}.

The keys K_2 and K_R SHALL be derived using the transcript hash TH_2 and the pseudorandom keys PRK_2 and PRK_R respectively. The keys K_3 and K_I SHALL be derived using the transcript hash TH_3 and the pseudorandom keys PRK_3 and PRK_I respectively. The keys SHALL be derived using AlgorithmID set to the integer value of the EDHOC AEAD in the selected cipher suite, and keyDataLength equal to the key length of the EDHOC AEAD.

If the EDHOC AEAD algorithm uses an IV, then IV_2 and IV_R SHALL be derived using the transcript hash TH_2 and pseudorandom keys PRK_2 and PRK_R respectively. IV_3 and IV_I SHALL be derived using the transcript hash TH_3 and pseudorandom keys PRK_3 and PRK_I respectively. The IVs SHALL be derived using AlgorithmID = "IV-GENERATION" as specified in Section 12.1.2. of {{RFC8152}}, and keyDataLength equal to the IV length of the EDHOC AEAD.

Assuming the output OKM length L is smaller than the hash function output size, the expand phase of HKDF consists of a single HMAC invocation

~~~~~~~~~~~~~~~~~~~~~~~
   OKM = first L bytes of HMAC( PRK, info || 0x01 )
~~~~~~~~~~~~~~~~~~~~~~~

where \|\| means byte string concatenation.

Example: Assume the use of the algorithm AES-CCM-16-64-128 and HMAC 256/256, K_i and IV_i are therefore the first 16 and 13 bytes, respectively, of

~~~~~~~~~~~~~~~~~~~~~~~
   HMAC-SHA-256( PRK_i, info || 0x01 )
~~~~~~~~~~~~~~~~~~~~~~~

calculated with (AlgorithmID, keyDataLength) = (10, 128) and (AlgorithmID, keyDataLength) = ("IV-GENERATION", 104), respectively.

### EDHOC-Exporter Interface {#exporter}

Application keys and other application specific data can be derived using the EDHOC-Exporter interface defined as:

~~~~~~~~~~~
   EDHOC-Exporter(label, length) = HKDF-Expand(PRK_4, info, length) 
~~~~~~~~~~~

The output of the EDHOC-Exporter function SHALL be derived using AlgorithmID = label, keyDataLength = 8 * length, and other = TH_4 where label is a tstr defined by the application and length is a uint defined by the application.  The label SHALL be different for each different exporter value. The transcript hash TH_4 is a CBOR encoded bstr and the input to the hash function is a CBOR Sequence.

~~~~~~~~~~~
   TH_4 = H( TH_3, CIPHERTEXT_3 )
~~~~~~~~~~~

where H() is the hash function in the HMAC algorithm. Example use of the EDHOC-Exporter is given in Sections {{chain}}{: format="counter"} and {{oscore}}{: format="counter"}.

### EDHOC PSK Chaining {#chain}

An application using EDHOC may want to derive new PSKs to use for authentication in future EDHOC exchanges.  In this case, the new PSK and the ID_PSK 'kid_value' parameter SHOULD be derived as follows where length is the key length (in bytes) of the EDHOC AEAD Algorithm.

~~~~~~~~~~~~~~~~~~~~~~~
   PSK    = EDHOC-Exporter( "EDHOC Chaining PSK", length )
   ID_PSK = EDHOC-Exporter( "EDHOC Chaining ID_PSK", 4 )
~~~~~~~~~~~~~~~~~~~~~~~

# EDHOC Authenticated with \asymmetric Keys {#asym}

## Overview {#asym-overview}

This section specifies authentication method = 0, 1, 2, and 3, see {{method-types}}. EDHOC supports authentication with signature or static Diffie-Hellman keys in the form of raw public keys (RPK) and public key certificates with the requirements that:

* Only the Responder SHALL have access to the Responder's private authentication key,

* Only the Initiator SHALL have access to the Initiator's private authentication key,

* The Initiator is able to retrieve the Responder's public authentication key using ID_CRED_R,

* The Responder is able to retrieve the Initiator's public authentication key using ID_CRED_I,

where the identifiers ID_CRED_I and ID_CRED_R are COSE header_maps, i.e. CBOR maps containing COSE Common Header Parameters, see Section 3.1 of {{RFC8152}}). ID_CRED_I and ID_CRED_R need to contain parameters that can identify a public authentication key. In the following paragraph we give some examples of possible COSE header parameters used.

Raw public keys are most optimally stored as COSE_Key objects and identified with a 'kid' parameter:

* ID_CRED_x = { 4 : kid_x }, where kid_x : bstr, for x = I or R.

Public key certificates can be identified in different ways. Several header parameters for identifying X.509 certificates are defined in {{I-D.ietf-cose-x509}} (the exact labels are TBD):

* by a hash value with the 'x5t' parameter;

   * ID_CRED_x = { TBD1 : COSE_CertHash }, for x = I or R,

* by a URL with the 'x5u' parameter;

   * ID_CRED_x = { TBD2 : uri }, for x = I or R,

* by a bag of certificates with the 'x5bag' parameter; or

   * ID_CRED_x = { TBD3 : COSE_X509 }, for x = I or R,

* by a certificate chain with the 'x5chain' parameter;

   * ID_CRED_x = { TBD4 : COSE_X509 }, for x = I or R,

In the latter two examples, ID_CRED_I and ID_CRED_R contain the actual credential used for authentication. The purpose of ID_CRED_I and ID_CRED_R is to facilitate retrieval of a public authentication key and when they do not contain the actual credential, they may be very short. It is RECOMMENDED that they uniquely identify the public authentication key as the recipient may otherwise have to try several keys. ID_CRED_I and ID_CRED_R are transported in the ciphertext, see {{asym-msg2-proc}} and {{asym-msg3-proc}}.

The authentication key MUST be a signature key or static Diffie-Hellman key. The Initiator and the Responder
 MAY use different types of authentication keys, e.g. one uses a signature key and the other uses a static Diffie-Hellman key. When using a signature key, the authentication is provided by a signature. When using a static Diffie-Hellman key the authentication is provided by a Message Authentication Code (MAC) computed from an ephemeral-static ECDH shared secret which enables significant reductions in message sizes. The MAC is implemented with an AEAD algorithm, so for static DH there are two applications of authenticated encryption in both messages 2 and 3: the MAC being the "inner" encryption, and the other encryption is called "outer".  When using a static Diffie-Hellman keys the Initiator's and Responder's private authentication keys are called I and R, respectively, and the public authentication keys are called G_I and G_R, respectively.

The actual credentials CRED_I and CRED_R (e.g., a COSE_Key or a single X.509 certificate) are signed or MAC:ed by the Initiator and the Responder respectively, see {{asym-msg3-form}} and {{asym-msg2-form}}. The Initiator and the Responder MAY use different types of credentials, e.g. one uses RPK and the other uses certificate. When included in signature or MAC, COSE_Keys of type OKP SHALL only include the parameters 1 (kty), -1 (crv), and -2 (x-coordinate). COSE_Keys of type EC2 SHALL only include the parameters 1 (kty), -1 (crv), -2 (x-coordinate), and -3 (y-coordinate). The parameters SHALL be encoded in decreasing order.

~~~~~~~~~~~
Initiator                                                   Responder
|               METHOD_CORR, SUITES_I, G_X, C_I, AD_1               |
+------------------------------------------------------------------>|
|                             message_1                             |
|                                                                   |
|    C_I, G_Y, C_R, Enc(K_2; ID_CRED_R, Signature_or_MAC_2, AD_2)   |
|<------------------------------------------------------------------+
|                             message_2                             |
|                                                                   |
|        C_R, AEAD(K_3; ID_CRED_I, Signature_or_MAC_3, AD_3)        |
+------------------------------------------------------------------>|
|                             message_3                             |
~~~~~~~~~~~
{: #fig-asym title="Overview of EDHOC with asymmetric key authentication."}
{: artwork-align="center"}

## EDHOC Message 1

### Formatting of Message 1 {#asym-msg1-form}

message_1 SHALL be a CBOR Sequence (see {{CBOR}}) as defined below

~~~~~~~~~~~ CDDL
message_1 = (
  METHOD_CORR : int,
  SUITES_I : suite / [ index : uint, 2* suite ],
  G_X : bstr,
  C_I : bstr,  
  ? AD_1 : bstr,
)

suite = int
~~~~~~~~~~~

where:

* METHOD_CORR = 4 * method + corr, where method = 0, 1, 2, or 3 (see {{method-types}}) and the correlation parameter corr is chosen based on the transport and determines which connection identifiers that are omitted (see {{transport}}).
* SUITES_I - cipher suites which the Initiator supports in order of decreasing preference. One cipher suite is selected. If a single cipher suite is conveyed then that cipher suite is selected. If multiple cipher suites are conveyed then zero-based index (i.e. 0 for the first suite, 1 for the second suite, etc.) identifies the selected cipher suite out of the array elements listing the cipher suites (see {{error}}).
* G_X - the ephemeral public key of the Initiator
* C_I - variable length connection identifier
* AD_1 - bstr containing unprotected opaque auxiliary data

### Initiator Processing of Message 1

The Initiator SHALL compose message_1 as follows:

* The supported cipher suites and the order of preference MUST NOT be changed based on previous error messages. However, the list SUITES_I sent to the Responder MAY be truncated such that cipher suites which are the least preferred are omitted. The amount of truncation MAY be changed between sessions, e.g. based on previous error messages (see next bullet), but all cipher suites which are more preferred than the least preferred cipher suite in the list MUST be included in the list.

* Determine the cipher suite to use with the Responder in message_1. If the Initiator previously received from the Responder an error message to a message_1 with diagnostic payload identifying a cipher suite that the Initiator supports, then the Initiator SHALL use that cipher suite. Otherwise the first cipher suite in SUITES_I MUST be used.

* Generate an ephemeral ECDH key pair as specified in Section 5 of {{SP-800-56A}} using the curve in the selected cipher suite and format it as a COSE_Key. Let G_X be the 'x' parameter of the COSE_Key.
   
* Choose a connection identifier C_I and store it for the length of the protocol.

* Encode message_1 as a sequence of CBOR encoded data items as specified in {{asym-msg1-form}}

### Responder Processing of Message 1

The Responder SHALL process message_1 as follows:

* Decode message_1 (see {{CBOR}}).

* Verify that the selected cipher suite is supported and that no prior cipher suites in SUITES_I are supported.

* Pass AD_1 to the security application.

If any verification step fails, the Initiator MUST send an EDHOC error message back, formatted as defined in {{error}}, and the protocol MUST be discontinued. If V does not support the selected cipher suite, then SUITES_R MUST include one or more supported cipher suites. If the Responder does not support the selected cipher suite, but supports another cipher suite in SUITES_I, then SUITES_R MUST include the first supported cipher suite in SUITES_I.

## EDHOC Message 2

### Formatting of Message 2 {#asym-msg2-form}

message_2 and data_2 SHALL be CBOR Sequences (see {{CBOR}}) as defined below

~~~~~~~~~~~ CDDL
message_2 = (
  data_2,
  CIPHERTEXT_2 : bstr,
)
~~~~~~~~~~~

~~~~~~~~~~~ CDDL
data_2 = (
  ? C_I : bstr,
  G_Y : bstr,
  C_R : bstr,
)
~~~~~~~~~~~

where:

* G_Y - the ephemeral public key of the Responder
* C_R - variable length connection identifier

### Responder Processing of Message 2 {#asym-msg2-proc}

The Responder SHALL compose message_2 as follows:

* If corr (METHOD_CORR mod 4) equals 1 or 3, C_I is omitted, otherwise C_I is not omitted.

* Generate an ephemeral ECDH key pair as specified in Section 5 of {{SP-800-56A}} using the curve in the selected cipher suite and format it as a COSE_Key. Let G_Y be the 'x' parameter of the COSE_Key.

* Choose a connection identifier C_R and store it for the length of the protocol.

* Compute the transcript hash TH_2 = H(message_1, data_2) where H() is the hash function in the HMAC algorithm. The transcript hash TH_2 is a CBOR encoded bstr and the input to the hash function is a CBOR Sequence.

* Compute an inner COSE_Encrypt0 as defined in Section 5.3 of {{RFC8152}}, with the EDHOC AEAD algorithm in the selected cipher suite and the following parameters:

   * protected =  << ID_CRED_R >>

      * ID_CRED_R - identifier to facilitate retrieval of CRED_R, see {{asym-overview}}

   * external_aad = << TH_2, CRED_R >>

      * CRED_R - bstr containing the credential of the Responder, see {{asym-overview}}. 

   * plaintext = h''

If method equals 0 or 2 (the authentication key is a signature key), then K_2, and IV_2 are used. If method equals 1 or 3 (the authentication key is a static Diffie-Hellman key), then K_R, and IV_R are used. COSE constructs the input to the AEAD {{RFC5116}} as follows: 

   * Key K = K_2 or K_R
   * Nonce N = IV_2 or IV_R
   * Plaintext P = 0x (the empty string)
   * Associated data A =

     \[ "Encrypt0", << ID_CRED_R >>, << TH_2, CRED_R >> \]

* If method equals 1 or 3, then Signature_or_MAC_2 is the 'ciphertext' (CIPHERTEXT_2i) of the inner COSE_Encrypt0. If method equals 0 or 2, then Signature_or_MAC_2 is the 'signature' of a COSE_Sign1 object as defined in Section 4.4 of {{RFC8152}} using the signature algorithm in the selected cipher suite, the private authentication key of the Responder, and the following parameters:

   * protected =  << ID_CRED_R >>

   * external_aad = << TH_2, CRED_R >>

   * payload = CIPHERTEXT_2i

   COSE constructs the input to the Signature Algorithm as:

   * The key is the private authentication key of the Responder.

   * The message M to be signed =

     \[ "Signature1", << ID_CRED_R >>, << TH_2, CRED_R >>, CIPHERTEXT_2i \]

* CIPHERTEXT_2 is the ciphertext resulting from XOR encrypting a plaintext with the following common parameters:

   * plaintext = ( ID_CRED_R / kid_R, Signature_or_MAC_2, ? AD_2 )

      * AD_2 = bstr containing opaque unprotected auxiliary data

      * Note that if ID_CRED_R contains a single 'kid' parameter, i.e., ID_CRED_R = { 4 : kid_R }, only kid_R is conveyed in the plaintext, see {{asym-overview}}.

   * CIPHERTEXT_2 = plaintext XOR K_2o

      * The key K_2o SHALL be derived using the pseudorandom key PRK_2, the transcript hash TH_2, AlgorithmID = "XOR-ENCRYPTION", and keyDataLength equal to the length of the plaintext.
      
* Encode message_2 as a sequence of CBOR encoded data items as specified in {{asym-msg2-form}}.

### Initiator Processing of Message 2

The Initiator SHALL process message_2 as follows:

* Decode message_2 (see {{CBOR}}).

* Retrieve the protocol state using the connection identifier C_I and/or other external information such as the CoAP Token and the 5-tuple.

* Decrypt CIPHERTEXT_2. The decryption process depends on the method, see {{asym-msg2-proc}}.

* Verify that the identity of the Responder is among the allowed identities for this connection.

* Verify Signature_or_MAC_2 using the algorithm in the selected cipher suite. The verification process depends on the method, see {{asym-msg2-proc}}.

* Pass AD_2 to the security application.

If any verification step fails, the Responder MUST send an EDHOC error message back, formatted as defined in {{error}}, and the protocol MUST be discontinued.

## EDHOC Message 3

### Formatting of Message 3 {#asym-msg3-form}

message_3 and data_3 SHALL be CBOR Sequences (see {{CBOR}}) as defined below

~~~~~~~~~~~ CDDL
message_3 = (
  data_3,
  CIPHERTEXT_3 : bstr,
)
~~~~~~~~~~~

~~~~~~~~~~~ CDDL
data_3 = (
  ? C_R : bstr,
)
~~~~~~~~~~~

### Initiator Processing of Message 3 {#asym-msg3-proc}

The Initiator  SHALL compose message_3 as follows:

* If corr (METHOD_CORR mod 4) equals 2 or 3, C_R is omitted, otherwise C_R is not omitted.

* Compute the transcript hash TH_3 = H(TH_2 , CIPHERTEXT_2, data_3) where H() is the hash function in the HMAC algorithm. The transcript hash TH_3 is a CBOR encoded bstr and the input to the hash function is a CBOR Sequence.

* Compute an inner COSE_Encrypt0 as defined in Section 5.3 of {{RFC8152}}, with the EDHOC AEAD algorithm in the selected cipher suite and the following parameters:

   * protected =  << ID_CRED_I >>

      * ID_CRED_I - identifier to facilitate retrieval of CRED_I, see {{asym-overview}}

   * external_aad = << TH_3, CRED_I >>

      * CRED_I - bstr containing the credential of the Initiator, see {{asym-overview}}. 

   * plaintext = h''

If method equals 0 or 1 (the authentication key is a signature key), then K_3, and IV_3 are used. If method equals 2 or 3 (the authentication key is a static Diffie-Hellman key), then K_I, and IV_U are used. COSE constructs the input to the AEAD {{RFC5116}} as follows: 

   * Key K = K_3 or K_I
   * Nonce N = IV_3 or IV_I
   * Plaintext P = 0x (the empty string)
   * Associated data A =

     \[ "Encrypt0", << ID_CRED_I >>, << TH_3, CRED_I >> \]

* If method equals 2 or 3, then Signature_or_MAC_3 is the 'ciphertext' (CIPHERTEXT_3i) of the inner COSE_Encrypt0. If method equals 0 or 1, then Signature_or_MAC_3 is the 'signature' of a COSE_Sign1 object as defined in Section 4.4 of {{RFC8152}} using the signature algorithm in the selected cipher suite, the private authentication key of the Initiator, and the following parameters:

   * protected =  << ID_CRED_I >>

   * external_aad = << TH_3, CRED_I >>

   * payload = CIPHERTEXT_3i

   COSE constructs the input to the Signature Algorithm as:

   * The key is the private authentication key of the Responder.

   * The message M to be signed =

     \[ "Signature1", << ID_CRED_I >>, << TH_3, CRED_I >>, CIPHERTEXT_3i \]

* Compute the outer COSE_Encrypt0 as defined in Section 5.3 of {{RFC8152}}, with the EDHOC AEAD algorithm in the selected cipher suite, K_3o, and IV_3o (TBD) and the parameters below. Note that only 'ciphertext' of the outer COSE_Encrypt0 object is used to create message_3, see next bullet. The protected header SHALL be empty. 

   * external_aad = TH_3

   * plaintext = ( ID_CRED_I / kid_I, Signature_or_MAC_3, ? AD_3 )

      * AD_3 = bstr containing opaque protected auxiliary data

      * Note that if ID_CRED_I contains a single 'kid' parameter, i.e., ID_CRED_I = { 4 : kid_I }, only kid_I is conveyed in the plaintext, see {{asym-overview}}.

   COSE constructs the input to the AEAD {{RFC5116}} as follows: 

   * Key K = K_3o
   * Nonce N = IV_3o
   * Plaintext P = ( ID_CRED_I / kid_I, Signature_or_MAC_3, ? AD_3 )
   * Associated data A = \[ "Encrypt0", h'', TH_3 \]

* Encode message_3 as a sequence of CBOR encoded data items as specified in {{asym-msg3-form}}. CIPHERTEXT_3 is the outer COSE_Encrypt0 ciphertext.

Pass the connection identifiers (C_I, C_R) and the application algorithms in the selected cipher suite to the application. The application can now derive application keys using the EDHOC-Exporter interface.

### Responder Processing of Message 3

The Responder SHALL process message_3 as follows:

* Decode message_3 (see {{CBOR}}).

* Retrieve the protocol state using the connection identifier C_R and/or other external information such as the CoAP Token and the 5-tuple.

* Decrypt and verify the outer COSE_Encrypt0 as defined in Section 5.3 of {{RFC8152}}, with the EDHOC AEAD algorithm in the selected cipher suite, K_3, and IV_3.

* Verify that the identity of the Initiator is among the allowed identities for this connection.

* Verify Signature_or_MAC_3 using the algorithm in the selected cipher suite. The verification process depends on the method, see {{asym-msg3-proc}}.

*  Pass AD_3, the connection identifiers (C_I, C_R), and the application algorithms in the selected cipher suite to the security application. The application can now derive application keys using the EDHOC-Exporter interface.

If any verification step fails, the Responder MUST send an EDHOC error message back, formatted as defined in {{error}}, and the protocol MUST be discontinued.

# EDHOC Authenticated with Symmetric Keys {#sym}

## Overview {#sym-overview}

EDHOC supports authentication with pre-shared keys (authentication method = 4, see {{method-types}}). The Initiator and the Responder are assumed to have a pre-shared key (PSK) with a good amount of randomness and the requirement that:

* Only the Initiator and the Responder SHALL have access to the PSK,

* The Responder is able to retrieve the PSK using ID_PSK.

where the identifier ID_PSK is a COSE header_map (i.e. a CBOR map containing COSE Common Header Parameters, see {{RFC8152}}) containing COSE header parameter that can identify a pre-shared key. Pre-shared keys are typically stored as COSE_Key objects and identified with a 'kid' parameter (see {{RFC8152}}):

* ID_PSK = { 4 : kid_psk } , where kid_psk : bstr

The purpose of ID_PSK is to facilitate retrieval of the PSK and in the case a 'kid' parameter is used it may be very short. It is RECOMMENDED that it uniquely identify the PSK as the recipient may otherwise have to try several keys.

EDHOC with symmetric key authentication is illustrated in {{fig-sym}}. 

~~~~~~~~~~~
Initiator                                                   Responder
|           METHOD_CORR, SUITES_I, G_X, C_I, ID_PSK, AD_1           |
+------------------------------------------------------------------>|
|                             message_1                             |
|                                                                   |
|               C_I, G_Y, C_R, AEAD(K_2; TH_2, AD_2)                |
|<------------------------------------------------------------------+
|                             message_2                             |
|                                                                   |
|                    C_R, AEAD(K_3; TH_3, AD_3)                     |
+------------------------------------------------------------------>|
|                             message_3                             |
~~~~~~~~~~~
{: #fig-sym title="Overview of EDHOC with symmetric key authentication."}
{: artwork-align="center"}

EDHOC with symmetric key authentication is very similar to EDHOC with asymmetric authentication. In the following subsections the differences compared to EDHOC with asymmetric authentication are described.

## EDHOC Message 1

### Formatting of Message 1 {#sym-msg1-form}

message_1 SHALL be a CBOR Sequence (see {{CBOR}}) as defined below

~~~~~~~~~~~ CDDL
message_1 = (
  METHOD_CORR : int,
  SUITES_I : suite / [ index : uint, 2* suite ],
  G_X : bstr,
  C_I : bstr,
  ID_PSK : header_map // kid_psk : bstr,
  ? AD_1 : bstr,
)
~~~~~~~~~~~

where:

* METHOD_CORR = 4 * method + corr, where method = 4 and the connection parameter corr is chosen based on the transport and determines which connection identifiers that are omitted (see {{transport}}).
* ID_PSK - identifier to facilitate retrieval of the pre-shared key. If ID_PSK contains a single 'kid' parameter, i.e., ID_PSK = { 4 : kid_psk }, with kid_psk: bstr, only kid_psk is conveyed.

## EDHOC Message 2

### Processing of Message 2

*  Signature_or_MAC_2 is not used.

* The outer COSE_Encrypt0 is computed as defined in Section 5.3 of {{RFC8152}}, with the EDHOC AEAD algorithm in the selected cipher suite, K_2, IV_2, and the following parameters. The protected header SHALL be empty.

   * plaintext = ? AD_2

      * AD_2 = bstr containing opaque unprotected auxiliary data

   * external_aad = TH_2

   COSE constructs the input to the AEAD {{RFC5116}} as follows: 

   * Key K = K_2
   * Nonce N = IV_2
   * Plaintext P = ? AD_2
   * Associated data A = \[ "Encrypt0", h'', TH_2 \]
      
## EDHOC Message 3

### Processing of Message 3

*  Signature_or_MAC_3 is not used.

* COSE_Encrypt0 is computed as defined in Section 5.3 of {{RFC8152}}, with the EDHOC AEAD algorithm in the selected cipher suite, K_3, IV_3, and the following parameters. The protected header SHALL be empty.

   * plaintext = ? AD_3

      * AD_3 = bstr containing opaque protected auxiliary data

   * external_aad = TH_3

   COSE constructs the input to the AEAD {{RFC5116}} as follows: 

   * Key K = K_3
   * Nonce N = IV_3
   * Plaintext P = ? AD_3
   * Associated data A = \[ "Encrypt0", h'', TH_3 \]

# Error Handling {#error}

## EDHOC Error Message

This section defines a message format for the EDHOC error message, used during the protocol. An EDHOC error message can be sent by both parties as a reply to any non-error EDHOC message. After sending an error message, the protocol MUST be discontinued. Errors at the EDHOC layer are sent as normal successful messages in the lower layers (e.g. CoAP POST and 2.04 Changed). An advantage of using such a construction is to avoid issues created by usage of cross protocol proxies (e.g. UDP to TCP).

error SHALL be a CBOR Sequence (see {{CBOR}}) as defined below

~~~~~~~~~~~ CDDL
error = (
  ? C_x : bstr,
  ERR_MSG : tstr,
  ? SUITES_R : suite / [ 2* suite ],
)
~~~~~~~~~~~

where:

* C_x - if error is sent by the Responder and corr (METHOD_CORR mod 4) equals 0 or 2 then C_x is set to C_I, else if error is sent by the Initiator and corr (METHOD_CORR mod 4) equals 0 or 1 then C_x is set to C_R, else C_x is omitted.
* ERR_MSG - text string containing the diagnostic payload, defined in the same way as in Section 5.5.2 of {{RFC7252}}. ERR_MSG MAY be a 0-length text string.
* SUITES_R - cipher suites from SUITES_I or the EDHOC cipher suites registry that the Responder supports. Note that SUITES_R only contains the values from the EDHOC cipher suites registry and no index. SUITES_R MUST only be included in replies to message_1.

### Example Use of EDHOC Error Message with SUITES_R

Assuming that the Initiator supports the five cipher suites \{5, 6, 7, 8, 9\} in decreasing order of preference, Figures {{fig-error1}}{: format="counter"} and {{fig-error2}}{: format="counter"} show examples of how the Responder can truncate SUITES_I and how SUITES_R is used by the Responder to give the Initiator information about the cipher suites that the Responder supports. In {{fig-error1}}, the Responder supports cipher suite 6 but not the selected cipher suite 5. 

~~~~~~~~~~~
Initiator                                                   Responder
|         METHOD_CORR, SUITES_I {0, 5, 6, 7}, G_X, C_I, AD_1        |
+------------------------------------------------------------------>|
|                             message_1                             |
|                                                                   |
|                     C_I, ERR_MSG, SUITES_R {6}                    |
|<------------------------------------------------------------------+
|                               error                               |
|                                                                   |
|          METHOD_CORR, SUITES_I {1, 5, 6}, G_X, C_I, AD_1          |
+------------------------------------------------------------------>|
|                             message_1                             |
~~~~~~~~~~~
{: #fig-error1 title="Example use of error message with SUITES_R."}
{: artwork-align="center"}

In {{fig-error2}}, the Responder supports cipher suite 7 but not cipher suites 5 and 6.

~~~~~~~~~~~
Initiator                                                   Responder
|          METHOD_CORR, SUITES_I {0, 5, 6}, G_X, C_I, AD_1          |
+------------------------------------------------------------------>|
|                             message_1                             |
|                                                                   |
|                    C_I, ERR_MSG, SUITES_R {7, 9}                  |
|<------------------------------------------------------------------+
|                               error                               |
|                                                                   |
|        METHOD_CORR, SUITES_I {2, 5, 6, 7}, G_X, C_I, AD_1         |
+------------------------------------------------------------------>|
|                             message_1                             |
~~~~~~~~~~~
{: #fig-error2 title="Example use of error message with SUITES_R."}
{: artwork-align="center"}

As the Initiator's list of supported cipher suites and order of preference is fixed, and the Responder only accepts message_1 if the selected cipher suite is the first cipher suite in SUITES_I that the Responder supports, the parties can verify that the selected cipher suite is the most preferred (by the Initiator) cipher suite supported by both parties. If the selected cipher suite is not the first cipher suite in SUITES_I that the Responder supports, the Responder will discontinue the protocol. 

# Transferring EDHOC and Deriving an OSCORE Context {#transfer}

## Transferring EDHOC in CoAP {#coap}

It is recommended to transport EDHOC as an exchange of CoAP {{RFC7252}} messages. CoAP is a reliable transport that can preserve packet ordering and handle message duplication. CoAP can also perform fragmentation and protect against denial of service attacks. It is recommended to carry the EDHOC messages in Confirmable messages, especially if fragmentation is used.

By default, the CoAP client is the Initiator and the CoAP server is the Responder, but the roles SHOULD be chosen to protect the most sensitive identity, see {{security}}. By default, EDHOC is transferred in POST requests and 2.04 (Changed) responses to the Uri-Path: "/.well-known/edhoc", but an application may define its own path that can be discovered e.g. using resource directory {{I-D.ietf-core-resource-directory}}.

By default, the message flow is as follows: EDHOC message_1 is sent in the payload of a POST request from the client to the server's resource for EDHOC. EDHOC message_2 or the EDHOC error message is sent from the server to the client in the payload of a 2.04 (Changed) response. EDHOC message_3 or the EDHOC error message is sent from the client to the server's resource in the payload of a POST request. If needed, an EDHOC error message is sent from the server to the client in the payload of a 2.04 (Changed) response.

An example of a successful EDHOC exchange using CoAP is shown in {{fig-coap1}}. In this case the CoAP Token enables the Initiator to correlate message_1 and message_2 so the correlation parameter corr = 1.

~~~~~~~~~~~~~~~~~~~~~~~
Client    Server
  |          |
  +--------->| Header: POST (Code=0.02)
  |   POST   | Uri-Path: "/.well-known/edhoc"
  |          | Content-Format: application/edhoc
  |          | Payload: EDHOC message_1
  |          |
  |<---------+ Header: 2.04 Changed
  |   2.04   | Content-Format: application/edhoc
  |          | Payload: EDHOC message_2
  |          |
  +--------->| Header: POST (Code=0.02)
  |   POST   | Uri-Path: "/.well-known/edhoc"
  |          | Content-Format: application/edhoc
  |          | Payload: EDHOC message_3
  |          |
  |<---------+ Header: 2.04 Changed
  |   2.04   | 
  |          |
~~~~~~~~~~~~~~~~~~~~~~~
{: #fig-coap1 title="Transferring EDHOC in CoAP"}
{: artwork-align="center"}

The exchange in {{fig-coap1}} protects the client identity against active attackers and the server identity against passive attackers. An alternative exchange that protects the server identity against active attackers and the client identity against passive attackers is shown in {{fig-coap2}}. In this case the CoAP Token enables the Responder to correlate message_2 and message_3 so the correlation parameter corr = 2.

~~~~~~~~~~~~~~~~~~~~~~~
Client    Server
  |          |
  +--------->| Header: POST (Code=0.02)
  |   POST   | Uri-Path: "/.well-known/edhoc"
  |          |
  |<---------+ Header: 2.04 Changed
  |   2.04   | Content-Format: application/edhoc
  |          | Payload: EDHOC message_1
  |          |
  +--------->| Header: POST (Code=0.02)
  |   POST   | Uri-Path: "/.well-known/edhoc"
  |          | Content-Format: application/edhoc
  |          | Payload: EDHOC message_2
  |          |
  |<---------+ Header: 2.04 Changed
  |   2.04   | Content-Format: application/edhoc
  |          | Payload: EDHOC message_3
  |          |
~~~~~~~~~~~~~~~~~~~~~~~
{: #fig-coap2 title="Transferring EDHOC in CoAP"}
{: artwork-align="center"}

To protect against denial-of-service attacks, the CoAP server MAY respond to the first POST request with a 4.01 (Unauthorized) containing an Echo option {{I-D.ietf-core-echo-request-tag}}. This forces the initiator to demonstrate its reachability at its apparent network address. If message fragmentation is needed, the EDHOC messages may be fragmented using the CoAP Block-Wise Transfer mechanism {{RFC7959}}.

### Deriving an OSCORE Context from EDHOC {#oscore}

When EDHOC is used to derive parameters for OSCORE {{RFC8613}}, the parties  make sure that the EDHOC connection identifiers are unique, i.e. C_R MUST NOT be equal to C_I. The CoAP client and server MUST be able to retrieve the OSCORE protocol state using its chosen connection identifier and optionally other information such as the 5-tuple. In case that the CoAP client is the Initiator and the CoAP server is the Responder:

* The client's OSCORE Sender ID is C_R and the server's OSCORE Sender ID is C_I, as defined in this document

* The AEAD Algorithm and the HMAC algorithms are the application AEAD and HMAC algorithms in the selected cipher suite.

* The Master Secret and Master Salt are derived as follows where length is the key length (in bytes) of the application AEAD Algorithm.

~~~~~~~~~~~~~~~~~~~~~~~
   Master Secret = EDHOC-Exporter( "OSCORE Master Secret", length )
   Master Salt   = EDHOC-Exporter( "OSCORE Master Salt", 8 )
~~~~~~~~~~~~~~~~~~~~~~~

# Security Considerations {#security}

## Security Properties

EDHOC inherits its security properties from the theoretical SIGMA-I protocol {{SIGMA}}. Using the terminology from {{SIGMA}}, EDHOC provides perfect forward secrecy, mutual authentication with aliveness, consistency, peer awareness. As described in {{SIGMA}}, peer awareness is provided to the Responder, but not to the Initiator.

When a Public Key Infrastructure (PKI) is used, EDHOC provides identity protection of the Initiator against active attacks and identity protection of the Responder against passive attacks. When PKI is not used (kid, x5t) the identity is not sent on the wire and EDHOC with asymmetric authentication protects the credential identifier of the Initiator against active attacks and the credential identifier of the Responder against passive attacks. The roles should be assigned to protect the most sensitive identity/identifier, typically that which is not possible to infer from routing information in the lower layers. EDHOC with symmetric authentication does not offer protection of the PSK identifier ID_PSK.

Compared to {{SIGMA}}, EDHOC adds an explicit method type and expands the message authentication coverage to additional elements such as algorithms, auxiliary data, and previous messages. This protects against an attacker replaying messages or injecting messages from another session.

EDHOC also adds negotiation of connection identifiers and downgrade protected negotiation of cryptographic parameters, i.e. an attacker cannot affect the negotiated parameters. A single session of EDHOC does not include negotiation of cipher suites, but it enables the Responder to verify that the selected cipher suite is the most preferred cipher suite by the Initiator which is supported by both the Initiator and the Responder.

As required by {{RFC7258}}, IETF protocols need to mitigate pervasive monitoring when possible. One way to mitigate pervasive monitoring is to use a key exchange that provides perfect forward secrecy. EDHOC therefore only supports methods with perfect forward secrecy. To limit the effect of breaches, it is important to limit the use of symmetrical group keys for bootstrapping. EDHOC therefore strives to make the additional cost of using raw public keys and self-signed certificates as small as possible. Raw public keys and self-signed certificates are not a replacement for a public key infrastructure, but SHOULD be used instead of symmetrical group keys for bootstrapping.

Compromise of the long-term keys (PSK or private authentication keys) does not compromise the security of completed EDHOC exchanges. Compromising the private authentication keys of one party lets an active attacker impersonate that compromised party in EDHOC exchanges with other parties, but does not let the attacker impersonate other parties in EDHOC exchanges with the compromised party. Compromising the PSK lets an active attacker impersonate the Initiator in EDHOC exchanges with the Responder and impersonate the Responder in EDHOC exchanges with the Initiator. Compromise of the long-term keys does not enable a passive attacker to compromise future session keys. Compromise of the HDKF input parameters (ECDH shared secret and/or PSK) leads to compromise of all session keys derived from that compromised shared secret. Compromise of one session key does not compromise other session keys.

Key compromise impersonation (KCI): In EDHOC authenticated with signature keys, EDHOC provides KCI protection against an attacker having access to the long term key or the ephemeral secret key. In EDHOC authenticated with symmetric keys, EDHOC provides KCI protection against an attacker having access to the ephemeral secret key, but not against an attacker having access to the long-term PSK. With static Diffie-Hellman key authentication, KCI protection would be provided against an attacker having access to the long-term Diffie-Hellman key, but not to an attacker having access to the ephemeral secret key. Note that the term KCI has typically been used for compromise of long-term keys, and that an attacker with access to the ephemeral secret key can only attack that specific protocol run.

Repudiation: In EDHOC authenticated with signature keys, Party U could theoretically prove that Party V performed a run of the protocol by presenting the private ephemeral key, and vice versa. Note that storing the private ephemeral keys violates the protocol requirements. With static Diffie-Hellman key authentication or PSK authentication, both parties can always deny having participated in the protocol.

## Cryptographic Considerations
The security of the SIGMA protocol requires the MAC to be bound to the identity of the signer. Hence the message authenticating functionality of the authenticated encryption in EDHOC is critical: authenticated encryption MUST NOT be replaced by plain encryption only, even if authentication is provided at another level or through a different mechanism. EDHOC implements SIGMA-I using the same Sign-then-MAC approach as TLS 1.3.

To reduce message overhead EDHOC does not use explicit nonces and instead rely on the ephemeral public keys to provide randomness to each session. A good amount of randomness is important for the key generation, to provide liveness, and to protect against interleaving attacks. For this reason, the ephemeral keys MUST NOT be reused, and both parties SHALL generate fresh random ephemeral key pairs. 

The choice of key length used in the different algorithms needs to be harmonized, so that a sufficient security level is maintained for certificates, EDHOC, and the protection of application data. The Initiator and the Responder should enforce a minimum security level.

The data rates in many IoT deployments are very limited. Given that the application keys are protected as well as the long-term authentication keys they can often be used for years or even decades before the cryptographic limits are reached. If the application keys established through EDHOC need to be renewed, the communicating parties can derive application keys with other labels or run EDHOC again.

## Cipher Suites

Cipher suite number 0 (AES-CCM-16-64-128, HMAC 256/256, X25519, EdDSA, Ed25519, AES-CCM-16-64-128, HMAC 256/256) is mandatory to implement. Implementations only need to implement the algorithms needed for their supported methods. For many constrained IoT devices it is problematic to support more than one cipher suites, so some deployments with P-256 may not support the mandatory cipher suite. This is not a problem for local deployments.

The HMAC algorithm HMAC 256/64 (HMAC w/ SHA-256 truncated to 64 bits) SHALL NOT be supported for use in EDHOC.

## Unprotected Data

The Initiator and the Responder must make sure that unprotected data and metadata do not reveal any sensitive information. This also applies for encrypted data sent to an unauthenticated party. In particular, it applies to AD_1, ID_CRED_R, AD_2, and ERR_MSG in the asymmetric case, and ID_PSK, AD_1, and ERR_MSG in the symmetric case. Using the same ID_PSK or AD_1 in several EDHOC sessions allows passive eavesdroppers to correlate the different sessions. The communicating parties may therefore anonymize ID_PSK. Another consideration is that the list of supported cipher suites may be used to identify the application.

The Initiator and the Responder must also make sure that unauthenticated data does not trigger any harmful actions. In particular, this applies to AD_1 and ERR_MSG in the asymmetric case, and ID_PSK, AD_1, and ERR_MSG in the symmetric case.

## Denial-of-Service

EDHOC itself does not provide countermeasures against Denial-of-Service attacks. By sending a number of new or replayed message_1 an attacker may cause the Responder to allocate state, perform cryptographic operations, and amplify messages. To mitigate such attacks, an implementation SHOULD rely on lower layer mechanisms such as the Echo option in CoAP {{I-D.ietf-core-echo-request-tag}} that forces the initiator to demonstrate reachability at its apparent network address.

## Implementation Considerations

The availability of a secure pseudorandom number generator and truly random seeds are essential for the security of EDHOC. If no true random number generator is available, a truly random seed must be provided from an external source. As each pseudorandom number must only be used once, an implementation need to get a new truly random seed after reboot, or continuously store state in nonvolatile memory, see ({{RFC8613}}, Appendix B.1.1) for issues and solution approaches for writing to nonvolatile memory. If ECDSA is supported, "deterministic ECDSA" as specified in {{RFC6979}} is RECOMMENDED.

The referenced processing instructions in {{SP-800-56A}} must be complied with, including deleting the intermediate computed values along with any ephemeral ECDH secrets after the key derivation is completed. The ECDH shared secret, keys (K_2, K_3), and IVs (IV_2, IV_3) MUST be secret. Implementations should provide countermeasures to side-channel attacks such as timing attacks. Depending on the selected curve, the parties should perform various validations of each other's public keys, see e.g. Section 5 of {{SP-800-56A}}.

The Initiator and the Responder are responsible for verifying the integrity of certificates. The selection of trusted CAs should be done very carefully and certificate revocation should be supported. The private authentication keys and the PSK (even though it is used as salt) MUST be kept secret.

The Initiator and the Responder are allowed to select the connection identifiers C_I and C_R, respectively, for the other party to use in the ongoing EDHOC protocol as well as in a subsequent application protocol (e.g. OSCORE {{RFC8613}}). The choice of connection identifier is not security critical in EDHOC but intended to simplify the retrieval of the right security context in combination with using short identifiers. If the wrong connection identifier of the other party is used in a protocol message it will result in the receiving party not being able to retrieve a security context (which will terminate the protocol) or retrieve the wrong security context (which also terminates the protocol as the message cannot be verified).

The Responder MUST finish the verification step of message_3 before passing AD_3 to the application.

If two nodes unintentionally initiate two simultaneous EDHOC message exchanges with each other even if they only want to complete a single EDHOC message exchange, they MAY terminate the exchange with the lexicographically smallest G_X. If the two G_X values are equal, the received message_1 MUST be discarded to mitigate reflection attacks. Note that in the case of two simultaneous EDHOC exchanges where the nodes only complete one and where the nodes have different preferred cipher suites, an attacker can affect which of the two nodes’ preferred cipher suites will be used by blocking the other exchange.

## Other Documents Referencing EDHOC

EDHOC has been analyzed in several other documents. A formal verification of EDHOC was done in {{SSR18}}, an analysis of EDHOC for certificate enrollment was done in {{Kron18}}, the use of EDHOC in LoRaWAN is analyzed in {{LoRa1}} and {{LoRa2}}, the use of EDHOC in IoT bootstrapping is analyzed in {{Perez18}}, and the use of EDHOC in 6TiSCH is described in {{I-D.ietf-6tisch-dtsecurity-zerotouch-join}}. 

# IANA Considerations {#iana}

## EDHOC Cipher Suites Registry

IANA has created a new registry titled "EDHOC Cipher Suites" under the new heading "EDHOC". The registration procedure is "Expert Review". The columns of the registry are Value, Array, Description, and Reference, where Value is an integer and the other columns are text strings. The initial contents of the registry are:

~~~~~~~~~~~~~~~~~~~~~~~
Value: -24
Algorithms: N/A
Desc: Reserved for Private Use
Reference: [[this document]]
~~~~~~~~~~~~~~~~~~~~~~~

~~~~~~~~~~~~~~~~~~~~~~~
Value: -23
Algorithms: N/A
Desc: Reserved for Private Use
Reference: [[this document]]
~~~~~~~~~~~~~~~~~~~~~~~

~~~~~~~~~~~~~~~~~~~~~~~
Value: 0
Array: 10, 5, 4, -8, 6, 10, 5
Desc: AES-CCM-16-64-128, HMAC 256/256, X25519, EdDSA, Ed25519,
      AES-CCM-16-64-128, HMAC 256/256
Reference: [[this document]]
~~~~~~~~~~~~~~~~~~~~~~~

~~~~~~~~~~~~~~~~~~~~~~~
Value: 1
Array: 30, 5, 4, -8, 6, 10, 5
Desc: AES-CCM-16-128-128, HMAC 256/256, X25519, EdDSA, Ed25519,
      AES-CCM-16-64-128, HMAC 256/256
Reference: [[this document]]
~~~~~~~~~~~~~~~~~~~~~~~

~~~~~~~~~~~~~~~~~~~~~~~
Value: 2
Array: 10, 5, 1, -7, 1, 10, 5
Desc: AES-CCM-16-64-128, HMAC 256/256, P-256, ES256, P-256,
      AES-CCM-16-64-128, HMAC 256/256
Reference: [[this document]]
~~~~~~~~~~~~~~~~~~~~~~~

~~~~~~~~~~~~~~~~~~~~~~~
Value: 3
Array: 30, 5, 1, -7, 1, 10, 5
Desc: AES-CCM-16-128-128, HMAC 256/256, P-256, ES256, P-256,
      AES-CCM-16-64-128, HMAC 256/256
Reference: [[this document]]
~~~~~~~~~~~~~~~~~~~~~~~

## EDHOC Method Type Registry {#method-types}

IANA has created a new registry titled "EDHOC Method Type" under the new heading "EDHOC". The registration procedure is "Expert Review". The columns of the registry are Value, Description, and Reference, where Value is an integer and the other columns are text strings. The initial contents of the registry are:

~~~~~~~~~~~
+-------+-------------------+-------------------+-------------------+
| Value | Initiator         | Responder         | Reference         |
+-------+-------------------+-------------------+-------------------+
|     0 | Signature Key     | Signature Key     | [[this document]] |
|     1 | Signature Key     | Static DH Key     | [[this document]] |
|     2 | Static DH Key     | Signature Key     | [[this document]] |
|     3 | Static DH Key     | Static DH Key     | [[this document]] |
|     4 | PSK               | PSK               | [[this document]] |
+-------+-------------------+-------------------+-------------------+
~~~~~~~~~~~
{: #fig-method-types title="Method Types"}
{: artwork-align="center"}

## The Well-Known URI Registry

IANA has added the well-known URI 'edhoc' to the Well-Known URIs registry.

- URI suffix: edhoc

- Change controller: IETF

- Specification document(s): \[\[this document\]\]

- Related information: None

## Media Types Registry

IANA has added the media type 'application/edhoc' to the Media Types registry.

- Type name: application

- Subtype name: edhoc

- Required parameters: N/A

- Optional parameters: N/A

- Encoding considerations: binary

- Security considerations: See Section 7 of this document.

- Interoperability considerations: N/A

- Published specification: \[\[this document\]\] (this document)

- Applications that use this media type: To be identified

- Fragment identifier considerations: N/A

- Additional information:

  * Magic number(s): N/A

  * File extension(s): N/A
  
  * Macintosh file type code(s): N/A

- Person & email address to contact for further information: See "Authors' Addresses" section.

- Intended usage: COMMON

- Restrictions on usage: N/A

- Author: See "Authors' Addresses" section.

- Change Controller: IESG

## CoAP Content-Formats Registry

IANA has added the media type 'application/edhoc' to the CoAP Content-Formats registry.

-  Media Type: application/edhoc

-  Encoding:

-  ID: TBD42

-  Reference: \[\[this document\]\]

## Expert Review Instructions

The IANA Registries established in this document is defined as "Expert Review". This section gives some general guidelines for what the experts should be looking for, but they are being designated as experts for a reason so they should be given substantial latitude.

Expert reviewers should take into consideration the following points:

* Clarity and correctness of registrations. Experts are expected to check the clarity of purpose and use of the requested entries. Expert needs to make sure the values of algorithms are taken from the right registry, when that's required. Expert should consider requesting an opinion on the correctness of registered parameters from relevant IETF working groups. Encodings that do not meet these objective of clarity and completeness should not be registered.
* Experts should take into account the expected usage of fields when approving point assignment. The length of the encoded value should be weighed against how many code points of that length are left, the size of device it will be used on, and the number of code points left that encode to that size.
* Specifications are recommended. When specifications are not provided, the description provided needs to have sufficient information to verify the points above.

--- back

# Use of CBOR, CDDL and COSE in EDHOC {#CBORandCOSE}

This Appendix is intended to simplify for implementors not familiar with CBOR {{RFC7049}}, CDDL {{RFC8610}}, COSE {{RFC8152}}, and HKDF {{RFC5869}}.

## CBOR and CDDL  {#CBOR}

The Concise Binary Object Representation (CBOR) {{RFC7049}} is a data format designed for small code size and small message size. CBOR builds on the JSON data model but extends it by e.g. encoding binary data directly without base64 conversion. In addition to the binary CBOR encoding, CBOR also has a diagnostic notation that is readable and editable by humans. The Concise Data Definition Language (CDDL) {{RFC8610}} provides a way to express structures for protocol messages and APIs that use CBOR. {{RFC8610}} also extends the diagnostic notation.

CBOR data items are encoded to or decoded from byte strings using a type-length-value encoding scheme, where the three highest order bits of the initial byte contain information about the major type. CBOR supports several different types of data items, in addition to integers (int, uint), simple values (e.g. null), byte strings (bstr), and text strings (tstr), CBOR also supports arrays \[\]  of data items, maps {} of pairs of data items, and sequences {{I-D.ietf-cbor-sequence}} of data items. Some examples are given below. For a complete specification and more examples, see {{RFC7049}} and {{RFC8610}}. We recommend implementors to get used to CBOR by using the CBOR playground {{CborMe}}. 

~~~~~~~~~~~~~~~~~~~~~~~
Diagnostic          Encoded              Type
------------------------------------------------------------------
1                   0x01                 unsigned integer    
24                  0x1818               unsigned integer
-24                 0x37                 negative integer
-25                 0x3818               negative integer 
null                0xf6                 simple value 
h'12cd'             0x4212cd             byte string
'12cd'              0x4431326364         byte string
"12cd"              0x6431326364         text string
{ 4 : h'cd' }       0xa10441cd           map                 
<< 1, 2, null >>    0x430102f6           byte string
[ 1, 2, null ]      0x830102f6           array      
( 1, 2, null )      0x0102f6             sequence
1, 2, null          0x0102f6             sequence
------------------------------------------------------------------
~~~~~~~~~~~~~~~~~~~~~~~
{: artwork-align="center"}

## COSE {#COSE}

CBOR Object Signing and Encryption (COSE) {{RFC8152}} describes how to create and process signatures, message authentication codes, and encryption using CBOR. COSE builds on JOSE, but is adapted to allow more efficient processing in constrained devices. EDHOC makes use of COSE_Key, COSE_Encrypt0, COSE_Sign1, and COSE_KDF_Context objects.





# Test Vectors {#vectors}

This appendix provides detailed test vectors to ease implementation and ensure interoperability. In addition to hexadecimal, all CBOR data items and sequences are given in CBOR diagnostic notation. The test vectors use 1 byte key identifiers, 1 byte connection IDs, and the default mapping to CoAP where the Initiator acts as CoAP client (this means that corr = 1). 

## Test Vectors for EDHOC Authenticated with Signature Keys (RPK)

EDHOC with signature authentication is used:

~~~~~~~~~~~~~~~~~~~~~~~
method (Signature Authentication)
0
~~~~~~~~~~~~~~~~~~~~~~~

CoaP is used as transport and the Initiator acts as CoAP client:

~~~~~~~~~~~~~~~~~~~~~~~
corr (the Initiator can correlate message_1 and message_2)
1
~~~~~~~~~~~~~~~~~~~~~~~

No unprotected opaque auxiliary data is sent in the message exchanges.

The pre-defined Cipher Suite 0 is in place both on the Initiator and the Responder, see {{cipher-suites}}.

### Input for the Initiator {#rpk-tv-input-u}

The following are the parameters that are set in the Initiator before the first message exchange.

~~~~~~~~~~~~~~~~~~~~~~~
Initiator's private authentication key (32 bytes)
53 21 fc 01 c2 98 20 06 3a 72 50 8f c6 39 25 1d c8 30 e2 f7 68 3e b8 e3
8a f1 64 a5 b9 af 9b e3 
~~~~~~~~~~~~~~~~~~~~~~~


~~~~~~~~~~~~~~~~~~~~~~~
Initiator's public authentication key (32 bytes)
42 4c 75 6a b7 7c c6 fd ec f0 b3 ec fc ff b7 53 10 c0 15 bf 5c ba 2e c0
a2 36 e6 65 0c 8a b9 c7 
~~~~~~~~~~~~~~~~~~~~~~~


~~~~~~~~~~~~~~~~~~~~~~~
kid value to identify the Initiator's public authentication key (1 byte)
a2 
~~~~~~~~~~~~~~~~~~~~~~~

This test vector uses COSE_Key objects to store the raw public keys. Moreover, EC2 keys with curve Ed25519 are used. That is in agreement with the Cipher Suite 0.

~~~~~~~~~~~~~~~~~~~~~~~
CRED_I =
<< {
  1:  1,
 -1:  6,
 -2:  h'424c756ab77cc6fdecf0b3ecfcffb75310c015bf5cba2ec0a236e6650c8ab9c7
        '
} >>
~~~~~~~~~~~~~~~~~~~~~~~


~~~~~~~~~~~~~~~~~~~~~~~
CRED_I (bstr-wrapped COSE_Key) (CBOR-encoded) (42 bytes)
58 28 a3 01 01 20 06 21 58 20 42 4c 75 6a b7 7c c6 fd ec f0 b3 ec fc ff
b7 53 10 c0 15 bf 5c ba 2e c0 a2 36 e6 65 0c 8a b9 c7 
~~~~~~~~~~~~~~~~~~~~~~~

Because COSE_Keys are used, and because kid = h'a2':
~~~~~~~~~~~~~~~~~~~~~~~
ID_CRED_I =
{ 
  4:  h'a2'
}
~~~~~~~~~~~~~~~~~~~~~~~

Note that since the map for ID_CRED_I contains a single 'kid' parameter, ID_CRED_I is used when transported in the protected header of the COSE Object, but only the kid_I is used when added to the plaintext (see {{asym-msg3-proc}}):

~~~~~~~~~~~~~~~~~~~~~~~
ID_CRED_I (in protected header) (CBOR-encoded) (4 bytes)
a1 04 41 a2 
~~~~~~~~~~~~~~~~~~~~~~~


~~~~~~~~~~~~~~~~~~~~~~~
kid_I (in plaintext) (CBOR-encoded) (2 bytes)
41 a2 
~~~~~~~~~~~~~~~~~~~~~~~

### Input for the Responder {#rpk-tv-input-v}

The following are the parameters that are set in the Responder before the first message exchange.

~~~~~~~~~~~~~~~~~~~~~~~
the Responder's private authentication key (32 bytes)
74 56 b3 a3 e5 8d 8d 26 dd 36 bc 75 d5 5b 88 63 a8 5d 34 72 f4 a0 1f 02
24 62 1b 1c b8 16 6d a9 
~~~~~~~~~~~~~~~~~~~~~~~


~~~~~~~~~~~~~~~~~~~~~~~
the Responder's public authentication key (32 bytes)
1b 66 1e e5 d5 ef 16 72 a2 d8 77 cd 5b c2 0f 46 30 dc 78 a1 14 de 65 9c
7e 50 4d 0f 52 9a 6b d3 
~~~~~~~~~~~~~~~~~~~~~~~


~~~~~~~~~~~~~~~~~~~~~~~
kid value to identify V's public authentication key (1 byte)
a3 
~~~~~~~~~~~~~~~~~~~~~~~

This test vector uses COSE_Key objects to store the raw public keys. Moreover, EC2 keys with curve Ed25519 are used. That is in agreement with the Cipher Suite 0.

~~~~~~~~~~~~~~~~~~~~~~~
CRED_R =
<< {
  1:  1,
 -1:  6,
 -2:  h'1b661ee5d5ef1672a2d877cd5bc20f4630dc78a114de659c7e504d0f529a6bd3
        '
} >>
~~~~~~~~~~~~~~~~~~~~~~~


~~~~~~~~~~~~~~~~~~~~~~~
CRED_R (bstr-wrapped COSE_Key) (CBOR-encoded) (42 bytes)
58 28 a3 01 01 20 06 21 58 20 1b 66 1e e5 d5 ef 16 72 a2 d8 77 cd 5b c2
0f 46 30 dc 78 a1 14 de 65 9c 7e 50 4d 0f 52 9a 6b d3 
~~~~~~~~~~~~~~~~~~~~~~~

Because COSE_Keys are used, and because kid = h'a3':
~~~~~~~~~~~~~~~~~~~~~~~
ID_CRED_R =
{ 
  4:  h'a3'
}
~~~~~~~~~~~~~~~~~~~~~~~

Note that since the map for ID_CRED_R contains a single 'kid' parameter, ID_CRED_I is used when transported in the protected header of the COSE Object, but only the kid_R is used when added to the plaintext (see {{asym-msg3-proc}}):

~~~~~~~~~~~~~~~~~~~~~~~
ID_CRED_R (in protected header) (CBOR-encoded) (4 bytes)
a1 04 41 a3 
~~~~~~~~~~~~~~~~~~~~~~~


~~~~~~~~~~~~~~~~~~~~~~~
kid_R (in plaintext) (CBOR-encoded) (2 bytes)
41 a3 
~~~~~~~~~~~~~~~~~~~~~~~

### Message 1 {#tv-rpk-1}

From the input parameters (in {{rpk-tv-input-u}}):

~~~~~~~~~~~~~~~~~~~~~~~
TYPE (4 * method + corr)
1
~~~~~~~~~~~~~~~~~~~~~~~


~~~~~~~~~~~~~~~~~~~~~~~
suite
0
~~~~~~~~~~~~~~~~~~~~~~~


~~~~~~~~~~~~~~~~~~~~~~~
SUITES_I : suite
0
~~~~~~~~~~~~~~~~~~~~~~~


~~~~~~~~~~~~~~~~~~~~~~~
Initiator's ephemeral private key (32 bytes)
d4 d8 1a ba fa d9 08 a0 cc ef ef 5a d6 b0 5d 50 27 02 f1 c1 6f 23 2c 25
92 93 09 ac 44 1b 95 8e 
~~~~~~~~~~~~~~~~~~~~~~~


~~~~~~~~~~~~~~~~~~~~~~~
G_X (X-coordinate of the ephemeral public key of the Initiator) (32 bytes)
b1 a3 e8 94 60 e8 8d 3a 8d 54 21 1d c9 5f 0b 90 3f f2 05 eb 71 91 2d 6d
b8 f4 af 98 0d 2d b8 3a 
~~~~~~~~~~~~~~~~~~~~~~~


~~~~~~~~~~~~~~~~~~~~~~~
C_I (Connection identifier chosen by the Initiator) (1 byte)
c3 
~~~~~~~~~~~~~~~~~~~~~~~

No AD_1 is provided, so AD_1 is absent from message_1.

Message_1 is constructed, as the CBOR Sequence of the CBOR data items above.

~~~~~~~~~~~~~~~~~~~~~~~
message_1 =
(
  1,
  0,
  h'b1a3e89460e88d3a8d54211dc95f0b903ff205eb71912d6db8f4af980d2db83a',
  h'c3'
)
~~~~~~~~~~~~~~~~~~~~~~~


~~~~~~~~~~~~~~~~~~~~~~~
message_1 (CBOR Sequence) (38 bytes)
01 00 58 20 b1 a3 e8 94 60 e8 8d 3a 8d 54 21 1d c9 5f 0b 90 3f f2 05 eb
71 91 2d 6d b8 f4 af 98 0d 2d b8 3a 41 c3 
~~~~~~~~~~~~~~~~~~~~~~~

### Message 2 {#tv-rpk-2}

Since TYPE mod 4 equals 1, C_I is omitted from data_2.


~~~~~~~~~~~~~~~~~~~~~~~
Responder's ephemeral private key (32 bytes)
17 cd c7 bc a3 f2 a0 bd a6 0c 6d e5 b9 6f 82 a3 62 39 b4 4b de 39 7a 38
62 d5 29 ba 8b 3d 7c 62 
~~~~~~~~~~~~~~~~~~~~~~~


~~~~~~~~~~~~~~~~~~~~~~~
G_Y (X-coordinate of the ephemeral public key of the Responder) (32 bytes)
8d b5 77 f9 b9 c2 74 47 98 98 7d b5 57 bf 31 ca 48 ac d2 05 a9 db 8c 32
0e 5d 49 f3 02 a9 64 74 
~~~~~~~~~~~~~~~~~~~~~~~


~~~~~~~~~~~~~~~~~~~~~~~
C_R (Connection identifier chosen by the Responder) (1 byte)
c4 
~~~~~~~~~~~~~~~~~~~~~~~

Data_2 is constructed, as the CBOR Sequence of the CBOR data items above.


~~~~~~~~~~~~~~~~~~~~~~~
data_2 =
(
  h'8db577f9b9c2744798987db557bf31ca48acd205a9db8c320e5d49f302a96474',
  h'c4'
)
~~~~~~~~~~~~~~~~~~~~~~~


~~~~~~~~~~~~~~~~~~~~~~~
data_2 (CBOR Sequence) (36 bytes)
58 20 8d b5 77 f9 b9 c2 74 47 98 98 7d b5 57 bf 31 ca 48 ac d2 05 a9 db
8c 32 0e 5d 49 f3 02 a9 64 74 41 c4 
~~~~~~~~~~~~~~~~~~~~~~~

From data_2 and message_1 (from {{tv-rpk-1}}), compute the input to the transcript hash TH_2 = H( message_1, data_2 ), as a CBOR Sequence of these 2 data items.


~~~~~~~~~~~~~~~~~~~~~~~
( message_1, data_2 ) (CBOR Sequence) (74 bytes)
01 00 58 20 b1 a3 e8 94 60 e8 8d 3a 8d 54 21 1d c9 5f 0b 90 3f f2 05 eb
71 91 2d 6d b8 f4 af 98 0d 2d b8 3a 41 c3 58 20 8d b5 77 f9 b9 c2 74 47
98 98 7d b5 57 bf 31 ca 48 ac d2 05 a9 db 8c 32 0e 5d 49 f3 02 a9 64 74
41 c4 
~~~~~~~~~~~~~~~~~~~~~~~

And from there, compute the transcript hash TH_2 = SHA-256( message_1, data_2 )


~~~~~~~~~~~~~~~~~~~~~~~
TH_2 value (32 bytes)
55 50 b3 dc 59 84 b0 20 9a e7 4e a2 6a 18 91 89 57 50 8e 30 33 2b 11 da
68 1d c2 af dd 87 03 55 
~~~~~~~~~~~~~~~~~~~~~~~

When encoded as a CBOR bstr, that gives:


~~~~~~~~~~~~~~~~~~~~~~~
TH_2 (CBOR-encoded) (34 bytes)
58 20 55 50 b3 dc 59 84 b0 20 9a e7 4e a2 6a 18 91 89 57 50 8e 30 33 2b
11 da 68 1d c2 af dd 87 03 55 
~~~~~~~~~~~~~~~~~~~~~~~

#### Signature Computation {#tv-rpk-2-sign}

COSE_Sign1 is computed with the following parameters. From {{rpk-tv-input-v}}:

* protected = bstr .cbor ID_CRED_R 

* payload = CRED_R

And from {{tv-rpk-2}}:

* external_aad = TH_2

The Sig_structure M_R to be signed is: \[ "Signature1", << ID_CRED_R >>, TH_2, CRED_R \] , as defined in {{asym-msg2-proc}}:


~~~~~~~~~~~~~~~~~~~~~~~
M_R =
[
  "Signature1",
  << { 4: h'a3' } >>,
  h'5550b3dc5984b0209ae74ea26a18918957508e30332b11da681dc2afdd870355',
  << {
    1:  1,
   -1:  6,
   -2:  h'1b661ee5d5ef1672a2d877cd5bc20f4630dc78a114de659c7e504d0f529a6b
            d3'
  } >>
]
~~~~~~~~~~~~~~~~~~~~~~~

Which encodes to the following byte string ToBeSigned:

~~~~~~~~~~~~~~~~~~~~~~~
M_R (message to be signed with Ed25519) (CBOR-encoded) (93 bytes)
84 6a 53 69 67 6e 61 74 75 72 65 31 44 a1 04 41 a3 58 20 55 50 b3 dc 59
84 b0 20 9a e7 4e a2 6a 18 91 89 57 50 8e 30 33 2b 11 da 68 1d c2 af dd
87 03 55 58 28 a3 01 01 20 06 21 58 20 1b 66 1e e5 d5 ef 16 72 a2 d8 77
cd 5b c2 0f 46 30 dc 78 a1 14 de 65 9c 7e 50 4d 0f 52 9a 6b d3 
~~~~~~~~~~~~~~~~~~~~~~~

The message is signed using the private authentication key of V, and produces the following signature:

~~~~~~~~~~~~~~~~~~~~~~~
V's signature (64 bytes)
52 3d 99 6d fd 9e 2f 77 c7 68 71 8a 30 c3 48 77 8c 5e b8 64 dd 53 7e 55
5e 4a 00 05 e2 09 53 07 13 ca 14 62 0d e8 18 7e 81 99 6e e8 04 d1 53 b8
a1 f6 08 49 6f dc d9 3d 30 fc 1c 8b 45 be cc 06 
~~~~~~~~~~~~~~~~~~~~~~~

#### Key and Nonce Computation {#tv-rpk-2-key}

The key and nonce for calculating the ciphertext are calculated as follows, as specified in {{key-der}}.

HKDF SHA-256 is the HKDF used (as defined by cipher suite 0).

PRK = HMAC-SHA-256(salt, G_XY)

Since this is the asymmetric case, salt is the empty byte string.

G_XY is the shared secret, and since the curve25519 is used, the ECDH shared secret is the output of the X25519 function.

~~~~~~~~~~~~~~~~~~~~~~~
G_XY (32 bytes)
c6 1e 09 09 a1 9d 64 24 01 63 ec 26 2e 9c c4 f8 8c e7 7b e1 23 c5 ab 53
8d 26 b0 69 22 a5 20 67 
~~~~~~~~~~~~~~~~~~~~~~~

From there, PRK is computed:

~~~~~~~~~~~~~~~~~~~~~~~
PRK (32 bytes)
ba 9c 2c a1 c5 62 14 a6 e0 f6 13 ed a8 91 86 8a 4c a3 e3 fa bc c7 79 8f
dc 01 60 80 07 59 16 71 
~~~~~~~~~~~~~~~~~~~~~~~

Key K_2 is the output of HKDF-Expand(PRK, info, L).

info is defined as follows:

~~~~~~~~~~~~~~~~~~~~~~~
info for K_2 =
[
  10,
  [ null, null, null ],
  [ null, null, null ],
  [ 128, h'', h'5550b3dc5984b0209ae74ea26a18918957508e30332b11da681dc2af
                dd870355']
]
~~~~~~~~~~~~~~~~~~~~~~~

Which as a CBOR encoded data item is:

~~~~~~~~~~~~~~~~~~~~~~~
info (K_2) (CBOR-encoded) (48 bytes)
84 0a 83 f6 f6 f6 83 f6 f6 f6 83 18 80 40 58 20 55 50 b3 dc 59 84 b0 20
9a e7 4e a2 6a 18 91 89 57 50 8e 30 33 2b 11 da 68 1d c2 af dd 87 03 55

~~~~~~~~~~~~~~~~~~~~~~~

L is the length of K_2, so 16 bytes.

From these parameters, K_2 is computed:

~~~~~~~~~~~~~~~~~~~~~~~
K_2 (16 bytes)
da d7 44 af 07 c4 da 27 d1 f0 a3 8a 0c 4b 87 38 
~~~~~~~~~~~~~~~~~~~~~~~

Nonce IV_2 is the output of HKDF-Expand(PRK, info, L).

info is defined as follows:

~~~~~~~~~~~~~~~~~~~~~~~
info for IV_2 =
[
  "IV-GENERATION",
  [ null, null, null ],
  [ null, null, null ],
  [ 104, h'', h'5550b3dc5984b0209ae74ea26a18918957508e30332b11da681dc2af
                dd870355']
]
~~~~~~~~~~~~~~~~~~~~~~~

Which as a CBOR encoded data item is:

~~~~~~~~~~~~~~~~~~~~~~~
info (IV_2) (CBOR-encoded) (61 bytes)
84 6d 49 56 2d 47 45 4e 45 52 41 54 49 4f 4e 83 f6 f6 f6 83 f6 f6 f6 83
18 68 40 58 20 55 50 b3 dc 59 84 b0 20 9a e7 4e a2 6a 18 91 89 57 50 8e
30 33 2b 11 da 68 1d c2 af dd 87 03 55 
~~~~~~~~~~~~~~~~~~~~~~~

L is the length of IV_2, so 13 bytes.

From these parameters, IV_2 is computed:

~~~~~~~~~~~~~~~~~~~~~~~
IV_2 (13 bytes)
fb a1 65 d9 08 da a7 8e 4f 84 41 42 d0 
~~~~~~~~~~~~~~~~~~~~~~~

#### Ciphertext Computation {#tv-rpk-2-ciph}

COSE_Encrypt0 is computed with the following parameters. Note that AD_2 is omitted.

* empty protected header

* external_aad = TH_2

* plaintext = CBOR Sequence of the items kid_R, signature, in this order.

with kid_R taken from {{rpk-tv-input-v}}, and signature as calculated in {{tv-rpk-2-sign}}.

The plaintext is the following:

~~~~~~~~~~~~~~~~~~~~~~~
P_2  (68 bytes)
41 a3 58 40 52 3d 99 6d fd 9e 2f 77 c7 68 71 8a 30 c3 48 77 8c 5e b8 64
dd 53 7e 55 5e 4a 00 05 e2 09 53 07 13 ca 14 62 0d e8 18 7e 81 99 6e e8
04 d1 53 b8 a1 f6 08 49 6f dc d9 3d 30 fc 1c 8b 45 be cc 06 
~~~~~~~~~~~~~~~~~~~~~~~

From the parameters above, the Enc_structure A_2 is computed.

~~~~~~~~~~~~~~~~~~~~~~~
A_2 =
[
  "Encrypt0",
  h'',
  h'5550b3dc5984b0209ae74ea26a18918957508e30332b11da681dc2afdd870355'
]
~~~~~~~~~~~~~~~~~~~~~~~

Which encodes to the following byte string to be used as Additional Authenticated Data:

~~~~~~~~~~~~~~~~~~~~~~~
A_2 (CBOR-encoded) (45 bytes)
83 68 45 6e 63 72 79 70 74 30 40 58 20 55 50 b3 dc 59 84 b0 20 9a e7 4e
a2 6a 18 91 89 57 50 8e 30 33 2b 11 da 68 1d c2 af dd 87 03 55 
~~~~~~~~~~~~~~~~~~~~~~~

The key and nonce used are defined in {{tv-rpk-2-key}}:

* key = K_2

* nonce = IV_2

Using the parameters above, the ciphertext CIPHERTEXT_2 can be computed:

~~~~~~~~~~~~~~~~~~~~~~~
CIPHERTEXT_2 (76 bytes)
1e 6b fe 0e 77 99 ce f0 66 a3 4f 08 ef aa 90 00 6d b4 4c 90 1c f7 9b 23
85 3a b9 7f d8 db c8 53 39 d5 ed 80 87 78 3c f7 a4 a7 e0 ea 38 c2 21 78
9f a3 71 be 64 e9 3c 43 a7 db 47 d1 e3 fb 14 78 8e 96 7f dd 78 d8 80 78
e4 9b 78 bf 
~~~~~~~~~~~~~~~~~~~~~~~

#### message_2

From the parameter computed in {{tv-rpk-2}} and {{tv-rpk-2-ciph}}, message_2 is computed, as the CBOR Sequence of the following items: (G_Y, C_R, CIPHERTEXT_2).


~~~~~~~~~~~~~~~~~~~~~~~
message_2 =
(
  h'8db577f9b9c2744798987db557bf31ca48acd205a9db8c320e5d49f302a96474',
  h'c4',
  h'1e6bfe0e7799cef066a34f08efaa90006db44c901cf79b23853ab97fd8dbc85339d5
    ed8087783cf7a4a7e0ea38c221789fa371be64e93c43a7db47d1e3fb14788e967fdd
    78d88078e49b78bf'
)
~~~~~~~~~~~~~~~~~~~~~~~

Which encodes to the following byte string:

~~~~~~~~~~~~~~~~~~~~~~~
message_2 (CBOR Sequence) (114 bytes)
58 20 8d b5 77 f9 b9 c2 74 47 98 98 7d b5 57 bf 31 ca 48 ac d2 05 a9 db
8c 32 0e 5d 49 f3 02 a9 64 74 41 c4 58 4c 1e 6b fe 0e 77 99 ce f0 66 a3
4f 08 ef aa 90 00 6d b4 4c 90 1c f7 9b 23 85 3a b9 7f d8 db c8 53 39 d5
ed 80 87 78 3c f7 a4 a7 e0 ea 38 c2 21 78 9f a3 71 be 64 e9 3c 43 a7 db
47 d1 e3 fb 14 78 8e 96 7f dd 78 d8 80 78 e4 9b 78 bf 
~~~~~~~~~~~~~~~~~~~~~~~

### Message 3 {#tv-rpk-3}

Since TYPE mod 4 equals 1, C_R is not omitted from data_3.


~~~~~~~~~~~~~~~~~~~~~~~
C_R (1 byte)
c4 
~~~~~~~~~~~~~~~~~~~~~~~

Data_3 is constructed, as the CBOR Sequence of the CBOR data item above.

~~~~~~~~~~~~~~~~~~~~~~~
data_3 =
(
  h'c4'
)
~~~~~~~~~~~~~~~~~~~~~~~


~~~~~~~~~~~~~~~~~~~~~~~
data_3 (CBOR Sequence) (2 bytes)
41 c4 
~~~~~~~~~~~~~~~~~~~~~~~

From data_3, CIPHERTEXT_2 ({{tv-rpk-2-ciph}}), and TH_2 ({{tv-rpk-2}}), compute the input to the transcript hash TH_2 = H(TH_2 , CIPHERTEXT_2, data_3), as a CBOR Sequence of these 3 data items.

~~~~~~~~~~~~~~~~~~~~~~~
( TH_2, CIPHERTEXT_2, data_3 ) (CBOR Sequence) (114 bytes)
58 20 55 50 b3 dc 59 84 b0 20 9a e7 4e a2 6a 18 91 89 57 50 8e 30 33 2b
11 da 68 1d c2 af dd 87 03 55 58 4c 1e 6b fe 0e 77 99 ce f0 66 a3 4f 08
ef aa 90 00 6d b4 4c 90 1c f7 9b 23 85 3a b9 7f d8 db c8 53 39 d5 ed 80
87 78 3c f7 a4 a7 e0 ea 38 c2 21 78 9f a3 71 be 64 e9 3c 43 a7 db 47 d1
e3 fb 14 78 8e 96 7f dd 78 d8 80 78 e4 9b 78 bf 41 c4 
~~~~~~~~~~~~~~~~~~~~~~~

And from there, compute the transcript hash TH_3 = SHA-256(TH_2 , CIPHERTEXT_2, data_3)

~~~~~~~~~~~~~~~~~~~~~~~
TH_3 value (32 bytes)
21 cc b6 78 b7 91 14 96 09 55 88 5b 90 a2 b8 2e 3b 2c a2 7e 8e 37 4a 79
07 f3 e7 85 43 67 fc 22 
~~~~~~~~~~~~~~~~~~~~~~~

When encoded as a CBOR bstr, that gives:


~~~~~~~~~~~~~~~~~~~~~~~
TH_3 (CBOR-encoded) (34 bytes)
58 20 21 cc b6 78 b7 91 14 96 09 55 88 5b 90 a2 b8 2e 3b 2c a2 7e 8e 37
4a 79 07 f3 e7 85 43 67 fc 22 
~~~~~~~~~~~~~~~~~~~~~~~

#### Signature Computation {#tv-rpk-3-sign}

COSE_Sign1 is computed with the following parameters. From {{rpk-tv-input-u}}:

* protected = bstr .cbor ID_CRED_I 

* payload = CRED_I

And from {{tv-rpk-3}}:

* external_aad = TH_3

The Sig_structure M_I to be signed is: \[ "Signature1", << ID_CRED_I >>, TH_3, CRED_I \] , as defined in {{asym-msg3-proc}}:


~~~~~~~~~~~~~~~~~~~~~~~
M_I =
[
  "Signature1",
  << { 4: h'a2' } >>,
  h'21ccb678b79114960955885b90a2b82e3b2ca27e8e374a7907f3e7854367fc22',
  << {
    1:  1,
   -1:  6,
   -2:  h'424c756ab77cc6fdecf0b3ecfcffb75310c015bf5cba2ec0a236e6650c8ab9
            c7'
  } >>
]
~~~~~~~~~~~~~~~~~~~~~~~

Which encodes to the following byte string ToBeSigned:

~~~~~~~~~~~~~~~~~~~~~~~
M_I (message to be signed with Ed25519) (CBOR-encoded) (93 bytes)
84 6a 53 69 67 6e 61 74 75 72 65 31 44 a1 04 41 a2 58 20 21 cc b6 78 b7
91 14 96 09 55 88 5b 90 a2 b8 2e 3b 2c a2 7e 8e 37 4a 79 07 f3 e7 85 43
67 fc 22 58 28 a3 01 01 20 06 21 58 20 42 4c 75 6a b7 7c c6 fd ec f0 b3
ec fc ff b7 53 10 c0 15 bf 5c ba 2e c0 a2 36 e6 65 0c 8a b9 c7 
~~~~~~~~~~~~~~~~~~~~~~~

The message is signed using the private authentication key of U, and produces the following signature:

~~~~~~~~~~~~~~~~~~~~~~~
Initiator's signature (64 bytes)
5c 7d 7d 64 c9 61 c5 f5 2d cf 33 91 25 92 a1 af f0 2c 33 62 b0 e7 55 0e
4b c5 66 b7 0c 20 61 f3 c5 f6 49 e5 ed 32 3d 30 a2 6c 61 2f bb 5c bd 25
f3 1c 27 22 8c ea ec 64 29 31 95 41 fe 07 8e 0e 
~~~~~~~~~~~~~~~~~~~~~~~

#### Key and Nonce Computation {#tv-rpk-3-key}

The key and nonce for calculating the ciphertext are calculated as follows, as specified in {{key-der}}.

HKDF SHA-256 is the HKDF used (as defined by cipher suite 0 ).

PRK = HMAC-SHA-256(salt, G_XY)

Since this is the asymmetric case, salt is the empty byte string.

G_XY is the shared secret, and since the curve25519 is used, the ECDH shared secret is the output of the X25519 function.


~~~~~~~~~~~~~~~~~~~~~~~
G_XY (32 bytes)
c6 1e 09 09 a1 9d 64 24 01 63 ec 26 2e 9c c4 f8 8c e7 7b e1 23 c5 ab 53
8d 26 b0 69 22 a5 20 67 
~~~~~~~~~~~~~~~~~~~~~~~

From there, PRK is computed:

~~~~~~~~~~~~~~~~~~~~~~~
PRK (32 bytes)
ba 9c 2c a1 c5 62 14 a6 e0 f6 13 ed a8 91 86 8a 4c a3 e3 fa bc c7 79 8f
dc 01 60 80 07 59 16 71 
~~~~~~~~~~~~~~~~~~~~~~~

Key K_3 is the output of HKDF-Expand(PRK, info, L).

info is defined as follows:

~~~~~~~~~~~~~~~~~~~~~~~
info for K_3 =
[
  10,
  [ null, null, null ],
  [ null, null, null ],
  [ 128, h'', h'21ccb678b79114960955885b90a2b82e3b2ca27e8e374a7907f3e785
                4367fc22']
]
~~~~~~~~~~~~~~~~~~~~~~~

Which as a CBOR encoded data item is:

~~~~~~~~~~~~~~~~~~~~~~~
info (K_3) (CBOR-encoded) (48 bytes)
84 0a 83 f6 f6 f6 83 f6 f6 f6 83 18 80 40 58 20 21 cc b6 78 b7 91 14 96
09 55 88 5b 90 a2 b8 2e 3b 2c a2 7e 8e 37 4a 79 07 f3 e7 85 43 67 fc 22

~~~~~~~~~~~~~~~~~~~~~~~

L is the length of K_3, so 16 bytes. 

From these parameters, K_3 is computed:

~~~~~~~~~~~~~~~~~~~~~~~
K_3 (16 bytes)
e1 ac d4 76 f5 96 a4 60 72 44 a8 da 8c ff 49 df 
~~~~~~~~~~~~~~~~~~~~~~~

Nonce IV_3 is the output of HKDF-Expand(PRK, info, L).info is defined as follows:

~~~~~~~~~~~~~~~~~~~~~~~
info for IV_3 =
[
  "IV-GENERATION",
  [ null, null, null ],
  [ null, null, null ],
  [ 104, h'', h'21ccb678b79114960955885b90a2b82e3b2ca27e8e374a7907f3e785
                4367fc22']
]
~~~~~~~~~~~~~~~~~~~~~~~

Which as a CBOR encoded data item is:

~~~~~~~~~~~~~~~~~~~~~~~
info (IV_3) (CBOR-encoded) (61 bytes)
84 6d 49 56 2d 47 45 4e 45 52 41 54 49 4f 4e 83 f6 f6 f6 83 f6 f6 f6 83
18 68 40 58 20 21 cc b6 78 b7 91 14 96 09 55 88 5b 90 a2 b8 2e 3b 2c a2
7e 8e 37 4a 79 07 f3 e7 85 43 67 fc 22 
~~~~~~~~~~~~~~~~~~~~~~~

From these parameters, IV_3 is computed:

~~~~~~~~~~~~~~~~~~~~~~~
IV_3 (13 bytes)
de 53 02 13 ab a2 6a 47 1a 51 f3 d6 fb 
~~~~~~~~~~~~~~~~~~~~~~~

#### Ciphertext Computation {#tv-rpk-3-ciph}

COSE_Encrypt0 is computed with the following parameters. Note that AD_3 is omitted.

* empty protected header

* external_aad = TH_3

* plaintext = CBOR Sequence of the items kid_I, signature, in this order.

with kid_I taken from {{rpk-tv-input-u}}, and signature as calculated in {{tv-rpk-3-sign}}.

The plaintext is the following:

~~~~~~~~~~~~~~~~~~~~~~~
P_3  (68 bytes)
41 a2 58 40 5c 7d 7d 64 c9 61 c5 f5 2d cf 33 91 25 92 a1 af f0 2c 33 62
b0 e7 55 0e 4b c5 66 b7 0c 20 61 f3 c5 f6 49 e5 ed 32 3d 30 a2 6c 61 2f
bb 5c bd 25 f3 1c 27 22 8c ea ec 64 29 31 95 41 fe 07 8e 0e 
~~~~~~~~~~~~~~~~~~~~~~~

From the parameters above, the Enc_structure A_3 is computed.

~~~~~~~~~~~~~~~~~~~~~~~
A_3 =
[
  "Encrypt0",
  h'',
  h'21ccb678b79114960955885b90a2b82e3b2ca27e8e374a7907f3e7854367fc22'
]
~~~~~~~~~~~~~~~~~~~~~~~

Which encodes to the following byte string to be used as Additional Authenticated Data:

~~~~~~~~~~~~~~~~~~~~~~~
A_3 (CBOR-encoded) (45 bytes)
83 68 45 6e 63 72 79 70 74 30 40 58 20 21 cc b6 78 b7 91 14 96 09 55 88
5b 90 a2 b8 2e 3b 2c a2 7e 8e 37 4a 79 07 f3 e7 85 43 67 fc 22 
~~~~~~~~~~~~~~~~~~~~~~~

The key and nonce used are defined in {{tv-rpk-3-key}}:

* key = K_3

* nonce = IV_3

Using the parameters above, the ciphertext CIPHERTEXT_3 can be computed:

~~~~~~~~~~~~~~~~~~~~~~~
CIPHERTEXT_3 (76 bytes)
de 4a 83 3d 48 b6 64 74 14 2c c9 bd ce 87 d9 3a f8 35 57 9c 2d bf 1b 9e
2f b4 dc 66 60 0d ba c6 bb 3c c0 5c 29 0e f3 5d 51 5b 4d 7d 64 83 f5 09
61 43 b5 56 44 cf af d1 ff aa 7f 2b a3 86 36 57 83 1d d2 e5 bd 04 04 38
60 14 0d c8 
~~~~~~~~~~~~~~~~~~~~~~~

#### message_3

From the parameter computed in {{tv-rpk-3}} and {{tv-rpk-3-ciph}}, message_3 is computed, as the CBOR Sequence of the following items: (C_R, CIPHERTEXT_3).


~~~~~~~~~~~~~~~~~~~~~~~
message_3 =
(
  h'c4',
  h'de4a833d48b66474142cc9bdce87d93af835579c2dbf1b9e2fb4dc66600dbac6bb3c
    c05c290ef35d515b4d7d6483f5096143b55644cfafd1ffaa7f2ba3863657831dd2e5
    bd04043860140dc8'
)
~~~~~~~~~~~~~~~~~~~~~~~

Which encodes to the following byte string:

~~~~~~~~~~~~~~~~~~~~~~~
message_3 (CBOR Sequence) (80 bytes)
41 c4 58 4c de 4a 83 3d 48 b6 64 74 14 2c c9 bd ce 87 d9 3a f8 35 57 9c
2d bf 1b 9e 2f b4 dc 66 60 0d ba c6 bb 3c c0 5c 29 0e f3 5d 51 5b 4d 7d
64 83 f5 09 61 43 b5 56 44 cf af d1 ff aa 7f 2b a3 86 36 57 83 1d d2 e5
bd 04 04 38 60 14 0d c8 
~~~~~~~~~~~~~~~~~~~~~~~

#### OSCORE Security Context Derivation

From the previous message exchange, the Common Security Context for OSCORE {{RFC8613}} can be derived, as specified in {{exporter}}.

First af all, TH_4 is computed: TH_4 = H( TH_3, CIPHERTEXT_3 ), where the input to the hash function is the CBOR Sequence of TH_3 and CIPHERTEXT_3

~~~~~~~~~~~~~~~~~~~~~~~
( TH_3, CIPHERTEXT_3 ) (CBOR Sequence) (112 bytes)
58 20 21 cc b6 78 b7 91 14 96 09 55 88 5b 90 a2 b8 2e 3b 2c a2 7e 8e 37
4a 79 07 f3 e7 85 43 67 fc 22 58 4c de 4a 83 3d 48 b6 64 74 14 2c c9 bd
ce 87 d9 3a f8 35 57 9c 2d bf 1b 9e 2f b4 dc 66 60 0d ba c6 bb 3c c0 5c
29 0e f3 5d 51 5b 4d 7d 64 83 f5 09 61 43 b5 56 44 cf af d1 ff aa 7f 2b
a3 86 36 57 83 1d d2 e5 bd 04 04 38 60 14 0d c8 
~~~~~~~~~~~~~~~~~~~~~~~

And from there, compute the transcript hash TH_4 = SHA-256( TH_3, CIPHERTEXT_3 )

~~~~~~~~~~~~~~~~~~~~~~~
TH_4 value (32 bytes)
51 ed 39 32 bc ba e8 90 1c 1d 4d eb 94 bd 67 3a b4 d3 8c 34 81 96 09 ee
0d 5c 9d a6 e9 80 7f e5 
~~~~~~~~~~~~~~~~~~~~~~~

When encoded as a CBOR bstr, that gives:

~~~~~~~~~~~~~~~~~~~~~~~
TH_4 (CBOR-encoded) (34 bytes)
58 20 51 ed 39 32 bc ba e8 90 1c 1d 4d eb 94 bd 67 3a b4 d3 8c 34 81 96
09 ee 0d 5c 9d a6 e9 80 7f e5 
~~~~~~~~~~~~~~~~~~~~~~~

To derive the Master Secret and Master Salt the same HKDF-Expand (PRK, info, L) is used, with different info and L.

For Master Secret:

L for Master Secret = 16

~~~~~~~~~~~~~~~~~~~~~~~
info for Master Secret =
[
  "OSCORE Master Secret",
  [ null, null, null ],
  [ null, null, null ],
  [ 128, h'', h'51ed3932bcbae8901c1d4deb94bd673ab4d38c34819609ee0d5c9da6
                e9807fe5']
]
~~~~~~~~~~~~~~~~~~~~~~~

When encoded as a CBOR bstr, that gives:

~~~~~~~~~~~~~~~~~~~~~~~
info (OSCORE Master Secret) (CBOR-encoded) (68 bytes)
84 74 4f 53 43 4f 52 45 20 4d 61 73 74 65 72 20 53 65 63 72 65 74 83 f6
f6 f6 83 f6 f6 f6 83 18 80 40 58 20 51 ed 39 32 bc ba e8 90 1c 1d 4d eb
94 bd 67 3a b4 d3 8c 34 81 96 09 ee 0d 5c 9d a6 e9 80 7f e5 
~~~~~~~~~~~~~~~~~~~~~~~

Finally, the Master Secret value computed is:

~~~~~~~~~~~~~~~~~~~~~~~
OSCORE Master Secret (16 bytes)
09 02 9d b0 0c 3e 01 27 42 c3 a8 69 04 07 4c 0e 
~~~~~~~~~~~~~~~~~~~~~~~

For Master Salt:

L for Master Salt = 8

~~~~~~~~~~~~~~~~~~~~~~~
info for Master Salt =
[
  "OSCORE Master Salt",
  [ null, null, null ],
  [ null, null, null ],
  [ 64, h'', h'51ed3932bcbae8901c1d4deb94bd673ab4d38c34819609ee0d5c9da6
                e9807fe5']
]
~~~~~~~~~~~~~~~~~~~~~~~

When encoded as a CBOR bstr, that gives:

~~~~~~~~~~~~~~~~~~~~~~~
info (OSCORE Master Salt) (CBOR-encoded) (66 bytes)
84 72 4f 53 43 4f 52 45 20 4d 61 73 74 65 72 20 53 61 6c 74 83 f6 f6 f6
83 f6 f6 f6 83 18 40 40 58 20 51 ed 39 32 bc ba e8 90 1c 1d 4d eb 94 bd
67 3a b4 d3 8c 34 81 96 09 ee 0d 5c 9d a6 e9 80 7f e5 
~~~~~~~~~~~~~~~~~~~~~~~

Finally, the Master Salt value computed is:

~~~~~~~~~~~~~~~~~~~~~~~
OSCORE Master Salt (8 bytes)
81 02 97 22 a2 30 4a 06 
~~~~~~~~~~~~~~~~~~~~~~~

The Client's Sender ID takes the value of C_R:

~~~~~~~~~~~~~~~~~~~~~~~
Client's OSCORE Sender ID (1 byte)
c4 
~~~~~~~~~~~~~~~~~~~~~~~

The Server's Sender ID takes the value of C_I:

~~~~~~~~~~~~~~~~~~~~~~~
Server's OSCORE Sender ID (1 byte)
c3 
~~~~~~~~~~~~~~~~~~~~~~~

The algorithms are those negociated in the cipher suite:

~~~~~~~~~~~~~~~~~~~~~~~
AEAD Algorithm
10
~~~~~~~~~~~~~~~~~~~~~~~


~~~~~~~~~~~~~~~~~~~~~~~
HMAC Algorithm
5
~~~~~~~~~~~~~~~~~~~~~~~

## Test Vectors for EDHOC Authenticated with Symmetric Keys (PSK)

Symmetric EDHOC is used:

~~~~~~~~~~~~~~~~~~~~~~~
method (Symmetric Authentication)
1
~~~~~~~~~~~~~~~~~~~~~~~

CoaP is used as transport and the Initiator acts as CoAP client:

~~~~~~~~~~~~~~~~~~~~~~~
corr (the Initiator can correlate message_1 and message_2)
1
~~~~~~~~~~~~~~~~~~~~~~~

No unprotected opaque auxiliary data is sent in the message exchanges.

The pre-defined Cipher Suite 0 is in place both on the Initiator and the Responder, see {{cipher-suites}}.

### Input for the Initiator {#psk-tv-input-u}

The following are the parameters that are set in the Initiator before the first message exchange.

~~~~~~~~~~~~~~~~~~~~~~~
Initiator's ephemeral private key (32 bytes)
f4 0c ea f8 6e 57 76 92 33 32 b8 d8 fd 3b ef 84 9c ad b1 9c 69 96 bc 27
2a f1 f6 48 d9 56 6a 4c 
~~~~~~~~~~~~~~~~~~~~~~~


~~~~~~~~~~~~~~~~~~~~~~~
Initiator's ephemeral public key (value of G_X) (32 bytes)
ab 2f ca 32 89 83 22 c2 08 fb 2d ab 50 48 bd 43 c3 55 c6 43 0f 58 88 97
cb 57 49 61 cf a9 80 6f 
~~~~~~~~~~~~~~~~~~~~~~~


~~~~~~~~~~~~~~~~~~~~~~~
Connection identifier chosen by the Initiator (value of C_I) (1 byte)
c1 
~~~~~~~~~~~~~~~~~~~~~~~


~~~~~~~~~~~~~~~~~~~~~~~
Pre-shared Key (PSK) (16 bytes)
a1 1f 8f 12 d0 87 6f 73 6d 2d 8f d2 6e 14 c2 de 
~~~~~~~~~~~~~~~~~~~~~~~


~~~~~~~~~~~~~~~~~~~~~~~
kid value to identify PSK (1 byte)
a1 
~~~~~~~~~~~~~~~~~~~~~~~

So ID_PSK is defined as the following:

~~~~~~~~~~~~~~~~~~~~~~~
ID_PSK =
{
  4:h'a1'
}
~~~~~~~~~~~~~~~~~~~~~~~

This test vector uses COSE_Key objects to store the pre-shared key.

Note that since the map for ID_PSK contains a single 'kid' parameter, ID_PSK is used when transported in the protected header of the COSE Object, but only the kid is used when added to the plaintext (see {{sym-overview}}):

~~~~~~~~~~~~~~~~~~~~~~~
ID_PSK (in protected header) (CBOR-encoded) (4 bytes)
a1 04 41 a1 
~~~~~~~~~~~~~~~~~~~~~~~


~~~~~~~~~~~~~~~~~~~~~~~
kid (in plaintext) (CBOR-encoded) (2 bytes)
41 a1 
~~~~~~~~~~~~~~~~~~~~~~~

### Input for the Responder {#psk-tv-input-v}

The following are the parameters that are set in the Responder before the first message exchange.

~~~~~~~~~~~~~~~~~~~~~~~
Responder's ephemeral private key (32 bytes)
d9 81 80 87 de 72 44 ab c1 b5 fc f2 8e 55 e4 2c 7f f9 c6 78 c0 60 51 81
f3 7a c5 d7 41 4a 7b 95 
~~~~~~~~~~~~~~~~~~~~~~~


~~~~~~~~~~~~~~~~~~~~~~~
Responder's ephemeral public key (value of G_Y) (32 bytes)
fc 3b 33 93 67 a5 22 5d 53 a9 2d 38 03 23 af d0 35 d7 81 7b 6d 1b e4 7d
94 6f 6b 09 a9 cb dc 06 
~~~~~~~~~~~~~~~~~~~~~~~


~~~~~~~~~~~~~~~~~~~~~~~
Connection identifier chosen by the Responder (value of C_R) (1 byte)
c2 
~~~~~~~~~~~~~~~~~~~~~~~


~~~~~~~~~~~~~~~~~~~~~~~
Pre-shared Key (PSK) (16 bytes)
a1 1f 8f 12 d0 87 6f 73 6d 2d 8f d2 6e 14 c2 de 
~~~~~~~~~~~~~~~~~~~~~~~


~~~~~~~~~~~~~~~~~~~~~~~
kid value to identify PSK (1 byte)
a1 
~~~~~~~~~~~~~~~~~~~~~~~

So ID_PSK is defined as the following:

~~~~~~~~~~~~~~~~~~~~~~~
ID_PSK =
{
  4:h'a1'
}
~~~~~~~~~~~~~~~~~~~~~~~

This test vector uses COSE_Key objects to store the pre-shared key.

Note that since the map for ID_PSK contains a single 'kid' parameter, ID_PSK is used when transported in the protected header of the COSE Object, but only the kid is used when added to the plaintext (see {{sym-overview}}):

~~~~~~~~~~~~~~~~~~~~~~~
ID_PSK (in protected header) (CBOR-encoded) (4 bytes)
a1 04 41 a1 
~~~~~~~~~~~~~~~~~~~~~~~


~~~~~~~~~~~~~~~~~~~~~~~
kid (in plaintext) (CBOR-encoded) (2 bytes)
41 a1 
~~~~~~~~~~~~~~~~~~~~~~~

### Message 1 {#tv-psk-1}

From the input parameters (in {{psk-tv-input-u}}):

~~~~~~~~~~~~~~~~~~~~~~~
TYPE (4 * method + corr)
5
~~~~~~~~~~~~~~~~~~~~~~~


~~~~~~~~~~~~~~~~~~~~~~~
suite
0
~~~~~~~~~~~~~~~~~~~~~~~


~~~~~~~~~~~~~~~~~~~~~~~
SUITES_I : suite
0
~~~~~~~~~~~~~~~~~~~~~~~


~~~~~~~~~~~~~~~~~~~~~~~
G_X (X-coordinate of the ephemeral public key of the Initiator) (32 bytes)
ab 2f ca 32 89 83 22 c2 08 fb 2d ab 50 48 bd 43 c3 55 c6 43 0f 58 88 97
cb 57 49 61 cf a9 80 6f 
~~~~~~~~~~~~~~~~~~~~~~~


~~~~~~~~~~~~~~~~~~~~~~~
C_I (Connection identifier chosen by the Initiator) (CBOR encoded) (2 bytes)
41 c1 
~~~~~~~~~~~~~~~~~~~~~~~


~~~~~~~~~~~~~~~~~~~~~~~
kid of ID_PSK (CBOR encoded) (2 bytes)
41 a1 
~~~~~~~~~~~~~~~~~~~~~~~

No UAD_1 is provided, so AD_1 is absent from message_1.

Message_1 is constructed, as the CBOR Sequence of the CBOR data items above.

~~~~~~~~~~~~~~~~~~~~~~~
message_1 =
(
  5,
  0,
  h'ab2fca32898322c208fb2dab5048bd43c355c6430f588897cb574961cfa9806f',
  h'c1',
  h'a1'
)
~~~~~~~~~~~~~~~~~~~~~~~


~~~~~~~~~~~~~~~~~~~~~~~
message_1 (CBOR Sequence) (40 bytes)
05 00 58 20 ab 2f ca 32 89 83 22 c2 08 fb 2d ab 50 48 bd 43 c3 55 c6 43
0f 58 88 97 cb 57 49 61 cf a9 80 6f 41 c1 41 a1 
~~~~~~~~~~~~~~~~~~~~~~~

### Message 2 {#tv-psk-2}

Since TYPE mod 4 equals 1, C_I is omitted from data_2.

~~~~~~~~~~~~~~~~~~~~~~~
G_Y (X-coordinate of the ephemeral public key of the Responder) (32 bytes)
fc 3b 33 93 67 a5 22 5d 53 a9 2d 38 03 23 af d0 35 d7 81 7b 6d 1b e4 7d
94 6f 6b 09 a9 cb dc 06 
~~~~~~~~~~~~~~~~~~~~~~~


~~~~~~~~~~~~~~~~~~~~~~~
C_R (Connection identifier chosen by the Responder) (1 byte)
c2 
~~~~~~~~~~~~~~~~~~~~~~~

Data_2 is constructed, as the CBOR Sequence of the CBOR data items above.

~~~~~~~~~~~~~~~~~~~~~~~
data_2 =
(
  h'fc3b339367a5225d53a92d380323afd035d7817b6d1be47d946f6b09a9cbdc06',
  h'c2'
)
~~~~~~~~~~~~~~~~~~~~~~~


~~~~~~~~~~~~~~~~~~~~~~~
data_2 (CBOR Sequence) (36 bytes)
58 20 fc 3b 33 93 67 a5 22 5d 53 a9 2d 38 03 23 af d0 35 d7 81 7b 6d 1b
e4 7d 94 6f 6b 09 a9 cb dc 06 41 c2 
~~~~~~~~~~~~~~~~~~~~~~~

From data_2 and message_1 (from {{tv-psk-1}}), compute the input to the transcript hash TH_2 = H( message_1, data_2 ), as a CBOR Sequence of these 2 data items.

~~~~~~~~~~~~~~~~~~~~~~~
( message_1, data_2 ) (CBOR Sequence) (76 bytes)
05 00 58 20 ab 2f ca 32 89 83 22 c2 08 fb 2d ab 50 48 bd 43 c3 55 c6 43
0f 58 88 97 cb 57 49 61 cf a9 80 6f 41 c1 41 a1 58 20 fc 3b 33 93 67 a5
22 5d 53 a9 2d 38 03 23 af d0 35 d7 81 7b 6d 1b e4 7d 94 6f 6b 09 a9 cb
dc 06 41 c2 
~~~~~~~~~~~~~~~~~~~~~~~

And from there, compute the transcript hash TH_2 = SHA-256( message_1, data_2 )

~~~~~~~~~~~~~~~~~~~~~~~
TH_2 value (32 bytes)
16 4f 44 d8 56 dd 15 22 2f a4 63 f2 02 d9 c6 0b e3 c6 9b 40 f7 35 8d 34
1c db 7b 07 de e1 70 ca 
~~~~~~~~~~~~~~~~~~~~~~~

When encoded as a CBOR bstr, that gives:

~~~~~~~~~~~~~~~~~~~~~~~
TH_2 (CBOR-encoded) (34 bytes)
58 20 16 4f 44 d8 56 dd 15 22 2f a4 63 f2 02 d9 c6 0b e3 c6 9b 40 f7 35
8d 34 1c db 7b 07 de e1 70 ca 
~~~~~~~~~~~~~~~~~~~~~~~

#### Key and Nonce Computation {#tv-psk-2-key}

The key and nonce for calculating the ciphertext are calculated as follows, as specified in {{key-der}}.

HKDF SHA-256 is the HKDF used (as defined by cipher suite 0).

PRK = HMAC-SHA-256(salt, G_XY)

Since this is the symmetric case, salt is the PSK:

~~~~~~~~~~~~~~~~~~~~~~~
salt (16 bytes)
a1 1f 8f 12 d0 87 6f 73 6d 2d 8f d2 6e 14 c2 de 
~~~~~~~~~~~~~~~~~~~~~~~

G_XY is the shared secret, and since the curve25519 is used, the ECDH shared secret is the output of the X25519 function.

~~~~~~~~~~~~~~~~~~~~~~~
G_XY (32 bytes)
d5 75 05 50 6d 8f 30 a8 60 a0 63 d0 1b 5b 7a d7 6a 09 4f 70 61 3b 4a e6
6c 5a 90 e5 c2 1f 23 11 
~~~~~~~~~~~~~~~~~~~~~~~

From there, PRK is computed:

~~~~~~~~~~~~~~~~~~~~~~~
PRK (32 bytes)
aa b2 f1 3c cb 1a 4f f7 96 a9 7a 32 a4 d2 fb 62 47 ef 0b 6b 06 da 04 d3
d1 06 39 4b 28 76 e2 8c 
~~~~~~~~~~~~~~~~~~~~~~~

Key K_2 is the output of HKDF-Expand(PRK, info, L).

info is defined as follows:

~~~~~~~~~~~~~~~~~~~~~~~
info for K_2 =
[
  10,
  [ null, null, null ],
  [ null, null, null ],
  [ 128, h'', h'164f44d856dd15222fa463f202d9c60be3c69b40f7358d341cdb7b07
                dee170ca']
]
~~~~~~~~~~~~~~~~~~~~~~~

Which as a CBOR encoded data item is:

~~~~~~~~~~~~~~~~~~~~~~~
info (K_2) (CBOR-encoded) (48 bytes)
84 0a 83 f6 f6 f6 83 f6 f6 f6 83 18 80 40 58 20 16 4f 44 d8 56 dd 15 22
2f a4 63 f2 02 d9 c6 0b e3 c6 9b 40 f7 35 8d 34 1c db 7b 07 de e1 70 ca

~~~~~~~~~~~~~~~~~~~~~~~

L is the length of K_2, so 16 bytes.

From these parameters, K_2 is computed:

~~~~~~~~~~~~~~~~~~~~~~~
K_2 (16 bytes)
ac 42 6e 5e 7d 7a d6 ae 3b 19 aa bd e0 f6 25 57 
~~~~~~~~~~~~~~~~~~~~~~~

Nonce IV_2 is the output of HKDF-Expand(PRK, info, L).
info is defined as follows:

~~~~~~~~~~~~~~~~~~~~~~~
info for IV_2 =
[
  "IV-GENERATION",
  [ null, null, null ],
  [ null, null, null ],
  [ 104, h'', h'164f44d856dd15222fa463f202d9c60be3c69b40f7358d341cdb7b07
                dee170ca']
]
~~~~~~~~~~~~~~~~~~~~~~~

Which as a CBOR encoded data item is:

~~~~~~~~~~~~~~~~~~~~~~~
info (IV_2) (CBOR-encoded) (61 bytes)
84 6d 49 56 2d 47 45 4e 45 52 41 54 49 4f 4e 83 f6 f6 f6 83 f6 f6 f6 83
18 68 40 58 20 16 4f 44 d8 56 dd 15 22 2f a4 63 f2 02 d9 c6 0b e3 c6 9b
40 f7 35 8d 34 1c db 7b 07 de e1 70 ca 
~~~~~~~~~~~~~~~~~~~~~~~

L is the length of IV_2, so 13 bytes.

From these parameters, IV_2 is computed:

~~~~~~~~~~~~~~~~~~~~~~~
IV_2 (13 bytes)
ff 11 2e 1c 26 8a a2 a7 7c c3 ee 6c 4d 
~~~~~~~~~~~~~~~~~~~~~~~

#### Ciphertext Computation {#tv-psk-2-ciph}

COSE_Encrypt0 is computed with the following parameters. Note that AD_2 is omitted.

* empty protected header

* external_aad = TH_2

* empty plaintext, since AD_2 is omitted

* empty plaintext, since AD_2 is omitted

From the parameters above, the Enc_structure A_2 is computed.

~~~~~~~~~~~~~~~~~~~~~~~
A_2 =
[
  "Encrypt0",
  h'',
  h'164f44d856dd15222fa463f202d9c60be3c69b40f7358d341cdb7b07dee170ca'
]
~~~~~~~~~~~~~~~~~~~~~~~

Which encodes to the following byte string to be used as Additional Authenticated Data:

~~~~~~~~~~~~~~~~~~~~~~~
A_2 (CBOR-encoded) (45 bytes)
83 68 45 6e 63 72 79 70 74 30 40 58 20 16 4f 44 d8 56 dd 15 22 2f a4 63
f2 02 d9 c6 0b e3 c6 9b 40 f7 35 8d 34 1c db 7b 07 de e1 70 ca 
~~~~~~~~~~~~~~~~~~~~~~~

The key and nonce used are defined in {{tv-psk-2-key}}:

* key = K_2

* nonce = IV_2

Using the parameters above, the ciphertext CIPHERTEXT_2 can be computed:

~~~~~~~~~~~~~~~~~~~~~~~
CIPHERTEXT_2 (8 bytes)
ba 38 b9 a3 fc 1a 58 e9 
~~~~~~~~~~~~~~~~~~~~~~~

#### message_2

From the parameter computed in {{tv-psk-2}} and {{tv-psk-2-ciph}}, message_2 is computed, as the CBOR Sequence of the following items: (G_Y, C_R, CIPHERTEXT_2).

~~~~~~~~~~~~~~~~~~~~~~~
message_2 =
(
  h'fc3b339367a5225d53a92d380323afd035d7817b6d1be47d946f6b09a9cbdc06',
  h'c2',
  h'ba38b9a3fc1a58e9'
)
~~~~~~~~~~~~~~~~~~~~~~~

Which encodes to the following byte string:

~~~~~~~~~~~~~~~~~~~~~~~
message_2 (CBOR Sequence) (45 bytes)
58 20 fc 3b 33 93 67 a5 22 5d 53 a9 2d 38 03 23 af d0 35 d7 81 7b 6d 1b
e4 7d 94 6f 6b 09 a9 cb dc 06 41 c2 48 ba 38 b9 a3 fc 1a 58 e9 
~~~~~~~~~~~~~~~~~~~~~~~

### Message 3 {#tv-psk-3}

Since TYPE mod 4 equals 1, C_R is not omitted from data_3.

~~~~~~~~~~~~~~~~~~~~~~~
C_R (1 byte)
c2 
~~~~~~~~~~~~~~~~~~~~~~~

Data_3 is constructed, as the CBOR Sequence of the CBOR data item above.

~~~~~~~~~~~~~~~~~~~~~~~
data_3 =
(
  h'c2'
)
~~~~~~~~~~~~~~~~~~~~~~~


~~~~~~~~~~~~~~~~~~~~~~~
data_3 (CBOR Sequence) (2 bytes)
41 c2 
~~~~~~~~~~~~~~~~~~~~~~~

From data_3, CIPHERTEXT_2 ({{tv-psk-2-ciph}}), and TH_2 ({{tv-psk-2}}), compute the input to the transcript hash TH_3 = H(TH_2 , CIPHERTEXT_2, data_3), as a CBOR Sequence of these 3 data items.

~~~~~~~~~~~~~~~~~~~~~~~
( TH_2, CIPHERTEXT_2, data_3 ) (CBOR Sequence) (45 bytes)
58 20 16 4f 44 d8 56 dd 15 22 2f a4 63 f2 02 d9 c6 0b e3 c6 9b 40 f7 35
8d 34 1c db 7b 07 de e1 70 ca 48 ba 38 b9 a3 fc 1a 58 e9 41 c2 
~~~~~~~~~~~~~~~~~~~~~~~

And from there, compute the transcript hash TH_3 = SHA-256(TH_2 , CIPHERTEXT_2, data_3)

~~~~~~~~~~~~~~~~~~~~~~~
TH_3 value (32 bytes)
11 98 aa b3 ed db 61 b8 a1 b1 93 a9 e5 60 2b 5d 5f ea 76 bc 28 52 89 54
81 b5 2b 8a f5 66 d7 fe 
~~~~~~~~~~~~~~~~~~~~~~~

When encoded as a CBOR bstr, that gives:

~~~~~~~~~~~~~~~~~~~~~~~
TH_3 (CBOR-encoded) (34 bytes)
58 20 11 98 aa b3 ed db 61 b8 a1 b1 93 a9 e5 60 2b 5d 5f ea 76 bc 28 52
89 54 81 b5 2b 8a f5 66 d7 fe 
~~~~~~~~~~~~~~~~~~~~~~~

#### Key and Nonce Computation {#tv-psk-3-key}

The key and nonce for calculating the ciphertext are calculated as follows, as specified in {{key-der}}.

HKDF SHA-256 is the HKDF used (as defined by cipher suite 0).

PRK = HMAC-SHA-256(salt, G_XY)

Since this is the symmetric case, salt is the PSK:

~~~~~~~~~~~~~~~~~~~~~~~
salt (16 bytes)
a1 1f 8f 12 d0 87 6f 73 6d 2d 8f d2 6e 14 c2 de 
~~~~~~~~~~~~~~~~~~~~~~~

G_XY is the shared secret, and since the curve25519 is used, the ECDH shared secret is the output of the X25519 function.

~~~~~~~~~~~~~~~~~~~~~~~
G_XY (32 bytes)
d5 75 05 50 6d 8f 30 a8 60 a0 63 d0 1b 5b 7a d7 6a 09 4f 70 61 3b 4a e6
6c 5a 90 e5 c2 1f 23 11 
~~~~~~~~~~~~~~~~~~~~~~~

From there, PRK is computed:

~~~~~~~~~~~~~~~~~~~~~~~
PRK (32 bytes)
aa b2 f1 3c cb 1a 4f f7 96 a9 7a 32 a4 d2 fb 62 47 ef 0b 6b 06 da 04 d3
d1 06 39 4b 28 76 e2 8c 
~~~~~~~~~~~~~~~~~~~~~~~

Key K_3 is the output of HKDF-Expand(PRK, info, L).

info is defined as follows:

~~~~~~~~~~~~~~~~~~~~~~~
info for K_3 =
[
  10,
  [ null, null, null ],
  [ null, null, null ],
  [ 128, h'', h'1198aab3eddb61b8a1b193a9e5602b5d5fea76bc2852895481b52b8a
                f566d7fe']
]
~~~~~~~~~~~~~~~~~~~~~~~

Which as a CBOR encoded data item is:

~~~~~~~~~~~~~~~~~~~~~~~
info (K_3) (CBOR-encoded) (48 bytes)
84 0a 83 f6 f6 f6 83 f6 f6 f6 83 18 80 40 58 20 11 98 aa b3 ed db 61 b8
a1 b1 93 a9 e5 60 2b 5d 5f ea 76 bc 28 52 89 54 81 b5 2b 8a f5 66 d7 fe

~~~~~~~~~~~~~~~~~~~~~~~

L is the length of K_3, so 16 bytes.

From these parameters, K_3 is computed:

~~~~~~~~~~~~~~~~~~~~~~~
K_3 (16 bytes)
fe 75 e3 44 27 f8 3a ad 84 16 83 c6 6f a3 8a 62 
~~~~~~~~~~~~~~~~~~~~~~~

Nonce IV_3 is the output of HKDF-Expand(PRK, info, L).

info is defined as follows:

~~~~~~~~~~~~~~~~~~~~~~~
info for IV_3 =
[
  "IV-GENERATION",
  [ null, null, null ],
  [ null, null, null ],
  [ 104, h'', h'1198aab3eddb61b8a1b193a9e5602b5d5fea76bc2852895481b52b8a
                f566d7fe']
]
~~~~~~~~~~~~~~~~~~~~~~~

Which as a CBOR encoded data item is:

~~~~~~~~~~~~~~~~~~~~~~~
info (IV_3) (CBOR-encoded) (61 bytes)
84 6d 49 56 2d 47 45 4e 45 52 41 54 49 4f 4e 83 f6 f6 f6 83 f6 f6 f6 83
18 68 40 58 20 11 98 aa b3 ed db 61 b8 a1 b1 93 a9 e5 60 2b 5d 5f ea 76
bc 28 52 89 54 81 b5 2b 8a f5 66 d7 fe 
~~~~~~~~~~~~~~~~~~~~~~~

L is the length of IV_3, so 13 bytes.

From these parameters, IV_3 is computed:

~~~~~~~~~~~~~~~~~~~~~~~
IV_3 (13 bytes)
60 0a 33 b4 16 de 08 23 52 67 71 ec 8a 
~~~~~~~~~~~~~~~~~~~~~~~

#### Ciphertext Computation {#tv-psk-3-ciph}

COSE_Encrypt0 is computed with the following parameters. Note that AD_3 is omitted.

* empty protected header

* external_aad = TH_3

* empty plaintext, since AD_3 is omitted

From the parameters above, the Enc_structure A_3 is computed.

~~~~~~~~~~~~~~~~~~~~~~~
A_3 =
[
  "Encrypt0",
  h'',
  h'1198aab3eddb61b8a1b193a9e5602b5d5fea76bc2852895481b52b8af566d7fe'
]
~~~~~~~~~~~~~~~~~~~~~~~

Which encodes to the following byte string to be used as Additional Authenticated Data:

~~~~~~~~~~~~~~~~~~~~~~~
A_3 (CBOR-encoded) (45 bytes)
83 68 45 6e 63 72 79 70 74 30 40 58 20 11 98 aa b3 ed db 61 b8 a1 b1 93
a9 e5 60 2b 5d 5f ea 76 bc 28 52 89 54 81 b5 2b 8a f5 66 d7 fe 
~~~~~~~~~~~~~~~~~~~~~~~

The key and nonce used are defined in {{tv-psk-3-key}}:

* key = K_3

* nonce = IV_3

Using the parameters above, the ciphertext CIPHERTEXT_3 can be computed:

~~~~~~~~~~~~~~~~~~~~~~~
CIPHERTEXT_3 (8 bytes)
51 29 07 92 61 45 40 04 
~~~~~~~~~~~~~~~~~~~~~~~

#### message_3

From the parameter computed in {{tv-psk-3}} and {{tv-psk-3-ciph}}, message_3 is computed, as the CBOR Sequence of the following items: (C_R, CIPHERTEXT_3).

~~~~~~~~~~~~~~~~~~~~~~~
message_3 =
(
  h'c2',
  h'5129079261454004'
)
~~~~~~~~~~~~~~~~~~~~~~~

Which encodes to the following byte string:

~~~~~~~~~~~~~~~~~~~~~~~
message_3 (CBOR Sequence) (11 bytes)
41 c2 48 51 29 07 92 61 45 40 04 
~~~~~~~~~~~~~~~~~~~~~~~

#### OSCORE Security Context Derivation

From the previous message exchange, the Common Security Context for OSCORE {{RFC8613}} can be derived, as specified in {{exporter}}.

First af all, TH_4 is computed: TH_4 = H( TH_3, CIPHERTEXT_3 ), where the input to the hash function is the CBOR Sequence of TH_3 and CIPHERTEXT_3

~~~~~~~~~~~~~~~~~~~~~~~
( TH_3, CIPHERTEXT_3 ) (CBOR Sequence) (43 bytes)
58 20 11 98 aa b3 ed db 61 b8 a1 b1 93 a9 e5 60 2b 5d 5f ea 76 bc 28 52
89 54 81 b5 2b 8a f5 66 d7 fe 48 51 29 07 92 61 45 40 04 
~~~~~~~~~~~~~~~~~~~~~~~

And from there, compute the transcript hash TH_4 = SHA-256( TH_3, CIPHERTEXT_3 )

~~~~~~~~~~~~~~~~~~~~~~~
TH_4 value (32 bytes)
df 7c 9b 06 f5 dc 0e e8 86 0b 39 6c 78 c5 be b7 57 41 3f a7 b6 a9 cf 28
3d db 4c d4 c1 fd e4 3c 
~~~~~~~~~~~~~~~~~~~~~~~

When encoded as a CBOR bstr, that gives:

~~~~~~~~~~~~~~~~~~~~~~~
TH_4 (CBOR-encoded) (34 bytes)
58 20 df 7c 9b 06 f5 dc 0e e8 86 0b 39 6c 78 c5 be b7 57 41 3f a7 b6 a9
cf 28 3d db 4c d4 c1 fd e4 3c 
~~~~~~~~~~~~~~~~~~~~~~~

To derive the Master Secret and Master Salt the same HKDF-Expand (PRK, info, L) is used, with different info and L.

For Master Secret:

L for Master Secret = 16

~~~~~~~~~~~~~~~~~~~~~~~
info for Master Secret =
[
  "OSCORE Master Secret",
  [ null, null, null ],
  [ null, null, null ],
  [ 128, h'', h'df7c9b06f5dc0ee8860b396c78c5beb757413fa7b6a9cf283ddb4cd4
                c1fde43c']
]
~~~~~~~~~~~~~~~~~~~~~~~

When encoded as a CBOR bstr, that gives:

~~~~~~~~~~~~~~~~~~~~~~~
info (OSCORE Master Secret) (CBOR-encoded) (68 bytes)
84 74 4f 53 43 4f 52 45 20 4d 61 73 74 65 72 20 53 65 63 72 65 74 83 f6
f6 f6 83 f6 f6 f6 83 18 80 40 58 20 df 7c 9b 06 f5 dc 0e e8 86 0b 39 6c
78 c5 be b7 57 41 3f a7 b6 a9 cf 28 3d db 4c d4 c1 fd e4 3c 
~~~~~~~~~~~~~~~~~~~~~~~

Finally, the Master Secret value computed is:

~~~~~~~~~~~~~~~~~~~~~~~
OSCORE Master Secret (16 bytes)
8d 36 8f 09 26 2d c5 52 7f e7 19 e6 6c 91 63 75 
~~~~~~~~~~~~~~~~~~~~~~~

For Master Salt:

L for Master Salt = 8

~~~~~~~~~~~~~~~~~~~~~~~
info for Master Salt =
[
  "OSCORE Master Salt",
  [ null, null, null ],
  [ null, null, null ],
  [ 64, h'', h'df7c9b06f5dc0ee8860b396c78c5beb757413fa7b6a9cf283ddb4cd4
                c1fde43c']
]
~~~~~~~~~~~~~~~~~~~~~~~

When encoded as a CBOR bstr, that gives:

~~~~~~~~~~~~~~~~~~~~~~~
info (OSCORE Master Salt) (CBOR-encoded) (66 bytes)
84 72 4f 53 43 4f 52 45 20 4d 61 73 74 65 72 20 53 61 6c 74 83 f6 f6 f6
83 f6 f6 f6 83 18 40 40 58 20 df 7c 9b 06 f5 dc 0e e8 86 0b 39 6c 78 c5
be b7 57 41 3f a7 b6 a9 cf 28 3d db 4c d4 c1 fd e4 3c 
~~~~~~~~~~~~~~~~~~~~~~~

Finally, the Master Salt value computed is:

~~~~~~~~~~~~~~~~~~~~~~~
OSCORE Master Salt (8 bytes)
4d b7 06 58 c5 e9 9f b6 
~~~~~~~~~~~~~~~~~~~~~~~

The Client's Sender ID takes the value of C_R:

~~~~~~~~~~~~~~~~~~~~~~~
Client's OSCORE Sender ID (1 byte)
c2 
~~~~~~~~~~~~~~~~~~~~~~~

The Server's Sender ID takes the value of C_I:

~~~~~~~~~~~~~~~~~~~~~~~
Server's OSCORE Sender ID (1 byte)
c1 
~~~~~~~~~~~~~~~~~~~~~~~

The algorithms are those negociated in the cipher suite:

~~~~~~~~~~~~~~~~~~~~~~~
AEAD Algorithm
10
~~~~~~~~~~~~~~~~~~~~~~~


~~~~~~~~~~~~~~~~~~~~~~~
HMAC Algorithm
5
~~~~~~~~~~~~~~~~~~~~~~~


## Test Vectors for EDHOC Authenticated with Static Diffie-Hellman Keys

EDHOC with static Diffie-Hellman keys and MAC authentication is used:

~~~~~~~~~~~~~~~~~~~~~~~
method (MAC Authentication)
3
~~~~~~~~~~~~~~~~~~~~~~~

CoaP is used as transport and the Initiator acts as CoAP client:

~~~~~~~~~~~~~~~~~~~~~~~
corr (Initiator can correlate message_1 and message_2)
1
~~~~~~~~~~~~~~~~~~~~~~~

No unprotected opaque auxiliary data is sent in the message exchanges.

The pre-defined Cipher Suite 0 is in place both on Initiator and Responder, see {{cipher-suites}}.

### Input for the Initiator {#ss-tv-input-u}

The following are the parameters that are set in the Initiator before the first message exchange.

~~~~~~~~~~~~~~~~~~~~~~~
Initiator's private static DH authentication key (I) (32 bytes)
be 55 8a 0e 56 34 23 ff 74 f6 d7 7a 36 8c 35 9d 4c 21 be d2 ef 1d 09 41
0d 71 6c 0a e2 64 9c 19 
~~~~~~~~~~~~~~~~~~~~~~~


~~~~~~~~~~~~~~~~~~~~~~~
Initiator's public static DH authentication key (G_I) (32 bytes)
6e 5d 68 76 a1 78 15 6c a0 b8 1d c8 0f 81 06 0f a1 a5 d1 35 13 d6 14 bc
c2 85 37 ef 98 90 06 44 
~~~~~~~~~~~~~~~~~~~~~~~


~~~~~~~~~~~~~~~~~~~~~~~
kid value to identify the Initiator's public DH authentication key (kid_I) (1 byte)
a7 
~~~~~~~~~~~~~~~~~~~~~~~

This test vector uses COSE_Key objects to store the raw public keys. Moreover, EC2 keys with curve X25519 are used. That is in agreement with the Cipher Suite 0.

~~~~~~~~~~~~~~~~~~~~~~~
CRED_I =
<< {
  1:  1,
 -1:  4,
 -2:  h'6e5d6876a178156ca0b81dc80f81060fa1a5d13513d614bcc28537ef98900644
        '
} >>
~~~~~~~~~~~~~~~~~~~~~~~


~~~~~~~~~~~~~~~~~~~~~~~
CRED_I (bstr-wrapped COSE_Key) (CBOR-encoded) (42 bytes)
58 28 a3 01 01 20 04 21 58 20 6e 5d 68 76 a1 78 15 6c a0 b8 1d c8 0f 81
06 0f a1 a5 d1 35 13 d6 14 bc c2 85 37 ef 98 90 06 44 
~~~~~~~~~~~~~~~~~~~~~~~

Because COSE_Keys are used, and because kid = h'a7':
~~~~~~~~~~~~~~~~~~~~~~~
ID_CRED_I =
{ 
  4:  h'a7'
}
~~~~~~~~~~~~~~~~~~~~~~~

Note that since the map for ID_CRED_I contains a single 'kid' parameter, ID_CRED_I is used when transported in the protected header of the COSE Object, but only kid_I is used when added to the plaintext (see {{asym-msg3-proc}}):

~~~~~~~~~~~~~~~~~~~~~~~
ID_CRED_I (in protected header) (CBOR-encoded) (5 bytes)
44 a1 04 41 a7 
~~~~~~~~~~~~~~~~~~~~~~~


~~~~~~~~~~~~~~~~~~~~~~~
kid_I (in plaintext) (CBOR-encoded) (2 bytes)
41 a7 
~~~~~~~~~~~~~~~~~~~~~~~

### Input for the Responder {#ss-tv-input-v}

The following are the parameters that are set in the Responder before the first message exchange.

~~~~~~~~~~~~~~~~~~~~~~~
Responder's private static DH authentication key (R) (32 bytes)
25 d8 0d 45 a1 1b 37 2d 5a 23 57 f9 96 ed 04 8e 26 14 ab 8a 40 66 2b 89
91 2a 83 77 9d 58 2c 85 
~~~~~~~~~~~~~~~~~~~~~~~


~~~~~~~~~~~~~~~~~~~~~~~
Responder's private static DH authentication key (G_R) (32 bytes)
32 82 44 f6 cd f5 f1 27 22 50 d7 cf bb a2 68 34 fb ef 25 e8 46 db 8b af
89 0f aa 8d 7e f6 e6 73 
~~~~~~~~~~~~~~~~~~~~~~~


~~~~~~~~~~~~~~~~~~~~~~~
kid value to identify the Responder's public authentication key (kid_R) (1 byte)
a8 
~~~~~~~~~~~~~~~~~~~~~~~

This test vector uses COSE_Key objects to store the raw public keys. Moreover, EC2 keys with curve X25519 are used. That is in agreement with the Cipher Suite 0.

~~~~~~~~~~~~~~~~~~~~~~~
CRED_R =
<< {
  1:  1,
 -1:  4,
 -2:  h'328244f6cdf5f1272250d7cfbba26834fbef25e846db8baf890faa8d7ef6e673
        '
} >>
~~~~~~~~~~~~~~~~~~~~~~~


~~~~~~~~~~~~~~~~~~~~~~~
CRED_R (bstr-wrapped COSE_Key) (CBOR-encoded) (42 bytes)
58 28 a3 01 01 20 04 21 58 20 32 82 44 f6 cd f5 f1 27 22 50 d7 cf bb a2
68 34 fb ef 25 e8 46 db 8b af 89 0f aa 8d 7e f6 e6 73 
~~~~~~~~~~~~~~~~~~~~~~~

Because COSE_Keys are used, and because kid = h'a8':
~~~~~~~~~~~~~~~~~~~~~~~
ID_CRED_R =
{ 
  4:  h'a8'
}
~~~~~~~~~~~~~~~~~~~~~~~

Note that since the map for ID_CRED_R contains a single 'kid' parameter, ID_CRED_R is used when transported in the protected header of the COSE Object, but only the kid_R is used when added to the plaintext (see {{asym-msg3-proc}}):

~~~~~~~~~~~~~~~~~~~~~~~
ID_CRED_R (in protected header) (CBOR-encoded) (5 bytes)
44 a1 04 41 a8 
~~~~~~~~~~~~~~~~~~~~~~~


~~~~~~~~~~~~~~~~~~~~~~~
kid_R (in plaintext) (CBOR-encoded) (2 bytes)
41 a8 
~~~~~~~~~~~~~~~~~~~~~~~

### Message 1 {#tv-ss-1}

From the input parameters (in {{rpk-tv-input-u}}):

~~~~~~~~~~~~~~~~~~~~~~~
TYPE (4 * method + corr)
13
~~~~~~~~~~~~~~~~~~~~~~~


~~~~~~~~~~~~~~~~~~~~~~~
suite
0
~~~~~~~~~~~~~~~~~~~~~~~


~~~~~~~~~~~~~~~~~~~~~~~
SUITES_I : suite
0
~~~~~~~~~~~~~~~~~~~~~~~


~~~~~~~~~~~~~~~~~~~~~~~
Initiator's ephemeral private key (I) (32 bytes)
11 34 9f 62 e8 d8 13 ed 79 d2 7d 57 dd 41 b9 af ec 4d d9 5e c4 d2 88 0e
72 0d 50 e6 37 fe c9 19 
~~~~~~~~~~~~~~~~~~~~~~~


~~~~~~~~~~~~~~~~~~~~~~~
G_X (X-coordinate of the ephemeral public key of the Initiator) (32 bytes)
65 22 d2 2d 50 87 46 6e a1 22 9b fb ee b8 52 9e 56 e1 d9 cb c7 79 cb 36
74 a9 42 91 fd 9b 1a 08 
~~~~~~~~~~~~~~~~~~~~~~~


~~~~~~~~~~~~~~~~~~~~~~~
C_I (Connection identifier chosen by the Initiator) (1 byte)
c7 
~~~~~~~~~~~~~~~~~~~~~~~

No AD_1 is provided, so AD_1 is absent from message_1.

Message_1 is constructed, as the CBOR Sequence of the CBOR data items above.

~~~~~~~~~~~~~~~~~~~~~~~
message_1 =
(
  13,
  0,
  h'6522d22d5087466ea1229bfbeeb8529e56e1d9cbc779cb3674a94291fd9b1a08',
  h'c7'
)
~~~~~~~~~~~~~~~~~~~~~~~


~~~~~~~~~~~~~~~~~~~~~~~
message_1 (CBOR Sequence) (38 bytes)
0d 00 58 20 65 22 d2 2d 50 87 46 6e a1 22 9b fb ee b8 52 9e 56 e1 d9 cb
c7 79 cb 36 74 a9 42 91 fd 9b 1a 08 41 c7 
~~~~~~~~~~~~~~~~~~~~~~~

### Message 2 {#tv-ss-2}

Since corr equals 1, C_I is omitted from data_2.

The Responder generates an ephemeral ECDH key pair:

~~~~~~~~~~~~~~~~~~~~~~~
Responder's ephemeral private key (32 bytes)
25 08 17 7e 3f 55 3e c0 5f 24 26 f5 0f 21 0c 7a bf 54 2e 53 23 b8 45 9e
17 52 33 be 6e 67 bb 91 
~~~~~~~~~~~~~~~~~~~~~~~


~~~~~~~~~~~~~~~~~~~~~~~
G_Y (X-coordinate of the ephemeral public key of the Responder) (32 bytes)
4a cd 37 41 73 cc 6f 2b 55 c7 59 ef 6e 78 2c a3 07 e7 98 21 f4 da 89 a6
78 07 7f 8b 79 6a 3f 65 
~~~~~~~~~~~~~~~~~~~~~~~

The Responder also choses a connection identifier:

~~~~~~~~~~~~~~~~~~~~~~~
C_R (Connection identifier chosen by the Responder) (1 byte)
c8 
~~~~~~~~~~~~~~~~~~~~~~~

Data_2 is constructed, as the CBOR Sequence of the CBOR data items above.


~~~~~~~~~~~~~~~~~~~~~~~
data_2 =
(
  h'4acd374173cc6f2b55c759ef6e782ca307e79821f4da89a678077f8b796a3f65',
  h'c8'
)
~~~~~~~~~~~~~~~~~~~~~~~


~~~~~~~~~~~~~~~~~~~~~~~
data_2 (CBOR Sequence) (36 bytes)
58 20 4a cd 37 41 73 cc 6f 2b 55 c7 59 ef 6e 78 2c a3 07 e7 98 21 f4 da
89 a6 78 07 7f 8b 79 6a 3f 65 41 c8 
~~~~~~~~~~~~~~~~~~~~~~~

From data_2 and message_1 (from {{tv-ss-1}}), compute the input to the transcript hash TH_2 = H( message_1, data_2 ), as a CBOR Sequence of these 2 data items.


~~~~~~~~~~~~~~~~~~~~~~~
( message_1, data_2 ) (CBOR Sequence) (74 bytes)
0d 00 58 20 65 22 d2 2d 50 87 46 6e a1 22 9b fb ee b8 52 9e 56 e1 d9 cb
c7 79 cb 36 74 a9 42 91 fd 9b 1a 08 41 c7 58 20 4a cd 37 41 73 cc 6f 2b
55 c7 59 ef 6e 78 2c a3 07 e7 98 21 f4 da 89 a6 78 07 7f 8b 79 6a 3f 65
41 c8 
~~~~~~~~~~~~~~~~~~~~~~~

And from there, compute the transcript hash TH_2 = SHA-256( message_1, data_2 )


~~~~~~~~~~~~~~~~~~~~~~~
TH_2 value (32 bytes)
4f 92 2e 15 50 2c ec fb 04 b3 af d8 05 1f ae 4f 98 d5 6b 24 51 c4 65 23
18 e0 ed 18 26 cb 21 c3 
~~~~~~~~~~~~~~~~~~~~~~~

When encoded as a CBOR bstr, that gives:


~~~~~~~~~~~~~~~~~~~~~~~
TH_2 (CBOR-encoded) (34 bytes)
58 20 4f 92 2e 15 50 2c ec fb 04 b3 af d8 05 1f ae 4f 98 d5 6b 24 51 c4
65 23 18 e0 ed 18 26 cb 21 c3 
~~~~~~~~~~~~~~~~~~~~~~~

#### MAC Computation {#tv-ss-2-mac}

Since method equals 3, a COSE_Encrypt0 is calculated.

##### Key and Nonce Computation {#tv-ss-2-key-mac}

The key and nonce for calculating the MAC are calculated as follows, as specified in {{key-der}}.

HKDF SHA-256 is the HKDF used (as defined by cipher suite 0).

PRK_2 = HMAC-SHA-256 (salt, G_XY)

Since this is the asymmetric case, salt is the empty byte string.

G_XY is the ECDH shared secret, and since the curve25519 is used, the ECDH shared secret is the output of the X25519 function.

~~~~~~~~~~~~~~~~~~~~~~~
G_XY (32 bytes)
12 2d f9 44 2b 2e 81 3c 3a 00 29 04 af 63 99 e0 f3 1c d5 96 7d 49 2a e6
02 0b c2 d7 7c cb 4f 28 
~~~~~~~~~~~~~~~~~~~~~~~

From there, PRK_2 is computed:

~~~~~~~~~~~~~~~~~~~~~~~
PRK_2 (32 bytes)
f1 8c ca 1d af 06 1a f1 40 94 19 26 19 a4 dd 5e 9e 41 94 fc 42 fe 5e 20
d0 27 9d 8d d3 1f ad 8f 
~~~~~~~~~~~~~~~~~~~~~~~

PRK_R = HKDF-Extract (PRK_2, G_RX)

G_RX is the ECDH shared secret calculated from G_X received in {{tv-ss-1}} and R in {{ss-tv-input-v}}, and since the curve25519 is used, the ECDH shared secret is the output of the X25519 function.

~~~~~~~~~~~~~~~~~~~~~~~
G_RX (32 bytes)
5f 40 10 ca 84 52 1e 2d e8 71 7c f4 d9 66 ab 33 96 86 6c 4c 74 f3 85 96
dd 8f 23 b6 c4 83 99 2e 
~~~~~~~~~~~~~~~~~~~~~~~

From there, PRK_R is computed:

~~~~~~~~~~~~~~~~~~~~~~~
PRK_R (32 bytes)
08 4a 87 01 49 07 ed 85 12 90 42 55 e1 8a df a8 39 53 92 28 29 48 8f f4
66 44 87 1e 07 1d 42 80 
~~~~~~~~~~~~~~~~~~~~~~~

Key K_R is the output of HKDF-Expand(PRK_R, info, L).

info is defined as follows:

~~~~~~~~~~~~~~~~~~~~~~~
info for K_R =
[
  10,
  [ null, null, null ],
  [ null, null, null ],
  [ 128, h'', h'4f922e15502cecfb04b3afd8051fae4f98d56b2451c4652318e0ed18
                26cb21c3']
]
~~~~~~~~~~~~~~~~~~~~~~~

Which as a CBOR encoded data item is:

~~~~~~~~~~~~~~~~~~~~~~~
info (K_R) (CBOR-encoded) (48 bytes)
84 0a 83 f6 f6 f6 83 f6 f6 f6 83 18 80 40 58 20 4f 92 2e 15 50 2c ec fb
04 b3 af d8 05 1f ae 4f 98 d5 6b 24 51 c4 65 23 18 e0 ed 18 26 cb 21 c3

~~~~~~~~~~~~~~~~~~~~~~~

L is the length of K_R, so 16 bytes.

From these parameters, K_R is computed:

~~~~~~~~~~~~~~~~~~~~~~~
K_R (16 bytes)
54 3b aa 32 53 c2 6e df e8 a7 00 93 62 98 94 ea 
~~~~~~~~~~~~~~~~~~~~~~~

Nonce IV_R is the output of HKDF-Expand(PRK_R, info, L).

info is defined as follows:

~~~~~~~~~~~~~~~~~~~~~~~
info for IV_R =
[
  "IV-GENERATION",
  [ null, null, null ],
  [ null, null, null ],
  [ 104, h'', h'4f922e15502cecfb04b3afd8051fae4f98d56b2451c4652318e0ed18
                26cb21c3']
]
~~~~~~~~~~~~~~~~~~~~~~~

Which as a CBOR encoded data item is:

~~~~~~~~~~~~~~~~~~~~~~~
info (IV_R) (CBOR-encoded) (61 bytes)
84 6d 49 56 2d 47 45 4e 45 52 41 54 49 4f 4e 83 f6 f6 f6 83 f6 f6 f6 83
18 68 40 58 20 4f 92 2e 15 50 2c ec fb 04 b3 af d8 05 1f ae 4f 98 d5 6b
24 51 c4 65 23 18 e0 ed 18 26 cb 21 c3 
~~~~~~~~~~~~~~~~~~~~~~~

L is the length of IV_R, so 13 bytes.

From these parameters, IV_R is computed:

~~~~~~~~~~~~~~~~~~~~~~~
IV_R (13 bytes)
1d 41 f4 41 cf e6 2f 07 19 84 17 41 14 
~~~~~~~~~~~~~~~~~~~~~~~

##### MAC Computation {#tv-ss-2-mac-comp}

COSE_Encrypt0 is computed with the following parameters.

* protected header = CBOR-encoded ID_CRED_R

* external_aad = CBOR Sequence of TH_2 and CRED_R, in this order

* empty plaintext


~~~~~~~~~~~~~~~~~~~~~~~
Protected header: ID_CRED_R (CBOR-encoded) (5 bytes)
44 a1 04 41 a8 
~~~~~~~~~~~~~~~~~~~~~~~

The external_aad is the following:

~~~~~~~~~~~~~~~~~~~~~~~
(TH_2 , CRED_R ) (CBOR Sequence) (72 bytes)
4f 92 2e 15 50 2c ec fb 04 b3 af d8 05 1f ae 4f 98 d5 6b 24 51 c4 65 23
18 e0 ed 18 26 cb 21 c3 a3 01 01 20 04 21 58 20 32 82 44 f6 cd f5 f1 27
22 50 d7 cf bb a2 68 34 fb ef 25 e8 46 db 8b af 89 0f aa 8d 7e f6 e6 73

~~~~~~~~~~~~~~~~~~~~~~~

Which encodes to the following byte string:

~~~~~~~~~~~~~~~~~~~~~~~
(TH_2 , CRED_R ) (CBOR Sequence) (CBOR-encoded) (74 bytes)
58 48 4f 92 2e 15 50 2c ec fb 04 b3 af d8 05 1f ae 4f 98 d5 6b 24 51 c4
65 23 18 e0 ed 18 26 cb 21 c3 a3 01 01 20 04 21 58 20 32 82 44 f6 cd f5
f1 27 22 50 d7 cf bb a2 68 34 fb ef 25 e8 46 db 8b af 89 0f aa 8d 7e f6
e6 73 
~~~~~~~~~~~~~~~~~~~~~~~

From the parameters above, the Enc_structure A_2 is computed.

~~~~~~~~~~~~~~~~~~~~~~~
A_R =
[
  "Encrypt0",
  h'a10441a8',
  h'4f922e15502cecfb04b3afd8051fae4f98d56b2451c4652318e0ed1826cb21c3a301
    012004215820328244f6cdf5f1272250d7cfbba26834fbef25e846db8baf890faa8d
    7ef6e673'
]
~~~~~~~~~~~~~~~~~~~~~~~

Which encodes to the following byte string to be used as Additional Authenticated Data:

~~~~~~~~~~~~~~~~~~~~~~~
A_R (CBOR-encoded) (89 bytes)
83 68 45 6e 63 72 79 70 74 30 44 a1 04 41 a8 58 48 4f 92 2e 15 50 2c ec
fb 04 b3 af d8 05 1f ae 4f 98 d5 6b 24 51 c4 65 23 18 e0 ed 18 26 cb 21
c3 a3 01 01 20 04 21 58 20 32 82 44 f6 cd f5 f1 27 22 50 d7 cf bb a2 68
34 fb ef 25 e8 46 db 8b af 89 0f aa 8d 7e f6 e6 73 
~~~~~~~~~~~~~~~~~~~~~~~

The key and nonce used are defined in {{tv-ss-2-key}}:

* key = K_R

* nonce = IV_R

Using the parameters above, the ciphertext CIPHERTEXT_R can be computed:

~~~~~~~~~~~~~~~~~~~~~~~
CIPHERTEXT_R (9 bytes)
00 00 00 00 00 00 00 00 00 
~~~~~~~~~~~~~~~~~~~~~~~

#### Key and Nonce Computation {#tv-ss-2-key}

The key and nonce for calculating the ciphertext are calculated as follows, as specified in {{key-der}}.

HKDF SHA-256 is the HKDF used (as defined by cipher suite 0).

PRK_2  = HMAC-SHA-256(salt, G_XY) as defined in {{tv-ss-2-key-mac}}


~~~~~~~~~~~~~~~~~~~~~~~
PRK_2 (32 bytes)
f1 8c ca 1d af 06 1a f1 40 94 19 26 19 a4 dd 5e 9e 41 94 fc 42 fe 5e 20
d0 27 9d 8d d3 1f ad 8f 
~~~~~~~~~~~~~~~~~~~~~~~

Key K_2 is the output of HKDF-Expand(PRK_2, info, L).

info is defined as follows:

~~~~~~~~~~~~~~~~~~~~~~~
info for K_2 =
[
  10,
  [ null, null, null ],
  [ null, null, null ],
  [ 128, h'', h'4f922e15502cecfb04b3afd8051fae4f98d56b2451c4652318e0ed18
                26cb21c3']
]
~~~~~~~~~~~~~~~~~~~~~~~

Which as a CBOR encoded data item is:

~~~~~~~~~~~~~~~~~~~~~~~
info (K_2) (CBOR-encoded) (48 bytes)
84 0a 83 f6 f6 f6 83 f6 f6 f6 83 18 80 40 58 20 4f 92 2e 15 50 2c ec fb
04 b3 af d8 05 1f ae 4f 98 d5 6b 24 51 c4 65 23 18 e0 ed 18 26 cb 21 c3

~~~~~~~~~~~~~~~~~~~~~~~

L is the length of K_2, so 16 bytes.

From these parameters, K_2 is computed:

~~~~~~~~~~~~~~~~~~~~~~~
K_2 (16 bytes)
73 e3 58 ef b5 7b 8f fa 15 c0 a2 ee 3e ed ed e1 
~~~~~~~~~~~~~~~~~~~~~~~

Nonce IV_2 is the output of HKDF-Expand(PRK, info, L).

info is defined as follows:

~~~~~~~~~~~~~~~~~~~~~~~
info for IV_2 =
[
  "IV-GENERATION",
  [ null, null, null ],
  [ null, null, null ],
  [ 104, h'', h'4f922e15502cecfb04b3afd8051fae4f98d56b2451c4652318e0ed18
                26cb21c3']
]
~~~~~~~~~~~~~~~~~~~~~~~

Which as a CBOR encoded data item is:

~~~~~~~~~~~~~~~~~~~~~~~
info (IV_2) (CBOR-encoded) (61 bytes)
84 6d 49 56 2d 47 45 4e 45 52 41 54 49 4f 4e 83 f6 f6 f6 83 f6 f6 f6 83
18 68 40 58 20 4f 92 2e 15 50 2c ec fb 04 b3 af d8 05 1f ae 4f 98 d5 6b
24 51 c4 65 23 18 e0 ed 18 26 cb 21 c3 
~~~~~~~~~~~~~~~~~~~~~~~

L is the length of IV_2, so 13 bytes.

From these parameters, IV_2 is computed:

~~~~~~~~~~~~~~~~~~~~~~~
IV_2 (13 bytes)
2c 41 5f 98 b2 9a 9c f7 0f 87 8c d0 d3 
~~~~~~~~~~~~~~~~~~~~~~~

#### Ciphertext Computation {#tv-ss-2-ciph}

COSE_Encrypt0 is computed with the following parameters. Note that AD_2 is omitted.

* empty protected header

* external_aad = TH_2

* plaintext = CBOR Sequence of the items kid_R, CIPHERTEXT_R, in this order.

with kid_R taken from {{ss-tv-input-v}}, and CIPHERTEXT_R as calculated in {{tv-ss-2-mac-comp}}.

The plaintext is the following:

~~~~~~~~~~~~~~~~~~~~~~~
P_2  (12 bytes)
41 a8 49 00 00 00 00 00 00 00 00 00 
~~~~~~~~~~~~~~~~~~~~~~~

From the parameters above, the Enc_structure A_2 is computed.

~~~~~~~~~~~~~~~~~~~~~~~
A_2 =
[
  "Encrypt0",
  h'',
  h'4f922e15502cecfb04b3afd8051fae4f98d56b2451c4652318e0ed1826cb21c3'
]
~~~~~~~~~~~~~~~~~~~~~~~

Which encodes to the following byte string to be used as Additional Authenticated Data:

~~~~~~~~~~~~~~~~~~~~~~~
A_2 (CBOR-encoded) (45 bytes)
83 68 45 6e 63 72 79 70 74 30 40 58 20 4f 92 2e 15 50 2c ec fb 04 b3 af
d8 05 1f ae 4f 98 d5 6b 24 51 c4 65 23 18 e0 ed 18 26 cb 21 c3 
~~~~~~~~~~~~~~~~~~~~~~~

The key and nonce used are defined in {{tv-ss-2-key}}:

* key = K_2

* nonce = IV_2

Using the parameters above, the ciphertext CIPHERTEXT_2 can be computed:

~~~~~~~~~~~~~~~~~~~~~~~
CIPHERTEXT_2 (20 bytes)
21 31 6c 24 04 22 65 0f 93 98 75 17 97 be 3e c2 98 d1 3e bd 
~~~~~~~~~~~~~~~~~~~~~~~

#### message_2

From the parameter computed in {{tv-ss-2}} and {{tv-ss-2-ciph}}, message_2 is computed, as the CBOR Sequence of the following items: (G_Y, C_R, CIPHERTEXT_2).


~~~~~~~~~~~~~~~~~~~~~~~
message_2 =
(
  h'4acd374173cc6f2b55c759ef6e782ca307e79821f4da89a678077f8b796a3f65',
  h'c8',
  h'21316c240422650f9398751797be3ec298d13ebd'
)
~~~~~~~~~~~~~~~~~~~~~~~

Which encodes to the following byte string:

~~~~~~~~~~~~~~~~~~~~~~~
message_2 (CBOR Sequence) (57 bytes)
58 20 4a cd 37 41 73 cc 6f 2b 55 c7 59 ef 6e 78 2c a3 07 e7 98 21 f4 da
89 a6 78 07 7f 8b 79 6a 3f 65 41 c8 54 21 31 6c 24 04 22 65 0f 93 98 75
17 97 be 3e c2 98 d1 3e bd 
~~~~~~~~~~~~~~~~~~~~~~~

### Message 3 {#tv-ss-3}

Since TYPE mod 4 equals 1, C_R is not omitted from data_3.


~~~~~~~~~~~~~~~~~~~~~~~
C_R (1 byte)
c8 
~~~~~~~~~~~~~~~~~~~~~~~

Data_3 is constructed, as the CBOR Sequence of the CBOR data item above.

~~~~~~~~~~~~~~~~~~~~~~~
data_3 =
(
  h'c8'
)
~~~~~~~~~~~~~~~~~~~~~~~


~~~~~~~~~~~~~~~~~~~~~~~
data_3 (CBOR Sequence) (2 bytes)
41 c8 
~~~~~~~~~~~~~~~~~~~~~~~

From data_3, CIPHERTEXT_2 ({{tv-rpk-2-ciph}}), and TH_2 ({{tv-rpk-2}}), compute the input to the transcript hash TH_2 = H(TH_2 , CIPHERTEXT_2, data_3), as a CBOR Sequence of these 3 data items.

~~~~~~~~~~~~~~~~~~~~~~~
( TH_2, CIPHERTEXT_2, data_3 ) (CBOR Sequence) (57 bytes)
58 20 4f 92 2e 15 50 2c ec fb 04 b3 af d8 05 1f ae 4f 98 d5 6b 24 51 c4
65 23 18 e0 ed 18 26 cb 21 c3 54 21 31 6c 24 04 22 65 0f 93 98 75 17 97
be 3e c2 98 d1 3e bd 41 c8 
~~~~~~~~~~~~~~~~~~~~~~~

And from there, compute the transcript hash TH_3 = SHA-256(TH_2 , CIPHERTEXT_2, data_3)

~~~~~~~~~~~~~~~~~~~~~~~
TH_3 value (32 bytes)
4d 2d 24 a8 fc 09 04 02 8a 97 40 62 2b c2 2f 6f 53 4c aa 57 3a 15 1c 74
c0 c4 bf 6c ce dd b0 3e 
~~~~~~~~~~~~~~~~~~~~~~~

When encoded as a CBOR bstr, that gives:


~~~~~~~~~~~~~~~~~~~~~~~
TH_3 (CBOR-encoded) (34 bytes)
58 20 4d 2d 24 a8 fc 09 04 02 8a 97 40 62 2b c2 2f 6f 53 4c aa 57 3a 15
1c 74 c0 c4 bf 6c ce dd b0 3e 
~~~~~~~~~~~~~~~~~~~~~~~

#### MAC Computation {#tv-ss-3-mac}

Since method equals 3, a COSE_Encrypt0 is calculated.

##### Key and Nonce Computation {#tv-ss-3-key-mac}

The key and nonce for calculating the MAC are calculated as follows, as specified in {{key-der}}.

HKDF SHA-256 is the HKDF used (as defined by cipher suite 0).

PRK_I = HMAC-SHA-256 (PRK_3, G_IY)

with PRK_3 = PRK_R.

G_IY is the ECDH shared secret, and since the curve25519 is used, the ECDH shared secret is the output of the X25519 function.

~~~~~~~~~~~~~~~~~~~~~~~
G_IY (32 bytes)
9f 70 4c 69 61 ae 11 4e 0f 06 53 e3 fa 72 0d 98 9d e4 79 63 b5 6f a3 a3
c3 c6 5f 0a 5b 6b 7f 20 
~~~~~~~~~~~~~~~~~~~~~~~

From there, PRK_I is computed:

~~~~~~~~~~~~~~~~~~~~~~~
PRK_I (32 bytes)
f1 df af 80 cb 4b b6 a8 1c 83 ad 2e d7 bb ed d5 ac bc 7b b2 b2 a8 a5 ea
8d fb 24 b9 45 1f fe 20 
~~~~~~~~~~~~~~~~~~~~~~~

Key K_I is the output of HKDF-Expand(PRK_I, info, L).

info is defined as follows:

~~~~~~~~~~~~~~~~~~~~~~~
info for K_I =
[
  10,
  [ null, null, null ],
  [ null, null, null ],
  [ 128, h'', h'4d2d24a8fc0904028a9740622bc22f6f534caa573a151c74c0c4bf6c
                ceddb03e']
]
~~~~~~~~~~~~~~~~~~~~~~~

Which as a CBOR encoded data item is:

~~~~~~~~~~~~~~~~~~~~~~~
info (K_I) (CBOR-encoded) (48 bytes)
84 0a 83 f6 f6 f6 83 f6 f6 f6 83 18 80 40 58 20 4d 2d 24 a8 fc 09 04 02
8a 97 40 62 2b c2 2f 6f 53 4c aa 57 3a 15 1c 74 c0 c4 bf 6c ce dd b0 3e

~~~~~~~~~~~~~~~~~~~~~~~

L is the length of K_I, so 16 bytes.

From these parameters, K_I is computed:

~~~~~~~~~~~~~~~~~~~~~~~
K_I (16 bytes)
78 00 55 60 2a 5a d1 72 eb a4 76 f7 e3 ff 48 c8 
~~~~~~~~~~~~~~~~~~~~~~~

Nonce IV_I is the output of HKDF-Expand(PRK_I, info, L).

info is defined as follows:

~~~~~~~~~~~~~~~~~~~~~~~
info for IV_I =
[
  "IV-GENERATION",
  [ null, null, null ],
  [ null, null, null ],
  [ 104, h'', h'4d2d24a8fc0904028a9740622bc22f6f534caa573a151c74c0c4bf6c
                ceddb03e']
]
~~~~~~~~~~~~~~~~~~~~~~~

Which as a CBOR encoded data item is:

~~~~~~~~~~~~~~~~~~~~~~~
info (IV_I) (CBOR-encoded) (61 bytes)
84 6d 49 56 2d 47 45 4e 45 52 41 54 49 4f 4e 83 f6 f6 f6 83 f6 f6 f6 83
18 68 40 58 20 4d 2d 24 a8 fc 09 04 02 8a 97 40 62 2b c2 2f 6f 53 4c aa
57 3a 15 1c 74 c0 c4 bf 6c ce dd b0 3e 
~~~~~~~~~~~~~~~~~~~~~~~

L is the length of IV_I, so 13 bytes.

From these parameters, IV_I is computed:

~~~~~~~~~~~~~~~~~~~~~~~
IV_I (13 bytes)
e1 1e bc 09 e7 cf 76 10 84 d8 00 56 1e 
~~~~~~~~~~~~~~~~~~~~~~~

##### MAC Computation {#tv-ss-3-mac-comp}

COSE_Encrypt0 is computed with the following parameters.

* protected header = CBOR-encoded ID_CRED_I

* external_aad = CBOR Sequence of TH_3 and CRED_I, in this order

* empty plaintext


~~~~~~~~~~~~~~~~~~~~~~~
Protected header: ID_CRED_I (CBOR-encoded) (5 bytes)
44 a1 04 41 a7 
~~~~~~~~~~~~~~~~~~~~~~~

The external_aad is the following:

~~~~~~~~~~~~~~~~~~~~~~~
(TH_3 , CRED_I ) (CBOR Sequence) (72 bytes)
4d 2d 24 a8 fc 09 04 02 8a 97 40 62 2b c2 2f 6f 53 4c aa 57 3a 15 1c 74
c0 c4 bf 6c ce dd b0 3e a3 01 01 20 04 21 58 20 6e 5d 68 76 a1 78 15 6c
a0 b8 1d c8 0f 81 06 0f a1 a5 d1 35 13 d6 14 bc c2 85 37 ef 98 90 06 44

~~~~~~~~~~~~~~~~~~~~~~~

Which encodes to the following byte string:

~~~~~~~~~~~~~~~~~~~~~~~
(TH_3 , CRED_I ) (CBOR Sequence) (CBOR-encoded) (74 bytes)
58 48 4d 2d 24 a8 fc 09 04 02 8a 97 40 62 2b c2 2f 6f 53 4c aa 57 3a 15
1c 74 c0 c4 bf 6c ce dd b0 3e a3 01 01 20 04 21 58 20 6e 5d 68 76 a1 78
15 6c a0 b8 1d c8 0f 81 06 0f a1 a5 d1 35 13 d6 14 bc c2 85 37 ef 98 90
06 44 
~~~~~~~~~~~~~~~~~~~~~~~

From the parameters above, the Enc_structure A_I is computed.

~~~~~~~~~~~~~~~~~~~~~~~
A_I =
[
  "Encrypt0",
  h'a10441a7',
  h'4d2d24a8fc0904028a9740622bc22f6f534caa573a151c74c0c4bf6cceddb03ea301
    0120042158206e5d6876a178156ca0b81dc80f81060fa1a5d13513d614bcc28537ef
    98900644'
]
~~~~~~~~~~~~~~~~~~~~~~~

Which encodes to the following byte string to be used as Additional Authenticated Data:

~~~~~~~~~~~~~~~~~~~~~~~
A_I (CBOR-encoded) (89 bytes)
83 68 45 6e 63 72 79 70 74 30 44 a1 04 41 a7 58 48 4d 2d 24 a8 fc 09 04
02 8a 97 40 62 2b c2 2f 6f 53 4c aa 57 3a 15 1c 74 c0 c4 bf 6c ce dd b0
3e a3 01 01 20 04 21 58 20 6e 5d 68 76 a1 78 15 6c a0 b8 1d c8 0f 81 06
0f a1 a5 d1 35 13 d6 14 bc c2 85 37 ef 98 90 06 44 
~~~~~~~~~~~~~~~~~~~~~~~

The key and nonce used are defined in {{tv-ss-3-key}}:

* key = K_I

* nonce = IV_I

Using the parameters above, the ciphertext CIPHERTEXT_I can be computed:

~~~~~~~~~~~~~~~~~~~~~~~
CIPHERTEXT_I (9 bytes)
00 00 00 00 00 00 00 00 00 
~~~~~~~~~~~~~~~~~~~~~~~

#### Key and Nonce Computation {#tv-ss-3-key}

The key and nonce for calculating the ciphertext are calculated as follows, as specified in {{key-der}}.

HKDF SHA-256 is the HKDF used (as defined by cipher suite 0).

PRK_3 = PRK_R = HMAC-SHA-256(PRK_2, G_RX) as defined in {{tv-ss-2-mac}}


~~~~~~~~~~~~~~~~~~~~~~~
PRK_3 (32 bytes)
08 4a 87 01 49 07 ed 85 12 90 42 55 e1 8a df a8 39 53 92 28 29 48 8f f4
66 44 87 1e 07 1d 42 80 
~~~~~~~~~~~~~~~~~~~~~~~

Key K_3 is the output of HKDF-Expand(PRK_3, info, L).

info is defined as follows:

~~~~~~~~~~~~~~~~~~~~~~~
info for K_3 =
[
  10,
  [ null, null, null ],
  [ null, null, null ],
  [ 128, h'', h'4d2d24a8fc0904028a9740622bc22f6f534caa573a151c74c0c4bf6c
                ceddb03e']
]
~~~~~~~~~~~~~~~~~~~~~~~

Which as a CBOR encoded data item is:

~~~~~~~~~~~~~~~~~~~~~~~
info (K_3) (CBOR-encoded) (48 bytes)
84 0a 83 f6 f6 f6 83 f6 f6 f6 83 18 80 40 58 20 4d 2d 24 a8 fc 09 04 02
8a 97 40 62 2b c2 2f 6f 53 4c aa 57 3a 15 1c 74 c0 c4 bf 6c ce dd b0 3e

~~~~~~~~~~~~~~~~~~~~~~~

L is the length of K_3, so 16 bytes.

From these parameters, K_3 is computed:

~~~~~~~~~~~~~~~~~~~~~~~
K_3 (16 bytes)
70 77 e4 d6 23 66 84 52 88 b7 00 ae 03 f8 a7 aa 
~~~~~~~~~~~~~~~~~~~~~~~

Nonce IV_3 is the output of HKDF-Expand(PRK, info, L).

info is defined as follows:

~~~~~~~~~~~~~~~~~~~~~~~
info for IV_3 =
[
  "IV-GENERATION",
  [ null, null, null ],
  [ null, null, null ],
  [ 104, h'', h'4d2d24a8fc0904028a9740622bc22f6f534caa573a151c74c0c4bf6c
                ceddb03e']
]
~~~~~~~~~~~~~~~~~~~~~~~

Which as a CBOR encoded data item is:

~~~~~~~~~~~~~~~~~~~~~~~
info (IV_3) (CBOR-encoded) (61 bytes)
84 6d 49 56 2d 47 45 4e 45 52 41 54 49 4f 4e 83 f6 f6 f6 83 f6 f6 f6 83
18 68 40 58 20 4d 2d 24 a8 fc 09 04 02 8a 97 40 62 2b c2 2f 6f 53 4c aa
57 3a 15 1c 74 c0 c4 bf 6c ce dd b0 3e 
~~~~~~~~~~~~~~~~~~~~~~~

L is the length of IV_3, so 13 bytes.

From these parameters, IV_3 is computed:

~~~~~~~~~~~~~~~~~~~~~~~
IV_3 (13 bytes)
e2 40 36 1e 0b 74 45 c6 d3 64 40 82 0d 
~~~~~~~~~~~~~~~~~~~~~~~

#### Ciphertext Computation {#tv-ss-3-ciph}

COSE_Encrypt0 is computed with the following parameters. Note that AD_3 is omitted.

* empty protected header

* external_aad = TH_3

* plaintext = CBOR Sequence of the items kid_R, CIPHERTEXT_R, in this order.

with kid_R taken from {{ss-tv-input-v}}, and CIPHERTEXT_R as calculated in {{tv-ss-2-mac-comp}}.

The plaintext is the following:

~~~~~~~~~~~~~~~~~~~~~~~
P_3  (12 bytes)
41 a7 49 00 00 00 00 00 00 00 00 00 
~~~~~~~~~~~~~~~~~~~~~~~

From the parameters above, the Enc_structure A_3 is computed.

~~~~~~~~~~~~~~~~~~~~~~~
A_3 =
[
  "Encrypt0",
  h'',
  h'4d2d24a8fc0904028a9740622bc22f6f534caa573a151c74c0c4bf6cceddb03e'
]
~~~~~~~~~~~~~~~~~~~~~~~

Which encodes to the following byte string to be used as Additional Authenticated Data:

~~~~~~~~~~~~~~~~~~~~~~~
A_3 (CBOR-encoded) (45 bytes)
83 68 45 6e 63 72 79 70 74 30 40 58 20 4d 2d 24 a8 fc 09 04 02 8a 97 40
62 2b c2 2f 6f 53 4c aa 57 3a 15 1c 74 c0 c4 bf 6c ce dd b0 3e 
~~~~~~~~~~~~~~~~~~~~~~~

The key and nonce used are defined in {{tv-ss-3-key}}:

* key = K_3

* nonce = IV_3

Using the parameters above, the ciphertext CIPHERTEXT_3 can be computed:

~~~~~~~~~~~~~~~~~~~~~~~
CIPHERTEXT_3 (20 bytes)
d2 85 38 ee f7 ae 1b 9d 7d 89 57 18 48 a9 08 86 e0 69 43 2b 
~~~~~~~~~~~~~~~~~~~~~~~

#### message_3

From the parameter computed in {{tv-ss-3}} and {{tv-ss-3-ciph}}, message_3 is computed, as the CBOR Sequence of the following items: (C_I, CIPHERTEXT_3).


~~~~~~~~~~~~~~~~~~~~~~~
message_3 =
(
  h'c7',
  h'd28538eef7ae1b9d7d89571848a90886e069432b'
)
~~~~~~~~~~~~~~~~~~~~~~~

Which encodes to the following byte string:

~~~~~~~~~~~~~~~~~~~~~~~
message_3 (CBOR Sequence) (23 bytes)
41 c8 54 d2 85 38 ee f7 ae 1b 9d 7d 89 57 18 48 a9 08 86 e0 69 43 2b 
~~~~~~~~~~~~~~~~~~~~~~~



# Acknowledgments
{: numbered="no"}

The authors want to thank Alessandro Bruni, Karthikeyan Bhargavan, Martin Disch, Theis Grønbech Petersen, Dan Harkins, Klaus Hartke, Russ Housley, Alexandros Krontiris, Ilari Liusvaara, Karl Norrman, Salvador Pérez, Eric Rescorla, Michael Richardson, Thorvald Sahl Jørgensen, Jim Schaad, Carsten Schürmann, Ludwig Seitz, Stanislav Smyshlyaev, Valery Smyslov, Rene Struik, and Erik Thormarker for reviewing and commenting on intermediate versions of the draft. We are especially indebted to Jim Schaad for his continuous reviewing and implementation of different versions of the draft.

--- fluff
