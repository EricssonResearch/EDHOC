---
title: Ephemeral Diffie-Hellman Over COSE (EDHOC)
docname: draft-selander-lake-cose-ecdhe-latest

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
        name: John Mattsson
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
  I-D.ietf-cbor-7049bis:
  I-D.ietf-core-echo-request-tag:
  
  RFC2119:
  RFC5116:
  RFC5869:
  RFC6090:
  RFC6979:
  RFC7252:
  RFC7748:
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

  RFC7228:
  RFC7258:
  RFC8446:
  
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

Security at the application layer provides an attractive option for protecting Internet of Things (IoT) deployments, for example where transport layer security is not sufficient {{I-D.hartke-core-e2e-security-reqs}} or where the protection needs to work over a variety of underlying protocols. IoT devices may be constrained in various ways, including memory, storage, processing capacity, and energy {{RFC7228}}. A method for protecting individual messages at the application layer suitable for constrained devices, is provided by CBOR Object Signing and Encryption (COSE) {{RFC8152}}), which builds on the Concise Binary Object Representation (CBOR) {{I-D.ietf-cbor-7049bis}}. Object Security for Constrained RESTful Environments (OSCORE) {{RFC8613}} is a method for application-layer protection of the Constrained Application Protocol (CoAP), using COSE. 

In order for a communication session to provide forward secrecy, the communicating parties can run an Elliptic Curve Diffie-Hellman (ECDH) key exchange protocol with ephemeral keys, from which shared key material can be derived. This document specifies Ephemeral Diffie-Hellman Over COSE (EDHOC), a lightweight key exchange protocol providing perfect forward secrecy and identity protection. Authentication is based on credentials established out of band, e.g. from a trusted third party, such as an Authorization Server as specified by {{I-D.ietf-ace-oauth-authz}}. EDHOC supports authentication using pre-shared keys (PSK), raw public keys (RPK), and public key certificates. After successful completion of the EDHOC protocol, application keys and other application specific data can be derived using the EDHOC-Exporter interface. A main use case for EDHOC is to establish an OSCORE security context. EDHOC uses COSE for cryptography, CBOR for encoding, and CoAP for transport. By reusing existing libraries, the additional code footprint can be kept very low. Note that this document focuses on authentication and key establishment: for integration with authorization of resource access, refer to {{I-D.ietf-ace-oscore-profile}}.

EDHOC is designed to work in highly constrained scenarios making it especially suitable for network technologies such as Cellular IoT, 6TiSCH {{I-D.ietf-6tisch-dtsecurity-zerotouch-join}}, and LoRaWAN {{LoRa1}}{{LoRa2}}. These network technologies are characterized by their low throughput, low power consumption, and small frame sizes. Compared to the DTLS 1.3 handshake {{I-D.ietf-tls-dtls13}} with ECDH and connection ID, the number of bytes in EDHOC is less than 1/4 when PSK authentication is used and less than 1/3 when RPK authentication is used, see {{I-D.ietf-lwig-security-protocol-comparison}}. Typical message sizes for EDHOC with pre-shared keys, raw public keys, and X.509 certificates are shown in {{fig-sizes}}.

~~~~~~~~~~~~~~~~~~~~~~~
=====================================================================
               PSK       RPK       x5t     x5chain                  
---------------------------------------------------------------------
message_1       40        38        38        38                     
message_2       45       114       126       116 + Certificate chain 
message_3       11        80        91        81 + Certificate chain 
---------------------------------------------------------------------
Total           96       232       255       235 + Certificate chains
=====================================================================
~~~~~~~~~~~~~~~~~~~~~~~
{: #fig-sizes title="Typical message sizes in bytes" artwork-align="center"}

The ECDH exchange and the key derivation follow {{SIGMA}}, NIST SP-800-56A {{SP-800-56A}}, and HKDF {{RFC5869}}. CBOR {{I-D.ietf-cbor-7049bis}} and COSE {{RFC8152}} are used to implement these standards. The use of COSE provides crypto agility and enables use of future algorithms and headers designed for constrained IoT.

This document is organized as follows: {{background}} describes how EDHOC builds on SIGMA-I, {{overview}} specifies general properties of EDHOC, including message flow, formatting of the ephemeral public keys, and key derivation, {{asym}} specifies EDHOC with asymmetric key authentication, {{sym}} specifies EDHOC with symmetric key authentication, {{error}} specifies the EDHOC error message, and {{transfer}} describes how EDHOC can be transferred in CoAP and used to establish an OSCORE security context.

## Rationale for EDHOC

Many constrained IoT systems today do not use any security at all, and when they do, they often do not follow best practices. One reason is that many current security protocols are not designed with constrained IoT in mind. Constrained IoT systems often deal with personal information, valuable business data, and actuators interacting with the physical world. Not only do such systems need security and privacy, they often need end-to-end protection with source authentication and perfect forward secrecy. EDHOC and OSCORE {{RFC8613}} enables security following current best practices to devices and systems where current security protocols are impractical. 

EDHOC is optimized for small message sizes and can therefore be sent over a small number of radio frames. The message size of a key exchange protocol may have a large impact on the performance of an IoT deployment, especially in noisy environments. For example, in a network bootstrapping setting a large number of devices turned on in a short period of time may result in large latencies caused by parallel key exchanges. Requirements on network formation time in constrained environments can be translated into key exchange overhead. In networks technologies with transmission back-off time, each additional frame significantly increases the latency even if no other devices are transmitting.

Power consumption for wireless devices is highly dependent on message transmission, listening, and reception. For devices that only send a few bytes occasionally, the battery lifetime may be significantly reduced by a heavy key exchange protocol. Moreover, a key exchange may need to be executed more than once, e.g. due to a device losing power or rebooting for other reasons.

EDHOC is adapted to primitives and protocols designed for the Internet of Things: EDHOC is built on CBOR and COSE which enables small message overhead and efficient parsing in constrained devices. EDHOC is not bound to a particular transport layer, but it is recommended to transport the EDHOC message in CoAP payloads. EDHOC is not bound to a particular communication security protocol but works off-the-shelf with OSCORE {{RFC8613}} providing the necessary input parameters with required properties. Maximum code complexity (ROM/Flash) is often a constraint in many devices and by reusing already existing libraries, the additional code footprint for EDHOC + OSCORE can be kept very low.


## Terminology and Requirements Language

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 {{RFC2119}} {{RFC8174}} when, and only when, they appear in all capitals, as shown here.

The word "encryption" without qualification always refers to authenticated encryption, in practice implemented with an Authenticated Encryption with Additional Data (AEAD) algorithm, see {{RFC5116}}.

Readers are expected to be familiar with the terms and concepts described in CBOR {{I-D.ietf-cbor-7049bis}}, COSE {{RFC8152}}, and CDDL {{RFC8610}}. The Concise Data Definition Language (CDDL) is used to express CBOR data structures {{I-D.ietf-cbor-7049bis}}. Examples of CBOR and CDDL are provided in {{CBOR}}.

# Background {#background}

SIGMA (SIGn-and-MAc) is a family of theoretical protocols with a large number of variants {{SIGMA}}. Like IKEv2 and (D)TLS 1.3 {{RFC8446}}, EDHOC is built on a variant of the SIGMA protocol which provide identity protection of the initiator (SIGMA-I), and like (D)TLS 1.3, EDHOC implements the SIGMA-I variant as Sign-then-MAC. The SIGMA-I protocol using an authenticated encryption algorithm is shown in {{fig-sigma}}.

~~~~~~~~~~~
Party U                                                   Party V
   |                          G_X                            |
   +-------------------------------------------------------->|
   |                                                         |
   |  G_Y, AEAD( K_2; ID_CRED_V, Sig(V; CRED_V, G_X, G_Y) )  |
   |<--------------------------------------------------------+
   |                                                         |
   |     AEAD( K_3; ID_CRED_U, Sig(U; CRED_U, G_Y, G_X) )    |
   +-------------------------------------------------------->|
   |                                                         |
~~~~~~~~~~~
{: #fig-sigma title="Authenticated encryption variant of the SIGMA-I protocol."}
{: artwork-align="center"}

The parties exchanging messages are called "U" and "V". They exchange identities and ephemeral public keys, compute the shared secret, and derive symmetric application keys. 

* G_X and G_Y are the ECDH ephemeral public keys of U and V, respectively.

* CRED_U and CRED_V are the credentials containing the public authentication keys of U and V, respectively.

* ID_CRED_U and ID_CRED_V are data enabling the recipient party to retrieve the credential of U and V, respectively.

* Sig(U; . ) and S(V; . ) denote signatures made with the private authentication key of U and V, respectively.

* AEAD(K; . ) denotes authenticated encryption with additional data using the key K derived from the shared secret. The authenticated encryption MUST NOT be replaced by plain encryption, see {{security}}.

In order to create a "full-fledged" protocol some additional protocol elements are needed. EDHOC adds:

* Explicit connection identifiers C_U, C_V chosen by U and V, respectively, enabling the recipient to find the protocol state.

* Transcript hashes TH_2, TH_3, TH_4 used for key derivation and as additional authenticated data.

* Computationally independent keys derived from the ECDH shared secret and used for encryption of different messages.

* Verification of a common preferred cipher suite (AEAD algorithm, ECDH algorithm, ECDH curve, signature algorithm):

   * U lists supported cipher suites in order of preference
   
   * V verifies that the selected cipher suite is the first supported cipher suite

* Method types and error handling.

* Transport of opaque application defined data.

EDHOC is designed to encrypt and integrity protect as much information as possible, and all symmetric keys are derived using as much previous information as possible. EDHOC is furthermore designed to be as compact and lightweight as possible, in terms of message sizes, processing, and the ability to reuse already existing CBOR, COSE, and CoAP libraries.

To simplify for implementors, the use of CBOR in EDHOC is summarized in {{CBORandCOSE}} and test vectors including CBOR diagnostic notation are given in {{vectors}}.

# EDHOC Overview {#overview}

EDHOC consists of three flights (message_1, message_2, message_3) that maps directly to the three messages in SIGMA-I, plus an EDHOC error message. EDHOC messages are CBOR Sequences {{I-D.ietf-cbor-sequence}}, where the first data item of message_1 is an int (TYPE) specifying the method (asymmetric, symmetric, error) and the correlation properties of the transport used.

While EDHOC uses the COSE_Key, COSE_Sign1, and COSE_Encrypt0 structures, only a subset of the parameters is included in the EDHOC messages. After creating EDHOC message_3, Party U can derive symmetric application keys, and application protected data can therefore be sent in parallel with EDHOC message_3. The application may protect data using the algorithms (AEAD, HKDF, etc.) in the selected cipher suite  and the connection identifiers (C_U, C_V). EDHOC may be used with the media type application/edhoc defined in {{iana}}.

~~~~~~~~~~~
Party U                                                 Party V
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

The EDHOC message exchange may be authenticated using pre-shared keys (PSK), raw public keys (RPK), or public key certificates. EDHOC assumes the existence of mechanisms (certification authority, manual distribution, etc.) for binding identities with authentication keys (public or pre-shared). When a public key infrastructure is used, the identity is included in the certificate and bound to the authentication key by trust in the certification authority. When the credential is manually distributed (PSK, RPK, self-signed certificate), the identity and authentication key is distributed out-of-band and bound together by trust in the distribution method. EDHOC with symmetric key authentication is very similar to EDHOC with asymmetric key authentication, the difference being that information is only MACed, not signed, and that session keys are derived from the ECDH shared secret and the PSK.

EDHOC allows opaque application data (UAD and PAD) to be sent in the EDHOC messages. Unprotected Application Data (UAD_1, UAD_2) may be sent in message_1 and message_2 and can be e.g. be used to transfer access tokens that are protected outside of EDHOC. Protected application data (PAD_3) may be used to transfer any application data in message_3.

Cryptographically, EDHOC does not put requirements on the lower layers. EDHOC is not bound to a particular transport layer, and can be used in environments without IP. It is recommended to transport the EDHOC message in CoAP payloads, see {{transfer}}. An implementation may support only Party U or only Party V.

## Cipher Suites

EDHOC cipher suites consist of a set of COSE algorithms: an AEAD algorithm, an ECDH algorithm (including HKDF algorithm), an ECDH curve, a signature algorithm, and signature algorithm parameters. The signature algorithm is not used when EDHOC is authenticated with symmetric keys. Each cipher suite is either identified with a pre-defined int label or with an array of labels and values from the COSE Algorithms and Elliptic Curves registries.

~~~~~~~~~~~
   suite = int / [ 4*4 algs: int / tstr, ? para: any ]
~~~~~~~~~~~

This document specifies two pre-defined cipher suites.

~~~~~~~~~~~
   0. [ 10, -27, 4, -8, 6 ]
      (AES-CCM-16-64-128, ECDH-SS + HKDF-256, X25519, EdDSA, Ed25519)

   1. [ 10, -27, 1, -7, 1 ]
      (AES-CCM-16-64-128, ECDH-SS + HKDF-256, P-256, ES256, P-256)
~~~~~~~~~~~

## Ephemeral Public Keys {#cose_key}
   
The ECDH ephemeral public keys are formatted as a COSE_Key of type EC2 or OKP according to Sections 13.1 and 13.2 of {{RFC8152}}, but only the x-coordinate is included in the EDHOC messages. For Elliptic Curve Keys of type EC2, compact representation as per {{RFC6090}} MAY be used also in the COSE_Key. If the COSE implementation requires an y-coordinate, any of the possible values of the y-coordinate can be used, see Appendix C of {{RFC6090}}. COSE {{RFC8152}} always use compact output for Elliptic Curve Keys of type EC2.

## Key Derivation {#key-der}

Key and IV derivation SHALL be performed with the HKDF {{RFC5869}} in the selected cipher suite following the specification in Section 11 of {{RFC8152}}. The PRK is derived using HKDF-Extract {{RFC5869}}

~~~~~~~~~~~~~~~~~~~~~~~
   PRK = HKDF-Extract( salt, IKM )
~~~~~~~~~~~~~~~~~~~~~~~

with the following input:

* The salt SHALL be the PSK when EDHOC is authenticated with symmetric keys, and the empty byte string when EDHOC is authenticated with asymmetric keys. The PSK is used as 'salt' to simplify implementation. Note that {{RFC5869}} specifies that if the salt is not provided, it is set to a string of zeros (see Section 2.2 of {{RFC5869}}). For implementation purposes, not providing the salt is the same as setting the salt to the empty byte string. 

* The IKM SHALL be the ECDH shared secret G_XY as defined in Section 12.4.1 of {{RFC8152}}. When using the mandatory-to-implement curve25519, the ECDH shared secret is the output of the X25519 function {{RFC7748}}.

Example: Assuming use of the mandatory-to-implement algorithm HKDF SHA-256 the extract phase of HKDF produces a pseudorandom key (PRK) as follows:

~~~~~~~~~~~~~~~~~~~~~~~
   PRK = HMAC-SHA-256( salt, G_XY )
~~~~~~~~~~~~~~~~~~~~~~~

where salt = 0x (the empty byte string) in the asymmetric case and salt = PSK in the symmetric case. The keys and IVs used in EDHOC are derived from PRK using HKDF-Expand {{RFC5869}}

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

For message_2 and message_3, the keys K_2 and K_3 SHALL be derived using transcript hashes TH_2 and TH_3 respectively. The key SHALL be derived using AlgorithmID set to the integer value of the AEAD in the selected cipher suite, and keyDataLength equal to the key length of the AEAD.

If the AEAD algorithm uses an IV, then IV_2 and IV_3 for message_2 and message_3 SHALL be derived using the transcript hashes TH_2 and TH_3 respectively. The IV SHALL be derived using AlgorithmID = "IV-GENERATION" as specified in Section 12.1.2. of {{RFC8152}}, and keyDataLength equal to the IV length of the AEAD.

Example: Assuming the output OKM length L is smaller than the hash function output size, the expand phase of HKDF consists of a single HMAC invocation

~~~~~~~~~~~~~~~~~~~~~~~
   OKM = first L bytes of HMAC-SHA-256( PRK, info || 0x01 )
~~~~~~~~~~~~~~~~~~~~~~~

where \|\| means byte string concatenation. Assuming use of the mandatory-to-implement algorithm AES-CCM-16-64-128, K_i and IV_i are therefore the first 16 and 13 bytes, respectively, of HMAC-SHA-256( PRK, info \|\| 0x01 ) calculated with (AlgorithmID, keyDataLength) = (10, 128) and (AlgorithmID, keyDataLength) = ("IV-GENERATION", 104), respectively.


### EDHOC-Exporter Interface {#exporter}

Application keys and other application specific data can be derived using the EDHOC-Exporter interface defined as:

~~~~~~~~~~~
   EDHOC-Exporter( label, length ) = HKDF-Expand( PRK, info, length ) 
~~~~~~~~~~~

The output of the EDHOC-Exporter function SHALL be derived using AlgorithmID = label, keyDataLength = 8 * length, and other = TH_4 where label is a tstr defined by the application and length is a uint defined by the application.  The label SHALL be different for each different exporter value. The transcript hash TH_4 is a CBOR encoded bstr and the input to the hash function is a CBOR Sequence.

~~~~~~~~~~~
   TH_4 = H( TH_3, CIPHERTEXT_3 )
~~~~~~~~~~~

where H() is the hash function in the HKDF. Example use of the EDHOC-Exporter is given in Sections {{chain}}{: format="counter"} and {{oscore}}{: format="counter"}.

### EDHOC PSK Chaining {#chain}

An application using EDHOC may want to derive new PSKs to use for authentication in future EDHOC exchanges.  In this case, the new PSK and the ID_PSK 'kid' parameter SHOULD be derived as follows where length is the key length (in bytes) of the AEAD Algorithm.

~~~~~~~~~~~~~~~~~~~~~~~
   PSK    = EDHOC-Exporter( "EDHOC Chaining PSK", length )
   ID_PSK = EDHOC-Exporter( "EDHOC Chaining ID_PSK", 4 )
~~~~~~~~~~~~~~~~~~~~~~~

# EDHOC Authenticated with Asymmetric Signature Keys {#asym}

## Overview {#asym-overview}

EDHOC supports authentication with raw public keys (RPK) and public key certificates with the requirements that:

* Only Party V SHALL have access to the private authentication key of Party V,

* Only Party U SHALL have access to the private authentication key of Party U,

* Party U is able to retrieve Party V's public authentication key using ID_CRED_V,

* Party V is able to retrieve Party U's public authentication key using ID_CRED_U,

where the identifiers ID_CRED_U and ID_CRED_V are COSE header maps containing COSE header parameter that can identify a public authentication key, see {{COSE}}. In the following we give some examples of possible COSE header parameters.

Raw public keys are most optimally stored as COSE_Key objects and identified with a 'kid' parameter (see {{RFC8152}}):

* ID_CRED_x = { 4 : bstr }, for x = U or V.

Public key certificates can be identified in different ways. Several header parameters for identifying X.509 certificates are defined in {{I-D.ietf-cose-x509}} (the exact labels are TBD):

* by a hash value with the 'x5t' parameter;

   * ID_CRED_x = { TBD1 : COSE_CertHash }, for x = U or V,

* by a URL with the 'x5u' parameter;

   * ID_CRED_x = { TBD2 : uri }, for x = U or V,

* or by a bag of certificates with the 'x5bag' parameter;

   * ID_CRED_x = { TBD3 : COSE_X509 }, for x = U or V.

* by a certificate chain with the 'x5chain' parameter;

   * ID_CRED_x = { TBD4 : COSE_X509 }, for x = U or V,

In the latter two examples, ID_CRED_U and ID_CRED_V contain the actual credential used for authentication. The purpose of ID_CRED_U and ID_CRED_V is to facilitate retrieval of a public authentication key and when they do not contain the actual credential, they may be very short. It is RECOMMENDED that they uniquely identify the public authentication key as the recipient may otherwise have to try several keys. ID_CRED_U and ID_CRED_V are transported in the ciphertext, see {{asym-msg2-proc}} and {{asym-msg3-proc}}.

The actual credentials CRED_U and CRED_V (e.g. a COSE_Key or a single X.509 certificate) are signed by party U and V, respectively to prevent duplicate-signature key selection (DSKS) attacks, see {{asym-msg3-form}} and {{asym-msg2-form}}. Party U and Party V MAY use different types of credentials, e.g. one uses RPK and the other uses certificate. When included in the signature payload, COSE_Keys of type OKP SHALL only include the parameters 1 (kty), -1 (crv), and -2 (x-coordinate). COSE_Keys of type EC2 SHALL only include the parameters 1 (kty), -1 (crv), -2 (x-coordinate), and -3 (y-coordinate). The parameters SHALL be encoded in decreasing order.

The connection identifiers C_U and C_V do not have any cryptographic purpose in EDHOC. They contain information facilitating retrieval of the protocol state and may therefore be very short. The connection identifier MAY be used with an application protocol (e.g. OSCORE) for which EDHOC establishes keys, in which case the connection identifiers SHALL adhere to the requirements for that protocol. Each party choses a connection identifier it desires the other party to use in outgoing messages.

The first data item of message_1 is an int TYPE = 4 * method + corr specifying the method and the correlation properties of the transport used. corr = 0 is used when there is no external correlation mechanism. corr = 1 is used when there is an external correlation mechanism (e.g. the Token in CoAP) that enables Party U to correlate message_1 and message_2. corr = 2 is used when there is an external correlation mechanism that enables Party V to correlate message_2 and message_3. corr = 3 is used when there is an external correlation mechanism that enables the parties to correlate all the messages. The use of the correlation parameter is exemplified in {{coap}}.

EDHOC with asymmetric key authentication is illustrated in {{fig-asym}}.

~~~~~~~~~~~
Party U                                                       Party V
|                  TYPE, SUITES_U, G_X, C_U, UAD_1                  |
+------------------------------------------------------------------>|
|                             message_1                             |
|                                                                   |
|  C_U, G_Y, C_V, AEAD(K_2; ID_CRED_V, Sig(V; CRED_V, TH_2), UAD_2) |
|<------------------------------------------------------------------+
|                             message_2                             |
|                                                                   |
|       C_V, AEAD(K_3; ID_CRED_U, Sig(U; CRED_U, TH_3), PAD_3)      |
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
  TYPE : int,
  SUITES_U : suite / [ index: uint, 2* suite ],
  G_X : bstr,
  C_U : bstr,  
  ? UAD_1 : bstr,
)
~~~~~~~~~~~

where:

* TYPE = 4 * method + corr, where the method = 0 and the correlation parameter corr is chosen based on the transport and determines which connection identifiers that are omitted (see {{asym-overview}}).
* SUITES_U - cipher suites which Party U supports, in order of decreasing preference. If a single cipher suite is conveyed, a single suite is used, if multiple cipher suites are conveyed, an array of suites and an index is used. The zero-based index (i.e. 0 for the first, 1 for the second, etc.) identifies a single selected cipher suite from the array.
* G_X - the x-coordinate of the ephemeral public key of Party U
* C_U - variable length connection identifier
* UAD_1 - bstr containing unprotected opaque application data

### Party U Processing of Message 1

Party U SHALL compose message_1 as follows:

* The supported cipher suites and the order of preference MUST NOT be changed based on previous error messages. However, the list SUITES_U sent to Party V MAY be truncated such that cipher suites which are the least preferred are omitted. The amount of truncation MAY be changed between sessions, e.g. based on previous error messages (see next bullet), but all cipher suites which are more preferred than the least preferred cipher suite in the list MUST be included in the list.

* Determine the cipher suite to use with Party V in message_1. If Party U previously received from Party V an error message to message_1 with diagnostic payload identifying a cipher suite that U supports, then U SHALL use that cipher suite. Otherwise the first cipher suite in SUITES_U MUST be used.

* Generate an ephemeral ECDH key pair as specified in Section 5 of {{SP-800-56A}} using the curve in the selected cipher suite. Let G_X be the x-coordinate of the ephemeral public key.
   
* Choose a connection identifier C_U and store it for the length of the protocol.

* Encode message_1 as a sequence of CBOR encoded data items as specified in {{asym-msg1-form}}

### Party V Processing of Message 1

Party V SHALL process message_1 as follows:

* Decode message_1 (see {{CBOR}}).

* Verify that the selected cipher suite is supported and that no prior cipher suites in SUITES_U are supported.

* Validate that there is a solution to the curve definition for the given x-coordinate G_X.

* Pass UAD_1 to the application.

If any verification step fails, Party V MUST send an EDHOC error message back, formatted as defined in {{error}}, and the protocol MUST be discontinued. If V does not support the selected cipher suite, then SUITES_V MUST include one or more supported cipher suites. If V does not support the selected cipher suite, but supports another cipher suite in SUITES_U, then SUITES_V MUST include the first supported cipher suite in SUITES_U.

## EDHOC Message 2

### Formatting of Message 2 {#asym-msg2-form}

message_2 and data_2 SHALL be a CBOR Sequences (see {{CBOR}}) as defined below

~~~~~~~~~~~ CDDL
message_2 = (
  data_2,
  CIPHERTEXT_2 : bstr,
)
~~~~~~~~~~~

~~~~~~~~~~~ CDDL
data_2 = (
  ? C_U : bstr,
  G_Y : bstr,
  C_V : bstr,
)
~~~~~~~~~~~

where:

* G_Y - the x-coordinate of the ephemeral public key of Party V
* C_V - variable length connection identifier

### Party V Processing of Message 2 {#asym-msg2-proc}

Party V SHALL compose message_2 as follows:

* If TYPE mod 4 equals 1 or 3, C_U is omitted, otherwise C_U is not omitted.

* Generate an ephemeral ECDH key pair as specified in Section 5 of {{SP-800-56A}} using the curve in the selected cipher suite. Let G_Y be the x-coordinate of the ephemeral public key.

* Choe a connection identifier C_V and store it for the length of the protocol.

* Compute the transcript hash TH_2 = H( message_1, data_2 ) where H() is the hash function in the HKDF. The transcript hash TH_2 is a CBOR encoded bstr and the input to the hash function is a CBOR Sequence.

*  Compute COSE_Sign1 as defined in Section 4.4 of {{RFC8152}}, using the signature algorithm in the selected cipher suite, the private authentication key of Party V, and the following parameters. The unprotected header (not included in the EDHOC message) MAY contain parameters (e.g. 'alg').
   
   * protected = bstr .cbor ID_CRED_V
     
   * payload = bstr .cbor CRED_V
   
   * external_aad = TH_2

   * ID_CRED_V - identifier to facilitate retrieval of a public authentication key of Party V, see {{asym-overview}}

   * CRED_V - bstr credential containing the public authentication key of Party V, see {{asym-overview}}
   
   Note that only 'signature' of the COSE_Sign1 object are used in message_2, see next bullet.
   
   COSE constructs the input to the Signature Algorithm as follows:
   
   * The key is the private authentication key of V.

   * The message M to be signed is the CBOR encoding of:

~~~~~~~~~~~
   [ "Signature1", << ID_CRED_V >>, TH_2, << CRED_V >> ]
~~~~~~~~~~~
   
* Compute COSE_Encrypt0 as defined in Section 5.3 of {{RFC8152}}, with the AEAD algorithm in the selected cipher suite, K_2, IV_2, and the following parameters. The protected header SHALL be empty. The unprotected header (not included in the EDHOC message) MAY contain parameters (e.g. 'alg').
 
   * plaintext = ( ID_CRED_V / kid_value, signature, ? UAD_2 )

   * external_aad = TH_2

   * UAD_2 = bstr containing opaque unprotected application data

    where signature is taken from the COSE_Sign1 object and ID_CRED_V is a COSE header_map or a bstr. If ID_CRED_V contains a single 'kid' parameter, i.e., ID_CRED_V = { 4 : kid_value }, only kid_value is conveyed in the plaintext. Note that only 'ciphertext' of the COSE_Encrypt0 object are used in message_2, see next bullet

   COSE constructs the input to the AEAD {{RFC5116}} as follows: Key K = K_2, Nonce N = IV_2, Plaintext P = ( ID_CRED_V / kid_value, signature, ? UAD_2 ), and the associated data A is the CBOR encoding of [ "Encrypt0", h'', TH_2 ].

* Encode message_2 as a sequence of CBOR encoded data items as specified in {{asym-msg2-form}}. CIPHERTEXT_2 is the COSE_Encrypt0 ciphertext. 

### Party U Processing of Message 2

Party U SHALL process message_2 as follows:

* Decode message_2 (see {{CBOR}}).

* Retrieve the protocol state using the connection identifier C_U and/or other external information such as the CoAP Token and the 5-tuple.

* Validate that there is a solution to the curve definition for the given x-coordinate G_Y.

* Decrypt and verify COSE_Encrypt0 as defined in Section 5.3 of {{RFC8152}}, with the AEAD algorithm in the selected cipher suite, K_2, and IV_2.

* Verify COSE_Sign1 as defined in Section 4.4 of {{RFC8152}}, using the signature algorithm in the selected cipher suite and the public authentication key of Party V.

If any verification step fails, Party U MUST send an EDHOC error message back, formatted as defined in {{error}}, and the protocol MUST be discontinued.

## EDHOC Message 3

### Formatting of Message 3 {#asym-msg3-form}

message_3 and data_3 SHALL be a CBOR Sequences (see {{CBOR}}) as defined below

~~~~~~~~~~~ CDDL
message_3 = (
  data_3,
  CIPHERTEXT_3 : bstr,
)
~~~~~~~~~~~

~~~~~~~~~~~ CDDL
data_3 = (
  ? C_V : bstr,
)
~~~~~~~~~~~

### Party U Processing of Message 3 {#asym-msg3-proc}

Party U SHALL compose message_3 as follows:

* If TYPE mod 4 equals 2 or 3, C_V is omitted, otherwise C_V is not omitted.

* Compute the transcript hash TH_3 = H( TH_2 , CIPHERTEXT_2, data_3 ) where H() is the hash function in the HKDF. The transcript hash TH_3 is a CBOR encoded bstr and the input to the hash function is a CBOR Sequence.

*  Compute COSE_Sign1 as defined in Section 4.4 of {{RFC8152}}, using the signature algorithm in the selected cipher suite, the private authentication key of Party U, and the following parameters. The unprotected header (not included in the EDHOC message) MAY contain parameters (e.g. 'alg').

   * protected = bstr .cbor ID_CRED_U

   * payload = bstr .cbor CRED_U

   * external_aad = TH_3

   * ID_CRED_U - identifier to facilitate retrieval of a public authentication key of Party U, see {{asym-overview}}

   * CRED_U - bstr credential containing the public authentication key of Party U, see {{asym-overview}}

   Note that only 'signature' of the COSE_Sign1 object are used in message_3, see next bullet.
   
   COSE constructs the input to the Signature Algorithm as follows:
   
   * The key is the private authentication key of U.

   * The message M to be signed is the CBOR encoding of:

~~~~~~~~~~~
   [ "Signature1", << ID_CRED_U >>, TH_3, << CRED_U >> ]
~~~~~~~~~~~

* Compute COSE_Encrypt0 as defined in Section 5.3 of {{RFC8152}}, with the AEAD algorithm in the selected cipher suite, K_3, and IV_3 and the following parameters. The protected header SHALL be empty. The unprotected header (not included in the EDHOC message) MAY contain parameters (e.g. 'alg').

   * plaintext = ( ID_CRED_U / kid_value, signature, ? PAD_3 )
         
   * external_aad = TH_3

   * PAD_3 = bstr containing opaque protected application data

    where signature is taken from the COSE_Sign1 object and ID_CRED_U is a COSE header_map or a bstr. If ID_CRED_U contains a single 'kid' parameter, i.e., ID_CRED_U = { 4 : kid_value }, only kid_value is conveyed in the plaintext. Note that only 'ciphertext' of the COSE_Encrypt0 object are used in message_3, see next bullet.

   COSE constructs the input to the AEAD {{RFC5116}} as follows: Key K = K_3, Nonce N = IV_2, Plaintext P = ( ID_CRED_U / kid_value, signature, ? PAD_3 ), and the associated data A is the CBOR encoding of [ "Encrypt0", h'', TH_3 ].

* Encode message_3 as a sequence of CBOR encoded data items as specified in {{asym-msg3-form}}. CIPHERTEXT_3 is the COSE_Encrypt0 ciphertext.

*  Pass the connection identifiers (C_U, C_V) and the selected cipher suite to the application. The application can now derive application keys using the EDHOC-Exporter interface.

### Party V Processing of Message 3

Party V SHALL process message_3 as follows:

* Decode message_3 (see {{CBOR}}).

* Retrieve the protocol state using the connection identifier C_V and/or other external information such as the CoAP Token and the 5-tuple.

* Decrypt and verify COSE_Encrypt0 as defined in Section 5.3 of {{RFC8152}}, with the AEAD algorithm in the selected cipher suite, K_3, and IV_3.

* Verify COSE_Sign1 as defined in Section 4.4 of {{RFC8152}}, using the signature algorithm in the selected cipher suite and the public authentication key of Party U.

If any verification step fails, Party V MUST send an EDHOC error message back, formatted as defined in {{error}}, and the protocol MUST be discontinued.

*  Pass PAD_3, the connection identifiers (C_U, C_V), and the selected cipher suite to the application. The application can now derive application keys using the EDHOC-Exporter interface.

# EDHOC Authenticated with Symmetric Keys {#sym}

## Overview {#sym-overview}

EDHOC supports authentication with pre-shared keys. Party U and V are assumed to have a pre-shared key (PSK) with a good amount of randomness and the requirement that:

* Only Party U and Party V SHALL have access to the PSK,

* Party V is able to retrieve the PSK using ID_PSK.

where the identifier ID_PSK is a COSE header map containing COSE header parameter that can identify a pre-shared key. Pre-shared keys are typically stored as COSE_Key objects and identified with a 'kid' parameter (see {{RFC8152}}):

* ID_PSK = { 4 : bstr }

The purpose of ID_PSK is to facilitate retrieval of the PSK and in the case a 'kid' parameter is used it may be very short. It is RECOMMENDED that it uniquely identify the PSK as the recipient may otherwise have to try several keys.

EDHOC with symmetric key authentication is illustrated in {{fig-sym}}. 

~~~~~~~~~~~
Party U                                                       Party V
|              TYPE, SUITES_U, G_X, C_U, ID_PSK, UAD_1              |
+------------------------------------------------------------------>|
|                             message_1                             |
|                                                                   |
|               C_U, G_Y, C_V, AEAD(K_2; TH_2, UAD_2)               |
|<------------------------------------------------------------------+
|                             message_2                             |
|                                                                   |
|                    C_V, AEAD(K_3; TH_3, PAD_3)                    |
+------------------------------------------------------------------>|
|                             message_3                             |
~~~~~~~~~~~
{: #fig-sym title="Overview of EDHOC with symmetric key authentication."}
{: artwork-align="center"}

EDHOC with symmetric key authentication is very similar to EDHOC with asymmetric key authentication. In the following subsections the differences compared to EDHOC with asymmetric key authentication are described.

## EDHOC Message 1

### Formatting of Message 1 {#sym-msg1-form}

message_1 SHALL be a CBOR Sequence (see {{CBOR}}) as defined below

~~~~~~~~~~~ CDDL
message_1 = (
  TYPE : int,
  SUITES_U : suite / [ index: uint, 2* suite ],
  G_X : bstr,
  C_U : bstr,
  ID_PSK : bstr / header_map,
  ? UAD_1 : bstr,
)
~~~~~~~~~~~

where:

* TYPE = 4 * method + corr, where the method = 1 and the connection parameter corr is chosen based on the transport and determines which connection identifiers that are omitted (see {{asym-overview}}).
* ID_PSK - identifier to facilitate retrieval of the pre-shared key. If ID_PSK contains a single 'kid' parameter, i.e., ID_PSK = { 4 : kid_value }, only the bstr kid_value is conveyed.

## EDHOC Message 2

### Processing of Message 2

*  COSE_Sign1 is not used.

* COSE_Encrypt0 is computed as defined in Section 5.3 of {{RFC8152}}, with the AEAD algorithm in the selected cipher suite, K_2, IV_2, and the following parameters. The protected header SHALL be empty. The unprotected header MAY contain parameters (e.g. 'alg').

   * external_aad = TH_2

   * plaintext = ? UAD_2
   
   * UAD_2 = bstr containing opaque unprotected application data

## EDHOC Message 3

### Processing of Message 3

*  COSE_Sign1 is not used.

* COSE_Encrypt0 is computed as defined in Section 5.3 of {{RFC8152}}, with the AEAD algorithm in the selected cipher suite, K_3, IV_3, and the following parameters. The protected header SHALL be empty. The unprotected header MAY contain parameters (e.g. 'alg').

   * external_aad = TH_3

   * plaintext = ? PAD_3
 
   * PAD_3 = bstr containing opaque protected application data

# Error Handling {#error}

## EDHOC Error Message

This section defines a message format for the EDHOC error message, used during the protocol. An EDHOC error message can be sent by both parties as a response to any non-error EDHOC message. After sending an error message, the protocol MUST be discontinued. Errors at the EDHOC layer are sent as normal successful messages in the lower layers (e.g. CoAP POST and 2.04 Changed). An advantage of using such a construction is to avoid issues created by usage of cross protocol proxies (e.g. UDP to TCP).

error SHALL be a CBOR Sequence (see {{CBOR}}) as defined below

~~~~~~~~~~~ CDDL
error = (
  ? C_x : bstr,
  ERR_MSG : tstr,
  ? SUITES_V : suite / [ 2* suite ],
)
~~~~~~~~~~~

where:

* C_x - if error is sent by Party V and TYPE mod 4 equals 0 or 2 then C_x is set to C_U, else if error is sent by Party U and TYPE mod 4 equals 0 or 1 then C_x is set to C_V, else C_x is omitted.
* ERR_MSG - text string containing the diagnostic payload, defined in the same way as in Section 5.5.2 of {{RFC7252}}
* SUITES_V - cipher suites from SUITES_U or the EDHOC cipher suites registry that V supports. Note that SUITES_V only contains the values from the EDHOC cipher suites registry and no index.

### Example Use of EDHOC Error Message with SUITES_V

Assuming that Party U supports the five cipher suites \{5, 6, 7, 8, 9\} in decreasing order of preference, Figures {{fig-error1}}{: format="counter"} and {{fig-error2}}{: format="counter"} show examples of how Party U can truncate SUITES_U and how SUITES_V is used by Party V to give Party U information about the cipher suites that Party V supports. In {{fig-error1}}, Party V supports cipher suite 6 but not the selected cipher suite 5. 

~~~~~~~~~~~
Party U                                                       Party V
|            TYPE, SUITES_U {0, 5, 6, 7}, G_X, C_U, UAD_1           |
+------------------------------------------------------------------>|
|                             message_1                             |
|                                                                   |
|                     C_U, ERR_MSG, SUITES_V {6}                    |
|<------------------------------------------------------------------+
|                               error                               |
|                                                                   |
|             TYPE, SUITES_U {1, 5, 6}, G_X, C_U, UAD_1             |
+------------------------------------------------------------------>|
|                             message_1                             |
~~~~~~~~~~~
{: #fig-error1 title="Example use of error message with SUITES_V."}
{: artwork-align="center"}

In {{fig-error2}}, Party V supports cipher suite 7 but not cipher suites 5 and 6.

~~~~~~~~~~~
Party U                                                       Party V
|             TYPE, SUITES_U {0, 5, 6}, G_X, C_U, UAD_1             |
+------------------------------------------------------------------>|
|                             message_1                             |
|                                                                   |
|                    C_U, ERR_MSG, SUITES_V {7, 9}                  |
|<------------------------------------------------------------------+
|                               error                               |
|                                                                   |
|            TYPE, SUITES_U {2, 5, 6, 7}, G_X, C_U, UAD_1           |
+------------------------------------------------------------------>|
|                             message_1                             |
~~~~~~~~~~~
{: #fig-error2 title="Example use of error message with SUITES_V."}
{: artwork-align="center"}

As Party U's list of supported cipher suites and order of preference is fixed, and Party V only accepts message_1 if the selected cipher suite is the first cipher suite in SUITES_U that Party V supports, the parties can verify that the selected cipher suite is the most preferred (by Party U) cipher suite supported by both parties. If the selected cipher suite is not the first cipher suite in SUITES_U that Party V supports, Party V will discontinue the protocol. 

# Transferring EDHOC and Deriving Application Keys {#transfer}

## Transferring EDHOC in CoAP {#coap}

It is recommended to transport EDHOC as an exchange of CoAP {{RFC7252}} messages. CoAP is a reliable transport that can preserve packet ordering and handle message duplication. CoAP can also perform fragmentation and protect against denial of service attacks. It is recommended to carry the EDHOC flights in Confirmable messages, especially if fragmentation is used.

By default, the CoAP client is Party U and the CoAP server is Party V, but the roles SHOULD be chosen to protect the most sensitive identity, see {{security}}. By default, EDHOC is transferred in POST requests and 2.04 (Changed) responses to the Uri-Path: "/.well-known/edhoc", but an application may define its own path that can be discovered e.g. using resource directory {{I-D.ietf-core-resource-directory}}.

By default, the message flow is as follows: EDHOC message_1 is sent in the payload of a POST request from the client to the server's resource for EDHOC. EDHOC message_2 or the EDHOC error message is sent from the server to the client in the payload of a 2.04 (Changed) response. EDHOC message_3 or the EDHOC error message is sent from the client to the server's resource in the payload of a POST request. If needed, an EDHOC error message is sent from the server to the client in the payload of a 2.04 (Changed) response.

An example of a successful EDHOC exchange using CoAP is shown in {{fig-coap1}}. In this case the CoAP Token enables Party U to correlate message_1 and message_2 so the correlation parameter corr = 1.

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

The exchange in {{fig-coap1}} protects the client identity against active attackers and the server identity against passive attackers. An alternative exchange that protects the server identity against active attackers and the client identity against passive attackers is shown in {{fig-coap2}}. In this case the CoAP Token enables Party V to correlate message_2 and message_3 so the correlation parameter corr = 2.

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

When EDHOC is used to derive parameters for OSCORE {{RFC8613}}, the parties must make sure that the EDHOC connection identifiers are unique, i.e. C_V MUST NOT be equal to C_U. The CoAP client and server MUST be able to retrieve the OCORE protocol state using its chosen connection identifier and optionally other information such as the 5-tuple. In case that the CoAP client is party U and the CoAP server is party V:

* The client's OSCORE Sender ID is C_V and the server's OSCORE Sender ID is C_U, as defined in this document

* The AEAD Algorithm and the HMAC-based Key Derivation Function (HKDF) are the AEAD and HKDF algorithms in the selected cipher suite.

* The Master Secret and Master Salt are derived as follows where length is the key length (in bytes) of the AEAD Algorithm.

~~~~~~~~~~~~~~~~~~~~~~~
   Master Secret = EDHOC-Exporter( "OSCORE Master Secret", length )
   Master Salt   = EDHOC-Exporter( "OSCORE Master Salt", 8 )
~~~~~~~~~~~~~~~~~~~~~~~

## Transferring EDHOC over Other Protocols {#non-coap}

EDHOC may be transported over a different transport than CoAP. In this case the lower layers need to handle message loss, reordering, message duplication, fragmentation, and denial of service protection.

# IANA Considerations {#iana}

## EDHOC Cipher Suites Registry

IANA has created a new registry titled "EDHOC Cipher Suites". The registration procedure is "Expert Review". The columns of the registry are Value, Array, Description, and Reference, where Value is an integer and the other columns are text strings. The initial contents of the registry are:

~~~~~~~~~~~~~~~~~~~~~~~
Value: 1
Array: [ 10, -27, 1, -7, 1 ]
Desc: AES-CCM-16-64-128, ECDH-SS + HKDF-256, P-256, ES256, P-256
Reference: [[this document]]
~~~~~~~~~~~~~~~~~~~~~~~

~~~~~~~~~~~~~~~~~~~~~~~
Value: 0
Array: [ 10, -27, 4, -8, 6 ]
Desc: AES-CCM-16-64-128, ECDH-SS + HKDF-256, X25519, EdDSA, Ed25519
Reference: [[this document]]
~~~~~~~~~~~~~~~~~~~~~~~

~~~~~~~~~~~~~~~~~~~~~~~
Value: -5
Array:
Desc: Reserved for Private Use
Reference: [[this document]]
~~~~~~~~~~~~~~~~~~~~~~~

~~~~~~~~~~~~~~~~~~~~~~~
Value: -6
Array:
Desc: Reserved for Private Use
Reference: [[this document]]
~~~~~~~~~~~~~~~~~~~~~~~

## EDHOC Method Type Registry

IANA has created a new registry titled "EDHOC Method Type". The registration procedure is "Expert Review". The columns of the registry are Value, Description, and Reference, where Value is an integer and the other columns are text strings. The initial contents of the registry are:

~~~~~~~~~~~
+-------+------------------------------------------+-------------------+
| Value | Specification                            | Reference         |
+-------+------------------------------------------+-------------------+
|     0 | EDHOC Authenticated with Asymmetric Keys | [[this document]] |
|     1 | EDHOC Authenticated with Symmetric Keys  | [[this document]] |
+-------+------------------------------------------+-------------------+
~~~~~~~~~~~
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

# Security Considerations {#security}

## Security Properties
EDHOC inherits its security properties from the theoretical SIGMA-I protocol {{SIGMA}}. Using the terminology from {{SIGMA}}, EDHOC provides perfect forward secrecy, mutual authentication with aliveness, consistency, peer awareness, and identity protection. As described in {{SIGMA}}, peer awareness is provided to Party V, but not to Party U. EDHOC also inherits Key Compromise Impersonation (KCI) resistance from SIGMA-I.

EDHOC with asymmetric authentication offers identity protection of Party U against active attacks and identity protection of Party V against passive attacks. The roles should be assigned to protect the most sensitive identity, typically that which is not possible to infer from routing information in the lower layers.

Compared to {{SIGMA}}, EDHOC adds an explicit method type and expands the message authentication coverage to additional elements such as algorithms, application data, and previous messages. This protects against an attacker replaying messages or injecting messages from another session.

EDHOC also adds negotiation of connection identifiers and downgrade protected negotiation of cryptographic parameters, i.e. an attacker cannot affect the negotiated parameters. A single session of EDHOC does not include negotiation of cipher suites, but it enables Party V to verify that the selected cipher suite is the most preferred cipher suite by U which is supported by both U and V.

As required by {{RFC7258}}, IETF protocols need to mitigate pervasive monitoring when possible. One way to mitigate pervasive monitoring is to use a key exchange that provides perfect forward secrecy. EDHOC therefore only supports methods with perfect forward secrecy. To limit the effect of breaches, it is important to limit the use of symmetrical group keys for bootstrapping. EDHOC therefore strives to make the additional cost of using raw public keys and self-signed certificates as small as possible. Raw public keys and self-signed certificates are not a replacement for a public key infrastructure, but SHOULD be used instead of symmetrical group keys for bootstrapping.

Compromise of the long-term keys (PSK or private authentication keys) does not compromise the security of completed EDHOC exchanges. Compromising the private authentication keys of one party lets the attacker impersonate that compromised party in EDHOC exchanges with other parties, but does not let the attacker impersonate other parties in EDHOC exchanges with the compromised party. Compromising the PSK lets the attacker impersonate Party U in EDHOC exchanges with Party V and impersonate Party V in EDHOC exchanges with Party U. Compromise of the HDKF input parameters (ECDH shared secret and/or PSK) leads to compromise of all session keys derived from that compromised shared secret. Compromise of one session key does not compromise other session keys.

## Cryptographic Considerations
The security of the SIGMA protocol requires the MAC to be bound to the identity of the signer. Hence the message authenticating functionality of the authenticated encryption in EDHOC is critical: authenticated encryption MUST NOT be replaced by plain encryption only, even if authentication is provided at another level or through a different mechanism. EDHOC implements SIGMA-I using the same Sign-then-MAC approach as TLS 1.3.

To reduce message overhead EDHOC does not use explicit nonces and instead rely on the ephemeral public keys to provide randomness to each session. A good amount of randomness is important for the key generation, to provide liveness, and to protect against interleaving attacks. For this reason, the ephemeral keys MUST NOT be reused, and both parties SHALL generate fresh random ephemeral key pairs. 

The choice of key length used in the different algorithms needs to be harmonized, so that a sufficient security level is maintained for certificates, EDHOC, and the protection of application data. Party U and V should enforce a minimum security level.

The data rates in many IoT deployments are very limited. Given that the application keys are protected as well as the long-term authentication keys they can often be used for years or even decades before the cryptographic limits are reached. If the application keys established through EDHOC need to be renewed, the communicating parties can derive application keys with other labels or run EDHOC again.

## Mandatory to Implement Cipher Suite

Cipher suite number 0 (AES-CCM-64-64-128, ECDH-SS + HKDF-256, X25519, Ed25519) is mandatory to implement. For many constrained IoT devices it is problematic to support more than one cipher suites, so some deployments with P-256 may not support the mandatory cipher suite. This is not a problem for local deployments. 

## Unprotected Data

Party U and V must make sure that unprotected data and metadata do not reveal any sensitive information. This also applies for encrypted data sent to an unauthenticated party. In particular, it applies to UAD_1, ID_CRED_V, UAD_2, and ERR_MSG in the asymmetric case, and ID_PSK, UAD_1, and ERR_MSG in the symmetric case. Using the same ID_PSK or UAD_1 in several EDHOC sessions allows passive eavesdroppers to correlate the different sessions. The communicating parties may therefore anonymize ID_PSK. Another consideration is that the list of supported cipher suites may be used to identify the application.

Party U and V must also make sure that unauthenticated data does not trigger any harmful actions. In particular, this applies to UAD_1 and ERR_MSG in the asymmetric case, and ID_PSK, UAD_1, and ERR_MSG in the symmetric case.

## Denial-of-Service

EDHOC itself does not provide countermeasures against Denial-of-Service attacks. By sending a number of new or replayed message_1 an attacker may cause Party V to allocate state, perform cryptographic operations, and amplify messages. To mitigate such attacks, an implementation SHOULD rely on lower layer mechanisms such as the Echo option in CoAP {{I-D.ietf-core-echo-request-tag}} that forces the initiator to demonstrate reachability at its apparent network address.

## Implementation Considerations

The availability of a secure pseudorandom number generator and truly random seeds are essential for the security of EDHOC. If no true random number generator is available, a truly random seed must be provided from an external source. If ECDSA is supported, "deterministic ECDSA" as specified in {{RFC6979}} is RECOMMENDED.

The referenced processing instructions in {{SP-800-56A}} must be complied with, including deleting the intermediate computed values along with any ephemeral ECDH secrets after the key derivation is completed. The ECDH shared secret, keys (K_2, K_3), and IVs (IV_2, IV_3) MUST be secret. Implementations should provide countermeasures to side-channel attacks such as timing attacks.

Party U and V are responsible for verifying the integrity of certificates. The selection of trusted CAs should be done very carefully and certificate revocation should be supported. The private authentication keys and the PSK (even though it is used as salt) MUST be kept secret.

Party U and V are allowed to select the connection identifiers C_U and C_V, respectively, for the other party to use in the ongoing EDHOC protocol as well as in a subsequent application protocol (e.g. OSCORE {{RFC8613}}). The choice of connection identifier is not security critical in EDHOC but intended to simplify the retrieval of the right security context in combination with using short identifiers. If the wrong connection identifier of the other party is used in a protocol message it will result in the receiving party not being able to retrieve a security context (which will terminate the protocol) or retrieve the wrong security context (which also terminates the protocol as the message cannot be verified).

Party V MUST finish the verification step of message_3 before passing PAD_3 to the application.

If two nodes unintentionally initiate two simultaneous EDHOC message exchanges with each other even if they only want to complete a single EDHOC message exchange, they MAY terminate the exchange with the lexicographically smallest G_X. If the two G_X values are equal, the received message_1 MUST be discarded to mitigate reflection attacks. Note that in the case of two simultaneous EDHOC exchanges where the nodes only complete one and where the nodes have different preferred cipher suites, an attacker can affect which of the two nodes’ preferred cipher suites will be used by blocking the other exchange.

## Other Documents Referencing EDHOC

EDHOC has been analyzed in several other documents. A formal verification of EDHOC was done in {{SSR18}}, an analysis of EDHOC for certificate enrollment was done in {{Kron18}}, the use of EDHOC in LoRaWAN is analyzed in {{LoRa1}} and {{LoRa2}}, the use of EDHOC in IoT bootstrapping is analyzed in {{Perez18}}, and the use of EDHOC in 6TiSCH is described in {{I-D.ietf-6tisch-dtsecurity-zerotouch-join}}. 

--- back

# Use of CBOR, CDDL and COSE in EDHOC {#CBORandCOSE}

This Appendix is intended to simplify for implementors not familiar with CBOR {{I-D.ietf-cbor-7049bis}}, CDDL {{RFC8610}}, COSE {{RFC8152}}, and HKDF {{RFC5869}}.

## CBOR and CDDL  {#CBOR}

The Concise Binary Object Representation (CBOR) {{I-D.ietf-cbor-7049bis}} is a data format designed for small code size and small message size. CBOR builds on the JSON data model but extends it by e.g. encoding binary data directly without base64 conversion. In addition to the binary CBOR encoding, CBOR also has a diagnostic notation that is readable and editable by humans. The Concise Data Definition Language (CDDL) {{RFC8610}} provides a way to express structures for protocol messages and APIs that use CBOR. {{RFC8610}} also extends the diagnostic notation.

CBOR data items are encoded to or decoded from byte strings using a type-length-value encoding scheme, where the three highest order bits of the initial byte contain information about the major type. CBOR supports several different types of data items, in addition to integers (int, uint), simple values (e.g. null), byte strings (bstr), and text strings (tstr), CBOR also supports arrays \[\]  of data items, maps {} of pairs of data items, and sequences {{I-D.ietf-cbor-sequence}} of data items. Some examples are given below. For a complete specification and more examples, see {{I-D.ietf-cbor-7049bis}} and {{RFC8610}}. We recommend implementors to get used to CBOR by using the CBOR playground {{CborMe}}. 

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
{ 4: h'cd' }        0xa10441cd           map                 
<< 1, 2, null >>    0x430102f6           byte string
[ 1, 2, null ]      0x830102f6           array      
[_ 1, 2, null ]     0x9f0102f6ff         array (indefinite-length)
( 1, 2, null )      0x0102f6             sequence
1, 2, null          0x0102f6             sequence
------------------------------------------------------------------
~~~~~~~~~~~~~~~~~~~~~~~
{: artwork-align="center"}

EDHOC messages are CBOR Sequences {{I-D.ietf-cbor-sequence}}. The message format specification uses the constructs '.cbor' and '.cborseq' enabling conversion between different CDDL types matching different CBOR items with different encodings. Some examples are given below.

A type (e.g. an uint) may be wrapped in a byte string (bstr):

~~~~~~~~~~~~~~~~~~~~~~~
CDDL Type                       Diagnostic                Encoded
------------------------------------------------------------------
uint                            24                        0x1818
bstr .cbor uint                 << 24 >>                  0x421818
------------------------------------------------------------------
~~~~~~~~~~~~~~~~~~~~~~~
{: artwork-align="center"}

An array, say of an uint and a byte string, may be converted into a byte string (bstr):

~~~~~~~~~~~~~~~~~~~~~~~
CDDL Type                       Diagnostic              Encoded
--------------------------------------------------------------------
bstr                            h'cd'                   0x41cd
[ uint, bstr ]                  [ 24, h'cd' ]           0x82181841cd
bstr .cborseq [ uint, bstr ]    << 24, h'cd' >>         0x44181841cd
--------------------------------------------------------------------
~~~~~~~~~~~~~~~~~~~~~~~
{: artwork-align="center"}


## COSE {#COSE}

CBOR Object Signing and Encryption (COSE) {{RFC8152}} describes how to create and process signatures, message authentication codes, and encryption using CBOR. COSE builds on JOSE, but is adapted to allow more efficient processing in constrained devices. EDHOC makes use of COSE_Key, COSE_Encrypt0, COSE_Sign1, and COSE_KDF_Context objects.

# Test Vectors {#vectors}

To help implementors, this appendix provides a wealth of test vectors to ease implementation and ensure interoperability. In addition to hexadecimal, all CBOR data items and sequences are given in CBOR diagnostic notation. The test vectors use 1 byte key identifiers, 1 byte connection IDs, and the default mapping to CoAP (corr = 1). 1 byte identifiers are realistic in many scenarios as most constrained devices only have a few keys and connections. In cases where a node only has one connection or key, the identifiers may even be the empty byte string.

TODO: This section needs to be updated by someone that likes Comic Sans.

# Acknowledgments
{: numbered="no"}

The authors want to thank Alessandro Bruni, Martin Disch, Theis Grønbech Petersen, Dan Harkins, Klaus Hartke, Russ Housley, Alexandros Krontiris, Ilari Liusvaara, Karl Norrman, Salvador Pérez, Eric Rescorla, Michael Richardson, Thorvald Sahl Jørgensen, Jim Schaad, Carsten Schürmann, Ludwig Seitz, Stanislav Smyshlyaev, Valery Smyslov, Rene Struik, and Erik Thormarker for reviewing and commenting on intermediate versions of the draft. We are especially indebted to Jim Schaad for his continuous reviewing and implementation of different versions of the draft.

--- fluff
