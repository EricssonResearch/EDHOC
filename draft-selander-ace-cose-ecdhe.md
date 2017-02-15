---
title: Ephemeral Diffie-Hellman Over COSE (EDHOC)
docname: draft-selander-ace-cose-ecdhe-latest

ipr: trust200902
wg: ACE Working Group
cat: std

coding: utf-8
pi:    # can use array (if all yes) or hash here
  toc: yes
  sortrefs: yes
  symrefs: yes
  tocdepth: 2

author:
      -
        ins: G. Selander
        name: Göran Selander
        org: Ericsson AB
        street: Färögatan 6
        city: Kista
        code: SE-164 80 Stockholm
        country: Sweden
        email: goran.selander@ericsson.com
      -
        ins: J. Mattsson
        name: John Mattsson
        org: Ericsson AB
        street: Färögatan 6
        city: Kista
        code: SE-164 80 Stockholm
        country: Sweden
        email: john.mattsson@ericsson.com
      -
        ins: F. Palombini
        name: Francesca Palombini
        org: Ericsson AB
        street: Färögatan 6
        city: Kista
        code: SE-164 80 Stockholm
        country: Sweden
        email: francesca.palombini@ericsson.com

normative:

  RFC2119:
  RFC7049:
  I-D.ietf-cose-msg:
  I-D.schaad-cose-x509:
  SP-800-56a:
    target: http://dx.doi.org/10.6028/NIST.SP.800-56Ar2
    title: Recommendation for Pair-Wise Key Establishment Schemes Using Discrete Logarithm Cryptography
    seriesinfo:
      "NIST": "Special Publication 800-56A Revision 2"
    author:
      -
        ins: E. Barker
      -
        ins: L. Chen
      -
        ins: A. Roginsky
      -
        ins: M. Smid
    date: May 2013

  SIGMA:
    target: http://webee.technion.ac.il/~hugo/sigma-pdf.pdf
    title: SIGMA - The 'SIGn-and-MAc' Approach to Authenticated Diffie-Hellman and Its Use in the IKE-Protocols (Long version)
    author:
      -
        ins: H. Krawczyk
    date: June 2003

informative:

  I-D.hartke-core-e2e-security-reqs:
  I-D.ietf-ace-oauth-authz:
  I-D.ietf-core-object-security:
  I-D.seitz-ace-oscoap-profile:
  I-D.greevenbosch-appsawg-cbor-cddl:

  RFC7228:
  RFC7252:
  RFC5869:

--- abstract

This document specifies Ephemeral Diffie-Hellman Over COSE (EDHOC), a compact, and lightweight authenticated Diffie-Hellman key exchange with ephemeral keys that can be used over any layer. EDHOC messages are encoded with CBOR and COSE, allowing reuse of existing libraries.

--- middle

# Introduction #       {#intro}

Security at the application layer provides an attractive option for protecting Internet of Things (IoT) deployments, for example where transport layer security is not sufficient {{I-D.hartke-core-e2e-security-reqs}}. IoT devices may be constrained in various ways, including memory, storage, processing capacity, and energy {{RFC7228}}. A method for protecting individual messages at the application layer suitable for constrained devices, is provided by CBOR Object Signing and Encryption (COSE) {{I-D.ietf-cose-msg}}), which builds on the Concise Binary Object Representation (CBOR) {{RFC7049}}.

In order for a communication session to provide forward secrecy, the communicating parties can run a Elliptic Curve Diffie-Hellman (ECDH) key exchange protocol with ephemeral keys, from which shared key material can be derived. This document specifies Ephemeral Diffie-Hellman Over COSE (EDHOC), an authenticated ECDH protocol using CBOR and COSE objects. Authentication is based on credentials established out of band, e.g. from a trusted third party, such as an Authorization Server as specified by {{I-D.ietf-ace-oauth-authz}}. EDHOC supports authenticated using pre-shared keys (PSK), raw public keys (RPK), and certificates (Cert).  Note that this document focuses on authentication and key establishment: for integration with authorization of resource access, refer to {{I-D.seitz-ace-oscoap-profile}}. This document also specifies the derivation of shared key material.

The ECDH exchange and the key derivation follow {{SIGMA}}, NIST SP-800-56a {{SP-800-56a}}, and HKDF {{RFC5869}}. CBOR {{RFC7049}} and COSE {{I-D.ietf-cose-msg}} are used to implement these standards.

## Terminology #  {#terminology}

This document use the same informational CBOR Data Definition Language (CDDL) {{I-D.greevenbosch-appsawg-cbor-cddl}} grammar as COSE (see Section 1.3 of {{I-D.ietf-cose-msg}}). A vertical bar \| denotes byte string concatenation.

## Requirements Language ###  {#terminology2}

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in {{RFC2119}}. These words may also appear in this document in lowercase, absent their normative meanings.


# Protocol Overview # {#protocol}
SIGMA (SIGn-and-MAc) is a family of theoretical protocols with a large number of variants {{SIGMA}}. Like IKEv2 and TLS 1.3, EDHOC is built on a variant of the SIGMA protocol which provide identity protection, and like TLS 1.3, EDHOC implements the SIGMA-I variant as Sign-then-MAC. The SIGMA-I protocol using an AEAD algorithm is shown in {{fig-sigma}}.

~~~~~~~~~~~
Party U                                                 Party V
   |                          E_U                          |
   +------------------------------------------------------>|
   |                                                       |
   |         E_V, Enc(K_2; ID_V, Sig(V; E_U, E_V);)        |
   |<------------------------------------------------------+
   |                                                       |
   |            Enc(K_3; ID_U, Sig(U; E_V, E_U);)          |
   +------------------------------------------------------>|
   |                                                       |
~~~~~~~~~~~
{: #fig-sigma title="AEAD variant of the SIGMA-I protocol"}
{: artwork-align="center"}

The parties exchanging messages are called "U" and "V". They exchange identities and ephemeral public keys, compute the shared secret, and derive the keying material. The messages are signed, MACed, and encrypted.

* E_U and E_V are the ECDH ephemeral public keys of U and V, respectively.

* ID_U and ID_V are identifiers for the public keys of U and V, respectively.

* Sig(U; . ) and S(V; . ) denote signatures made with the private key of U and V, respectively.

* Enc(K; P; A) denotes AEAD encryption of plaintext P and additional authenticated data A using the key K derived from the shared secret. The AEAD MUST NOT be replaced by plain encryption, see {{sec-cons}}.

As described in Appendix B of {{SIGMA}}, in order to create a "full-fledge" protocol some additional protocol elements are needed. EDHOC adds:

* Explicit session identifiers S_U, S_V chosen by U and V, respectively.

* Explicit nonces N_U, N_V chosen freshly and anew with each session by U and V, respectively.

* Computationally independent keys derived from the ECDH shared secret and used for different directions and operations.

EDHOC also makes the following additions:

* Negotiation of key derivation, AEAD, and signature algorithms:

   * U proposes one or more algorithms of each kind.

   * V selects one algorithm of each kind, and additionally proposes an array of signature algorithms.

   * U selects and uses one signature algorithm.

* Transmission of application defined extensions.

EDHOC is designed to encrypt and integrity protect as much information as possible, and all symmetric keys are derived using as much previous information as possible. EDHOC is furthermore designed to be as compact and lightweight as possible, in terms of message sizes, processing, and the ability to reuse already existing CBOR and COSE libraries. EDHOC does not put any requirement on the lower layers and can therefore be also be used e.g. in environments without IP.

This paper is organized as follows: {{general}} specifies general properties of EDHOC, including formatting of the ephemeral public keys and key derivation, {{asym}} specifies EDHOC with asymmetric key authentication, {{sym}} specifies EDHOC with symmetric key authentication, and {{examples}} provides a wealth of test vectors to ease implementation and ensure interoperability.

# EDHOC Overview # {#general}

EDHOC consists of three messages (message_1, message_2, message_3) that maps directly to the three messages in SIGMA-I. All EDHOC messages consists of an CBOR array where the first element is an int specifying the message type (MSG_TYPE). After creating EDHOC message_3, Party U can derive the traffic key (master secret) and protected application data can therefore be sent in parallel with EDHOC message_3. The application data may e.g. be protected using the negotiated AEAD algorithm. EDHOC may be used with the media type application/edhoc defined in {{iana}}.

~~~~~~~~~~~
Party U                                                 Party V
   |                                                       |
   | ------------------ EDHOC message_1 -----------------> |
   |                                                       |
   | <----------------- EDHOC message_2 ------------------ |
   |                                                       |
   | ---- Protected Application Data + EDHOC message_3 --> |
   |                                                       |
~~~~~~~~~~~
{: #fig-flow title="EDHOC message flow"}
{: artwork-align="center"}

The EDHOC message exchange may be authenticated using pre-shared keys (PSK), raw public keys (RPK), or certificates (Cert). EDHOC assumes the existence of mechanisms (certification authority, manual distribution, etc.) for binding identities with authentication keys (public or pre-shared). EDHOC with symmetric key authentication is very similar to EDHOC with asymmetric key authentication, the
differences are that information is only MACed (not signed) and that EDHOC with symmetric key authentication offers encryption, integrity protection, and key proof-of-possession already in message_1.

EDHOC allows application defined extensions (EXT_1, EXT_2, EXT_3) to be sent in the respective messages. When EDHOC are used with asymmetric key authentication, EXT_1 is unprotected, EXT_2 is protected (encrypted and integrity protected), but sent to an unauthenticated party, and EXT_3 is protected and mutually authenticated. When EDHOC is used with symmetric key authentication, all extensions are protected and mutually authenticated.

## Formatting of the Ephemeral Public Keys ## {#cose_key}

The ECDH ephemeral public key SHALL be formatted as a COSE_Key of type EC2 or OKP according to section 13.1 and 13.2 of {{I-D.ietf-cose-msg}}. The curve X25519 is mandatory-to-implement. For Elliptic Curve Keys of type EC2, point compression is mandatory-to-implement.

## Key Derivation ## {#key-der}

Key and IV derivation SHALL be done as specified in Section 11.1 of [I-D.ietf-cose-msg] with the following input:

* The PRF SHALL be the HKDF [RFC5869] in the ECDH-SS w/ HKDF negotiated during the message exchange (HKDF_V).

* The secret SHALL be the ECDH shared secret as defined in Section 12.4.1 of [I-D.ietf-cose-msg].

* salt = PSK / nil

* The context information SHALL be the serialized COSE_KDF_Context with the following values:

  + PartyInfo = ( nil, nil, nil )

  + SuppPubInfo SHALL contain:

    + protected SHALL be a zero length bstr
    
~~~~~~~~~~~
      +  other = aad_1  / aad_2  / aad_3 /
                 message_1 | message_2 | message_3 | label
~~~~~~~~~~~

The salt SHALL only be present in the symmetric case.

The symmetric key and IV used to protect message_i is called K_i and IV_i etc., and are derived using byte string aad_i defined for each EDHOC message that make use of a symmetric key.

K_1 and IV_1 are only used in EDHOC with symmetric key authentication and are derived with the exceptions that secret SHALL be empty and the PRF SHALL be HKDF-256 (or a HKDF decided by the application).

All other keys are derived with the negotiated PRF and with the secret set to the ECDH shared secret.

Application specific traffic keys and key identifiers are derived using the byte string message_1 \| message_2 \| message_3 \| label, where label is a byte string and \| denotes byte string concatenation. Each application making use of EDHOC defines its own labels and how they are used.



# EDHOC Authenticated with Asymmetric Keys # {#asym}

## Overview ##

EDHOC supports authentication with raw public keys (RPK) and certificates (Cert) with the requirements that:

* Party U's SHALL be able to uniquely identify Party V's public key using ID_V.

* Party V's SHALL be able to uniquely identify Party U's public key using ID_U.

ID_U and ID_V either enable the other party to retrieve the public key (kid, x5t, x5u) or they contain the public key (x5c), see {{I-D.schaad-cose-x509}}.

EDHOC with asymmetric key authentication is illustrated in {{fig-asym}}.

~~~~~~~~~~~
Party U                                                          Party V
|                      S_U, N_U, E_U, ALG_1, EXT_1                     |
+--------------------------------------------------------------------->|
|                               message_1                              |
|                                                                      |
|S_U, S_V, N_V, E_V, ALG_2, Enc(K_2; EXT_2, ID_V, Sig(V; aad_2); aad_2)|
|<---------------------------------------------------------------------+
|                               message_2                              |
|                                                                      |
|        S_V, ALG_3, Enc(K_3; EXT_3, ID_U, Sig(U; aad_3); aad_3)       |
+--------------------------------------------------------------------->|
|                               message_3                              |
~~~~~~~~~~~
{: #fig-asym title="EDHOC with asymmetric key authentication. "}
{: artwork-align="center"}

### Mandatory to Implement Algorithms ### {#asym-mti}

For EDHOC authenticated with asymmetric keys, the COSE algorithms ECDH-SS + HKDF-256, AES-CCM-64-64-128, and EdDSA are mandatory to implement.

## EDHOC Message 1 ## {#asym-msg1}

### Formatting of Message 1 ### {#asym-msg1-form}

message_1 SHALL be a CBOR array as defined below

~~~~~~~~~~~
message_1 = [
  MSG_TYPE : int,
  S_U : bstr,  
  N_U : bstr,  
  E_U : serialized_COSE_Key,
  HKDFs_U : alg_array,
  AEADs_U : alg_array,
  SIGs_V : alg_array,
  SIGs_U : alg_array,  
  ? EXT_1 : bstr
]

serialized_COSE_Key = bstr .cbor COSE_Key

alg_array = [ + alg : int / tstr ]
~~~~~~~~~~~

where:

* MSG_TYPE = 1
* S_U - variable length session identifier
* N_U - 64-bit random nonce
* E_U - the ephemeral public key of Party U
* HKDFs_U - supported ECDH-SS w/ HKDF algorithms
* AEADs_U - supported AEAD algorithms
* SIGs_V - signature algorithms that Party U supports verifying with
* SIGs_U - signature algorithms that Party U supports signing with
* EXT_1 - application defined extensions

### Party U Processing of Message 1 ### {#asym-msg1-procU}

Party U SHALL compose message_1 as follows:

* Generate a fresh ephemeral ECDH key pair as specified in Section 5 of {{SP-800-56a}} and format the ephemeral public key E_U as a COSE_key as specified in {{cose_key}}.

* Generate the pseudo-random nonce N_U 

* Chose a session identifier S_U and store it for the length of the protocol.

* Format message_1 as specified in {{asym-msg1-form}}.

### Party V Processing of Message 1 ### {#asym-msg1-procV}

Party V SHALL process message_1 as follows:

* Verify (OPTIONAL) that N_U has not been received before.

* Verify that at least one of each kind of the proposed algorithms are supported.

If any verification step fails, the message MUST be discarded and the protocol discontinued.



## EDHOC Message 2 ## {#asym-msg2}

### Formatting of Message 2 ### {#asym-msg2-form}

message_2 SHALL be a CBOR array as defined below

~~~~~~~~~~~
message_2 = [
  data_2,
  COSE_ENC_2 : COSE_Encrypt0
]

data_2 = (
  MSG_TYPE : int,
  S_U : bstr,
  S_V : bstr,  
  N_V : bstr,
  E_V : serialized_COSE_Key,
  HKDF_V : int / tstr,
  AEAD_V : int / tstr,
  SIG_V : int / tstr,
  SIG_U : int / tstr
)

aad_2 = message_1 | [ data_2 ] | ? Cert_V
~~~~~~~~~~~

where:

* MSG_TYPE = 2
* S_V - variable length session identifier
* N_V - 64-bit random nonce
* E_V - the ephemeral public key of Party V
* HKDF_V - an single chosen algorithm from HKDFs_U
* AEAD_V - an single chosen algorithm from AEADs_U
* SIG_V - an single chosen algorithm from SIGs_V that Party V signs with
* SIG_U - an single chosen algorithm from SIGs_U that Party U signs with
* COSE_ENC_2 has the following fields and values:

   + external_aad = aad_2

   + plaintext = \[ COSE_SIG_V, ? EXT_2 \]

* COSE_SIG_V is a COSE_Sign1 object with the following fields and values:
   
   - unprotected = { xyz: ID_V }

   - detached payload = aad_2

* xyz - any COSE map label that can identify a public key

* ID_V - identifier for the public key of Party V

* EXT_2 - application defined extensions

* Cert_V - The end-entity certificate of Party V encoded as a bstr



### Party V Processing of Message 2 ### {#asym-msg2-procV}

Party V SHALL compose message_2 as follows:

* Generate a fresh ephemeral ECDH key pair as specified in Section 5 of {{SP-800-56a}} using same curve as used in E_U. Format the ephemeral public key E_V as a COSE_key as specified in {{cose_key}}.

* Generate the pseudo-random nonce N_V

* Chose a session identifier S_V and store it for the length of the protocol.
      
*  Select HKDF_V, AEAD_V, and SIG_V from the algorithms proposed in HKDFs_U, AEADs_U, and SIGs_U.

*  Format message_2 as specified in {{asym-msg2-form}}:

   - COSE_Sign1 is computed as defined in section 4.4 of {{I-D.ietf-cose-msg}}, using algorithm SIG_V and the private key of Party V.

   -  COSE_Encrypt0 is computed as defined in section 5.3 of {{I-D.ietf-cose-msg}}, with AEAD_V, K_2, and IV_2. The AEAD algorithm MUST NOT be replaced by plain encryption, see {{sec-cons}}.

### Party U Processing of Message 2 ### {#asym-msg2-procU}

Party U SHALL process message_2 as follows:

* Use the session identifier S_U to retrieve the protocol state.

* Verify that HKDF_V, AEAD_V, and SIG_V were proposed in HKDFs_U, AEADs_U, and SIGs_U.

* Verify (OPTIONAL) that E_V has not been received before.

* Verify message_2 as specified in {{asym-msg2-form}}:

   - COSE_Encrypt0 is decrypted defined in section 5.3 of {{I-D.ietf-cose-msg}}, with AEAD_V, K_2, and IV_2.

   - COSE_Sign1 is verified as defined in section 4.4 of {{I-D.ietf-cose-msg}}, using algorithm SIG_V and the public key of Party V.

If any verification step fails, the message MUST be discarded and the protocol discontinued.




## EDHOC Message 3 ## {#asym-msg3}

### Formatting of Message 3 ### {#asym-msg3-form}

message_3 SHALL be a CBOR array as defined below

~~~~~~~~~~~
message_3 = [
  data_3,
  COSE_ENC_3 : COSE_Encrypt0
]

data_3 = (
  MSG_TYPE : int,
  S_V : bstr
)

aad_3 = message_1 | message_2 | [ data_3 ] | ? Cert_U
~~~~~~~~~~~

where:

* MSG_TYPE = 3
* COSE_ENC_3 has the following fields and values:

   + external_aad = aad_3

   + plaintext = \[ COSE_SIG_U, ? EXT_3 \]
   
* COSE_SIG_U is a COSE_Sign1 object with the following fields and values:
   
   - unprotected = { xyz: ID_U }

   - detached payload = aad_3
      
* xyz - any COSE map label that can identify a public key
* ID_U - identifier for the public key of Party U
* EXT_3 - application defined extensions
* Cert_U - The end-entity certificate of Party U encoded as a bstr

### Party U Processing of Message 3 ### {#asym-msg3-procU}

Party U SHALL compose message_3 as follows:

* Select SIG_U from the algorithms proposed in SIGs_V.

* Format message_3 as specified in {{asym-msg3-form}}:

   *  COSE_Sign1 is computed as defined in section 4.4 of {{I-D.ietf-cose-msg}}, using algorithm SIG_U and the private key of Party U.

   *  COSE_Encrypt0 is computed as defined in section 5.3 of {{I-D.ietf-cose-msg}}, with AEAD_V, K_3, and IV_3. The AEAD algorithm MUST NOT be replaced by plain encryption, see {{sec-cons}}.

### Party V Processing of Message 3 ### {#asym-msg3-procV}

Party V SHALL process message_3 as follows:

* Use the session identifier S_V to retrieve the protocol state.

* Verify that SIG_U was proposed in SIGs_V.

* Verify message_3 as specified in {{asym-msg3-form}}.

   * COSE_Encrypt0 is decrypted as defined in section 5.3 of {{I-D.ietf-cose-msg}}, with AEAD_V, K_3, and IV_3.

   * COSE_Sign1 is verified as defined in section 4.4 of {{I-D.ietf-cose-msg}}, using algorithm SIG_U and the public key of Party U;

If any verification step fails, the message MUST be discarded and the protocol discontinued.





# EDHOC Authenticated with Symmetric Keys # {#sym}

## Overview ##

EDHOC supports authentication with pre-shared keys. Party U and V are assumed to have a pre-shared uniformly random key (PSK) with the requirement that:

* Party V's SHALL be able to uniquely identify the PSK using KID.

KID either enable the other party to retrieve the PSK or contain the PSK (e.g. CBOR Web Token).

EDHOC with symmetric key authentication is illustrated in {{fig-sym}}.

~~~~~~~~~~~
Party U                                                       Party V
|         KID, S_U, N_U, E_U, ALG_1, Enc(K_1; EXT_1; aad_1)         |
+------------------------------------------------------------------>|
|                             message_1                             |
|                                                                   |
|         S_U, S_V, N_V, E_V, ALG_2, Enc(K_2; EXT_2; aad_2)         |
|<------------------------------------------------------------------+
|                             message_2                             |
|                                                                   |
|                    S_V, Enc(K_3; EXT_3; aad_3)                    |
+------------------------------------------------------------------>|
|                             message_3                             |
~~~~~~~~~~~
{: #fig-sym title="EDHOC with symmetric key authentication. "}
{: artwork-align="center"}

### Mandatory to Implement Algorithms ### {#sym-mti}

For EDHOC authenticated with symmetric keys, the COSE algorithms ECDH-SS + HKDF-256 and AES-CCM-64-64-128 are mandatory to implement.

## EDHOC Message 1 ## {#sym-msg1}

### Formatting of Message 1 ### {#sym-msg1-form}

message_1 SHALL be a CBOR array as defined below

~~~~~~~~~~~
message_1 = [
  data_1,
  COSE_ENC_1 : COSE_Encrypt0
]

data_1 = (
  MSG_TYPE : int,
  KID : bstr,
  S_U : bstr,  
  N_U : bstr,    
  E_U : serialized_COSE_Key,
  HKDFs_U : alg_array,
  AEADs_U : alg_array
)

aad_1 = [ data_1 ]

serialized_COSE_Key = bstr .cbor COSE_Key

alg_array = [ + alg : int / tstr ]
~~~~~~~~~~~

where:

* MSG_TYPE = 4
* KID - identifier of the pre-shared key
* S_U - variable length session identifier
* N_U - 64-bit random nonce
* E_U - the ephemeral public key of Party U
* HKDFs_U - supported ECDH-SS w/ HKDF algorithms
* AEADs_U - supported AEAD algorithms
* COSE_ENC_1 has the following fields and values:

   + external_aad = aad_1
   
   + plaintext = ? EXT_1

* EXT_1 - bstr containing application defined extensions

### Party U Processing of Message 1 ### {#sym-msg1-procU}

Party U SHALL compose message_1 as follows:

*  Generate a fresh ephemeral ECDH key pair as specified in Section 5 of {{SP-800-56a}} and format the ephemeral public key E_U as a COSE_key as specified in {{cose_key}}.

* Generate the pseudo-random nonce N_U 

* Chose a session identifier S_U and store it for the length of the protocol.

*  Format message_1 as specified in {{sym-msg1-form}} where COSE_Encrypt0 is computed as defined in section 5.3 of {{I-D.ietf-cose-msg}}, with AES-CCM-64-64-128 (or an AEAD decided by the application), K_1, and IV_1.


### Party V Processing of Message 1 ### {#sym-msg1-procV}

Party V SHALL process message_1 as follows:

* Verify (OPTIONAL) that N_U has not been received before.

* Verify that at least one of each kind of the proposed algorithms are supported.

* Verify message_1 as specified in {{sym-msg1-form}} where COSE_Encrypt0 is decrypted defined in section 5.3 of {{I-D.ietf-cose-msg}}, with AES-CCM-64-64-128 (or an AEAD decided by the application), K_1, and IV_1.

If any verification step fails, the message MUST be discarded and the protocol discontinued.




## EDHOC Message 2 ## {#sym-msg2}

### Formatting of Message 2 ### {#sym-msg2-form}

message_2 SHALL be a CBOR array as defined below

~~~~~~~~~~~
message_2 = [
  data_2,
  COSE_ENC_2 : COSE_Encrypt0
]

data_2 = (
  MSG_TYPE : int,
  S_U : bstr,  
  S_V : bstr,  
  N_V : bstr,
  E_V : serialized_COSE_Key,
  HKDF_V : int / tstr,
  AEAD_V : int / tstr
)

aad_2 = message_1 | [ data_2 ]
~~~~~~~~~~~

where:

* MSG_TYPE = 5
* S_V - variable length session identifier
* N_V - 64-bit random nonce
* E_V - the ephemeral public key of Party V
* HKDF_V - an single chosen algorithm from HKDFs_U
* AEAD_V - an single chosen algorithm from AEADs_U

* COSE_ENC_2 has the following fields and values:

   + external_aad = aad_2
   
   + plaintext = ? EXT_2

* EXT_2 - bstr containing application defined extensions

### Party V Processing of Message 2 ### {#sym-msg2-procV}

Party V SHALL compose message_2 as follows:

* Generate a fresh ephemeral ECDH key pair as specified in Section 5 of {{SP-800-56a}} using same curve as used in E_U. Format the ephemeral public key E_V as a COSE_key as specified in {{cose_key}}.

* Generate the pseudo-random nonce N_V

* Chose a session identifier S_V and store it for the length of the protocol.

*  Select HKDF_V and AEAD_V from the algorithms proposed in HKDFs_U and AEADs_U.

*  Format message_2 as specified in {{sym-msg2-form}} where COSE_Encrypt0 is computed as defined in section 5.3 of {{I-D.ietf-cose-msg}}, with AEAD_V, K_2, and IV_2.
   
### Party U Processing of Message 2 ### {#sym-msg2-procU}

Party U SHALL process message_2 as follows:

* Use the session identifier S_U to retrieve the protocol state.

* Verify message_2 as specified in {{sym-msg2-form}} where COSE_Encrypt0 is decrypted defined in section 5.3 of {{I-D.ietf-cose-msg}}, with AEAD_V, K_2, and IV_2.

If any verification step fails, the message MUST be discarded and the protocol discontinued.



## EDHOC Message 3 ## {#sym-msg3}

### Formatting of Message 3 ### {#sym-msg3-form}

message_3 SHALL be a CBOR array as defined below

~~~~~~~~~~~
message_3 = [
  data_3,
  COSE_ENC_3 : COSE_Encrypt0
]

data_3 = (
  MSG_TYPE : int,
  S_V : bstr 
)

aad_3 = message_1 | message_2 | [ data_3 ]
~~~~~~~~~~~

where:

* MSG_TYPE = 6
* COSE_ENC_3 has the following fields and values:

   + external_aad = aad_3
   
   + plaintext = ? EXT_3

* EXT_3 - bstr containing application defined extensions


### Party U Processing of Message 3 ### {#sym-msg3-procU}

Party U SHALL compose message_3 as follows:

*  Format message_3 as specified in {{sym-msg3-form}} where COSE_Encrypt0 is computed as defined in section 5.3 of {{I-D.ietf-cose-msg}}, with AEAD_V, K_3, and IV_3.

### Party V Processing of Message 3 ### {#sym-msg3-procV}

Party V SHALL process message_3 as follows:

* Use the session identifier S_V to retrieve the protocol state.

* Verify message_3 as specified in {{sym-msg3-form}} where COSE_Encrypt0 is decrypted and verified as defined in section 5.3 of {{I-D.ietf-cose-msg}}, with AEAD_V, K_3, and IV_3.

If any verification step fails, the message MUST be discarded and the protocol discontinued.

# Error Handling # {#error}

TODO: One error is e.g. if the ephemeral key is unsupported.

# IANA Considerations # {#iana}

## Media Types Registry ##

IANA has added the media type 'application/edhoc' to the Media Types registry:

        Type name: application

        Subtype name: edhoc

        Required parameters: N/A

        Optional parameters: N/A

        Encoding considerations: binary

        Security considerations: See Section 7 of this document.

        Interoperability considerations: N/A

        Published specification: [[this document]] (this document)

        Applications that use this media type: To be identified

        Fragment identifier considerations: N/A

        Additional information:

        * Magic number(s): N/A

        * File extension(s): N/A

        * Macintosh file type code(s): N/A

        Person & email address to contact for further information:
           Göran Selander <goran.selander@ericsson.com>

        Intended usage: COMMON

        Restrictions on usage: N/A

        Author: Göran Selander <goran.selander@ericsson.com>

        Change Controller: IESG

## COSE Header Parameters Registry ##

IANA has added the header parameter 'edhoc' to the COSE Header Parameters registry:

~~~~~~~~~~~
+-----------+-------+----------------+-------------+----------------+
| name      | label | value type     | value       | description    |
|           |       |                | registry    |                |
+-----------+-------+----------------+-------------+----------------+
| edhoc     | TBD   | bstr           |             | EDHOC message  |
+-----------+-------+----------------+-------------+----------------+
~~~~~~~~~~~
{: artwork-align="center"}

# Security Considerations # {#sec-cons}

EDHOC builds on the SIGMA-I family of theoretical protocols that provides perfect forward secrecy and identity protection with a minimal number of messages. The encryption algorithm of the SIGMA-I protocol provides identity protection, but the security of the protocol requires the MAC to cover the identity of the signer. Hence the message authenticating functionality of the authenticated encryption in EDHOC is critical: authenticated encryption MUST NOT be replaced by plain encryption only, even if authentication is provided at another level or through a different mechanism.

EDHOC adds an explicit message type and expands the authentication coverage to additional elements such as algorithms, extensions, and previous messages. EDHOC uses the same Sign-then-MAC approach as TLS 1.3.

Party U and V must make sure that unprotected data and metadata do not reveal any sensitive information. This also applies for encrypted data sent to an unauthenticated party. In particular, it applies to EXT_1 and EXT_2 in the asymmetrical case, and KID in the symmetrical case. The communicating parties may therefore anonymize KID.

Using the same KID or unprotected extension in several EDHOC sessions allows passive eavesdroppers to correlate the different sessions. Another consideration is that the list of supported algorithms may be used to identify the application.

Party U and V must make sure that unprotected data does not trigger any harmful actions. In particular, this applies to EXT_1 in the asymmetrical case, and KID in the symmetrical case. Party V should be aware that replays of EDHOC message_1 cannot be detected unless unless previous nonces are stored.

The availability of a secure pseudorandom number generator and truly random seeds are essential for the security of EDHOC. If no true random number generator is available, a truly random seed must be provided from an external source. If ECDSA is supported, "deterministic ECDSA" as specified in RFC6979 is RECOMMENDED.

Nonces MUST NOT be reused, both parties MUST generate fresh random nonces. Ephemeral keys SHOULD NOT be reused, both parties SHOULD generate fresh random ephemeral key pairs.

The referenced processing instructions in {{SP-800-56a}} must be complied with, including deleting the intermediate computed values along with any ephemeral ECDH secrets after the key derivation is completed.

Party U and V are responsible for verifying the integrity of certificates. The selection of trusted CAs should be done very carefully and certificate revocation should be supported.

The choice of key length used in the different algorithms needs to be harmonized, so that a sufficient security level is maintained for certificates, EDHOC, and the protection of application data. Party U and V should enforce a minimum security level. 

Note that, depending on the application, the keys established through the EDHOC protocol will need to be renewed, in which case the communicating parties need to run the protocol again.

Implementations should provide countermeasures to side-channel attacks such as timing attacks.


# Acknowledgments #

The authors want to thank Ilari Liusvaara, Jim Schaad, and Ludwig Seitz for reviewing previous versions of the draft. 

TODO: This section should be after Appendixes and before Author's address according to RFC7322.



--- back

# Test Vectors {#examples}

TODO: This section needs to be updated.

# Implementing EDHOC with CoAP and OSCOAP # {#app-a}

EDHOC can be implemented as an exchange of CoAP {{RFC7252}} messages, with the CoAP client as party U and the CoAP server as party V. Additionally, EDHOC and OSCOAP {{I-D.ietf-core-object-security}} can be run in sequence embedded into a 2-round trip exchange, such that the security context input parameters required for OSCOAP (Section 3 of {{I-D.ietf-core-object-security}}) are obtained from EDHOC. 

One procedure for running EDHOC over CoAP combined with OSCOAP is presented in this section. The EDHOC protocol is combined with OSCOAP such that EDHOC message_3 is sent together with the OSCOAP request, see {{fig-edhoc-oscoap}}.

~~~~~~~~~~~~~~~~~~~~~~~
Client                                         Server
   |                                             |
   | ------------- EDHOC message_1 ------------> |
   |                                             |
   | <------------ EDHOC message_2 ------------- |
   |                                             |
   | ---- OSCOAP Request + EDHOC message_3 ----> |
   |                                             |
   | <------------ OSCOAP Response ------------- |
   |                                             |
~~~~~~~~~~~~~~~~~~~~~~~
{: #fig-edhoc-oscoap title="EDHOC and OSCOAP in two CoAP message exchanges"}
{: artwork-align="center"}

As specified below and illustrated in {{fig-edhoc-oscoap-det}}, EDHOC message_1 and message_2 are transported in the CoAP payload, and EDHOC message_3 is transported as an unprotected header parameter in the OSCOAP request.

~~~~~~~~~~~~~~~~~~~~~~~
Client     Server
  |           |
  +---------->| Header: POST (Code=0.02)
  |   POST    | Uri-Path: "edhoc"
  |           | Content-Type: application/edhoc
  |           | Payload: EDHOC message_1
  |           |
  |<----------+ Header: 2.04 Changed
  |   2.04    | Content-Type: application/edhoc
  |           | Payload: EDHOC message_2
  |           |
  +---------->| CoAP request including:
  |  OSCOAP   | Object-Security option
  |  request  | COSE_Encrypt0 
  |           | (protected request and
  |           | EDHOC message_3)
  |           |
  |<----------+ CoAP response including:
  |  OSCOAP   | Object-Security option
  |  response | COSE_Encrypt0 
  |           | (protected response)
  |           |
~~~~~~~~~~~~~~~~~~~~~~~
{: #fig-edhoc-oscoap-det title="CoAP binding of EDHOC combined with OSCOAP"}
{: artwork-align="center"}

The client makes the following CoAP request:

* The request method is POST
* Content-Format is "application/edhoc"
* The Uri-Path is "edhoc"
* The Payload is EDHOC message_1, computed as defined in this document

The CoAP server processes message_1 as specified in this document. If successful, the server composes message_2 and sends the following CoAP response:

* The response Code is 2.04 (Changed)
* Content-Format is "application/edhoc"
* The Payload is EDHOC message_2, computed as defined in this document

The client verifies message_2 as specified in this document. If successful, the client composes EDHOC message_3.

The client also derives the OSCOAP Security Context (Section 3 of {{I-D.ietf-core-object-security}}) from the EDHOC messages:

* The OSCOAP Master Secret (master_secret) and Context Identifier (CID) are derived as specified in {{key-der}} of this document, using:
 
   * For OSCOAP master_secret, 'label' is the byte string "OSCOAP_master_secret".
   * For OSCOAP CID, 'label' is the byte string "OSCOAP_CID".

* The AEAD Algorithm is AEAD_V, as defined in this document
* The Key Derivation Function is HKDF_V, as defined in this document
* For the other OSCOAP security context input parameters, the default values are used as specified in section 3.2 of {{I-D.ietf-core-object-security}}.

The client builds the intended CoAP request and protects the request with OSCOAP. The request thus contains the Object-Security option and a COSE_Encrypt0 object as defined in {{I-D.ietf-core-object-security}}. EDHOC message_3 is added as an unprotected header parameter with label 'edhoc' in the COSE_Encrypt0 object 

The server extracts and verifies EDHOC message_3 from the unprotected part of the COSE_Encrypt0 object in the OSCOAP request. If successful, the server derives the OSCOAP security context parameters as in the same way as the client as decsribed above. The server processes the OSCOAP request as specified in {{I-D.ietf-core-object-security}} and returns the OSCOAP response.

EDHOC can also be embedded into CoAP without OSCOAP by simply sending all ECHOC messages as CoAP payloads.

--- fluff
