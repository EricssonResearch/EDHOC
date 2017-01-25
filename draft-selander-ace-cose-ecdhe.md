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
        street: Färogatan 6
        city: Kista
        code: SE-164 80 Stockholm
        country: Sweden
        email: goran.selander@ericsson.com
      -
        ins: J. Mattsson
        name: John Mattsson
        org: Ericsson AB
        street: Färogatan 6
        city: Kista
        code: SE-164 80 Stockholm
        country: Sweden
        email: john.mattsson@ericsson.com
      -
        ins: F. Palombini
        name: Francesca Palombini
        org: Ericsson AB
        street: Färogatan 6
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

  RFC7228:
  RFC7252:
  RFC5869:

--- abstract

This document specifies authenticated Diffie-Hellman key exchange with ephemeral keys, embedded in messages encoded with CBOR and using the CBOR Object Signing and Encryption (COSE) format. 


--- middle

# Introduction #       {#intro}

Security at the application layer provides an attractive option for protecting Internet of Things (IoT) deployments, for example where transport layer security is not sufficient {{I-D.hartke-core-e2e-security-reqs}}. IoT devices may be constrained in various ways, including memory, storage, processing capacity, and energy {{RFC7228}}. A method for protecting individual messages at the application layer suitable for constrained devices, is provided by COSE {{I-D.ietf-cose-msg}}), which builds on CBOR {{RFC7049}}.

In order for a communication session to provide forward secrecy, the communicating parties can run a Diffie-Hellman (DH) key exchange protocol with ephemeral keys, from which shared key material can be derived. This document specifies authenticated DH protocols using CBOR and COSE objects. The DH key exchange messages may be authenticated using pre-shared keys (PSK), raw public keys (RPK), or certificates (Cert). Authentication is based on credentials established out of band, or from a trusted third party, such as an Authorization Server as specified by {{I-D.ietf-ace-oauth-authz}}. Note that this document focuses on authentication and key establishment: for integration with authorization of resource access, refer to {{I-D.seitz-ace-oscoap-profile}}. This document also specifies the derivation of shared key material.

The DH exchange and the key derivation follow {{SIGMA}}, NIST SP-800-56a {{SP-800-56a}}, and HKDF {{RFC5869}}. CBOR {{RFC7049}} and COSE {{I-D.ietf-cose-msg}} are used to implement these standards.

## Terminology ##  {#terminology}

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in {{RFC2119}}. These words may also appear in this document in lowercase, absent their normative meanings.


# Protocol Overview # {#protocol}
SIGMA (SIGn-and-MAc) is a family of theoretical protocols with a large number of variants {{SIGMA}}. Like IKEv2 and TLS 1.3, EDHOC is built on the SIGMA-I protocol, which provides identity protection, and like TLS 1.3, EDHOC implements SIGMA as Sign-then-MAC. The SIGMA-I protocol using an AEAD algorithm is shown in {{fig-sigma}}.

~~~~~~~~~~~
Party U                                                 Party V
   |                          E_U                          |
   +------------------------------------------------------>|
   |                                                       |
   |          E_V, Enc(K; ID_V; Sig(V; E_U, E_V))          |
   |<------------------------------------------------------+
   |                                                       |
   |             Enc(K; ID_U; Sig(U; E_V, E_U)             |
   +------------------------------------------------------>|
   |                                                       |
~~~~~~~~~~~
{: #fig-sigma title="Sign-then-MAC variant of the SIGMA-I protocol"}
{: artwork-align="center"}

The parties exchanging messages are called "U" and "V". They exchange identities and ephemeral public keys, compute the shared secret, and derive the keying material. The messages are signed, MACed, and encrypted.

* E_U and E_V are the ECDH ephemeral public keys of U and V, respectively.

* ID_U and ID_V are identifiers for the public keys of U and V, respectively.

* Sig(U; . ) and S(V; . ) denote signatures made with the private key of U and V, respectively.

* Enc(K; P; A) denotes AEAD encryption of plaintext P and additional authenticated data A using keys derived from the shared secret.

As described in Appendix B of {{SIGMA}}, in order to create a "full-fledge" protocol some additional protocol elements are needed. EDHOC adds:

* Session identifiers S_U, S_V derived from the ephemeral public keys.

* Computationally independent keys derived from the DH-shared secret and used for different directions and operations.

EDHOC also makes the following addition:

* Negotiation of key derivation, AEAD, and signature algorithms:

   * U proposes one or more algorithms of each kind.

   * V selects one algorithm of each kind, and additionally proposes an array of signature algorithms.

   * U selects and uses one signature algorithm.

* Transmission of application defined extensions.

EDHOC is designed with the intention to encrypts and integrity protect as much information as possible, furthermore, all symmetric keys are derived using as much previous information as possible. EDHOC is furthermore designed to be as lightweight as possible, in terms of message sizes, processing, and the ability to reuse already existing CBOR and COSE libraries.

This paper is organized as follows: {{general}} specifies general aspects of EDHOC, including formatting of the ephemeral public keys and key derivation, {{asym}} specifies EDHOC with asymmetric authentication, {{sym}} specifies EDHOC with symmetric authentication, and {{examples}} provides a wealth of test vectors to ease implementation and ensure interoperability.

# EDHOC Overview # {#general}

EDHOC consists of three messages (message_1, message_2, message_3) that maps directly to the three messages in SIGMA-I. All ECDHOC messages consists of an CBOR array where the first element is an int specifying the message type (MSG_TYPE). After creating EDHOC message_3, Party U can derive the traffic key (master secret) and protected application data can therefore be sent in parallel with EDHOC message_3. The application data may e.g. be protected using the negotiated AEAD algorithm. EDHOC may be used with the media type application/edhoc defined in {{iana}}.

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

The EDHOC message exchange may be authenticated using pre-shared keys (PSK), raw public keys (RPK), or certificates (Cert). EDHOC assumes the existence of mechanisms (certification authority, manual distribution, etc.) for binding identities with authentication keys (public or pre-shared). EDHOC with symmetric authentication is very similar to EDHOC with asymmetric authentication, the
differences are that information is only MACed (not signed) and that EDHOC with symmetric authentication offers encryption, integrity protection, and key proof-of-possession already in message_1.

EDHOC allows application defined extensions (EXT_1, EXT_2, EXT_3) to be sent in the respective messages. When EDHOC are used with asymmetric authentication, EXT_1 is unprotected, EXT_2 is protected (encrypted and integrity protected), but sent to an unauthenticated party, and EXT_3 is protected and mutually authenticated. When EDHOC is used with symmetric authentication, all extensions are protected and mutually authenticated.

## Formatting of the Ephemeral Public Keys ## {#cose_key}

The ECDH ephemeral public key SHALL be formatted as a COSE_Key of type EC2 or OKP according to section 13.1 and 13.2 of {{I-D.ietf-cose-msg}}. The curve X25519 is mandatory-to-implement. For Elliptic Curve Keys of type EC2, point compression is mandatory-to-implement.

## Key Derivation ## {#key-der}

Key and IV derivation SHALL be done as specified in Section 11.1 of [I-D.ietf-cose-msg] with the following input:

* The secret SHALL be the ECDH shared secret as defined in Section 12.4.1 of [I-D.ietf-cose-msg].

* The PRF SHALL be the HKDF [RFC5869] in the the ECDH-SS w/ HKDF negotiated during the message exchange (HKDF_V).

* The context information SHALL be the serialized COSE_KDF_Context with the following values:

  + PartyInfo = ( nil, nil, nil )

  + SuppPubInfo SHALL contain:

    + protected SHALL be a zero length bstr

~~~~~~~~~~~
      +  other = aad_1  / aad_2  / aad_3 /
                 [ message_1, message_2, message_3, label ]

   * ? SuppPrivInfo = PSK
~~~~~~~~~~~

SuppPrivInfo SHALL only be present in the symmetric case.

The symmetric key and IV used to protect message_i is called K_i and IV_i etc., and are derived using the structure aad_i defined for each EDHOC message that make use of a symmetric key.

K_1 and IV_1 are only used in EDHOC with symmetric authentication and are derived using aad_1 and with the exceptions that secret SHALL be empty, the PRF SHALL be HKDF-256 (or a HKDF decided by the application), and SuppPrivInfo SHALL be the PSK.

All other keys are derived with the negotiated PRF and with the secret set to the ECDH shared secret.

Application specific traffic keys and key identifiers are derived using the CBOR array \[ message_1, message_2, message_3, label \], where label is any CBOR type. Each application making use of EDHOC defines its own labels and how they are used.

# EDHOC Authenticated with Asymmetric Keys # {#asym}

## Overview ##

EDHOC supports authentication with raw public keys (RPK) and certificates (Cert) with the requirements that:

* Party V's SHALL be able to uniquely identify Party U's public key using ID_U.

* Party U's SHALL be able to uniquely identify Party V's public key using ID_V.

ID_U and ID_V either enable the other party to retrieve the public key (kid, x5t, x5u) or they contain the public key (x5c), see {{I-D.schaad-cose-x509}}.

EDHOC with asymmetric authentication is illustrated in {{fig-asym}}.

~~~~~~~~~~~
Party U                                                       Party V
|                         E_U, ALG_1, EXT_1                         |
+------------------------------------------------------------------>|
|                             message_1                             |
|                                                                   |
|       S_U, E_V, ALG_2, Enc(K_2; EXT_2, ID_V; Sig(V; aad_2))       |
|<------------------------------------------------------------------+
|                             message_2                             |
|                                                                   |
|          S_V, ALG_3, Enc(K_3; EXT_3, ID_U; Sig(U; aad_3))         |
+------------------------------------------------------------------>|
|                             message_3                             |
~~~~~~~~~~~
{: #fig-asym title="EDHOC with asymmetric authentication. "}
{: artwork-align="center"}


### Mandatory to Implement Algorithms ### {#asym-mti}

For EDHOC authenticated with asymmetric keys, the COSE algorithms ECDH-SS + HKDF-256, AES-CCM-64-64-128, and EdDSA are mandatory to implement.

## EDHOC Message 1 ## {#asym-msg1}

### Formatting of Message 1 ### {#asym-msg1-form}

message_1 SHALL be a CBOR array object containing:

~~~~~~~~~~~
message_1 = [
  MSG_TYPE : int,
  E_U : COSE_Key,
  HKDFs_U : alg_array,
  AEADs_U : alg_array,
  SIGs_U : alg_array,
  ? EXT_1 : bstr
]

alg_array = [ + alg : int / tstr ]
~~~~~~~~~~~

where:

* MSG_TYPE = 1
* E_U - the ephemeral public key of Party U
* HKDFs_U - supported ECDH-SS w/ HKDF algorithms
* AEADs_U - supported AEAD algorithms
* SIGs_U - signature algorithms that Party U supports signing with
* EXT_1 - application defined extensions

### Party U Processing of Message 1 ### {#asym-msg1-procU}

Party U SHALL compose message_1 as follows:

*  Generate a fresh ephemeral ECDH key pair as specified in Section 5 of {{SP-800-56a}} and format the ephemeral public key E_U as a COSE_key as specified in {{cose_key}}.

*  Format message_1 as specified in {{asym-msg1-form}}.

### Party V Processing of Message 1 ### {#asym-msg1-procV}

Party V SHALL process message_1 as follows:

* Verify (OPTIONAL) that E_U has not been received before.

* Verify that at least one of each kind of the proposed algorithms are supported.

If any verification step fails, the message MUST be discarded and the protocol discontinued.



## EDHOC Message 2 ## {#asym-msg2}

### Formatting of Message 2 ### {#asym-msg2-form}

message_2 SHALL be a CBOR array object containing:

~~~~~~~~~~~
message_2 = [
  MSG_TYPE : int,
  S_U : bstr,
  E_V : COSE_Key,
  HKDF_V : int / tstr,
  AEAD_V : int / tstr,
  SIG_V : int / tstr,
  SIGs_V : alg_array,
  COSE_ENC_2 : COSE_Encrypt0
]

aad_2 = [
  MSG_TYPE : int,
  S_U : bstr,
  E_V : COSE_Key,
  HKDF_V : int / tstr,
  AEAD_V : int / tstr,
  SIG_V : int / tstr,
  SIGs_V : alg_array,
  message_1 : bstr,
  ? EXT_2 : bstr,
]
~~~~~~~~~~~

where:

* MSG_TYPE = 2
* S_U - SHA-256(message_1) truncated to 64 bits.
* E_V - the ephemeral public key of Party V
* HKDF_V - an single chosen algorithm from HKDFs_U
* AEAD_V - an single chosen algorithm from AEADs_U
* SIG_V - an single chosen algorithm from SIGs_U
* SIGs_V - signature algorithms that Party V supports signing with
* COSE_ENC_2 has the following fields and values:

   + plaintext = \[ COSE_SIG_V, ? EXT_2 \]

* COSE_SIG_V is a COSE_Sign1 object with the following fields and values:
   
   - protected = { xyz: ID_V }

   - detached payload = aad_2

* xyz - any COSE map label that can identify a public key

* ID_V - identifier for the public key of Party V

* EXT_2 - application defined extensions


### Party V Processing of Message 2 ### {#asym-msg2-procV}

Party V SHALL compose message_2 as follows:

* Generate a fresh ephemeral ECDH key pair as specified in Section 5 of {{SP-800-56a}} using same curve as used in E_U. Format the ephemeral public key E_V as a COSE_key as specified in {{cose_key}}.

*  Select HKDF_V, AEAD_V, and SIG_V from the algorithms proposed in HKDFs_U, AEADs_U, and SIGs_U.

*  Format message_2 as specified in {{asym-msg2-form}}:

   - COSE_Sign1 is computed as defined in section 4.4 of {{I-D.ietf-cose-msg}}, using algorithm SIG_V and the private key of Party V.

   -  COSE_Encrypt0 is computed as defined in section 5.3 of {{I-D.ietf-cose-msg}}, with AEAD_V, K_2, and IV_2.

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

message_3 SHALL be a CBOR array object containing:

~~~~~~~~~~~
message_3 = [
  MSG_TYPE : int,
  S_V : bstr,
  SIG_U : int / tstr,
  COSE_ENC_3 : COSE_Encrypt0
]

aad_3 = [
  MSG_TYPE : int,
  S_V : bstr,
  SIG_U : int / tstr,
  message_1 : bstr,
  message_2 : bstr,
  ? EXT_3 : bstr
]
~~~~~~~~~~~

where:

* MSG_TYPE = 3
* S_V - SHA-256(E_V) truncated to 64 bits.
* SIG_U - an single chosen algorithm from SIGs_V
* COSE_ENC_3 has the following fields and values:

   + plaintext = \[ COSE_SIG_U, ? EXT_3 \]
   
* COSE_SIG_U is a COSE_Sign1 object with the following fields and values:
   
   - protected = { xyz: ID_U }

   - detached payload = aad_3
      
* xyz - any COSE map label that can identify a public key
* ID_U - identifier for the public key of Party U
* EXT_3 - application defined extensions

### Party U Processing of Message 3 ### {#asym-msg3-procU}

Party U SHALL compose message_3 as follows:

* Select SIG_U from the algorithms proposed in SIGs_V.

* Format message_3 as specified in {{asym-msg3-form}}:

   *  COSE_Sign1 is computed as defined in section 4.4 of {{I-D.ietf-cose-msg}}, using algorithm SIG_U and the private key of Party U.

   *  COSE_Encrypt0 is computed as defined in section 5.3 of {{I-D.ietf-cose-msg}}, with AEAD_V, K_3, and IV_3.

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

EDHOC with symmetric authentication is illustrated in {{fig-sym}}.

~~~~~~~~~~~
Party U                                                       Party V
|              KID, E_U, ALG_1, Enc(K_1; EXT_1; aad_1)              |
+------------------------------------------------------------------>|
|                             message_1                             |
|                                                                   |
|              S_U, E_V, ALG_2, Enc(K_2; EXT_2; aad_2)              |
|<------------------------------------------------------------------+
|                             message_2                             |
|                                                                   |
|                    S_V, Enc(K_3; EXT_3; aad_3)                    |
+------------------------------------------------------------------>|
|                             message_3                             |
~~~~~~~~~~~
{: #fig-sym title="EDHOC with symmetric authentication. "}
{: artwork-align="center"}

### Mandatory to Implement Algorithms ### {#sym-mti}

For EDHOC authenticated with symmetric keys, the COSE algorithms ECDH-SS + HKDF-256 and AES-CCM-64-64-128 are mandatory to implement.

## EDHOC Message 1 ## {#sym-msg1}

### Formatting of Message 1 ### {#sym-msg1-form}

message_1 SHALL be a CBOR array object containing:

~~~~~~~~~~~
message_1 = [
  MSG_TYPE : int,
  KID : bstr,
  E_U : COSE_Key,
  HKDFs_U : alg_array,
  AEADs_U : alg_array,
  COSE_ENC_1 : COSE_Encrypt0
]

aad_1 = [
  MSG_TYPE : int,
  KID : bstr,
  E_U : COSE_Key,
  HKDFs_U : alg_array,
  AEADs_U : alg_array
]

alg_array = [ + alg : int / tstr ]
~~~~~~~~~~~

where:

* MSG_TYPE = 4
* KID - identifier of the pre-shared key
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

*  Format message_1 as specified in {{sym-msg1-form}} where COSE_Encrypt0 is computed as defined in section 5.3 of {{I-D.ietf-cose-msg}}, with AES-CCM-64-64-128 (or an AEAD decided by the application), K_1, and IV_1.


### Party V Processing of Message 1 ### {#sym-msg1-procV}

Party V SHALL process message_1 as follows:

* Verify (OPTIONAL) that E_U has not been received before.

* Verify that at least one of each kind of the proposed algorithms are supported.

* Verify message_1 as specified in {{sym-msg1-form}} where COSE_Encrypt0 is decrypted defined in section 5.3 of {{I-D.ietf-cose-msg}}, with AES-CCM-64-64-128 (or an AEAD decided by the application), K_1, and IV_1.

If any verification step fails, the message MUST be discarded and the protocol discontinued.



## EDHOC Message 2 ## {#sym-msg2}

### Formatting of Message 2 ### {#sym-msg2-form}

message_2 SHALL be a CBOR array object containing:

~~~~~~~~~~~
message_2 = [
  MSG_TYPE : int,
  S_U : bstr,
  E_V : COSE_Key,
  HKDF_V : int / tstr,
  AEAD_V : int / tstr,
  COSE_ENC_2 : COSE_Encrypt0
]

aad_2 = [
  MSG_TYPE : int,
  S_U : bstr,
  E_V : COSE_Key,
  HKDF_V : int / tstr,
  AEAD_V : int / tstr,
  message_1 : bstr
]
~~~~~~~~~~~

where:

* MSG_TYPE = 5
* S_U - SHA-256(message_1) truncated to 64 bits.
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

*  Select HKDF_V and AEAD_V from the algorithms proposed in HKDFs_U and AEADs_U.

*  Format message_2 as specified in {{sym-msg2-form}} where COSE_Encrypt0 is computed as defined in section 5.3 of {{I-D.ietf-cose-msg}}, with AEAD_V, K_2, and IV_2.
   
### Party U Processing of Message 2 ### {#sym-msg2-procU}

Party U SHALL process message_2 as follows:

* Use the session identifier S_U to retrieve the protocol state.

* Verify message_2 as specified in {{sym-msg2-form}} where COSE_Encrypt0 is decrypted defined in section 5.3 of {{I-D.ietf-cose-msg}}, with AEAD_V, K_2, and IV_2.

If any verification step fails, the message MUST be discarded and the protocol discontinued.




## EDHOC Message 3 ## {#sym-msg3}

### Formatting of Message 3 ### {#sym-msg3-form}

message_3 SHALL be a CBOR array object containing:

~~~~~~~~~~~
message_3 = [
  MSG_TYPE : int,
  S_V : bstr,
  COSE_ENC_3 : COSE_Encrypt0
]

aad_3 = [
  MSG_TYPE : int,
  S_V : bstr,
  message_1 : bstr,
  message_2 : bstr
]
~~~~~~~~~~~

where:

* MSG_TYPE = 6
* S_V - SHA-256(E_V) truncated to 64 bits.
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


# IANA Considerations # {#iana}

IANA has added the media type application/edhoc to the Media Types registry:

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
           Goeran Selander <goran.selander@ericsson.com>

        Intended usage: COMMON

        Restrictions on usage: N/A

        Author: Goeran Selander <goran.selander@ericsson.com>

        Change Controller: IESG


# Security Considerations # {#sec-cons}

EDHOC build on the SIGMA-I family of theoretical protocols that provides perfect forward secrecy and identity protection with a minimal number of messages. The security of the SIGMA-I protocol does not depend on the encryption and SIGMA-I is secure as long as the MAC covers the identity of the signer. EDHOC expands the authentication coverage to additional elements such as algorithms, extensions, and previous messages. EDHOC uses the same Sign-then-MAC approach as TLS 1.3.

Party U and V must make sure that unprotected data and metadata do not reveal any sensitive information. This also applies for encrypted data sent to an unauthenticated party. In particular, it applies to EXT_1 and EXT_2 in the asymmetrical case, and KID in the symmetrical case. The communicating parties may therefore anonymize KID.

Using the same KID or unprotected extension in several EDHOC sessions allows passive eavesdroppers to correlate the different sessions. Another consideration is that the list of supported algorithms may be used to identify the application.

Party U and V must make sure that unprotected data does not trigger any harmful actions. In particular, this applies to EXT_1 in the asymmetrical case, and KID in the symmetrical case. Party V should be aware that EDHOC message_1 might be replayed unless previous messages are stored.

The availability of a secure pseudorandom number generator and truly random seeds are essential for the security of ECDHOC. If no true random number generator is available, a truly random seed must be provided from an external source. If ECDSA is supported, "deterministic ECDSA" as specified in RFC6979 is RECOMMENDED.

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

TODO: This section needs to be updated.

The DH key exchange specified in this document can be implemented as a CoAP {{RFC7252}} message exchange with the CoAP client as party U and the CoAP server as party V. EDHOC and OSCOAP {{I-D.ietf-core-object-security}} could be run in sequence embedded in a 2-round trip message exchange, where the base_key used in OSCOAP is obtained from EDHOC.

The process to run EDHOC over CoAP, combined with and followed by OSCOAP is described here and showed in {{edhoc-oscoap}} and {{edhoc-oscoap-det}}.

~~~~~~~~~~~~~~~~~~~~~~~

        Client                                        Server
           | ------------- EDHOC message_1 ------------> | 
           |                                             |
           | <------------ EDHOC message_2 ------------- |
           |                                             |
           | ---- OSCOAP Request + EDHOC message_3 ----> |
           |                                             |
           | <------------ OSCOAP Response ------------- |
           |                                             |

~~~~~~~~~~~~~~~~~~~~~~~
{: #edhoc-oscoap title="EDHOC and OSCOAP"}

~~~~~~~~~~~~~~~~~~~~~~~

          Client    Server
            |          |
            |          |
            +--------->| Header: POST (Code=0.02)
            | POST     | Uri-Path:"edhoc"
            |          | Content-Type: application/cbor
            |          | Payload: EDHOC message_1
            |          |
            |<---------+ Header: 2.04 Changed
            |          | Content-Type: application/cose+cbor
            | 2.05     | Payload: EDHOC message_2
            |          |   
            |          |
            +--------->| CoAP message including:
            |  OSCOAP  | Object-Security option
            | request  | COSE_Encrypt0 includes
            |          | EDHOC message_3
            |          |
            |<---------+ CoAP message including:
            |  OSCOAP  | Object-Security option
            | response | 
            |          |  
 
~~~~~~~~~~~~~~~~~~~~~~~
{: #edhoc-oscoap-det title="Detail of EDHOC and OSCOAP"}

The CoAP client makes the following request:

* The request method is POST
* Content-Format is "application/cose+cbor"
* The Uri-Path is "edhoc"
* The Payload is EDHOC message_1, computed as defined in this document

The CoAP server performs the first step of the protocol as specified in this document. Then the server provides the following response:

* The response Code is 2.04 (Changed)
* The Payload is EDHOC message_2, computed as defined in this document

The CoAP client verifies the message_2 as specified in this document. If successful, the client continues the protocol and generates EDHOC message\_3. 

The client derives OSCOAP Common Context (section 3.1 of {{I-D.ietf-core-object-security}}) from the messages exchanged:

* base_key is the traffic secret, output of EDHOC (section 6 of this document)
* Context Identifier is the HMAC computed over the hash of the concatenation of EDHOC message\_1, message\_2, and message\_3 using the key base\_key: Cid = HMAC(base_key, hash(message\_1 \|\| message\_2 \|\| message\_3))
* the Algorithm is the AEAD algorithm negotiated during EDHOC

Additionally, we define here that:

* Sender ID for the CoAP client is set to '0'
* Recipient ID for the CoAP client is set to '1'

With these parameters, the CoAP client can derive the full security context, following section 3.2 of {{I-D.ietf-core-object-security}}.

Finally, the client generates the OSCOAP request, containing the Object-Security option and the COSE\_Encrypt0 object as defined in {{I-D.ietf-core-object-security}}. EDHOC message\_3 is added to the unprotected part of the COSE\_Encrypt0 Headers, with label 'edhoc_m3'. The OSCOAP request is sent, and includes also EDHOC message\_3. Note that this may considerably increase the size of the COSE\_Encrypt0 object (see {#ex-rpk3}), so in case the OSCOAP request method does not allow payload, the Object-Security option may become large.

The server receives the message and extract the message\_3 from the unprotected part of the COSE\_Encrypt0 object of the OSCOAP request. If the object does not contain the 'edhoc\_m3' label, or if the 'edhoc\_m3' value does not comply with the specifications, the message is discarded and the communication terminated.
Otherwise, the server process and verifies the EDHOC message\_3 as described in this document. If successful, the server derives OSCOAP Common Context (section 3.1 of {{I-D.ietf-core-object-security}}) from the messages exchanged:

* base_key is the traffic secret, output of EDHOC (section 6 of this document)
* Context Identifier is the HMAC computed over the hash of the concatenation of EDHOC message\_1, message\_2, and message\_3 using the key base\_key: Cid = HMAC(base_key, hash(message\_1 \|\| message\_2 \|\| message\_3))
* the Algorithm is the AEAD algorithm negotiated during EDHOC

Additionally, we define here that:

* Sender ID for the CoAP server is set to '1'
* Recipient ID for the CoAP server is set to '0'

With these parameters, the CoAP server can derive the full security context, following section 3.2 of {{I-D.ietf-core-object-security}}.

Finally, the client can verify the OSCOAP request using the security context, and act according to {{I-D.ietf-core-object-security}}. Further communication can be protected using OSCOAP.


--- fluff



