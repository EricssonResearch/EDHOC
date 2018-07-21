---
title: Ephemeral Diffie-Hellman Over COSE (EDHOC)
docname: draft-selander-ace-cose-ecdhe-latest

ipr: trust200902
wg: ACE Working Group
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

  RFC2119:
  RFC6090:  
  RFC7049:
  RFC8152:
  RFC8174:
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
  I-D.ietf-ace-oscore-profile:
  I-D.ietf-cbor-cddl:
  I-D.ietf-core-resource-directory:

  RFC7228:
  RFC7252:
  RFC5869:

--- abstract

This document specifies Ephemeral Diffie-Hellman Over COSE (EDHOC), a very compact, and lightweight authenticated Diffie-Hellman key exchange with ephemeral keys that can be used over any layer. EDHOC uses CBOR and COSE, allowing reuse of existing libraries.

--- middle

# Introduction {#intro}

Security at the application layer provides an attractive option for protecting Internet of Things (IoT) deployments, for example where transport layer security is not sufficient {{I-D.hartke-core-e2e-security-reqs}} or where the protocol needs to work on a variety of underlying protocols. IoT devices may be constrained in various ways, including memory, storage, processing capacity, and energy {{RFC7228}}. A method for protecting individual messages at the application layer suitable for constrained devices, is provided by CBOR Object Signing and Encryption (COSE) {{RFC8152}}), which builds on the Concise Binary Object Representation (CBOR) {{RFC7049}}.

In order for a communication session to provide forward secrecy, the communicating parties can run an Elliptic Curve Diffie-Hellman (ECDH) key exchange protocol with ephemeral keys, from which shared key material can be derived. This document specifies Ephemeral Diffie-Hellman Over COSE (EDHOC), an authenticated ECDH protocol using CBOR and COSE objects. Authentication is based on credentials established out of band, e.g. from a trusted third party, such as an Authorization Server as specified by {{I-D.ietf-ace-oauth-authz}}. EDHOC supports authentication using pre-shared keys (PSK), raw public keys (RPK), and certificates.  Note that this document focuses on authentication and key establishment: for integration with authorization of resource access, refer to {{I-D.ietf-ace-oscore-profile}}. This document also specifies the derivation of shared key material.

The ECDH exchange and the key derivation follow {{SIGMA}}, NIST SP-800-56a {{SP-800-56a}}, and HKDF {{RFC5869}}. CBOR {{RFC7049}} and COSE {{RFC8152}} are used to implement these standards.

## Terminology {#terminology}

This document uses the Concise Data Definition Language (CDDL) {{I-D.ietf-cbor-cddl}} to express CBOR data structures {{RFC7049}}. A vertical bar \| denotes byte string concatenation.

## Requirements Language {#terminology2}

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 {{RFC2119}} {{RFC8174}} when, and only when, they appear in all capitals, as shown here.

# Protocol Overview {#protocol}
SIGMA (SIGn-and-MAc) is a family of theoretical protocols with a large number of variants {{SIGMA}}. Like IKEv2 and TLS 1.3, EDHOC is built on a variant of the SIGMA protocol which provide identity protection (SIGMA-I), and like TLS 1.3, EDHOC implements the SIGMA-I variant as Sign-then-MAC. The SIGMA-I protocol using an AEAD algorithm is shown in {{fig-sigma}}.

~~~~~~~~~~~
Party U                                                 Party V
   |                          E_U                          |
   +------------------------------------------------------>|
   |                                                       |
   |         E_V, Enc(K_2; ID_V, Sig(V; E_U, E_V);)        |
   |<------------------------------------------------------+
   |                                                       |
   |           Enc(K_3; ID_U, Sig(U; E_V, E_U);)           |
   +------------------------------------------------------>|
   |                                                       |
~~~~~~~~~~~
{: #fig-sigma title="AEAD variant of the SIGMA-I protocol"}
{: artwork-align="center"}

The parties exchanging messages are called "U" and "V". They exchange identities and ephemeral public keys, compute the shared secret, and derive application keys. The messages are signed, MACed, and encrypted.

* E_U and E_V are the ECDH ephemeral public keys of U and V, respectively.

* ID_U and ID_V are identifiers for the public keys of U and V, respectively.

* Sig(U; . ) and S(V; . ) denote signatures made with the private key of U and V, respectively.

* Enc(K; P; A) denotes AEAD encryption of plaintext P and additional authenticated data A using the key K derived from the shared secret. The AEAD MUST NOT be replaced by plain encryption, see {{sec-cons}}.

As described in Appendix B of {{SIGMA}}, in order to create a "full-fledged" protocol some additional protocol elements are needed. EDHOC adds:

* Explicit session identifiers S_U, S_V different from other concurrent session identifiers (EDHOC or other used protocol identifier) chosen by U and V, respectively. 

* Computationally independent keys derived from the ECDH shared secret and used for encryption of different messages.

EDHOC also makes the following additions:

* Negotiation of key derivation, encryption, and signature algorithms:

   * U proposes one or more algorithms of the following kinds: 
       *  HKDF
       *  AEAD
       *  Signature verification 
       *  Signature generation 

   * V selects one algorithm of each kind

* Verification of common preferred ECDH curve:

   * U lists supported ECDH curves in order of preference
   
   * V verifies that the ECDH curve of the ephemeral key is the most preferred common curve

* Transport of opaque application defined data.

EDHOC is designed to encrypt and integrity protect as much information as possible, and all symmetric keys are derived using as much previous information as possible. EDHOC is furthermore designed to be as compact and lightweight as possible, in terms of message sizes, processing, and the ability to reuse already existing CBOR and COSE libraries. EDHOC does not put any requirement on the lower layers and can therefore also be used e.g. in environments without IP.

This paper is organized as follows: {{general}} specifies general properties of EDHOC, including formatting of the ephemeral public keys and key derivation, {{asym}} specifies EDHOC with asymmetric key authentication, {{sym}} specifies EDHOC with symmetric key authentication, and {{examples}} provides a wealth of test vectors to ease implementation and ensure interoperability.

# EDHOC Overview {#general}

EDHOC consists of three messages (message_1, message_2, message_3) that maps directly to the three messages in SIGMA-I, plus an EDHOC error message. All EDHOC messages consists of a sequence of CBOR elements, where the first element is an int specifying the message type (MSG_TYPE). After creating EDHOC message_3, Party U can derive application keys, and protected application data can therefore be sent in parallel with EDHOC message_3. The application data may be protected using the negotiated AEAD algorithm and the explicit session identifiers S_U and S_V. EDHOC may be used with the media type application/edhoc defined in {{iana}}.

~~~~~~~~~~~
Party U                                                 Party V
   |                                                       |
   | ------------------ EDHOC message_1 -----------------> |
   |                                                       |
   | <----------------- EDHOC message_2 ------------------ |
   |                                                       |
   | ------------------ EDHOC message_3 -----------------> |
   |                                                       |
   | <----------- Protected Application Data ------------> |
   |                                                       |
~~~~~~~~~~~
{: #fig-flow title="EDHOC message flow"}
{: artwork-align="center"}

The EDHOC message exchange may be authenticated using pre-shared keys (PSK), raw public keys (RPK), or certificates. EDHOC assumes the existence of mechanisms (certification authority, manual distribution, etc.) for binding identities with authentication keys (public or pre-shared). When a public key infrastructure is used, the identity is transported in the certificate and bound to the authentication key by trust in the certification authority. When the credential is manually distributed (PSK, RPK, self-signed certificate), the identity and authentication key is distributed out-of-band and bound together by trust in the distribution method. EDHOC with symmetric key authentication is very similar to EDHOC with asymmetric key authentication, the difference being that information is only MACed, not signed.

EDHOC also allows opaque application data (UAD and PAD) to be sent. Unprotected Application Data (UAD_1, UAD_2) may be sent in message_1 and message_2, while Protected Application Data (PAD_3) may be send in message_3. 

## Ephemeral Public Keys {#cose_key}
   
The ECDH ephemeral public keys are formatted as a COSE_Key of type EC2 or OKP according to section 13.1 and 13.2 of [RFC8152], but only a subset of the parameters are included in the EDHOC messages.  The curve X25519 is mandatory to implement.  For Elliptic Curve Keys of type EC2, compact representation and compact output as per [RFC6090] MAY be used, i.e. the 'y' parameter is not present in the COSE_Key object.  COSE [RFC8152] always use compact output for Elliptic Curve Keys of type EC2.

## Key Derivation {#key-der}

Key and IV derivation SHALL be done as specified in Section 11.1 of {{RFC8152}} with the following input:

* The PRF SHALL be the HKDF {{RFC5869}} in the ECDH-SS w/ HKDF negotiated during the message exchange (HKDF_V).

* The secret SHALL be the ECDH shared secret as defined in Section 12.4.1 of {{RFC8152}}.

* The salt SHALL be the PSK when EDHOC is authenticated with symmetric keys and the empty string "" when EDHOC is authenticated with asymmetric keys.

* The fields in the context information COSE_KDF_Context SHALL have the following values:

  + AlgorithmID is an int or tstr as defined below

  + PartyUInfo = PartyVInfo = ( nil, nil, nil )
  
  + keyDataLength is a uint as defined below
  
  + protected SHALL be a zero length bstr

  + other is a bstr and SHALL be aad_2, aad_3, or exchange_hash 

where exchange_hash, in non-CDDL notation, is:

exchange_hash = H( H( message_1 \| message_2 ) \| message_3 ) 

where H() is the hash function in HKDF_V.

For message_i the key, called K_i, SHALL be derived using other = aad_i, where i = 2 or 3. The key SHALL be derived using AlgorithmID set to the integer value of the negotiated AEAD (AEAD_V), and keyDataLength equal to the key length of AEAD_V. 

If the AEAD algorithm requires an IV, then IV_i for message_i SHALL be derived using other = aad_i, where i = 2 or 3. The IV SHALL be derived using AlgorithmID = "IV-GENERATION" as specified in section 12.1.2. of {{RFC8152}}, and keyDataLength equal to the IV length of AEAD_V.

Application keys and other application specific data can be derived using the EDHOC-Exporter interface:

EDHOC-Exporter(label, length)

The output of the EDHOC-Exporter function SHALL be derived using other = exchange_hash, AlgorithmID = label, and keyDataLength = 8 * length, where label is a tstr defined by the application and length is a uint defined by the application. The label SHALL be different for each different exporter value. An example use of the EDHOC-Exporter is given in {{app-a2}}).


# EDHOC Authenticated with Asymmetric Keys {#asym}

## Overview {#asym-overview}

EDHOC supports authentication with raw public keys (RPK) and certificates with the requirements that:

* Party U SHALL be able to identify Party V's public key using ID_CRED_V.

* Party V SHALL be able to identify Party U's public key using ID_CRED_U.

Raw public keys are stored as COSE_Key objects and identified with a 'kid' value, see {{RFC8152}}. Certificates can be identified in different ways, ID_CRED_U and ID_CRED_V may contain the credential used for authentication (e.g. x5bag or x5chain) or identify the credential used for authentication (e.g. x5t, x5u), see {{I-D.schaad-cose-x509}}. The full credentials (e.g. X.509 certificates or a COSE_Key) are always signed by inclusion in CRED_V and CRED_U.

Party U and Party V MAY use different type of credentials, e.g. one uses RPK and the other uses certificates. Party U and Party V MAY use different signature algorithms.

EDHOC with asymmetric key authentication is illustrated in {{fig-asym}}.

~~~~~~~~~~~
Party U                                                          Party V
|                        S_U, X_U, ALG_1, UAD_1                        |
+--------------------------------------------------------------------->|
|                               message_1                              |
|                                                                      |
|    S_U, S_V, X_V, ALG_2, UAD_2, Enc(K_2; Sig(V; CRED_V, aad_2); )    |
|<---------------------------------------------------------------------+
|                               message_2                              |
|                                                                      |
|            S_V, Enc(K_3; Sig(U; CRED_U, aad_3), PAD_3; )             |
+--------------------------------------------------------------------->|
|                               message_3                              |
~~~~~~~~~~~
{: #fig-asym title="EDHOC with asymmetric key authentication."}
{: artwork-align="center"}

### Mandatory to Implement Algorithms {#asym-mti}

For EDHOC authenticated with asymmetric keys, the COSE algorithms ECDH-SS + HKDF-256, AES-CCM-64-64-128, and Ed25519 are mandatory to implement.

## EDHOC Message 1 {#asym-msg1}

### Formatting of Message 1 {#asym-msg1-form}

message_1 SHALL be a sequence of CBOR elements as defined below

~~~~~~~~~~~ CDDL
message_1 = (
  MSG_TYPE : int,
  S_U : bstr,  
  ECDH-Curves_U : alg_array,
  ECDH-Curve_U : uint,
  X_U : bstr,
  HKDFs_U : alg_array,
  AEADs_U : alg_array,
  SIGs_V : alg_array,
  SIGs_U : alg_array,
  ? UAD_1 : bstr
)

alg_array = [ + alg : int / tstr ]
~~~~~~~~~~~

where:

* MSG_TYPE = 1
* S_U - variable length session identifier
* ECDH-Curves_U - EC curves for ECDH which Party U supports, in the order of decreasing preference
* ECDH-Curve_U - a single chosen algorithm from ECDH-Curves_U (array index with zero-based indexing)
* X_U - the x-coordinate of the ephemeral public key of Party U
* HKDFs_U - supported ECDH-SS w/ HKDF algorithms
* AEADs_U - supported AEAD algorithms
* SIGs_V - signature algorithms, with which Party U supports verification
* SIGs_U - signature algorithms, with which Party U supports signing
* UAD_1 - bstr containing unprotected opaque application data

### Party U Processing of Message 1 {#asym-msg1-procU}

Party U SHALL compose message_1 as follows:

* Determine the curve ECDH-Curve_U to use with Party V. If U previously received from Party V an error message to message_1 with diagnostic payload identifying an ECDH curve in ECDH-Curves_U, then U SHALL use that curve. Otherwise the first curve in ECDH-Curves_U MUST be used. The content of ECDH-Curves_U SHALL be fixed, and SHALL not be changed based on previous error messages.

* Generate an ephemeral ECDH key pair as specified in Section 5 of {{SP-800-56a}} using the curve indicated by ECDH-Curve_U. Format an ephemeral public key as a COSE_Key as specified in {{cose_key}}. Let X_U be the x-coordinate of the ephemeral public key.
   
* Choose a session identifier S_U and store it for the length of the protocol. Party U needs to be able to retrieve the protocol state using the session identifier S_U and other information such as the 5-tuple. The session identifier MAY be used with the protocol for which EDHOC establishes traffic keys/master secret, in which case S_U SHALL be different from the concurrently used session identifiers of that protocol.

* Format message_1 as specified in {{asym-msg1-form}}.

### Party V Processing of Message 1 {#asym-msg1-procV}

Party V SHALL process message_1 as follows:
 
* Verify that at least one of each kind of the proposed algorithms are supported.

* Verify that the ECDH curve indicated by ECDH-Curve_U is supported, and that no prior curve in ECDH-Curves_U is supported.

* Validate that there is a solution to the curve definition for the given x-coordinate X_U.

If any verification step fails, Party V MUST send an EDHOC error message back, formatted as defined in {{err-format}}, and the protocol MUST be discontinued. If V does not support the curve ECDH-Curve_U, but supports another ECDH curves in ECDH-Curves_U, then the error message MUST include the following diagnostic payload describing the first supported ECDH curve in ECDH-Curves_U:

~~~~~~~~~~~
ERR_MSG = "Curve not supported; Z"

where Z is the index of the first curve in ECDH-Curves_U that V supports
~~~~~~~~~~~

* Pass UAD_1 to the application.

## EDHOC Message 2 {#asym-msg2}

### Formatting of Message 2 {#asym-msg2-form}

message_2 SHALL be a sequence of CBOR elements as defined below

~~~~~~~~~~~ CDDL
message_2 = (
  data_2,
  CIPHERTEXT_2 : bstr
)

data_2 = (
  MSG_TYPE : int,
  S_U : bstr / nil,
  S_V : bstr,
  X_V : bstr,
  HKDF_V : uint,
  AEAD_V : uint,
  SIG_V : uint,
  SIG_U : uint
)

aad_2 : bstr
~~~~~~~~~~~

where aad_2, in non-CDDL notation, is:

~~~~~~~~~~~
aad_2 = H( message_1 | data_2 )
~~~~~~~~~~~

where:

* MSG_TYPE = 2
* S_V - variable length session identifier
* X_V - the x-coordinate of the ephemeral public key of Party V
* HKDF_V - a single chosen algorithm from HKDFs_U
* AEAD_V - a single chosen algorithm from AEADs_U
* SIG_V - a single chosen algorithm from SIGs_V with which Party V signs
* SIG_U - a single chosen algorithm from SIGs_U with which Party U signs
* H() - the hash function in HKDF_V

### Party V Processing of Message 2 {#asym-msg2-procV}

Party V SHALL compose message_2 as follows:

* Generate an ephemeral ECDH key pair as specified in Section 5 of {{SP-800-56a}} using the curve indicated by ECDH-Curve_U. Format an ephemeral public key as a COSE_Key as specified in {{cose_key}}. Let X_V be the x-coordinate of the ephemeral public key.

* Choose a session identifier S_V and store it for the length of the protocol. Party V needs to be able to retrieve the protocol state using the session identifier S_V and other information such as the 5-tuple. The session identifier MAY be used with the protocol for which EDHOC establishes traffic keys/master secret, in which case S_V SHALL be different from the concurrently used session identifiers of that protocol.

*  Select HKDF_V, AEAD_V, SIG_V, and SIG_U from the algorithms proposed in HKDFs_U, AEADs_U, SIGs_V, and SIGs_U.

*  Compute COSE_Sign1 as defined in section 4.4 of {{RFC8152}}, using algorithm SIG_V, the private key of Party V, and the following parameters. The unprotected header MAY contain parameters (e.g. alg).
   
   * protected = { xyz : ID_CRED_V }

   * payload = ( CRED_V, aad_2 )

   * xyz - any COSE map label that can identify a public key, see {{asym-overview}}

   * ID_CRED_V - identifier for the public key of Party V, see {{asym-overview}}

   * CRED_V - bstr containing the credential containing the public key of Party V, see {{asym-overview}}

* Compute COSE_Encrypt0 as defined in section 5.3 of [RFC8152], with AEAD_V, K_2, IV_2, and the following parameters. The protected header SHALL be empty. The unprotected header MAY contain parameters (e.g. alg, kid, or IV).
 
   * external_aad = aad_2

   * plaintext = ( PROTECTED_2, SIGNATURE_2, ? UAD_2 )

   * PROTECTED_2 - bstr containing the COSE_Sign1 protected header
   
   * SIGNATURE_2 - bstr containing the COSE_Sign1 signature
  
   * UAD_2 = bstr containing opaque unprotected application data

*  Format message_2 as specified in {{asym-msg2-form}}, where CIPHERTEXT_2 is the COSE_Encrypt0 ciphertext.

### Party U Processing of Message 2 {#asym-msg2-procU}

Party U SHALL process message_2 as follows:

* Retrieve the protocol state using the session identifier S_U and other information such as the 5-tuple.

* Validate that there is a solution to the curve definition for the given x-coordinate X_V.

* Decrypt and verify COSE_Encrypt0 as defined in section 5.3 of {{RFC8152}}, with AEAD_V, K_2, and IV_2.

* Verify COSE_Sign1 as defined in section 4.4 of {{RFC8152}}, using algorithm SIG_V and the public key of Party V.

If any verification step fails, Party U MUST send an EDHOC error message back, formatted as defined in {{err-format}}, and the protocol MUST be discontinued.

## EDHOC Message 3 {#asym-msg3}

### Formatting of Message 3 {#asym-msg3-form}

message_3 SHALL be a sequence of CBOR elements as defined below

~~~~~~~~~~~ CDDL
message_3 = (
  data_3,
  CIPHERTEXT_3 : bstr
)

data_3 = (
  MSG_TYPE : int,
  S_V : bstr
)

aad_3 : bstr
~~~~~~~~~~~

where aad_3, in non-CDDL notation, is:

~~~~~~~~~~~
aad_3 = H( H( message_1 | message_2 ) | data_3 )

~~~~~~~~~~~

where:

* MSG_TYPE = 3

### Party U Processing of Message 3 {#asym-msg3-procU}

Party U SHALL compose message_3 as follows:

*  Compute COSE_Sign1 as defined in section 4.4 of {{RFC8152}}, using algorithm SIG_U, the private key of Party U, and the following parameters. The unprotected header MAY contain parameters (e.g. alg).

   * protected = { xyz : ID_CRED_U }

   * payload = ( CRED_U, aad_3 )
   
   * xyz - any COSE map label that can identify a public key, see {{asym-overview}}

   * ID_CRED_U - identifier for the public key of Party U, see {{asym-overview}}

   * CRED_U - bstr containing the credential containing the public key of Party U, see {{asym-overview}}

* Compute COSE_Encrypt0 as defined in section 5.3 of [RFC8152], with AEAD_V, K_3, and IV_3 and the following parameters. The protected header SHALL be empty. The unprotected header MAY contain parameters (e.g. alg, kid, or IV).

   * external_aad = aad_3

   * plaintext = ( PROTECTED_3, SIGNATURE_3, ? PAD_3 )
   
   * PROTECTED_3 - bstr containing the COSE_Sign1 protected header
   
   * SIGNATURE_3 - bstr containing the COSE_Sign1 signature

   * PAD_3 = bstr containing opaque protected application data

*  Format message_3 as specified in {{asym-msg3-form}}, where CIPHERTEXT_3 is the COSE_Encrypt0 ciphertext.

* Pass S_U, S_V, and the algorithm identified by AEAD_V to the application. The application can now derive application keys.

### Party V Processing of Message 3 {#asym-msg3-procV}

Party V SHALL process message_3 as follows:

* Retrieve the protocol state using the session identifier S_V and other information such as the 5-tuple.

* Decrypt and verify COSE_Encrypt0 as defined in section 5.3 of {{RFC8152}}, with AEAD_V, K_3, and IV_3.

* Verify COSE_Sign1 as defined in section 4.4 of {{RFC8152}}, using algorithm SIG_U and the public key of Party U.

If any verification step fails, Party V MUST send an EDHOC error message back, formatted as defined in {{err-format}}, and the protocol MUST be discontinued.

* Pass PAD_3, S_U, S_V, and the algorithm identified by AEAD_V to the application. The application can now derive application keys.

# EDHOC Authenticated with Symmetric Keys {#sym}

## Overview

EDHOC supports authentication with pre-shared keys. Party U and V are assumed to have a pre-shared key (PSK) with a good amount of randomness and the requirement that:

* Party V SHALL be able to identify the PSK using KID.

KID may optionally contain information about how to retrieve the PSK.

EDHOC with symmetric key authentication is illustrated in {{fig-sym}}.

~~~~~~~~~~~
Party U                                                       Party V
|                    S_U, X_U, ALG_1, KID, UAD_1                    |
+------------------------------------------------------------------>|
|                             message_1                             |
|                                                                   |
|           S_U, S_V, X_V, ALG_2, Enc(K_2; UAD_2; aad_2)            |
|<------------------------------------------------------------------+
|                             message_2                             |
|                                                                   |
|                    S_V, Enc(K_3; PAD_3; aad_3)                    |
+------------------------------------------------------------------>|
|                             message_3                             |
~~~~~~~~~~~
{: #fig-sym title="EDHOC with symmetric key authentication. "}
{: artwork-align="center"}

### Mandatory to Implement Algorithms {#sym-mti}

For EDHOC authenticated with symmetric keys, the COSE algorithms ECDH-SS + HKDF-256 and AES-CCM-64-64-128 are mandatory to implement.

## EDHOC Message 1 {#sym-msg1}

### Formatting of Message 1 {#sym-msg1-form}

message_1 SHALL be a sequence of CBOR elements as defined below

~~~~~~~~~~~ CDDL
message_1 = (
  MSG_TYPE : int,
  S_U : bstr,
  ECDH-Curves_U : alg_array,
  ECDH-Curve_U : uint,
  X_U : bstr,
  HKDFs_U : alg_array,
  AEADs_U : alg_array,
  KID : bstr,
  ? UAD_1 : bstr
)

alg_array = [ + alg : int / tstr ]
~~~~~~~~~~~

where:

* MSG_TYPE = 4
* S_U - variable length session identifier
* ECDH-Curves_U - EC curves for ECDH which Party U supports, in the order of decreasing preference
* ECDH-Curve_U - a single chosen algorithm from ECDH-Curves_U (array index with zero-based indexing)
* X_U - the x-coordinate of the ephemeral public key of Party U
* HKDFs_U - supported ECDH-SS w/ HKDF algorithms
* AEADs_U - supported AEAD algorithms
* KID - identifier of the pre-shared key
* UAD_1 - bstr containing unprotected opaque application data

### Party U Processing of Message 1 {#sym-msg1-procU}

Party U SHALL compose message_1 as follows:

* Determine the curve ECDH-Curve_U to use with Party V. If U previously received from Party V an error message to message_1 with diagnostic payload identifying an ECDH curve in ECDH-Curves_U, then U SHALL use that curve. Otherwise the first curve in ECDH-Curves_U MUST be used. The content of ECDH-Curves_U SHALL be fixed, and SHALL not be changed based on previous error messages.

* Generate an ephemeral ECDH key pair as specified in Section 5 of {{SP-800-56a}} using the curve indicated by ECDH-Curve_U. Format an ephemeral public key as a COSE_Key as specified in {{cose_key}}. Let X_U be the x-coordinate of the ephemeral public key.

* Choose a session identifier S_U and store it for the length of the protocol. Party U needs to be able to retrieve the protocol state using the session identifier S_U and other information such as the 5-tuple. The session identifier MAY be used with the protocol for which EDHOC establishes traffic keys/master secret, in which case S_U SHALL be different from the concurrently used session identifiers of that protocol.

* Format message_1 as specified in {{sym-msg1-form}}.

### Party V Processing of Message 1 {#sym-msg1-procV}

Party V SHALL process message_1 as follows:

* Verify that at least one of each kind of the proposed algorithms are supported.

* Verify that the ECDH curve indicated by ECDH-Curve_U is supported, and that no prior curve in ECDH-Curves_U is supported.

* Validate that there is a solution to the curve definition for the given x-coordinate X_U.

If any verification step fails, Party V MUST send an EDHOC error message back, formatted as defined in {{err-format}}, and the protocol MUST be discontinued. If V does not support the curve ECDH-Curve_U, but supports another ECDH curves in ECDH-Curves_U, then the error message MUST include a diagnostic payload describing the first supported ECDH curve in ECDH-Curves_U.

* Pass UAD_1 to the application.

## EDHOC Message 2 {#sym-msg2}

### Formatting of Message 2 {#sym-msg2-form}

message_2 SHALL be a sequence of CBOR elements as defined below

~~~~~~~~~~~ CDDL
message_2 = (
  data_2,
  CIPHERTEXT_2 : bstr
)

data_2 = (
  MSG_TYPE : int,
  S_U : bstr / nil,  
  S_V : bstr,  
  X_V : bstr,
  HKDF_V : uint,
  AEAD_V : uint
)

aad_2 : bstr
~~~~~~~~~~~

where aad_2, in non-CDDL notation, is:

~~~~~~~~~~~
aad_2 = H( message_1 | data_2 )
~~~~~~~~~~~

where:

* MSG_TYPE = 5
* S_V - variable length session identifier
* X_V - the x-coordinate of the ephemeral public key of Party V
* HKDF_V - a single chosen algorithm from HKDFs_U
* AEAD_V - a single chosen algorithm from AEADs_U
* H() - the hash function in HKDF_V

### Party V Processing of Message 2 {#sym-msg2-procV}

Party V SHALL compose message_2 as follows:

* Generate an ephemeral ECDH key pair as specified in Section 5 of {{SP-800-56a}} using the curve indicated by ECDH-Curve_U. Format an ephemeral public key as a COSE_Key as specified in {{cose_key}}. Let X_V be the x-coordinate of the ephemeral public key.

* Choose a session identifier S_V and store it for the length of the protocol. Party V needs to be able to retrieve the protocol state using the session identifier S_V and other information such as the 5-tuple. The session identifier MAY be used with the protocol for which EDHOC establishes traffic keys/master secret, in which case S_V SHALL be different from the concurrently used session identifiers of that protocol.

*  Select HKDF_V and AEAD_V from the algorithms proposed in HKDFs_U and AEADs_U.

* Compute COSE_Encrypt0 as defined in section 5.3 of [RFC8152], with AEAD_V, K_2, IV_2, and the following parameters. The protected header SHALL be empty. The unprotected header MAY contain parameters (e.g. alg, kid, or IV).

   * external_aad = aad_2

   * plaintext = ? UAD_2

   * UAD_2 = bstr containing opaque unprotected application data

*  Format message_2 as specified in {{sym-msg2-form}}, where CIPHERTEXT_2 is the COSE_Encrypt0 ciphertext.
   
### Party U Processing of Message 2 {#sym-msg2-procU}

Party U SHALL process message_2 as follows:

* Retrieve the protocol state using the session identifier S_U and other information such as the 5-tuple.

* Validate that there is a solution to the curve definition for the given x-coordinate X_V.

* Decrypt and verify COSE_Encrypt0 as defined in section 5.3 of {{RFC8152}}, with AEAD_V, K_2, and IV_2.

If any verification step fails, Party U MUST send an EDHOC error message back, formatted as defined in {{err-format}}, and the protocol MUST be discontinued.

* Pass UAD_2 to the application.

## EDHOC Message 3 {#sym-msg3}

### Formatting of Message 3 {#sym-msg3-form}

message_3 SHALL be a sequence of CBOR elements as defined below

~~~~~~~~~~~ CDDL
message_3 = (
  data_3,
  CIPHERTEXT_3 : bstr
)

data_3 = (
  MSG_TYPE : int,
  S_V : bstr 
)

aad_3 : bstr
~~~~~~~~~~~

where aad_3, in non-CDDL notation, is:

~~~~~~~~~~~
aad_3 = H( H( message_1 | message_2 ) | data_3 )
~~~~~~~~~~~

where:

* MSG_TYPE = 6

### Party U Processing of Message 3 {#sym-msg3-procU}

Party U SHALL compose message_3 as follows:

* Compute COSE_Encrypt0 as defined in section 5.3 of [RFC8152], with AEAD_V, K_3, IV_3, and the following parameters. The protected header SHALL be empty. The unprotected header MAY contain parameters (e.g. alg, kid, or IV).

   * external_aad = aad_3

   * plaintext = ? PAD_3

   * PAD_3 = bstr containing opaque protected application data

*  Format message_3 as specified in {{sym-msg3-form}}, where CIPHERTEXT_3 is the COSE_Encrypt0 ciphertext.

* Pass S_U, S_V, and the algorithm identified by AEAD_V to the application. The application can now derive application keys.

### Party V Processing of Message 3 {#sym-msg3-procV}

Party V SHALL process message_3 as follows:

* Retrieve the protocol state using the session identifier S_V and other information such as the 5-tuple.

* Decrypt and verify COSE_Encrypt0 as defined in section 5.3 of {{RFC8152}}, with AEAD_V, K_3, and IV_3.

If any verification step fails, Party V MUST send an EDHOC error message back, formatted as defined in {{err-format}}, and the protocol MUST be discontinued.

* Pass PAD_3, S_U, S_V, and the algorithm identified by AEAD_V to the application. The application can now derive application keys.

# Error Handling {#error}

## Error Message Format {#err-format}

This section defines a message format for the EDHOC error message, used during the protocol. An EDHOC error message can be send by both parties as a response to any non-error EDHOC message. After sending an error message, the protocol MUST be discontinued. Errors at the EDHOC layer are independent of the lower layers and are therefore sent as normal successful messages (e.g. POST and 2.04 Changed). An advantage of using such a construction is to avoid issues created by usage of cross protocol proxies (e.g. UDP to TCP).

error SHALL be a sequence of CBOR elements as defined below

~~~~~~~~~~~ CDDL
error = (
  MSG_TYPE : int,
  ? ERR_MSG : tstr 
)
~~~~~~~~~~~

where:

* MSG_TYPE = 0
* ERR_MSG is an optional text string containing the diagnostic payload, defined in the same way as in Section 5.5.2 of {{RFC7252}}.

# IANA Considerations {#iana}

## The Well-Known URI Registry

IANA has added the well-known URI 'edhoc' in the Well-Known URIs registry.

   URI suffix: edhoc

   Change controller: IETF

   Specification document(s): [[this document]]

   Related information: None

## Media Types Registry

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

# Security Considerations {#sec-cons}

EDHOC builds on the SIGMA-I family of theoretical protocols that provides perfect forward secrecy and identity protection with a minimal number of messages. The encryption algorithm of the SIGMA-I protocol provides identity protection, but the security of the protocol requires the MAC to cover the identity of the signer. Hence the message authenticating functionality of the authenticated encryption in EDHOC is critical: authenticated encryption MUST NOT be replaced by plain encryption only, even if authentication is provided at another level or through a different mechanism.

EDHOC adds an explicit message type and expands the message authentication coverage to additional elements such as algorithms, application data, and previous messages. EDHOC uses the same Sign-then-MAC approach as TLS 1.3.

EDHOC does not include negotiation of parameters related to the ephemeral key, but it enables Party V to verify that the ECDH curve used in the protocol is the most preferred curve by U which is supported by both U and V.

Party U and V must make sure that unprotected data and metadata do not reveal any sensitive information. This also applies for encrypted data sent to an unauthenticated party. In particular, it applies to UAD_1 and UAD_2 in the asymmetric case, and UAD_1 and KID in the symmetric case. The communicating parties may therefore anonymize KID.

Using the same KID or unprotected application data in several EDHOC sessions allows passive eavesdroppers to correlate the different sessions. Another consideration is that the list of supported algorithms may be used to identify the application.

Party U and V are allowed to select the session identifiers S_U and S_V, respectively, for the other party to use in the ongoing EDHOC protocol as well as in a subsequent traffic protection protocol (e.g. OSCORE {{I-D.ietf-core-object-security}}). The choice of session identifier is not security critical but intended to simplify the retrieval of the right security context in combination with using short identifiers. If the wrong session identifier of the other party is used in a protocol message it will result in the receiving party not being able to retrieve a security context (which will terminate the protocol) or retrieving the wrong security context (which also terminates the protocol as the message cannot be verified).

Party U and V must make sure that unprotected data does not trigger any harmful actions. In particular, this applies to UAD_1 in the asymmetric case, and UAD_1 and KID in the symmetric case. Party V should be aware that spoofed EDHOC message_1 cannot be detected.

The availability of a secure pseudorandom number generator and truly random seeds are essential for the security of EDHOC. If no true random number generator is available, a truly random seed must be provided from an external source. If ECDSA is supported, "deterministic ECDSA" as specified in RFC6979 is RECOMMENDED.

Ephemeral keys MUST NOT be reused, both parties SHALL generate fresh random ephemeral key pairs.

The referenced processing instructions in {{SP-800-56a}} must be complied with, including deleting the intermediate computed values along with any ephemeral ECDH secrets after the key derivation is completed.

Party U and V are responsible for verifying the integrity of certificates. The selection of trusted CAs should be done very carefully and certificate revocation should be supported.

The choice of key length used in the different algorithms needs to be harmonized, so that a sufficient security level is maintained for certificates, EDHOC, and the protection of application data. Party U and V should enforce a minimum security level. 

Note that, depending on the application, the keys established through the EDHOC protocol will need to be renewed, in which case the communicating parties need to run the protocol again.

Implementations should provide countermeasures to side-channel attacks such as timing attacks.

--- back

# Test Vectors {#examples}

TODO: This section needs to be updated.

# PSK Chaining

An application using EDHOC may want to derive new PSKs to use for authentication in future EDHOC sessions. In this case, the new PSK SHALL be derived as EDHOC-Exporter("Chaining PSK", length), where length is equal to the key length (in bytes) of AEAD_V and the new PSK identifier SHALL be derived as KID = EDHOC-Exporter("Chaining KID", 4).

# EDHOC with CoAP and OSCORE {#app-a}

## Transferring EDHOC in CoAP {#app-a1}

EDHOC can be transferred as an exchange of CoAP {{RFC7252}} messages, with the CoAP client as party U and the CoAP server as party V. By default, EDHOC is sent to the Uri-Path: "/.well-known/edhoc", but an application may define its own path that can be discovered e.g. using resource directory {{I-D.ietf-core-resource-directory}}.

In practice, EDHOC message\_1 is sent in the payload of a POST request from the client to the server's resource for EDHOC. EDHOC message\_2 or the EDHOC error message is sent from the server to the client in the payload of a 2.04 Changed response. EDHOC message\_3 or the EDHOC error message is sent from the client to the server's resource in the payload of a POST request. If needed, an EDHOC error message is sent from the server to the client in the payload of a 2.04 Changed response

An example of successful EDHOC exchange using CoAP is shown in {{fig-edhoc-oscore-det}}.

~~~~~~~~~~~~~~~~~~~~~~~
Client    Server
  |          |
  +--------->| Header: POST (Code=0.02)
  |   POST   | Uri-Path: "/.well-known/edhoc"
  |          | Content-Type: application/edhoc
  |          | Payload: EDHOC message_1
  |          |
  |<---------+ Header: 2.04 Changed
  |   2.04   | Content-Type: application/edhoc
  |          | Payload: EDHOC message_2
  |          |
  +--------->| Header: POST (Code=0.02)
  |   POST   | Uri-Path: "/.well-known/edhoc"
  |          | Content-Type: application/edhoc
  |          | Payload: EDHOC message_3
  |          |
  |<---------+ Header: 2.04 Changed
  |   2.04   | 
  |          |
~~~~~~~~~~~~~~~~~~~~~~~
{: #fig-edhoc-oscore-det title="Transferring EDHOC in CoAP"}
{: artwork-align="center"}

## Deriving an OSCORE context from EDHOC {#app-a2}

When EDHOC is used to derive parameters for OSCORE {{I-D.ietf-core-object-security}}, the parties must make sure that the EDHOC session identifiers are unique Recipient IDs in OSCORE.  In case that the CoAP client is party U and the CoAP server is party V:

* The AEAD Algorithm is AEAD_V, as defined in this document

* The Key Derivation Function (KDF) is HKDF_V, as defined in this document

* The Client's Sender ID is S_V, as defined in this document

* The Server's Sender ID is S_U, as defined in this document

* The Master Secret is derived as EDHOC-Exporter("OSCORE Master Secret", length), where length is equal to the key length (in bytes) of AEAD_V.

* The Master Salt is derived as EDHOC-Exporter("OSCORE Master Salt", 8)

# Message Sizes

This appendix gives an estimate of the message sizes when EDHOC is used with raw public keys and pre-shared keys. Note that the examples in this appendix are not test vectors, the cryptographic parts are just replaced with byte strings of the same length. All examples are given in CBOR diagnostic notation and hexadecimal.

## Message Sizes RPK

~~~~~~~~~~~~~~~~~~~~~~~
message_1 = (
  1,
  h'c3',
  [4],
  0,
  h'000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d
    1e1f',
  [-27],
  [10],
  [-8],
  [-8]
)
~~~~~~~~~~~~~~~~~~~~~~~

~~~~~~~~~~~~~~~~~~~~~~~
message_1 (49 bytes):
01 41 C3 81 04 00 58 20 00 01 02 03 04 05 06 07 08 09 0A 0B
0C 0D 0E 0F 10 11 12 13 14 15 16 17 18 19 1A 1B 1C 1D 1E 1F
81 38 1A 81 0A 81 27 81 27
~~~~~~~~~~~~~~~~~~~~~~~

~~~~~~~~~~~~~~~~~~~~~~~
plaintext = (
  { 4 : 'abba' },
  h'000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d
    1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b
    3c3d3e3f'
)
~~~~~~~~~~~~~~~~~~~~~~~

~~~~~~~~~~~~~~~~~~~~~~~
plaintext (73 bytes):
A1 04 44 61 62 62 61 58 40 00 01 02 03 04 05 06 07 08 09 0A
0B 0C 0D 0E 0F 10 11 12 13 14 15 16 17 18 19 1A 1B 1C 1D 1E
1F 20 21 22 23 24 25 26 27 28 29 2A 2B 2C 2D 2E 2F 30 31 32
33 34 35 36 37 38 39 3A 3B 3C 3D 3E 3F
~~~~~~~~~~~~~~~~~~~~~~~

The size of plaintext is 73 bytes so assuming a 64-bit MAC value the ciphertext is 81 bytes

~~~~~~~~~~~~~~~~~~~~~~~
message_2 = (
  2,
  null,
  h'c4',
  h'000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d
    1e1f',
  0,
  0,
  0,
  0,
  h'000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d
    1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b
    3c3d3e3f404142434445464748494a4b4c4d4e4f50'
)
~~~~~~~~~~~~~~~~~~~~~~~

~~~~~~~~~~~~~~~~~~~~~~~
message_2 (125 bytes):
02 F6 41 C4 58 20 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D
0E 0F 10 11 12 13 14 15 16 17 18 19 1A 1B 1C 1D 1E 1F 00 00
00 00 58 51 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F
10 11 12 13 14 15 16 17 18 19 1A 1B 1C 1D 1E 1F 20 21 22 23
24 25 26 27 28 29 2A 2B 2C 2D 2E 2F 30 31 32 33 34 35 36 37
38 39 3A 3B 3C 3D 3E 3F 40 41 42 43 44 45 46 47 48 49 4A 4B
4C 4D 4E 4F 50
~~~~~~~~~~~~~~~~~~~~~~~

~~~~~~~~~~~~~~~~~~~~~~~
message_3 = (
  3,
  h'c3',
  h'000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d
    1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b
    3c3d3e3f404142434445464748494a4b4c4d4e4f50'
)
~~~~~~~~~~~~~~~~~~~~~~~

~~~~~~~~~~~~~~~~~~~~~~~
message_3 (86 bytes):
03 41 C3 58 51 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E
0F 10 11 12 13 14 15 16 17 18 19 1A 1B 1C 1D 1E 1F 20 21 22
23 24 25 26 27 28 29 2A 2B 2C 2D 2E 2F 30 31 32 33 34 35 36
37 38 39 3A 3B 3C 3D 3E 3F 40 41 42 43 44 45 46 47 48 49 4A
4B 4C 4D 4E 4F 50
~~~~~~~~~~~~~~~~~~~~~~~

## Message Sizes PSK

~~~~~~~~~~~~~~~~~~~~~~~
message_1 = (
  4,
  h'c3',
  [4],
  0,
  h'000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d
    1e1f',
  [-27],
  [10],
  'acdc'
)
~~~~~~~~~~~~~~~~~~~~~~~

~~~~~~~~~~~~~~~~~~~~~~~
message_1 (50 bytes):
04 41 C3 81 04 00 58 20 00 01 02 03 04 05 06 07 08 09 0A 0B
0C 0D 0E 0F 10 11 12 13 14 15 16 17 18 19 1A 1B 1C 1D 1E 1F
81 38 1A 81 0A 44 61 63 64 63
~~~~~~~~~~~~~~~~~~~~~~~

Assuming a 0 byte plaintext and a 64-bit MAC value the ciphertext is 8 bytes

~~~~~~~~~~~~~~~~~~~~~~~
message_2 = (
  5,
  null,
  h'c4',
  h'000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d
    1e1f',
  0,
  0,
  h'0001020304050607'
)
~~~~~~~~~~~~~~~~~~~~~~~

~~~~~~~~~~~~~~~~~~~~~~~
message_2 (49 bytes):
05 F6 41 C4 58 20 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D
0E 0F 10 11 12 13 14 15 16 17 18 19 1A 1B 1C 1D 1E 1F 00 00
48 61 62 63 64 65 66 67 68
~~~~~~~~~~~~~~~~~~~~~~~

~~~~~~~~~~~~~~~~~~~~~~~
message_3 = (
  6,
  h'c3',
  h'0001020304050607'
)
~~~~~~~~~~~~~~~~~~~~~~~

~~~~~~~~~~~~~~~~~~~~~~~
message_3 (12 bytes):
06 41 C3 48 00 01 02 03 04 05 06 07
~~~~~~~~~~~~~~~~~~~~~~~

# Acknowledgments
{: numbered="no"}

The authors want to thank Dan Harkins, Ilari Liusvaara, Jim Schaad, and Ludwig Seitz for reviewing intermediate versions of the draft and contributing concrete proposals incorporated in this version. We are especially indebted to Jim Schaad for his continuous reviewing and implementation of different versions of the draft.

We are also grateful to Theis Grønbech Petersen, Thorvald Sahl Jørgensen, Alessandro Bruni, and Carsten Schürmann for their work on formal analysis of EDHOC.

--- fluff
