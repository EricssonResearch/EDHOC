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

  I-D.schaad-cose-x509:
  I-D.ietf-core-echo-request-tag:
  
  RFC2119:
  RFC6090:  
  RFC7049:
  RFC8152:
  RFC8174:
  
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
  I-D.ietf-6tisch-dtsecurity-zerotouch-join:

  RFC5116:
  RFC5869:
  RFC7228:
  RFC7252:
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

  CertEnr:
    target: http://www.nada.kth.se/~ann/exjobb/alexandros_krontiris.pdf
    title: Evaluation of Certificate Enrollment over Application Layer Security
    author:
      -
        ins: A. Krontiris
    date: May 2018

--- abstract

This document specifies Ephemeral Diffie-Hellman Over COSE (EDHOC), a very compact, and lightweight authenticated Diffie-Hellman key exchange with ephemeral keys that can be used over any layer. EDHOC provides mutual authentication, perfect forward secrecy, and identity protection. EDHOC uses CBOR and COSE, allowing reuse of existing libraries.

--- middle

# Introduction

Security at the application layer provides an attractive option for protecting Internet of Things (IoT) deployments, for example where transport layer security is not sufficient {{I-D.hartke-core-e2e-security-reqs}} or where the protocol needs to work on a variety of underlying protocols. IoT devices may be constrained in various ways, including memory, storage, processing capacity, and energy {{RFC7228}}. A method for protecting individual messages at the application layer suitable for constrained devices, is provided by CBOR Object Signing and Encryption (COSE) {{RFC8152}}), which builds on the Concise Binary Object Representation (CBOR) {{RFC7049}}.

In order for a communication session to provide forward secrecy, the communicating parties can run an Elliptic Curve Diffie-Hellman (ECDH) key exchange protocol with ephemeral keys, from which shared key material can be derived. This document specifies Ephemeral Diffie-Hellman Over COSE (EDHOC), a mutually authenticated key exchange protocol providing perfect forward secrecy and identity protection. EDHOC uses CBOR and COSE, allowing reuse of existing libraries. Authentication is based on credentials established out of band, e.g. from a trusted third party, such as an Authorization Server as specified by {{I-D.ietf-ace-oauth-authz}}. EDHOC supports authentication using pre-shared keys (PSK), raw public keys (RPK), and public key certificates. After successful completion of the EDHOC protocol, application keys and other application specific data can be derived using the EDHOC-Exporter interface.  Note that this document focuses on authentication and key establishment: for integration with authorization of resource access, refer to {{I-D.ietf-ace-oscore-profile}}.

EDHOC is designed to work in highly constrained scenarios making it especially suitable for network technologies such as NB-IoT, 6TiSCH {{I-D.ietf-6tisch-dtsecurity-zerotouch-join}}, and LoRaWAN {{LoRa1}}{{LoRa2}}. Compared to the TLS 1.3 handshake with ECDH {{RFC8446}}, the number of bytes in EDHOC is less than 1/3 when PSK authentication is used and less than 1/2 when RPK authentication is used, see {{sizes}}.

The ECDH exchange and the key derivation follow {{SIGMA}}, NIST SP-800-56a {{SP-800-56a}}, and HKDF {{RFC5869}}. CBOR {{RFC7049}} and COSE {{RFC8152}} are used to implement these standards.

This paper is organized as follows: {{background}} describes how EDHOC builds on SIGMA-I, {{overview}} specifies general properties of EDHOC, including message flow, formatting of the ephemeral public keys, and key derivation, {{asym}} specifies EDHOC with asymmetric key authentication, {{sym}} specifies EDHOC with symmetric key authentication, {{error}} specifies the EDHOC error message, and {{vectors}} provides a wealth of test vectors to ease implementation and ensure interoperability.

## Terminology and Requirements Language

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 {{RFC2119}} {{RFC8174}} when, and only when, they appear in all capitals, as shown here.

The word "encryption" without qualification always refers to authenticated encryption, in practice implemented with an Authenticated Encryption with Additional Data (AEAD) algorithm, see {{RFC5116}}.

This document uses the Concise Data Definition Language (CDDL) {{I-D.ietf-cbor-cddl}} to express CBOR data structures {{RFC7049}}. A vertical bar \| denotes byte string concatenation.

# Background {#background}

SIGMA (SIGn-and-MAc) is a family of theoretical protocols with a large number of variants {{SIGMA}}. Like IKEv2 and TLS 1.3, EDHOC is built on a variant of the SIGMA protocol which provide identity protection of the initiator (SIGMA-I), and like TLS 1.3, EDHOC implements the SIGMA-I variant as Sign-then-MAC. The SIGMA-I protocol using an authenticated encryption algorithm is shown in {{fig-sigma}}.

~~~~~~~~~~~
Party U                                                 Party V
   |                          X_U                          |
   +------------------------------------------------------>|
   |                                                       |
   |  X_V, AE( K_2; ID_CRED_V, Sig(V; CRED_V, X_U, X_V) )  |
   |<------------------------------------------------------+
   |                                                       |
   |    AE( K_3; ID_CRED_U, Sig(U; CRED_U, X_V, X_U) )     |
   +------------------------------------------------------>|
   |                                                       |
~~~~~~~~~~~
{: #fig-sigma title="Authenticated encryption variant of the SIGMA-I protocol."}
{: artwork-align="center"}

The parties exchanging messages are called "U" and "V". They exchange identities and ephemeral public keys, compute the shared secret, and derive symmetric application keys. 

* X_U and X_V are the ECDH ephemeral public keys of U and V, respectively.

* CRED_U and CRED_V are the credentials containing the public authentication keys of U and V, respectively.

* ID_CRED_U and ID_CRED_V are data enabling the recipient party to retrieve the credential of U and V, respectively

* Sig(U; . ) and S(V; . ) denote signatures made with the private authentication key of U and V, respectively.

* AE(K; P) denotes authenticated encryption of plaintext P using the key K derived from the shared secret. The authenticated encryption MUST NOT be replaced by plain encryption, see {{security}}.

In order to create a "full-fledged" protocol some additional protocol elements are needed. EDHOC adds:

* Explicit connection identifiers C_U, C_V chosen by U and V, respectively, enabling the recipient to find the protocol state.

* An Authenticated Encryption with Additional Data (AEAD) algorithm is used.

* Computationally independent keys derived from the ECDH shared secret and used for encryption of different messages.

* Negotiation of key derivation, encryption, and signature algorithms:

   * U proposes one or more algorithms of the following kinds in order of preference: 
       *  HKDF
       *  AEAD
       *  Signature verification 
       *  Signature generation 

   * V selects the first supported algorithm of each kind

* Verification of common preferred ECDH curve:

   * U lists supported ECDH curves in order of preference
   
   * V verifies that the ECDH curve of the ephemeral key is the first supported curve

* Transport of opaque application defined data.

EDHOC is designed to encrypt and integrity protect as much information as possible, and all symmetric keys are derived using as much previous information as possible. EDHOC is furthermore designed to be as compact and lightweight as possible, in terms of message sizes, processing, and the ability to reuse already existing CBOR and COSE libraries. EDHOC does not put any requirement on the lower layers and can therefore also be used e.g. in environments without IP.

To simplify implementation, the use of CBOR and COSE in EDHOC is summarized in {{CBORandCOSE}}.

# EDHOC Overview {#overview}

EDHOC consists of three messages (message_1, message_2, message_3) that maps directly to the three messages in SIGMA-I, plus an EDHOC error message. All EDHOC messages consists of a sequence of CBOR elements, where the first element is an int specifying the message type (MSG_TYPE). After creating EDHOC message_3, Party U can derive symmetric application keys, and application protected data can therefore be sent in parallel with EDHOC message_3. The application may protect data using the negotiated algorithms (AEAD, HKDF, etc.) and the connection identifiers (C_U, C_V). EDHOC may be used with the media type application/edhoc defined in {{iana}}.

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

The EDHOC message exchange may be authenticated using pre-shared keys (PSK), raw public keys (RPK), or public key certificates. EDHOC assumes the existence of mechanisms (certification authority, manual distribution, etc.) for binding identities with authentication keys (public or pre-shared). When a public key infrastructure is used, the identity is included in the certificate and bound to the authentication key by trust in the certification authority. When the credential is manually distributed (PSK, RPK, self-signed certificate), the identity and authentication key is distributed out-of-band and bound together by trust in the distribution method. EDHOC with symmetric key authentication is very similar to EDHOC with asymmetric key authentication, the difference being that information is only MACed, not signed.

EDHOC allows opaque application data (UAD and PAD) to be sent in the EDHOC messages. Unprotected Application Data (UAD_1, UAD_2) may be sent in message_1 and message_2, while Protected Application Data (PAD_3) may be send in message_3. 

## Ephemeral Public Keys {#cose_key}
   
The ECDH ephemeral public keys are formatted as a COSE_Key of type EC2 or OKP according to Sections 13.1 and 13.2 of {{RFC8152}}, but only a subset of the parameters are included in the EDHOC messages.  The curve X25519 is mandatory to implement. For Elliptic Curve Keys of type EC2, compact representation as per {{RFC6090}} MAY be used also in the COSE_Key. If the COSE implementation requires an y-coordinate, any of the possible values of the y-coordinate can be used, see Appendix C of {{RFC6090}}. COSE {{RFC8152}} always use compact output for Elliptic Curve Keys of type EC2.

## Key Derivation {#key-der}

Key and IV derivation SHALL be performed as specified in Section 11 of {{RFC8152}} with the following input:

* The KDF SHALL be the HKDF {{RFC5869}} in the ECDH-SS w/ HKDF negotiated during the message exchange (HKDF_V).

* The secret (Section 11.1 of {{RFC8152}}) SHALL be the ECDH shared secret as defined in Section 12.4.1 of {{RFC8152}}.

* The salt (Section 11.1 of {{RFC8152}}) SHALL be the PSK when EDHOC is authenticated with symmetric keys, and the empty byte string when EDHOC is authenticated with asymmetric keys. Note that {{RFC5869}} specifies that if the salt is not provided, it is set to a string of zeros (see Section 2.2 of {{RFC5869}}). For implementation purposes, not providing the salt is the same as setting the salt to the empty byte string. 

* The fields in the context information COSE_KDF_Context (Section 11.2 of {{RFC8152}}) SHALL have the following values:

  + AlgorithmID is an int or tstr, see below

  + PartyUInfo = PartyVInfo = ( nil, nil, nil )
  
  + keyDataLength is a uint, see below
  
  + protected SHALL be a zero length bstr

  + other is a bstr and SHALL be aad_2, aad_3, or exchange_hash; see below

where exchange_hash, in non-CDDL notation, is:

exchange_hash = H( H( message_1 \| message_2 ) \| message_3 ) 

where H() is the hash function in HKDF_V.

We define EDHOC-Key-Derivation to be the function which produces the output as described in {{RFC5869}} and {{RFC8152}} depending on the variable input AlgorithmID, keyDataLength and other:

output = EDHOC-Key-Derivation(AlgorithmID, keyDataLength, other)

For message_i the key, called K_i, SHALL be derived using other = aad_i, where i = 2 or 3. The key SHALL be derived using AlgorithmID set to the integer value of the negotiated AEAD (AEAD_V), and keyDataLength equal to the key length of AEAD_V.

If the AEAD algorithm uses an IV, then IV_i for message_i SHALL be derived using other = aad_i, where i = 2 or 3. The IV SHALL be derived using AlgorithmID = "IV-GENERATION" as specified in Section 12.1.2. of {{RFC8152}}, and keyDataLength equal to the IV length of AEAD_V.

### EDHOC-Exporter Interface {#exporter}

Application keys and other application specific data can be derived using the EDHOC-Exporter interface defined as:

EDHOC-Exporter(label, length) = EDHOC-Key-Derivation(label, 8 * length, exchange_hash)

The output of the EDHOC-Exporter function SHALL be derived using other = exchange_hash, AlgorithmID = label, and keyDataLength = 8 * length, where label is a tstr defined by the application and length is a uint defined by the application. The label SHALL be different for each different exporter value. An example use of the EDHOC-Exporter is given in {{oscore}}).

# EDHOC Authenticated with Asymmetric Keys {#asym}

## Overview {#asym-overview}

EDHOC supports authentication with raw public keys (RPK) and public key certificates with the requirements that:

* Party U SHALL be able to retrieve Party V's public authentication key using ID_CRED_V.

* Party V SHALL be able to retrieve Party U's public authentication key using ID_CRED_U.

Raw public keys are most optimally stored as COSE_Key objects and identified with a 'kid' value (see {{RFC8152}}):

* kid : ID_CRED_x, for x = U or V

Public key certificates can be identified in different ways, for example (see {{I-D.schaad-cose-x509}}):

* by a hash value;

   * x5t : ID_CRED_x, for x = U or V,

* by a URL;

   * x5u : ID_CRED_x, for x = U or V,

* by a certificate chain;

   * x5chain : ID_CRED_x, for x = U or V,

* or by a bag of certificates.

   * x5bag : ID_CRED_x, for x = U or V.

In the latter two examples, ID_CRED_U and ID_CRED_V contains the credential used for authentication. ID_CRED_U and ID_CRED_V do not need to uniquely identify the public authentication key, but doing so is recommended as the recipient may otherwise have to try several public keys. ID_CRED_U and ID_CRED_V are transported in the ciphertext, see {{asym-msg2-proc}} and {{asym-msg3-proc}}.

The actual credentials CRED_U and CRED_V (e.g. a COSE_Key or a single X.509 certificate) are signed by party U and V, respectively, see {{asym-msg3-form}} and {{asym-msg2-form}}.  Party U and Party V MAY use different type of credentials, e.g. one uses RPK and the other uses certificates. Party U and Party V MAY use different signature algorithms.

EDHOC with asymmetric key authentication is illustrated in {{fig-asym}}.

~~~~~~~~~~~
Party U                                                          Party V
|                        C_U, X_U, ALG_1, UAD_1                        |
+--------------------------------------------------------------------->|
|                               message_1                              |
|                                                                      |
| C_U, C_V, X_V, ALG_2, AEAD(K_2; Sig(V; CRED_V, aad_2), UAD_2; aad_2) |
|<---------------------------------------------------------------------+
|                               message_2                              |
|                                                                      |
|          S_V, AEAD(K_3; Sig(U; CRED_U, aad_3), PAD_3; aad_3)         |
+--------------------------------------------------------------------->|
|                               message_3                              |
~~~~~~~~~~~
{: #fig-asym title="EDHOC with asymmetric key authentication."}
{: artwork-align="center"}

### Mandatory to Implement Algorithms

For EDHOC authenticated with asymmetric keys, the COSE algorithms ECDH-SS + HKDF-256, AES-CCM-64-64-128, and Ed25519 are mandatory to implement.

## EDHOC Message 1

### Formatting of Message 1 {#asym-msg1-form}

message_1 SHALL be a sequence of CBOR elements as defined below

~~~~~~~~~~~ CDDL
message_1 = (
  MSG_TYPE : int,
  C_U : bstr,  
  ECDH-Curves_U : algs,
  ECDH-Curve_U : uint,
  X_U : bstr,
  HKDFs_U : algs,
  AEADs_U : algs,
  SIGs_V : algs,
  SIGs_U : algs,
  ? UAD_1 : bstr
)
~~~~~~~~~~~

~~~~~~~~~~~ CDDL
alg : int / tstr
~~~~~~~~~~~

~~~~~~~~~~~ CDDL
algs = alg / [ 2* alg ]
~~~~~~~~~~~

where:

* MSG_TYPE = 1
* C_U - variable length connection identifier
* ECDH-Curves_U - EC curves for ECDH which Party U supports, in order of decreasing preference. If a single algorithm is conveyed, it is placed in an int or text string, if multiple algorithms are conveyed, an array is used.
* ECDH-Curve_U - a single chosen algorithm from ECDH-Curves_U (zero-based index, i.e. 0 for the first or only, 1 for the second, etc.)
* X_U - the x-coordinate of the ephemeral public key of Party U
* HKDFs_U - supported ECDH-SS w/ HKDF algorithms, in order of decreasing preference
* AEADs_U - supported AEAD algorithms, in order of decreasing preference
* SIGs_V - signature algorithms, with which Party U supports verification, in order of decreasing preference.
* SIGs_U - signature algorithms, with which Party U supports signing, in order of decreasing preference.
* UAD_1 - bstr containing unprotected opaque application data

### Party U Processing of Message 1

Party U SHALL compose message_1 as follows:

* The supported algorithms and the order of preference MUST NOT be changed based on previous error messages. However, the lists sent to Party V (ECDH-Curves_U, HKDFs_U, AEADs_U, SIGs_V, SIGs_U) MAY be truncated such that curves/algorithms which are the least preferred are omitted. The amount of truncation MAY be changed between sessions, e.g. based on previous error messages (see next bullet), but all curves/algorithms which are more preferred than the least preferred curve in the list MUST be included in the list.

* Determine the curve ECDH-Curve_U to use with Party V in message_1. If Party U previously received from Party V an error message to message_1 with diagnostic payload identifying an ECDH curve that U supports, then U SHALL use that curve (which implies that ECDH_Curves_U in message_1 SHALL include that curve). Otherwise the first curve in ECDH-Curves_U MUST be used.

* Generate an ephemeral ECDH key pair as specified in Section 5 of {{SP-800-56a}} using the curve indicated by ECDH-Curve_U. Let X_U be the x-coordinate of the ephemeral public key.
   
* Choose a connection identifier C_U and store it for the length of the protocol. Party U MUST be able to retrieve the protocol state using the connection identifier C_U and optionally other information such as the 5-tuple. The connection identifier MAY be used with protocols for which EDHOC establishes application keys, in which case C_U SHALL be different from the concurrently used identifiers of that protocol.

* Format message_1 as specified in {{asym-msg1-form}}.

### Party V Processing of Message 1

Party V SHALL process message_1 as follows:
 
* Verify that at least one of each kind of the proposed algorithms are supported.

* Verify that the ECDH curve indicated by ECDH-Curve_U is supported, and that no prior curve in ECDH-Curves_U is supported.

* Validate that there is a solution to the curve definition for the given x-coordinate X_U.

* Pass UAD_1 to the application.

If any verification step fails, Party V MUST send an EDHOC error message back, formatted as defined in {{error}}, and the protocol MUST be discontinued. If V does not support the curve ECDH-Curve_U, but supports another ECDH curves in ECDH-Curves_U, then ALGs_V MUST include the first supported ECDH curve in ECDH-Curves_U. If V does not support any of the algorithms of one kind (ECDH-Curves_U, HKDFs_U, AEADs_U, SIGs_V, or SIGs_U), then ALGs_V MUST include one or more supported algorithms of that kind.

## EDHOC Message 2

### Formatting of Message 2 {#asym-msg2-form}

message_2 SHALL be a sequence of CBOR elements as defined below

~~~~~~~~~~~ CDDL
message_2 = (
  data_2,
  CIPHERTEXT_2 : bstr
)
~~~~~~~~~~~

~~~~~~~~~~~ CDDL
data_2 = (
  MSG_TYPE : int,
  C_U : bstr / nil,
  C_V : bstr,
  X_V : bstr,
  HKDF_V : uint,
  AEAD_V : uint,
  SIG_V : uint,
  SIG_U : uint
)
~~~~~~~~~~~

~~~~~~~~~~~ CDDL
aad_2 : bstr
~~~~~~~~~~~

where aad_2, in non-CDDL notation, is:

~~~~~~~~~~~
aad_2 = H( message_1 | data_2 )
~~~~~~~~~~~

where:

* MSG_TYPE = 2
* C_V - variable length connection identifier
* X_V - the x-coordinate of the ephemeral public key of Party V
* HKDF_V - the first supported algorithm from HKDFs_U
* AEAD_V - the first supported algorithm from AEADs_U
* SIG_V - the first supported algorithm from SIGs_V with which Party V signs
* SIG_U - the first supported algorithm from SIGs_U with which Party U signs
* H() - the hash function in HKDF_V

### Party V Processing of Message 2 {#asym-msg2-proc}

Party V SHALL compose message_2 as follows:

* Generate an ephemeral ECDH key pair as specified in Section 5 of {{SP-800-56a}} using the curve indicated by ECDH-Curve_U. Let X_V be the x-coordinate of the ephemeral public key.

* Choose a connection identifier C_V and store it for the length of the protocol. Party V MUST be able to retrieve the protocol state using the connection identifier C_V and optionally other information such as the 5-tuple. The connection identifier MAY be used with protocols for which EDHOC establishes application keys, in which case C_V SHALL be different from the concurrently used identifiers of that protocol. To reduce message overhead, party V can set the message field C_U in message_2 to null (still storing the actual value of C_U) if there is an external correlation mechanism (e.g. the Token in CoAP) that enables Party U to correlate message_1 and message_2.

*  Select HKDF_V, AEAD_V, SIG_V, and SIG_U as the first supported algorithms in HKDFs_U, AEADs_U, SIGs_V, and SIGs_U.

*  Compute COSE_Sign1 as defined in Section 4.4 of {{RFC8152}}, using algorithm SIG_V, the private authentication key of Party V, and the following parameters. The unprotected header MAY contain parameters (e.g. 'alg').
   
   * protected = { xyz : ID_CRED_V }

   * payload = ( CRED_V, aad_2 )

   * xyz - any COSE map label that can identify a public authentication key, see {{asym-overview}}

   * ID_CRED_V - bstr enabling the retrieval of the public authentication key of Party V, see {{asym-overview}}

   * CRED_V - bstr credential containing the public authentication key of Party V, see {{asym-overview}}
   
   Note that only 'protected' and 'signature' of the COSE_Sign1 structure are used in message_2, see next bullet.
   
* Compute COSE_Encrypt0 as defined in Section 5.3 of {{RFC8152}}, with AEAD_V, K_2, IV_2, and the following parameters. The protected header SHALL be empty. The unprotected header MAY contain parameters (e.g. 'alg').
 
   * external_aad = aad_2

   * plaintext = ( PROTECTED_2, SIGNATURE_2, ? UAD_2 )

   * PROTECTED_2 - bstr containing the COSE_Sign1 protected header
   
   * SIGNATURE_2 - bstr containing the COSE_Sign1 signature
  
   * UAD_2 = bstr containing opaque unprotected application data

   Note that only 'ciphertext' of the COSE_Encrypt0 structure are used in message_2, see next bullet.   

*  Format message_2 as specified in {{asym-msg2-form}}, where CIPHERTEXT_2 is the COSE_Encrypt0 ciphertext.

### Party U Processing of Message 2

Party U SHALL process message_2 as follows:

* Retrieve the protocol state using the connection identifier C_U and optionally other information such as the 5-tuple.

* Validate that there is a solution to the curve definition for the given x-coordinate X_V.

* Decrypt and verify COSE_Encrypt0 as defined in Section 5.3 of {{RFC8152}}, with AEAD_V, K_2, and IV_2.

* Verify COSE_Sign1 as defined in Section 4.4 of {{RFC8152}}, using algorithm SIG_V and the public authentication key of Party V.

If any verification step fails, Party U MUST send an EDHOC error message back, formatted as defined in {{error}}, and the protocol MUST be discontinued.

## EDHOC Message 3

### Formatting of Message 3 {#asym-msg3-form}

message_3 SHALL be a sequence of CBOR elements as defined below

~~~~~~~~~~~ CDDL
message_3 = (
  data_3,
  CIPHERTEXT_3 : bstr
)
~~~~~~~~~~~

~~~~~~~~~~~ CDDL
data_3 = (
  MSG_TYPE : int,
  C_V : bstr
)
~~~~~~~~~~~

~~~~~~~~~~~ CDDL
aad_3 : bstr
~~~~~~~~~~~

where aad_3, in non-CDDL notation, is:

~~~~~~~~~~~
aad_3 = H( H( message_1 | message_2 ) | data_3 )
~~~~~~~~~~~

where:

* MSG_TYPE = 3

### Party U Processing of Message 3 {#asym-msg3-proc}

Party U SHALL compose message_3 as follows:

*  Compute COSE_Sign1 as defined in Section 4.4 of {{RFC8152}}, using algorithm SIG_U, the private authentication key of Party U, and the following parameters. The unprotected header MAY contain parameters (e.g. 'alg').

   * protected = { xyz : ID_CRED_U }

   * payload = ( CRED_U, aad_3 )
   
   * xyz - any COSE map label that can identify a public authentication key, see {{asym-overview}}

   * ID_CRED_U - bstr enabling the retrieval of the public authentication key of Party U, see {{asym-overview}}

   * CRED_U - bstr credential containing the public authentication key of Party U, see {{asym-overview}}

   Note that only 'protected' and 'signature' of the COSE_Sign1 structure are used in message_3, see next bullet.

* Compute COSE_Encrypt0 as defined in Section 5.3 of {{RFC8152}}, with AEAD_V, K_3, and IV_3 and the following parameters. The protected header SHALL be empty. The unprotected header MAY contain parameters (e.g. 'alg').

   * external_aad = aad_3

   * plaintext = ( PROTECTED_3, SIGNATURE_3, ? PAD_3 )
   
   * PROTECTED_3 - bstr containing the COSE_Sign1 protected header
   
   * SIGNATURE_3 - bstr containing the COSE_Sign1 signature

   * PAD_3 = bstr containing opaque protected application data

   Note that only 'ciphertext' of the COSE_Encrypt0 structure are used in message_3, see next bullet.  

*  Format message_3 as specified in {{asym-msg3-form}}, where CIPHERTEXT_3 is the COSE_Encrypt0 ciphertext.

*  Pass the connection identifiers (C_U, C_V) and the negotiated algorithms (AEAD, HDKF, etc.) to the application. The application can now derive application keys using the EDHOC-Exporter interface.

### Party V Processing of Message 3

Party V SHALL process message_3 as follows:

* Retrieve the protocol state using the connection identifier C_V and optionally other information such as the 5-tuple.

* Decrypt and verify COSE_Encrypt0 as defined in Section 5.3 of {{RFC8152}}, with AEAD_V, K_3, and IV_3.

* Verify COSE_Sign1 as defined in Section 4.4 of {{RFC8152}}, using algorithm SIG_U and the public authentication key of Party U.

If any verification step fails, Party V MUST send an EDHOC error message back, formatted as defined in {{error}}, and the protocol MUST be discontinued.

*  Pass PAD_3, the connection identifiers (C_U, C_V), and the negotiated algorithms (AEAD, HDKF, etc.) to the application. The application can now derive application keys using the EDHOC-Exporter interface.

# EDHOC Authenticated with Symmetric Keys {#sym}

## Overview {#sym-overview}

EDHOC supports authentication with pre-shared keys. Party U and V are assumed to have a pre-shared key (PSK) with a good amount of randomness and the requirement that:

* Party V SHALL be able to retrieve the PSK using KID.

KID may optionally contain information about how to retrieve the PSK. KID does not need to uniquely identify the PSK, but doing so is recommended as the recipient may otherwise have to try several PSKs.

EDHOC with symmetric key authentication is illustrated in {{fig-sym}}.

~~~~~~~~~~~
Party U                                                       Party V
|                    C_U, X_U, ALG_1, KID, UAD_1                    |
+------------------------------------------------------------------>|
|                             message_1                             |
|                                                                   |
|           C_U, C_V, X_V, ALG_2, AEAD(K_2; UAD_2; aad_2)           |
|<------------------------------------------------------------------+
|                             message_2                             |
|                                                                   |
|                    S_V, AEAD(K_3; PAD_3; aad_3)                   |
+------------------------------------------------------------------>|
|                             message_3                             |
~~~~~~~~~~~
{: #fig-sym title="EDHOC with symmetric key authentication. "}
{: artwork-align="center"}

### Mandatory to Implement Algorithms

For EDHOC authenticated with symmetric keys, the COSE algorithms ECDH-SS + HKDF-256 and AES-CCM-64-64-128 are mandatory to implement.

## EDHOC Message 1

### Formatting of Message 1 {#sym-msg1-form}

message_1 SHALL be a sequence of CBOR elements as defined below

~~~~~~~~~~~ CDDL
message_1 = (
  MSG_TYPE : int,
  C_U : bstr,
  ECDH-Curves_U : algs,
  ECDH-Curve_U : uint,
  X_U : bstr,
  HKDFs_U : algs,
  AEADs_U : algs,
  KID : bstr,
  ? UAD_1 : bstr
)
~~~~~~~~~~~

~~~~~~~~~~~ CDDL
alg : int / tstr
~~~~~~~~~~~

~~~~~~~~~~~ CDDL
algs = alg / [ 2* alg ]
~~~~~~~~~~~

where:

* MSG_TYPE = 4
* C_U - variable length connection identifier
* ECDH-Curves_U - EC curves for ECDH which Party U supports, in order of decreasing preference. If a single algorithm is conveyed, it is placed in an int or text string, if multiple algorithms are conveyed, an array is used.
* ECDH-Curve_U - a single chosen algorithm from ECDH-Curves_U (zero-based index, i.e. 0 for the first or only, 1 for the second, etc.)
* X_U - the x-coordinate of the ephemeral public key of Party U
* HKDFs_U - supported ECDH-SS w/ HKDF algorithms, in order of decreasing preference
* AEADs_U - supported AEAD algorithms, in order of decreasing preference
* KID - bstr enabling the retrieval of the pre-shared key
* UAD_1 - bstr containing unprotected opaque application data

### Party U Processing of Message 1

Party U SHALL compose message_1 as follows:

* The supported algorithms and the order of preference MUST NOT be changed based on previous error messages. However, the lists sent to Party V (ECDH-Curves_U, HKDFs_U, AEADs_U) MAY be truncated such that curves/algorithms which are the least preferred are omitted. The amount of truncation MAY be changed between sessions, e.g. based on previous error messages (see next bullet), but all curves/algorithms which are more preferred than the least preferred curve in the list MUST be included in the list.

* Determine the curve ECDH-Curve_U to use with Party V in message_1. If Party U previously received from Party V an error message to message_1 with diagnostic payload identifying an ECDH curve that U supports, then U SHALL use that curve (which implies that ECDH_Curves_U in message_1 SHALL include that curve). Otherwise the first curve in ECDH-Curves_U MUST be used.

* Generate an ephemeral ECDH key pair as specified in Section 5 of {{SP-800-56a}} using the curve indicated by ECDH-Curve_U. Let X_U be the x-coordinate of the ephemeral public key.

* Choose a connection identifier C_U and store it for the length of the protocol. Party U MUST be able to retrieve the protocol state using the connection identifier C_U and optionally other information such as the 5-tuple. The connection identifier MAY be used with protocols for which EDHOC establishes application keys, in which case C_U SHALL be different from the concurrently used identifiers of that protocol.

* Format message_1 as specified in {{sym-msg1-form}}.

### Party V Processing of Message 1

Party V SHALL process message_1 as follows:

* Verify that at least one of each kind of the proposed algorithms are supported.

* Verify that the ECDH curve indicated by ECDH-Curve_U is supported, and that no prior curve in ECDH-Curves_U is supported.

* Validate that there is a solution to the curve definition for the given x-coordinate X_U.

* Pass UAD_1 to the application.

If any verification step fails, Party V MUST send an EDHOC error message back, formatted as defined in {{error}}, and the protocol MUST be discontinued. If V does not support the curve ECDH-Curve_U, but supports another ECDH curves in ECDH-Curves_U, then ALGs_V MUST include the first supported ECDH curve in ECDH-Curves_U. If V does not support any of the algorithms of one kind (ECDH-Curves_U, HKDFs_U, AEADs_U), then ALGs_V MUST include one or more supported algorithms of that kind.

## EDHOC Message 2

### Formatting of Message 2 {#sym-msg2-form}

message_2 SHALL be a sequence of CBOR elements as defined below

~~~~~~~~~~~ CDDL
message_2 = (
  data_2,
  CIPHERTEXT_2 : bstr
)
~~~~~~~~~~~

~~~~~~~~~~~ CDDL
data_2 = (
  MSG_TYPE : int,
  C_U : bstr / nil,  
  C_V : bstr,  
  X_V : bstr,
  HKDF_V : uint,
  AEAD_V : uint
)
~~~~~~~~~~~

~~~~~~~~~~~ CDDL
aad_2 : bstr
~~~~~~~~~~~

where aad_2, in non-CDDL notation, is:

~~~~~~~~~~~
aad_2 = H( message_1 | data_2 )
~~~~~~~~~~~

where:

* MSG_TYPE = 5
* C_V - variable length connection identifier
* X_V - the x-coordinate of the ephemeral public key of Party V
* HKDF_V - the first supported algorithm from HKDFs_U
* AEAD_V - the first supported algorithm from AEADs_U
* H() - the hash function in HKDF_V

### Party V Processing of Message 2

Party V SHALL compose message_2 as follows:

* Generate an ephemeral ECDH key pair as specified in Section 5 of {{SP-800-56a}} using the curve indicated by ECDH-Curve_U. Let X_V be the x-coordinate of the ephemeral public key.

* Choose a connection identifier C_V and store it for the length of the protocol. Party V MUST be able to retrieve the protocol state using the connection identifier C_V and optionally other information such as the 5-tuple. The connection identifier MAY be used with protocols for which EDHOC establishes application keys, in which case C_V SHALL be different from the concurrently used identifiers of that protocol. To reduce message overhead, party V can set the message field C_U in message_2 to null (still storing the actual value of C_U) if there is an external correlation mechanism (e.g. the Token in CoAP) that enables Party U to correlate message_1 and message_2.

*  Select HKDF_V and AEAD_V as the first supported algorithms in HKDFs_U and AEADs_U.

* Compute COSE_Encrypt0 as defined in Section 5.3 of {{RFC8152}}, with AEAD_V, K_2, IV_2, and the following parameters. The protected header SHALL be empty. The unprotected header MAY contain parameters (e.g. 'alg').

   * external_aad = aad_2

   * plaintext = ? UAD_2

   * UAD_2 = bstr containing opaque unprotected application data

   Note that only 'ciphertext' of the COSE_Encrypt0 structure are used in message_2, see next bullet.   

*  Format message_2 as specified in {{sym-msg2-form}}, where CIPHERTEXT_2 is the COSE_Encrypt0 ciphertext.
   
### Party U Processing of Message 2

Party U SHALL process message_2 as follows:

* Retrieve the protocol state using the connection identifier C_U and optionally other information such as the 5-tuple.

* Validate that there is a solution to the curve definition for the given x-coordinate X_V.

* Decrypt and verify COSE_Encrypt0 as defined in Section 5.3 of {{RFC8152}}, with AEAD_V, K_2, and IV_2.

If any verification step fails, Party U MUST send an EDHOC error message back, formatted as defined in {{error}}, and the protocol MUST be discontinued.

* Pass UAD_2 to the application.

## EDHOC Message 3

### Formatting of Message 3 {#sym-msg3-form}

message_3 SHALL be a sequence of CBOR elements as defined below

~~~~~~~~~~~ CDDL
message_3 = (
  data_3,
  CIPHERTEXT_3 : bstr
)
~~~~~~~~~~~

~~~~~~~~~~~ CDDL
data_3 = (
  MSG_TYPE : int,
  C_V : bstr 
)
~~~~~~~~~~~

~~~~~~~~~~~ CDDL
aad_3 : bstr
~~~~~~~~~~~

where aad_3, in non-CDDL notation, is:

~~~~~~~~~~~
aad_3 = H( H( message_1 | message_2 ) | data_3 )
~~~~~~~~~~~

where:

* MSG_TYPE = 6

### Party U Processing of Message 3

Party U SHALL compose message_3 as follows:

* Compute COSE_Encrypt0 as defined in Section 5.3 of {{RFC8152}}, with AEAD_V, K_3, IV_3, and the following parameters. The protected header SHALL be empty. The unprotected header MAY contain parameters (e.g. 'alg').

   * external_aad = aad_3

   * plaintext = ? PAD_3

   * PAD_3 = bstr containing opaque protected application data

   Note that only 'ciphertext' of the COSE_Encrypt0 structure are used in message_3, see next bullet.   

*  Format message_3 as specified in {{sym-msg3-form}}, where CIPHERTEXT_3 is the COSE_Encrypt0 ciphertext.

*  Pass the connection identifiers (C_U, C_V) and the negotiated algorithms (AEAD, HDKF, etc.) to the application. The application can now derive application keys using the EDHOC-Exporter interface.

### Party V Processing of Message 3

Party V SHALL process message_3 as follows:

* Retrieve the protocol state using the connection identifier C_V and optionally other information such as the 5-tuple.

* Decrypt and verify COSE_Encrypt0 as defined in Section 5.3 of {{RFC8152}}, with AEAD_V, K_3, and IV_3.

If any verification step fails, Party V MUST send an EDHOC error message back, formatted as defined in {{error}}, and the protocol MUST be discontinued.

*  Pass PAD_3, the connection identifiers (C_U, C_V), and the negotiated algorithms (AEAD, HDKF, etc.) to the application. The application can now derive application keys using the EDHOC-Exporter interface.

# Error Handling {#error}

## EDHOC Error Message

This section defines a message format for the EDHOC error message, used during the protocol. An EDHOC error message can be send by both parties as a response to any non-error EDHOC message. After sending an error message, the protocol MUST be discontinued. Errors at the EDHOC layer are sent as normal successful messages in the lower layers (e.g. POST and 2.04 Changed). An advantage of using such a construction is to avoid issues created by usage of cross protocol proxies (e.g. UDP to TCP).

error SHALL be a sequence of CBOR elements as defined below

~~~~~~~~~~~ CDDL
error = (
  MSG_TYPE : int,
  ERR_MSG : tstr,
  ? ALGs_V: algs
)
~~~~~~~~~~~

~~~~~~~~~~~ CDDL
alg : int / tstr
~~~~~~~~~~~

~~~~~~~~~~~ CDDL
algs = alg / [ 2* alg ]
~~~~~~~~~~~

where:

* MSG_TYPE = 0
* ERR_MSG - text string containing the diagnostic payload, defined in the same way as in Section 5.5.2 of {{RFC7252}}
* ALGs_V - algorithms that V supports that were not included in ECDH-Curve_U, HKDFs_U, AEADs_U, SIGs_V, and SIGs_U

# IANA Considerations {#iana}

## The Well-Known URI Registry

IANA has added the well-known URI 'edhoc' to the Well-Known URIs registry.

- URI suffix: edhoc

- Change controller: IETF

- Specification document(s): [[this document]]

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

- Published specification: [[this document]] (this document)

- Applications that use this media type: To be identified

- Fragment identifier considerations: N/A

- Additional information:

  * Magic number(s): N/A

  * File extension(s): N/A
  
  * Macintosh file type code(s): N/A

- Person & email address to contact for further information: Göran Selander <goran.selander@ericsson.com>

- Intended usage: COMMON

- Restrictions on usage: N/A

- Author: Göran Selander <goran.selander@ericsson.com>

- Change Controller: IESG

## CoAP Content-Formats Registry

IANA has added the media type 'application/edhoc' to the CoAP Content-Formats registry.

-  Media Type: application/edhoc

-  Encoding:

-  ID: TBD42

-  Reference: [[this document]]

# Security Considerations {#security}

## Security Properties
EDHOC inherits its security properties from the theoretical SIGMA-I protocol {{SIGMA}}. Using the terminology from {{SIGMA}}, EDHOC provides perfect forward secrecy, mutual authentication with aliveness, consistency, peer awareness, and identity protection. As described in {{SIGMA}}, peer awareness is provided to Party V, but not to Party U.

EDHOC with asymmetric authentication offers identity protection of Party U against active attacks and identity protection of Party V against passive attacks. The roles should be assigned to protect the most sensitive identity, typically the one that is not derivable from routing information in the lower layers.

Compared to {{SIGMA}}, EDHOC adds an explicit message type and expands the message authentication coverage to additional elements such as algorithms, application data, and previous messages. This protects against an attacker replaying messages or injecting messages from another session.

EDHOC also adds negotiation of connection identifiers and downgrade protected negotiation of cryptographic parameters, i.e. an attacker cannot affect the negotiated parameters. A single session of EDHOC does not include negotiation of parameters related to the ephemeral key, but it enables Party V to verify that the ECDH curve used in the protocol is the most preferred curve by U which is supported by both U and V. 

## Cryptographic Considerations
The security of the SIGMA protocol requires the MAC to be bound to the identity of the signer. Hence the message authenticating functionality of the authenticated encryption in EDHOC is critical: authenticated encryption MUST NOT be replaced by plain encryption only, even if authentication is provided at another level or through a different mechanism. EDHOC implements SIGMA-I using the same Sign-then-MAC approach as TLS 1.3.

To reduce message overhead EDHOC does not use explicit nonces and instead rely on the ephemeral public keys to provide randomness to each session. A good amount of randomness is important for the key generation, to provide aliveness, and to protect against interleaving attacks. For this reason, the ephemeral keys MUST NOT be reused, and both parties SHALL generate fresh random ephemeral key pairs. 

The choice of key length used in the different algorithms needs to be harmonized, so that a sufficient security level is maintained for certificates, EDHOC, and the protection of application data. Party U and V should enforce a minimum security level.

The data rates in many IoT deployments are very limited. Given that the application keys are protected as well as the long-term authentication keys they can often be used for years or even decades before the cryptographic limits are reached. If the application keys established through EDHOC need to be renewed, the communicating parties can derive application keys with other labels or run EDHOC again.

## Unprotected Data

Party U and V must make sure that unprotected data and metadata do not reveal any sensitive information. This also applies for encrypted data sent to an unauthenticated party. In particular, it applies to UAD_1, ID_CRED_V, UAD_2, and ERR_MSG in the asymmetric case, and KID, UAD_1, and ERR_MSG in the symmetric case. Using the same KID or UAD_1 in several EDHOC sessions allows passive eavesdroppers to correlate the different sessions. The communicating parties may therefore anonymize KID. Another consideration is that the list of supported algorithms may be used to identify the application.

Party U and V must also make sure that unauthenticated data does not trigger any harmful actions. In particular, this applies to UAD_1 and ERR_MSG in the asymmetric case, and KID, UAD_1, and ERR_MSG in the symmetric case.

## Denial-of-Service

EDHOC itself does not provide countermeasures against Denial-of-Service attacks. By sending a number of new or replayed message_1 an attacker may cause Party V to allocate state, perform cryptographic operations, and amplify messages. To mitigate such attacks, an implementation SHOULD rely on lower layer mechanisms such as the Echo option in CoAP {{I-D.ietf-core-echo-request-tag}} that forces the initiator to demonstrate reachability at their apparent network address.

## Implementation Considerations

The availability of a secure pseudorandom number generator and truly random seeds are essential for the security of EDHOC. If no true random number generator is available, a truly random seed must be provided from an external source. If ECDSA is supported, "deterministic ECDSA" as specified in RFC6979 is RECOMMENDED.

The referenced processing instructions in {{SP-800-56a}} must be complied with, including deleting the intermediate computed values along with any ephemeral ECDH secrets after the key derivation is completed. The ECDH shared secret, keys (K_2, K_3), and IVs (IV_2, IV_3) MUST be secret. Implementations should provide countermeasures to side-channel attacks such as timing attacks.

Party U and V are responsible for verifying the integrity of certificates. The selection of trusted CAs should be done very carefully and certificate revocation should be supported. The private authentication keys MUST be kept secret.

Party U and V are allowed to select the connection identifiers C_U and C_V, respectively, for the other party to use in the ongoing EDHOC protocol as well as in a subsequent application protocol (e.g. OSCORE {{I-D.ietf-core-object-security}}). The choice of connection identifier is not security critical in EDHOC but intended to simplify the retrieval of the right security context in combination with using short identifiers. If the wrong connection identifier of the other party is used in a protocol message it will result in the receiving party not being able to retrieve a security context (which will terminate the protocol) or retrieve the wrong security context (which also terminates the protocol as the message cannot be verified).

## Other Documents Referencing EDHOC

EDHOC has been analyzed in several other documents. An analysis of EDHOC for certificate enrollment was done in {{CertEnr}}, the use of EDHOC in LoRaWAN is analyzed in {{LoRa1}} and {{LoRa2}}, and the use of EDHOC in 6TiSCH is described in {{I-D.ietf-6tisch-dtsecurity-zerotouch-join}}. 

--- back

# Use of CBOR and COSE in EDHOC {#CBORandCOSE}

This Appendix is intended to simplify for implementors not familiar with CBOR {{RFC7049}}, COSE {{RFC8152}}, and HKDF {{RFC5869}}. 

TODO: This section needs to be updated.

## CBOR

The Concise Binary Object Representation (CBOR) {{RFC7049}} is a data format designed for small code size and small message size. CBOR builds on the JSON data model but extends it by e.g. encoding binary data directly without base64 conversion. In addition to the binary CBOR encoding, CBOR also has a diagnostic notation that is readable and editable by humans. CBOR data items are encoded to or decoded from byte strings using a type-length-value encoding scheme. In addition to integers, simple values (e.g. null), byte strings, and text strings, CBOR also supports arrays [] and maps {} of data items. For a complete specification and more examples, see {{RFC7049}}.

~~~~~~~~~~~~~~~~~~~~~~~
Diagnostic      Encoded
------------------------------------------
1               0x01
-27             0x381a
null            0xf6
h'c3'           0x41c3
"Pickle Rick"   0x6b5069636b6c65205269636b
[1, 2]          0x820102
{4: h'c3'}      0xa10441c3
------------------------------------------
~~~~~~~~~~~~~~~~~~~~~~~

## COSE

CBOR Object Signing and Encryption (COSE) {{RFC8152}} describes how to create and process signatures, message authentication codes, and encryption using CBOR. COSE build on JOSE, but makes some design changes to make it more suitable for the Internet of Things (IoT). EDHOC makes use of COSE_Key, COSE_Encrypt0, COSE_Sign1, and COSE_KDF_Context objects.

### Encryption and Decryption

In all encryption operations (both encryption and decryption) the input to the AEAD is a follows:

* The key K and nonce N (IV) are the output EDHOC-Key-Derivation function as defined in {{key-der}}.

* The plaintext P is just the concatenation the included CBOR data items ecnoded as byte strings (but not CBOR byte strings).

* The associated data A is = Enc_structure = [ "Encrypt0", h'', aad_2 ] = 0x8368456E63727970743040 \| aad_i

where aad_i is the  concatenation the included CBOR data items ecnoded as byte strings (but not necessarily CBOR byte strings).

# Test Vectors {#vectors}

This appendix provides a wealth of test vectors to ease implementation and ensure interoperability.

TODO: This section needs to be updated.

# EDHOC PSK Chaining

An application using EDHOC may want to derive new PSKs to use for authentication in future EDHOC sessions.  In this case, the new PSK and KID SHOULD be derived as follows where length is the key length (in bytes) of AEAD_V.

~~~~~~~~~~~~~~~~~~~~~~~
PSK = EDHOC-Exporter("EDHOC Chaining PSK", length)
KID = EDHOC-Exporter("EDHOC Chaining KID", 4)
~~~~~~~~~~~~~~~~~~~~~~~

# EDHOC with CoAP and OSCORE

## Transferring EDHOC in CoAP {#coap}

EDHOC can be transferred as an exchange of CoAP {{RFC7252}} messages. By default, the CoAP client is Party U and the CoAP server is Party V, but the roles SHOULD be chosen to protect the most sensitive identity, see {{security}}. By default, EDHOC is transferred in POST requests and 2.04 (Changed) responses to the Uri-Path: "/.well-known/edhoc", but an application may define its own path that can be discovered e.g. using resource directory {{I-D.ietf-core-resource-directory}}.

By default, the message flow is as follows: EDHOC message_1 is sent in the payload of a POST request from the client to the server's resource for EDHOC. EDHOC message_2 or the EDHOC error message is sent from the server to the client in the payload of a 2.04 (Changed) response. EDHOC message_3 or the EDHOC error message is sent from the client to the server's resource in the payload of a POST request. If needed, an EDHOC error message is sent from the server to the client in the payload of a 2.04 (Changed) response.

An example of a successful EDHOC exchange using CoAP is shown in {{fig-coap}}.

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
{: #fig-coap title="Example of transferring EDHOC in CoAP"}
{: artwork-align="center"}

## Deriving an OSCORE context from EDHOC {#oscore}

When EDHOC is used to derive parameters for OSCORE {{I-D.ietf-core-object-security}}, the parties must make sure that the EDHOC connection identifiers are unique, i.e. C_V MUST NOT be equal to C_U.  In case that the CoAP client is party U and the CoAP server is party V:

* The client's OSCORE Sender ID is C_V and the server's OSCORE Sender ID is C_U, as defined in this document

* The AEAD Algorithm is AEAD_V and the HMAC-based Key Derivation Function (HKDF) is HKDF_V, as defined in this document

* The Master Secret and Master Salt are derived as follows where length is the key length (in bytes) of AEAD_V.

~~~~~~~~~~~~~~~~~~~~~~~
   Master Secret = EDHOC-Exporter("OSCORE Master Secret", length)
   Master Salt   = EDHOC-Exporter("OSCORE Master Salt", 8)
~~~~~~~~~~~~~~~~~~~~~~~

# Message Sizes {#sizes}

This appendix gives an estimate of the message sizes of EDHOC with different authentication methods. Note that the examples in this appendix are not test vectors, the cryptographic parts are just replaced with byte strings of the same length. All examples are given in CBOR diagnostic notation and hexadecimal.

## Message Sizes RPK

### message_1

~~~~~~~~~~~~~~~~~~~~~~~
message_1 = (
  1,
  h'c3',
  4,
  0,
  h'000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d
    1e1f',
  -27,
  10,
  -8,
  -8
)
~~~~~~~~~~~~~~~~~~~~~~~

~~~~~~~~~~~~~~~~~~~~~~~
message_1 (44 bytes):
01 41 C3 04 00 58 20 00 01 02 03 04 05 06 07 08 09 0A 0B 0C
0D 0E 0F 10 11 12 13 14 15 16 17 18 19 1A 1B 1C 1D 1E 1F
38 1A 0A 27 27
~~~~~~~~~~~~~~~~~~~~~~~

### message_2

~~~~~~~~~~~~~~~~~~~~~~~
plaintext = (
  { 4 : 'acdc' },
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

The size of the protected header field is 7 bytes. The size of the plaintext is 73 bytes so assuming a 64-bit MAC value the ciphertext is 81 bytes

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

### message_3

The plaintext and ciphertext in message_3 are assumed to be of equal sizes as in message_2.

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

## Message Sizes Certificates

When the certificates are distributed out-of-band and identified with the x5t header and a SHA256/64 hash value, the protected COSE_Sign1 protected header will be 13 bytes instead of 7 bytes (assuming labels in the range -24&hellip;23).

~~~~~~~~~~~~~~~~~~~~~~~
protected = { TDB1 : [ TDB6, h'0001020304050607' ] }
~~~~~~~~~~~~~~~~~~~~~~~

When the certificates are identified with the x5chain header, the message sizes depends on the size of the (truncated) certificate chains. The COSE_Sign1 protected header will be 3 bytes + the size of the certificate chain (assuming a label in the range -24&hellip;23).

~~~~~~~~~~~~~~~~~~~~~~~
protected = { TDB3 : h'0001020304050607...' }
~~~~~~~~~~~~~~~~~~~~~~~

## Message Sizes PSK

### message_1

~~~~~~~~~~~~~~~~~~~~~~~
message_1 = (
  4,
  h'c3',
  4,
  0,
  h'000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d
    1e1f',
  -27,
  10,
  'abba'
)
~~~~~~~~~~~~~~~~~~~~~~~

~~~~~~~~~~~~~~~~~~~~~~~
message_1 (47 bytes):
04 41 C3 04 00 58 20 00 01 02 03 04 05 06 07 08 09 0A 0B 0C
0D 0E 0F 10 11 12 13 14 15 16 17 18 19 1A 1B 1C 1D 1E 1F
38 1A 0A 44 61 63 64 63
~~~~~~~~~~~~~~~~~~~~~~~

### message_2

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

### message_3

The plaintext and ciphertext in message_3 are assumed to be of equal sizes as in message_2.

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

## Summary

~~~~~~~~~~~~~~~~~~~~~~~
              PSK       RPK       x5t     x5chain                  
--------------------------------------------------------------------
message_1      47        44        44        44                     
message_2      49       125       131       121 + Certificate chain 
message_3      12        86        92        82 + Certificate chain 
--------------------------------------------------------------------
Total         108       255       267       247 + Certificate chains
~~~~~~~~~~~~~~~~~~~~~~~
{: #fig-context title="Typical message sizes in bytes" artwork-align="center"}

# Acknowledgments
{: numbered="no"}

The authors want to thank Dan Harkins, Ilari Liusvaara, Jim Schaad, and Ludwig Seitz for reviewing intermediate versions of the draft and contributing concrete proposals incorporated in this version. We are especially indebted to Jim Schaad for his continuous reviewing and implementation of different versions of the draft.

We are also grateful to Theis Grønbech Petersen, Thorvald Sahl Jørgensen, Alessandro Bruni, and Carsten Schürmann for their work on formal analysis of EDHOC.

--- fluff
