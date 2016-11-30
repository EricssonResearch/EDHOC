---
title:  Ephemeral Diffie-Hellman Over COSE (EDHOC)
docname: draft-selander-ace-cose-ecdhe-latest

# stand_alone: true

ipr: trust200902
area: Applications
wg: ACE Working Group
kw: Internet-Draft
cat: std

coding: us-ascii
pi:    # can use array (if all yes) or hash here
#  - toc
#  - sortrefs
#  - symrefs
  toc: yes
  sortrefs:   # defaults to yes
  symrefs: yes

author:
      -
        ins: G. Selander
        name: Goeran Selander
        org: Ericsson AB
        street: Farogatan 6
        city: Kista
        code: SE-16480 Stockholm
        country: Sweden
        email: goran.selander@ericsson.com
      -
        ins: J. Mattsson
        name: John Mattsson
        org: Ericsson AB
        street: Farogatan 6
        city: Kista
        code: SE-16480 Stockholm
        country: Sweden
        email: john.mattsson@ericsson.com
      -
        ins: F. Palombini
        name: Francesca Palombini
        org: Ericsson AB
        street: Farogatan 6
        city: Kista
        code: SE-16480 Stockholm
        country: Sweden
        email: francesca.palombini@ericsson.com


normative:
#        - rfc2119
#        - I-D.ietf-cose-msg

  RFC7049:
  I-D.ietf-cose-msg:
  RFC2119:
  SP-800-56a:
    target: http://dx.doi.org/10.6028/NIST.SP.800-56Ar2
    title: Recommendation for Pair-Wise Key Establishment Schemes Using Discrete Logarithm Cryptography
    seriesinfo:
      "NIST": "Special Publication 800-56A"
    author:
      -
        ins: E. Barker
        name: Elaine Barker
      -
        ins: L. Chen
        name: Lily Chen
      -
        ins: A. Roginsky
        name: Allen Roginsky
      -
        ins: M. Smid
        name: Miles Smid
    date: May 2013
    format:
      PDF: http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-56Ar2.pdf
  SIGMA:
    target: http://dx.doi.org/10.1007/978-3-540-45146-4_24
    title: SIGMA - The 'SIGn-and-MAc' Approach to Authenticated Diffie-Hellman and Its Use in the IKE-Protocols
    seriesinfo:
      "Advances in Cryptology - CRYPTO 2003,": "23rd Annual International Cryptology Conference, Santa Barbara, California, USA, August 17-21, 2003, Proceedings"
    author:
      -
        ins: H. Krawczyk
        name: Hugo Krawczyk
    date: August 2003
    format:
      PDF: http://www.iacr.org/cryptodb/archive/2003/CRYPTO/1495/1495.pdf


informative:

#        - RFC5869:
#		     - I-D.ietf-ace-oauth-authz
#        - rfc7228
#        - rfc7252
#        - I-D.hartke-core-e2e-security-reqs
#        - I-D.ietf-core-object-security:
#        - I-D.wahlstroem-ace-cbor-web-token:
#        - RFC7519:
  I-D.hartke-core-e2e-security-reqs:
  I-D.ietf-ace-oauth-authz:
  I-D.ietf-core-object-security:
  I-D.seitz-ace-oscoap-profile:

  RFC4492:
  RFC7228:
  RFC7252:
  RFC5869:
  

--- abstract

This document specifies authenticated Diffie-Hellman key exchange with ephemeral keys, embedded in messages encoded with CBOR and using the CBOR Object Signing and Encryption (COSE) format. 

--- middle

# Introduction #       {#intro}


Security at the application layer provides an attractive option for protecting Internet of Things (IoT) deployments, for example where transport layer security is not sufficient {{I-D.hartke-core-e2e-security-reqs}}. IoT devices may be constrained in various ways, including memory, storage, processing capacity, and energy {{RFC7228}}. A method for protecting individual messages at application layer suitable for constrained devices, is provided by COSE {{I-D.ietf-cose-msg}}), which builds on CBOR {{RFC7049}}. 

In order for a communication session to provide forward secrecy, the communicating parties can run a Diffie-Hellman (DH) key exchange protocol with ephemeral keys, from which shared key material can be derived. This document specifies authenticated DH protocols using CBOR and COSE objects. The DH key exchange messages may be authenticated using either a pre-shared key (PSK), a raw public key (RPK) or an X.509 certificate (Cert). Authentication is based on credentials established out of band, or from a trusted third party, such as an Authorization Server as specified by {{I-D.ietf-ace-oauth-authz}}. Note that this document focuses on authentication and key establishment: for integration with authorization of resource access, refer to {{I-D.seitz-ace-oscoap-profile}}. This document also specifies the derivation of shared key material.

The DH exchange and the key derviation follow {{SIGMA}}, NIST SP-800-56a {{SP-800-56a}} and HKDF {{RFC5869}}, and make use of the data structures of COSE which are aligned with these standards. 


## Terminology ##  {#terminology}

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in {{RFC2119}}. These
words may also appear in this document in lowercase, absent their
normative meanings.


# Protocol Overview # {#protocol}

This section gives an overview of EDHOC, together with {{mess-proc}} and {{mess-proc-sym}}, which explains how the messages are processed, while {{asym}} and {{sym}} focus on the detailed message formats embedded as CBOR objects, and {{key-der-asym}}, {{key-der-sym}}, and {{final-key-der}} specify the key derivation.

EDHOC is built on the SIGMA family of protocols, with the basic protocol specified in Section 5 of {{SIGMA}}. {{mess-ex0}} shows  variant (ii) specified in Section 5.4 of {{SIGMA}}.

~~~~~~~~~~~

Party U                                                 Party V
  |                                                       | 
  |                                                       | 
  |                       E_U                             |  
  +------------------------------------------------------>|
  |                                                       |          
  |        E_V, ID_V, Sig(V; Mac(Km; E_U, E_V, ID_V))     |
  |<------------------------------------------------------+
  |                                                       |       
  |           ID_U, Sig(U; Mac(Km; E_V, E_U, ID_U))       | 
  +------------------------------------------------------>|
  |                                                       |    
                       
~~~~~~~~~~~
{: #mess-ex0 title="The basic SIGMA protocol"}
{: artwork-align="center"}


The parties exchanging messages are called "U" and "V". U and V exchange identities and ephemeral public keys. They compute the shared secret and derive the keying material. The messages are signed and MAC-ed according to the SIGMA protocol ({{mess-ex0}}):

*  E_U and E_V are the ECDH ephemeral public keys of U and V, respectively.
* ID_U and ID_V are used to identify U and V, respectively. In case of public key certificate, C_U and C_V are used instead.
* Sig(U; . ) and Sig(V; . ) denote signatures made with the private key of U and V, respectively.
* Mac(Km; . ) denote message authentication using keys derived from the shared secret

EDHOC used with symmetric keys is based on the basic SIGMA protocol. The underlying scheme for EDHOC using asymmetric keys is the SIGMA-I protocol as specified in Section 5.2, with variant (ii) in Section 5.4, of {{SIGMA}}, see {{mess-ex}}. This protocol adds encryption which is required for identity protection in the asymmetric key case:

* Enc(Ke; .) denote encryption using keys derived from the shared secret

~~~~~~~~~~~

Party U                                                 Party V
  |                                                       | 
  |                                                       | 
  |                       E_U                             |  
  +------------------------------------------------------>|
  |                                                       |          
  |  E_V, Enc(Ke; ID_V, Sig(V; Mac(Km; E_U, E_V, ID_V)))  |
  |<------------------------------------------------------+
  |                                                       |       
  |     Enc(Ke; ID_U, Sig(U; Mac(Km; E_V, E_U, ID_U)))    | 
  +------------------------------------------------------>|
  |                                                       |    
                                        
~~~~~~~~~~~
{: #mess-ex title="The SIGMA-I protocol"}
{: artwork-align="center"}


The protocols are detailed further in the following sections.


<!--# Message formatting using COSE # {#mess-format}

This section details the format for the objects used. Examples are provided for each object in {{examples}}. -->

# ECDH Public Keys using COSE\_Key ## {#COSE_key}

This section defines the formatting of the ephemeral public keys E_U and E_V.

The ECDH ephemeral public key SHALL be formatted as a COSE_Key with the following fields and values (see {{I-D.ietf-cose-msg}}):

* kty: The value SHALL be 2 (Elliptic Curve Keys)
* crv: The value of the Curve used.
* x: 
* y: The value SHOULD be boolean.

For the field 'crv', refer to Table 22 of {{I-D.ietf-cose-msg}}. The value 1 MUST be supported by party V (NIST P-256 a.k.a. secp256r1 {{RFC4492}}).

TODO: Consider replacing P-256 with Curve25519 as mandatory

# Asymmetric Keys # {#asym-keys-intro}

In this section we assume that the protocol messages are authenticated with asymmetric keys. Both the scenarios where the parties use raw public keys (RPK) and X.509 certificates (Cert) are supported.

* Party U's public key SHALL be uniquely identified at V by ID_U.
* Party V's public key SHALL be uniquely identified at U by ID_V.

ID_U and ID_V may be public key certificates {{SIGMA}}, which we then denote as C_U and C_V, respectively.

The pre-established credentials may thus be the public keys of U at V, and of V at U. Alternatively, a pre-established public key of a Certificate Authority (CA) may be used as trust anchor for verification of received certificate. 

The protocol is based on SIGMA-I ({{protocol}}). As described in Appendix B of {{SIGMA}}, in order to create a "full-fledge" protocol some additional protocol elements are needed:

* Explicit freshness nonces/session identifiers N_U, N_V chosen freshly and anew with each session by U and V, respectively
* Computationally independent keys K_UE, K_UM, K_VE, K_VM derived from the DH-shared secret and used for different directions and operations.

EDHOC makes the following additions to this scheme (see {{mess-ex2}}):

* Negotiation of algorithms used: AEAD-, signature- and MAC-algorithm used in the protocol, and ECDH-ES w/ HKDF algorithm used in the key derivation:
   * U proposes one or more algorithms (Alg_U).
   * V decides and responds with selected algorithms (Alg_V).
   * Subsequent traffic is protected with the AEAD agreed in this negotiation.


~~~~~~~~~~~
     
Party U                                                     Party V
|                                                                 |
|                        N_U, E_U, Alg_U                          |
+---------------------------------------------------------------> |
|                             message_1                           |
|                                                                 | 
|                                                                 | 
| N_U, N_V, E_V, Alg_V, Enc(K_VE; ID_V, Sig(V; Mac(K_VM; prot_2)))|  
| <---------------------------------------------------------------+
|                             message_2                           |
|                                                                 |
|                                                                 | 
|    N_U, N_V, Enc(K_UE; ID_U, Sig(U; Mac(K_UM; prot_3)))         |
+---------------------------------------------------------------> |
|                             message_3                           |  
|                                                                 |

where prot_2 = N_U, N_V, E_V, Alg_V, ID_V
and   prot_3 = N_V, N_U, E_U, Alg_U, ID_U
~~~~~~~~~~~
{: #mess-ex2 title="EDHOC with asymmetric keys. "}
{: artwork-align="center"}



## Message Formatting using COSE ## {#asym}

This section details the format for the objects used. Examples are provided for each object in {{examples}}.

Note that \* identifies fields that do not exist in COSE structures ({{I-D.ietf-cose-msg}}), and are thus defined in this document.

### Message 1 ### {#asym-m1}

This section defines the formatting of message_1.

message_1 is a CBOR map object containing:

* N_U: nonce
* E_U: the ephemeral public key of Party U
* ECDH_arr: an array of proposed ECDH-ES w/ HKDF algorithms
* AEAD_arr: an array of proposed AEAD algorithms
* SIG_arr: an array of proposed Signature algorithms
* MAC_arr: an array of proposed MAC algorithms
 
~~~~~~~~~~~ CDDL
message_1 = {
  N_U : bstr,
  E_U : COSE_Key,
  ALG_U : alg_arr
  }

alg_arr = [
  ECDH_arr : alg_array, 
  AEAD_arr : alg_array,
  SIG_arr : alg_array,
  MAC_arr : alg_array
  ]

alg_array = [ + alg : bstr/int ]
~~~~~~~~~~~

### Message 2 ### {#asym-m2}

In case of asymmetric keys, message\_2 SHALL have the COSE\_Encrypt structure {{I-D.ietf-cose-msg}} with the following fields and values:

* Headers:
  - protected:
    + alg: AEAD, the Authenticated Encryption with Additional Data algorithm chosen by Party V from the set of proposed algorithms AEAD_arr
  - unprotected:
    + nonces\*: nonce-array
* ciphertext: encrypted plaintext as defined below
* recipient: 
  - Headers:
    + protected: ECDH-ES + HKDF algorithm chosen by Party V from the set of proposed algorithms ECDH_arr (table 18 in {{I-D.ietf-cose-msg}})
    + unprotected: 
      * E\_V: COSE\_Key
    + ciphertext: empty

~~~~~~~~~~~ CDDL
nonce-array = [
  N_U: bstr,
  N_V: bstr
  ]
~~~~~~~~~~~

The plaintext for message\_2 SHALL have the COSE\_Sign1 structure {{I-D.ietf-cose-msg}} with the following fields and values:

* Headers
  - protected
    + alg: SIG, the Sign algorithm chosen by Party V from the set of proposed algorithms SIG_arr
    + MAC-alg\*: MAC, the MAC algorithm chosen by Party V from the set of proposed algorithms MAC_arr
  - Unprotected:
    + kid: ID_V (if raw public keys are used) or
    + x5c\*: C_V (if certificates are used)
* detached payload: as defined below
* signature: computed as in Section 4.4 of {{I-D.ietf-cose-msg}}

The payload for COSE_Sign1 SHALL have the COSE\_MAC0 structure {{I-D.ietf-cose-msg}} with the following fields and values:

* Headers
  - protected
    + alg: MAC (same value as MAC-alg in COSE_Sign1 structure above)
  - unprotected: empty
* payload: payl_2_rpk (resp. payl_2_cert) as defined below if raw public keys (resp. certificates) are used
* tag

~~~~~~~~~~~ CDDL
payl_2_rpk = [
  N_U: bstr,
  N_V: bstr,
  E_V: COSE_Key,
  ID_V: bstr
  ]
~~~~~~~~~~~

~~~~~~~~~~~ CDDL
payl_2_cert = [
  N_U: bstr,
  N_V: bstr,
  E_V: COSE_Key,
  C_V: bstr
  ]
~~~~~~~~~~~

### Message 3 ### {#asym-m3}

In case of asymmetric keys, message\_3 SHALL have the COSE\_Encrypt0 structure {{I-D.ietf-cose-msg}} with the following fields and values:

* Headers:
  - protected:
    + alg: AEAD
  - unprotected:
    + nonces\*: nonce-array
* ciphertext: encrypted plaintext as defined below

The plaintext for message\_3 SHALL have the COSE\_Sign1 structure {{I-D.ietf-cose-msg}} with the following fields and values:

* Headers
  - protected
    + alg: SIG
    + MAC-alg\*: MAC
  - Unprotected:
    + kid: ID_U (if raw public keys are used) or
    + x5c\*: C_U (if certificates are used)
* detached payload: as defined below
* signature: computed as in Section 4.4 of {{I-D.ietf-cose-msg}}

The payload for COSE_Sign1 SHALL have the COSE\_MAC0 structure {{I-D.ietf-cose-msg}} with the following fields and values:

* Headers
  - protected
    + alg: MAC (same value as MAC-alg in COSE_Sign1 structure above)
  - unprotected: empty
* payload: payl_3_rpk (resp. payl_3_cert) as defined below if raw public keys (resp. certificates) are used
* tag

~~~~~~~~~~~ CDDL
payl_3_rpk = [
  N_V : bstr,
  N_U : bstr,
  E_U : COSE_Key,
  ALG_U : alg_arr,
  ID_V : bstr
  ]
~~~~~~~~~~~

~~~~~~~~~~~ CDDL
payl_3_cert = [
  N_V : bstr,
  N_U : bstr,
  E_U : COSE_Key,
  ALG_U : alg_arr,
  C_V : bstr
  ]
~~~~~~~~~~~

## Key Derivation with Asymmetric Keys ## {#key-der-asym}

It is described in this section how the keys for encryption (K\_UE, K\_VE) and MAC (K\_UM, K\_VM) are derived.

Party U and Party V SHALL derive K\_UE, K\_VE, K\_UM, and K\_VM from the information available in message\_1 and message\_2 through the key exchange, as described in this section. 

The key derivation is identical to Section 11.1 of {{I-D.ietf-cose-msg}}, using HKDF {{RFC5869}} agreed as part of the ECDH-ES w/ HKDF negociation during the message exchange.

* the secret SHALL be the ECDH shared secret as defined in Section 12.4.1 of {{I-D.ietf-cose-msg}}, where the computed secret is specified in section 5.7.1.2 of {{SP-800-56a}}
* the salt SHALL be the concatenation of N\_U and N\_V.
* the length SHALL be the length of the key, depending on the algorithm used.
* the context information SHALL be the serialized COSE\_KDF\_Context defined in the next paragraph.
* the PRF SHALL be the one indicated in HKDF using the Table 18 of {{I-D.ietf-cose-msg}} (in our examples, -27 corresponds to HMAC with SHA-256)

The context information COSE\_KDF\_Context is defined as follows:

* AlgorithmID SHALL be the algorithm for which the key material will be derived. It's value is AEAD (to derive K\_UE and K\_VE) or MAC (to derive K\_UM and K\_VM)
* PartyUInfo SHALL contain:
  - nonce SHALL be equal to N\_U
* PartyVInfo SHALL contain:
  - nonce SHALL be equal to N\_V
* SuppPubInfo SHALL contain:
  - KeyDataLength SHALL be equal to 'length'
  - protected SHALL be a zero length bstr
  - other SHALL contain the HMAC (as defined by the agreed HKDF) of the concatenation of message\_1, the COSE Headers of COSE_Encrypt (message\_2) and the string "PartyU" (resp. "PartyV") to derive K\_UE or K\_UM (resp. K\_VE or K\_VM)
* SuppPrivInfo SHALL be empty

The key derivation is done using the following context information COSE\_KDF\_Context for asymmetric keys:

~~~~~~~~~~~
   COSE_KDF_Context = [
       AlgorithmID : AEAD / MAC,
       PartyUInfo : [ PartyInfo_U ],
       PartyVInfo : [ PartyInfo_V ],
       SuppPubInfo : [
           keyDataLength : uint,      ; length
           protected : bstr,          ; zero length bstr
           other : bstr               ; Hash(message_1 || 
                                          COSE Headers of COSE_Encrypt 
                                          (message_2) ||
                                          "PartyU"/"PartyV")
       ]
   ]
~~~~~~~~~~~

~~~~~~~~~~~
  PartyInfo_U = (
    nonce : N_U
    )

  PartyInfo_V = (
    nonce : N_V
    )
~~~~~~~~~~~

Using the different combination of these parameters creates the four keys K\_UE, K\_UM, K\_VE and K\_VM when raw public keys or certificates are used.

For example, to derive K\_UE when asymmetric keys are used, the context MUST include:

* AEAD as Algorithm ID
* "PartyU" as the chosen string in SuppPubInfo other

## Message Processing ## {#mess-proc}

Party U and V are assumed to have pre-established credentials as described in {{asym-keys-intro}}. 

### U -> message_1 ###

Party U processes message\_1 for party V as follows:

*  Party U SHALL generate a fresh ephemeral ECDH key pair as specified in Section 5 of {{SP-800-56a}} using ECC domain parameters of a curve complying with security policies for communicating with party V.
  -  The ephemeral public key, E\_U, SHALL be formatted as a COSE\_key as specified in {{COSE_key}}.
*  Party U SHALL generate a pseudo-random 64-bits nonce N\_U and store it for the length of the protocol, for future verifications.
*  Party U SHALL set the proposed algorithms for communicating with party V.
*  Party U SHALL format message_1 as specified in {{asym-m1}}.
*  Party U sends message\_1 to party V. 

### message_1 -> V ###

Party V processes the received message\_1 as follows:

* Party V SHALL verify that the nonce has not been received before. If the verification fails, the message MUST be discarded. Otherwise, Party V SHALL store a representation of the nonce for future verifications.
* Party V SHALL select a set of algorithms (AEAD, SIG, MAC, and ECDH-ES) compliant with its security policy for communicating with U. If no compliant algorithm was proposed by Party U, Party V SHALL stop processing the message and MAY respond with an error, indicating that no common algorithm could be found.

### message_2 <- V ###

Party V composes message\_2 for party U as follows:

* Party V SHALL generate a fresh ephemeral ECDH key pair as specified in Section 5 of {{SP-800-56a}} using same curve/ECC domain parameters as used by party U. 
  -  The ephemeral public key, E\_V, SHALL be formatted as a COSE\_key as specified in {{COSE_key}}.
*  Party V SHALL generate a pseudo-random 64-bits nonce N\_V and store it for the length of the protocol, for future verifications.
*  Party V SHALL derive K\_UE, K\_VE, K\_UM and K\_VM as defined in {{key-der-asym}}.
*  Party V SHALL format message_2 as specified in {{asym-m2}}:
  -  COSE\_MAC0 is computed as defined in section 6.3 of {{I-D.ietf-cose-msg}}, with key K\_VM and algorithm MAC;
  -  COSE\_Sign1 is computed as defined in section 4.4 of {{I-D.ietf-cose-msg}}, using the private key of Party V and algorithm SIG;
  -  COSE\_Encrypt is computed as defined in section 5.3 of {{I-D.ietf-cose-msg}}, with key K\_VE and algorithm AEAD.
  -  Note that the COSE_Sign1 payload is detached (as defined in section 4.1 of {{I-D.ietf-cose-msg}}).
  -  Note that in case of certificates, the certificate of Party V, C\_V, is sent in place of ID_V 
*  Party V sends message\_2 to party U.

### U <- message_2 ###

Party U processes the received message\_2 as follows:

* Party U SHALL verify than the received N\_U is identical to the saved nonce N\_U. 
* Party U SHALL verify that the nonce has not been received before. If the verification fails, the message MUST be discarded. Otherwise, Party U SHALL store a representation of the nonce for future verifications.
* Party U SHALL derive K\_UE, K\_VE, K\_UM and K\_VM as defined in {{key-der-asym}}.
* Party U SHALL verify message_2:
  - COSE\_Encrypt is decrypted and verified as defined in section 5.3 of {{I-D.ietf-cose-msg}}, with key K\_VE.
  - If the message contains a certificate, party U SHALL verify the certificate using the pre-established trust anchor and the revokation verification policies relevant for party U. If the verification fails the message is discarded.
  - COSE\_MAC0 is re-constructed as defined in section 6.3 of {{I-D.ietf-cose-msg}}, with key K\_VM. The result is inserted as payload of the received COSE\_Sign1 (which was sent with detached payload); 
  - COSE\_Sign1 is verified as defined in section 4.4 of {{I-D.ietf-cose-msg}}, using the public key of Party V;
  - Note that Party U SHALL verify that the algorithms used in message_2 are taken from the set of proposed algorithms in message\_1, else stop processing the message.
* If the verification of message_2 fails, the message MUST be discarded and Party U SHALL discontinue the protocol.

### U -> message_3 ###

Party U composes message\_3 for party V as follows:

*  Party U SHALL format message_3 as specified in {{asym-m3}}:
  -  COSE\_MAC0 is computed as defined in section 6.3 of {{I-D.ietf-cose-msg}}, with key K\_UM and algorithm MAC;
  -  COSE\_Sign1 is computed as defined in section 4.4 of {{I-D.ietf-cose-msg}}, using the private key of Party U and algorithm SIG;
  -  COSE\_Encrypt0 is computed as defined in section 5.3 of {{I-D.ietf-cose-msg}}, with key K\_UE and algorithm AEAD.
  -  Note that the COSE_Sign1 payload is detached (as defined in section 4.1 of {{I-D.ietf-cose-msg}}).
  -  Note that in case of certificates, the certificate of Party U, C\_U, is sent in place of ID_U 
*  Party U sends message\_3 to party V.

### message_3 -> V ###

Party V processes the received message\_3 as follows:

* Party V SHALL verify than the received N\_U and N\_V are identical to the saved nonces N\_U and N\_V. If the verification fails, the message MUST be discarded.
* Party V SHALL verify message_3:
  - COSE\_Encrypt0 is decrypted and verified as defined in section 5.3 of {{I-D.ietf-cose-msg}}, with key K\_UE.
  - If the message contains a certificate, party V SHALL verify the certificate using the pre-established trust anchor and the revokation verification policies relevant for party U. If the verification fails the message is discarded.
  - COSE\_MAC0 is re-constructed as defined in section 6.3 of {{I-D.ietf-cose-msg}}, with key K\_UM. The result is inserted as payload of the received COSE\_Sign1 (which was sent with detached payload); 
  - COSE\_Sign1 is verified as defined in section 4.4 of {{I-D.ietf-cose-msg}}, using the public key of Party U;
  - Note that Party V SHALL verify that the set of algorithms sent in message_3 is the same as sent in message\_1, else stop processing the message.
* If the verification of message_3 fails, the message MUST be discarded and Party V SHALL discontinue the protocol.

# Symmetric Keys # {#PSK}

In this section we assume that the protocol messages are authenticated with pre-shared symmetric keys.

Parties U and V are assumed to have a pre-shared uniformly random key, PSK. The value of the key identifier (kid_psk) SHALL be unique for U and V.

The protocol is based on the basic SIGMA protocol ({{protocol}}), but the signatures Sig(U; . ), Sig(V; . ) are replaced with message authentication codes MAC(K_UMP; . ), MAC(K_VMP; . ), respectively. K_UMP and K_VMP are computationally independent keys, associated to U and V, respectively, and derived from PSK. Also, party U needs to send the key identifier in message\_1 to indicate what PSK that V should use (kid\_psk). In this case identity protection is achieved by anonymizing the kid ({{sec-cons}}).

 For a specific pre-shared key (and corresponding kid-psk):

* Party U SHALL be identified by ID_U. 
* Party V SHALL be identified by ID_V.

Since kid-psk is unique, only one additional pre-established bit is needed to identify the parties. 

As in the asymmetric case, some additional protocol elements are added to the final protocol:

* Explicit freshness nonces/session identifiers N_U, N_V chosen freshly and anew with each session by U and V, respectively
* Computationally independent keys K_UM, K_VM derived from the DH-shared secret and used for different directions and operations.
* Negotiation of algorithms: 
   * MAC-algorithm used in the protocol
   * HKDF with hash algorithm used in the key derivation
   * AEAD-algorithm used to protect subsequent traffic
   * U proposes one or more algorithms (Alg_U).
   * V decides and responds with selected algorithms (Alg_V).


~~~~~~~~~~~
     
Party U                                                     Party V
|                                                                 |
|                        N_U, E_U, Kid, Alg_U                     |
+---------------------------------------------------------------> |
|                             message_1                           |
|                                                                 | 
|                                                                 | 
|  N_U, N_V, E_V, Kid, ID_V, Alg_V, Mac(K_VMP; Mac(K_VM; prot_2)) |  
| <---------------------------------------------------------------+
|                             message_2                           |
|                                                                 |
|                                                                 | 
|      N_U, N_V, Kid, ID_U, Mac(K_UMP; Mac(K_UM; prot_3))         |
+---------------------------------------------------------------> |
|                             message_3                           |  
|                                                                 |

where prot_2 = N_U, N_V, E_V, Kid, ID_V, Alg_V
and   prot_3 = N_V, N_U, E_U, Kid, ID_U, Alg_U
~~~~~~~~~~~
{: #mess-ex3 title="EDHOC with symmetric keys. "}
{: artwork-align="center"}


## Message Formatting using COSE ## {#sym}

This section details the format for the objects used. Examples are provided for each object in {{examples}}.

Note that \* identifies fields that do not exist in COSE structures ({{I-D.ietf-cose-msg}}), and are thus defined in this document.

### Message 1 ## {#m1-psk}

This section defines the formatting of message_1.

message_1 is a CBOR map object containing:

* N_U: nonce
* E_U: the ephemeral public key of Party U
* KID: identifier of the pre-shared key (it's value is kid_psk)
* ECDH_arr: an array of proposed ECDH-ES w/ HKDF algorithms
* AEAD_arr: an array of proposed AEAD algorithms
* MAC_arr: an array of proposed MAC algorithms

~~~~~~~~~~~ CDDL
message_1_a = {
  N_U : bstr,
  E_U : COSE_Key,
  KID: bstr,
  ALG_U : alg_arr_a
  }

alg_arr_a = [
  ECDH_arr : alg_array_a, 
  AEAD_arr : alg_array_a,
  MAC_arr : alg_array_a
  ]

alg_array_a = [
  + alg : bstr/int
  ]
~~~~~~~~~~~

### Message 2 ### {#m2-psk}

In case of pre-shared key, message\_2 SHALL have the COSE\_MAC structure {{I-D.ietf-cose-msg}} with the following fields and values:

* Headers:
  - protected:
    + alg: MAC
  - unprotected:
    + nonces\*: nonce-array
    + kid: kid_psk
    + sid\*: ID\_V
    + AEAD-alg\*: AEAD
* detached payload: defined below
* tag: calculated as in section 6.3 of {{I-D.ietf-cose-msg}}
* recipient: 
  - Headers:
    + protected: ECDH-ES + HKDF algorithm chosen by Party V from the set of proposed algorithms ECDH_arr (table 18 in {{I-D.ietf-cose-msg}})
    + unprotected: 
      * E\_U: COSE\_Key
    + ciphertext: empty

~~~~~~~~~~~
nonce-array = [
  N_U: bstr,
  N_V: bstr
  ]
~~~~~~~~~~~

The payload for message\_2 SHALL have the COSE\_MAC0 structure {{I-D.ietf-cose-msg}} with the following fields and values:

* Headers
  - protected
    + alg: MAC (same value as MAC in COSE_MAC structure above)
  - unprotected: empty
* payload: payl_2_psk as defined below
* tag: calculated as in section 6.3 of {{I-D.ietf-cose-msg}}

~~~~~~~~~~~ CDDL
payl_2_psk = [
  N_U: bstr,
  N_V: bstr,
  E_V: COSE_Key,
  KID: bstr,        ; has value kid_psk
  ID_V: bstr,
  ALG_V: alg_array  ; [ECDH, AEAD, MAC]
  ]
~~~~~~~~~~~

Note that ALG\_V contains the set of chosen algorithms, in order ECDH, AEAD, MAC, selected from the list provided in ALG\_U.

### Message 3 ### {#m3-psk}

In case of symmetric keys, message\_3 SHALL have the COSE\_MAC0 structure {{I-D.ietf-cose-msg}} with the following fields and values:

* Headers:
  - protected:
    + alg: MAC
  - unprotected:
    + nonces\*: nonce-array
    + kid: kid_psk
    + sid\*: ID\_U
* detached payload: defined below
* tag: calculated as in section 6.3 of {{I-D.ietf-cose-msg}}

The payload for message\_3 SHALL have the COSE\_MAC0 structure {{I-D.ietf-cose-msg}} with the following fields and values:

* Headers
  - protected
    + alg: MAC (same value as in COSE_MAC0 structure above)
  - unprotected: empty
* payload: payl_3_psk as defined below
* tag: calculated as in section 6.3 of {{I-D.ietf-cose-msg}}

~~~~~~~~~~~ CDDL
payl_3_psk = [
  N_V: bstr,
  N_U: bstr,
  E_U: COSE_Key,
  KID: bstr,      ; has value kid_psk
  ID_V: bstr,
  ALG_U : alg_arr
  ]
~~~~~~~~~~~

## Key Derivation with Symmetric Keys ## {#key-der-sym}

It is described in this section how the keys for MAC (K\_UM, K\_VM, K\_UMP, K\_VMP) are derived.

Party U and Party V SHALL derive K\_UM, K\_VM, K\_UMP and K\_VMP from the information available in message\_1 and message\_2 through the key exchange, as described in this section. 

The key derivation is identical to {{key-der-asym}}, with 3 differences:

* to derive K\_UM and K\_VM, the secret SHALL be the ECDH shared secret as defined in Section 12.4.1 of {{I-D.ietf-cose-msg}}, where the computed secret is specified in section 5.7.1.2 of {{SP-800-56a}}
* to derive K\_UMP and K\_VMP, the secret SHALL be the pre-shared key
* The COSE\_KDF\_Context SHALL be the serialized COSE\_KDF\_Context defined in the next paragraph.

The context information COSE\_KDF\_Context is defined as follows:

* AlgorithmID SHALL be the algorithm for which the key material will be derived. It's value is MAC.
* PartyUInfo SHALL contain:
  - nonce SHALL be equal to N\_U
* PartyVInfo SHALL contain:
  - nonce SHALL be equal to N\_V
  - identity SHALL be equal to ID\_V
* SuppPubInfo SHALL contain:
  - KeyDataLength SHALL be equal to 'length'
  - protected SHALL be a zero length bstr
  - other SHALL contain the HMAC (as defined by the agreed HKDF) of the concatenation of message\_1, the COSE Headers of message\_2 and the string "PartyU" (resp. "PartyV") to derive K\_UM or K\_UMP (resp. K\_VM or K\_VMP)
* SuppPrivInfo SHALL be empty

The key derivation is done using the following context information COSE\_KDF\_Context for symmetric keys:

~~~~~~~~~~~
   COSE_KDF_Context = [
       AlgorithmID : MAC,
       PartyUInfo : [ PartyInfo_U_psk ],
       PartyVInfo : [ PartyInfo_V_psk ],
       SuppPubInfo : [
           keyDataLength : uint,      ; length
           protected : bstr,          ; zero length bstr
           other : bstr               ; Hash(message_1 || 
                                          COSE Headers of COSE_MAC
                                          (message_2) ||
                                          "PartyU"/"PartyV")
       ]
   ]
~~~~~~~~~~~

~~~~~~~~~~~
  PartyInfo_U_psk = (
    nonce : N_U
    )

  PartyInfo_V_psk = (
    nonce : N_V
    identity: ID_V
    )
~~~~~~~~~~~

In practice, the difference in deriving K\_UM or K\_VM is in the SuppPubInfo string: to derive K\_UM the context MUST include "PartyU", while to derive K\_VM the context MUST include "PartyV".

## Message Processing ## {#mess-proc-sym}

Party U and V are assumed to have pre-established credentials as previously described in {{PSK}}. 

### U -> message_1 ###

Party U processes message\_1 for party V as follows:

*  Party U SHALL generate a fresh ephemeral ECDH key pair as specified in Section 5 of {{SP-800-56a}} using ECC domain parameters of a curve complying with security policies for communicating with party V.
  -  The ephemeral public key, E\_U, SHALL be formatted as a COSE\_key as specified in {{COSE_key}}.
*  Party U SHALL generate a pseudo-random 64-bits nonce N\_U and store it for the length of the protocol, for future verifications.
*  Party U SHALL set the proposed algorithms for communicating with party V.
*  Party U SHALL format message_1 as specified in {{m1-psk}}.
*  Party U sends message\_1 to party V. 

### message_1 -> V ###

Party V processes the received message\_1 as follows:

* Party V SHALL verify that the nonce has not been received before. If the verification fails, the message MUST be discarded. Otherwise, Party V SHALL store a representation of the nonce for future verifications.
* Party V SHALL select a set of algorithms (AEAD, MAC, and ECDH-ES) compliant with its security policy. If no compliant algorithm was proposed by Party U, Party V SHALL stop processing the message and MAY respond with an error, indicating that no common algorithm could be found.

### message_2 <- V ###

Party V composes message\_2 for party U as follows:

* Party V SHALL generate a fresh ephemeral ECDH key pair as specified in Section 5 of {{SP-800-56a}} using same curve/ECC domain parameters as used by party U. 
  -  The ephemeral public key, E\_V, SHALL be formatted as a COSE\_key as specified in {{COSE_key}}.
*  Party V SHALL generate a pseudo-random 64-bits nonce N\_V and store it for the length of the protocol, for future verifications.
*  Party V SHALL derive K\_UM, K\_VM, K\_UMP and K\_VMP as defined in {{key-der-sym}}.
*  Party V SHALL format message_2 as specified in {{m2-psk}}:
  -  COSE\_MAC0 is computed as defined in section 6.3 of {{I-D.ietf-cose-msg}}, with key K\_VM and algorithm MAC;
  -  COSE\_MAC is computed as defined in section 6.3 of {{I-D.ietf-cose-msg}}, with key K\_VMP and algorithm MAC.
  -  Note that the COSE_MAC payload is detached (as defined in section 6.1 of {{I-D.ietf-cose-msg}}).
*  Party V sends message\_2 to party U.

### U <- message_2 ###

Party U processes the received message\_2 as follows:

* Party U SHALL verify than the received N\_U is identical to the saved nonce N\_U. 
* Party U SHALL verify that the nonce has not been received before. If the verification fails, the message MUST be discarded. Otherwise, Party U SHALL store a representation of the nonce for future verifications.
* Party U SHALL derive K\_UM, K\_VM, K\_UMP and K\_VMP as defined in {{key-der-sym}}.
* Party U SHALL verify message_2:
  - COSE\_MAC0 is re-constructed as defined in section 6.3 of {{I-D.ietf-cose-msg}}, with key K\_VM. The result is inserted as payload of the received COSE\_MAC (which was sent with detached payload); 
  - COSE\_MAC is verified as defined in section 6.3 of {{I-D.ietf-cose-msg}}, with key K\_VMP and algorithm MAC;
  - Note that Party U SHALL verify that the MAC algorithm used and the AEAD algorithm sent in message_2 are taken from the set of proposed algorithms in message\_1, else stop processing the message.
* If the verification of message_2 fails, the message MUST be discarded and Party U SHALL discontinue the protocol.

### U -> message_3 ###

Party U composes message\_3 for party V as follows:

*  Party U SHALL format message_3 as specified in {{m3-psk}}:
  -  COSE\_MAC0 (containing payl\_3\_psk) is computed as defined in section 6.3 of {{I-D.ietf-cose-msg}}, with key K\_UM and algorithm MAC;
  -  COSE\_MAC0 is computed as defined in section 6.3 of {{I-D.ietf-cose-msg}}, with key K\_UMP and algorithm MAC.
  -  Note that the second COSE_MAC0 payload is detached (as defined in section 6.1 of {{I-D.ietf-cose-msg}}).
*  Party U sends message\_3 to party V.

### message_3 -> V ###

Party V processes the received message\_3 as follows:

* Party V SHALL verify than the received N\_U and N\_V are identical to the saved nonces N\_U and N\_V. If the verification fails, the message MUST be discarded.
* Party V SHALL verify message_3:
  - COSE\_MAC0 (containing payl\_3\_psk) is re-constructed as defined in section 6.3 of {{I-D.ietf-cose-msg}}, with key K\_UM. The result is inserted as payload of the received COSE\_MAC0 (which was sent with detached payload); 
  - COSE\_MAC0 is verified as defined in section 6.3 of {{I-D.ietf-cose-msg}}, with key K\_UMP and algorithm MAC;
  - Note that by verifying message\_3, Party V ensures that message\_1 was not modified in transit.
* If the verification of message_3 fails, the message MUST be discarded and Party V SHALL discontinue the protocol.

# Derive Traffic Secret # {#final-key-der}

It is described in this section how the traffic secret for further communication is derived, based on the messages exchanged.

Party U and Party V SHALL derive the traffic secret (base\_key) from the information available in message\_1, message\_2 and message\_3 through the key exchange, as described in this section. 

The key derivation is identical to Section 11.1 of {{I-D.ietf-cose-msg}}, using HKDF {{RFC5869}} agreed as part of the ECDH-ES w/ HKDF negotiation during the message exchange.

* the secret SHALL be the ECDH shared secret as defined in Section 12.4.1 of {{I-D.ietf-cose-msg}}, where the computed secret is specified in section 5.7.1.2 of {{SP-800-56a}}
* the salt SHALL be the concatenation of N\_U and N\_V.
* the length SHALL be the length of the key, depending on the AEAD algorithm with which the base_key will be used.
* the context information SHALL be the serialized COSE\_KDF\_Context defined in the next paragraph.
* the PRF SHALL be the one indicated in HKDF using the Table 18 of {{I-D.ietf-cose-msg}} (in our examples, -27 corresponds to HMAC with SHA-256)

The context information COSE\_KDF\_Context is defined as follows:

* AlgorithmID SHALL be the AEAD algorithm for which the key material will be derived.
* PartyUInfo SHALL contain:
  - nonce SHALL be equal to N\_U
  - identity SHALL be ID\_U (resp.  C\_U) if raw public keys (resp. certificates) are used
* PartyVInfo SHALL contain:
  - nonce SHALL be equal to N\_V
  - identity SHALL be ID\_V (resp.  C\_V) if raw public keys (resp. certificates) are used
* SuppPubInfo SHALL contain:
  - KeyDataLength SHALL be equal to 'length'
  - protected SHALL be a zero length bstr
  - other SHALL contain the HMAC (as defined by the agreed HKDF) of the concatenation of message\_1, message\_2 and message\_3.
* SuppPrivInfo SHALL be empty

The key derivation is done using the following context information COSE\_KDF\_Context:

~~~~~~~~~~~
   COSE_KDF_Context = [
       AlgorithmID : AEAD,
       PartyUInfo : [ PartyInfo_U ],
       PartyVInfo : [ PartyInfo_V ],
       SuppPubInfo : [
           keyDataLength : uint,      ; length
           protected : bstr,          ; zero length bstr
           other : bstr               ; Hash(message_1 || 
                                             message_2 ||
                                             message_3)
       ]
   ]
~~~~~~~~~~~

~~~~~~~~~~~
  PartyInfo_U = (
    nonce : N_U,
    identity: ID_U / C_U
    )

  PartyInfo_V = (
    nonce : N_V,
    identity: ID_V / C_V
    )
~~~~~~~~~~~

# Security Considerations # {#sec-cons}

The referenced processing instructions in {{SP-800-56a}} must be complied with, including deleting the intermediate computed values along with any ephemeral ECDH secrets after the key derivation is completed.

The choice of key length used in the different algorithms needs to be harmonized, so that right security level is maintained throughout the calculations.

Note that, depending on the use, the key established through the EDHOC protocol will need to be renewed, in which case the communicating parties need to run the protocol again.

In case of symmetric keys, the key identifier for the pre-shared secret identifies one party to the other. The kid may reveal information about the communicating parties to others. The communicating parties may protect against this by anonymizing the kid either only initially or between each run of the protocol.

# Privacy Considerations #

TODO


# IANA Considerations # {#iana}



# Acknowledgments #

The authors wants to thank Ilari Liusvaara, Jim Schaad and Ludwig Seitz for reviewing previous versions of the draft.

--- back

# Examples {#examples}

In this section we give examples of messages used in the protocol for the pre-shared key case and for the raw public keys case. Note that the message size is not optimized, for example the labels could be registered and thereby reducing the overhead.

## ECDH Public Key ## 

An example of COSE_Key structure, representing an ECDH public key, is given in {{ex-cose-key}}, using CBOR's diagnostic
notation. 

~~~~~~~~~~~
   / ephemeral / -1:{
               / kty / 1:2,
               / crv / -1:1,
               / x / -2:h'98f50a4ff6c05861c8860d13a638ea56c3f5ad7590b
               bfbf054e1c7b4d91d6280',
               / y / -3:true
             }
~~~~~~~~~~~
{: #ex-cose-key title="Example of an ECDH public key formatted as a COSE_Key" }

The equivalent CBOR encoding is:
h'a120a40102200121582098f50a4ff6c05861c8860d13a638ea56c3f5ad7590bbfbf054e1c7b4d91d628022f5',
which has a size of 44 bytes.

## Example with Asymmetric Keys (RPK) ##

In this example, the identifier of V is 4 bytes.

### Message 1 ## {#ex-rpk1}

An example of COSE encoding for message\_1 is given in {{message1}}, using CBOR's diagnostic notation.

The message\_1 is:

~~~~~~~~~~~ CBORdiag
{
  'N_U':h'5598a57b47db7f2c',
  'E_U':h'a120a40102200121582098f50a4ff6c05861c8860d13a638ea56c3f5ad7
  590bbfbf054e1c7b4d91d628022f5', / COSE_Key E_U { /
    / ephemeral -1:{ /
    / kty 1:2, /
    / crv -1:1, /
    / x -2:h'98f50a4ff6c05861c8860d13a638ea56c3f5ad7590bbfb /
    / f054e1c7b4d91d6280', /
    / y -3:true /
    / } /
  / } /
  'ALG_U' : h'8481381a810c81268104' 
    / [ /
      / [ -27 ], ECDH-SS + HKDF-256 /
      / [ 12 ],  AES-CCM-64-64-128 /
      / [ -7 ],  ES256 /
      / [ 4 ]    HMAC 256-64 /
    / ] /  
}
~~~~~~~~~~~
{: #message1 title="Example of message_1"} 

The equivalent CBOR encoding of the message_1 is:
h'a3434e5f55485598a57b47db7f2c43455f55582ca120a40102200121582098f50a4ff6c05861c8860d13a638ea56c3f5ad7590bbfbf054e1c7b4d91d628022f545414c475f554a8481381a810c81268104',
which has a size of 81 bytes.
Note that by registering the labels 'N\_U', 'E\_U' and 'ALG\_U' to unsigned values the size can be reduced to 70 bytes.

### Message 2 ## {#ex-rpk2}

An example of COSE encoding for message\_2 is given in {{message2}} using CBOR's diagnostic notation.

The payload of the COSE_MAC0 is:

~~~~~~~~~~~ CBORdiag

[
  h'7ce4cae9c9698bac', / N_V /
  h'5598a57b47db7f2c', / N_U /
  h'a120a501022001215820acbee6672a28340affce41c721901eb
  d7868231bd1d86e41888a07822214050022f5', / COSE_Key E_V { /
    / ephemeral -1:{ /
    / kty 1:2, /
    / crv -1:1, /
    / x -2:h'acbee6672a28340affce41c721901ebd7868231bd1d /
    / 86e41888a078222140500', /
    / y -3:true /
    / } /
  / } / 
  h'0f4907e1' / ID_V /
]

~~~~~~~~~~~

The equivalent CBOR encoding of the payload of the COSE_MAC0 is:
h'84485598a57b47db7f2c487ce4cae9c9698bac5832a120a401022001215820acbee6672a28340affce41c721901ebd7868231bd1d86e41888a07822214050022f5440f4907e1',
which has a size of 70 bytes. Note that these bytes are not sent in the message.

The COSE_MAC0 is:

~~~~~~~~~~~ CBORdiag

[
  h'a10104', / protected : {01:04} /             
  {}, / unprotected /
  h'84485598a57b47db7f2c487ce4cae9c9698bac5832a120a401022001215820acb
  ee6672a28340affce41c721901ebd7868231bd1d86e41888a07822214050022f544
  0f4907e1', / payload /
  MAC / truncated 8-byte MAC /
]

~~~~~~~~~~~

The equivalent CBOR encoding of the COSE_MAC0 is:
h'8443a10104a0584684485598a57b47db7f2c487ce4cae9c9698bac5832a120a401022001215820acbee6672a28340affce41c721901ebd7868231bd1d86e41888a07822214050022f5440f4907e148'\|\|MAC,
which has a size of 87 bytes. Note that these bytes are not sent in the message.

The COSE_Sign1 is:

~~~~~~~~~~~ CBORdiag

[
  h'a20126474d41432d616c6704', / protected : {1:-7, 'MAC-alg':04} /
  {04:h'00'}, / unprotected /
  h'', / detached payload /
  SIG  / 64-byte signature /
]
~~~~~~~~~~~

The equivalent CBOR encoding of the COSE_Sign1 is:
h'844ca20126474d41432d616c6704a1044100405840'\|\|SIG,
which has a size of 85 bytes.
Note that by registering the label 'MAC-alg' to unsigned values the size can be reduced to 78 bytes.

The COSE_Encrypt is:

~~~~~~~~~~~ CBORdiag
[
  h'a1010c', / protected : {1:12} /
  {'nonces':h'82485598a57b47db7f2c487ce4cae9c9698bac'},/unprotected /
    / [ /
      /  h'5598a57b47db7f2c', N_U /
      /  h'7ce4cae9c9698bac' N_V /
    / ] /
  CIPH+TAG, / 85 bytes-cipher text + truncated 8-byte TAG /
  [ / recipients /
    [
      h'a101381a' / protected : {1:-27} / , 
      { / unprotected /
        'E_V':h'a120a401022001215820a
        cbee6672a28340affce41c721901ebd7868231bd1
        d86e41888a07822214050022f5' / COSE_Key E_V { /
          / ephemeral -1:{ /
          / kty 1:2, /
          / crv -1:1, /
          / x -2:h'acbee6672a28340affce41c721901ebd7868231bd1d /
          / 86e41888a078222140500', /
          / y -3:true /
          / } /
        / } /
      }, 
      h'' / ciphertext /
    ]
  ]
]
~~~~~~~~~~~
{: #message2 title="Example of message_2"} 

The equivalent CBOR encoding of the COSE_Encrypt is:
h'8443a1010ca1466e6f6e6365735382485598a57b47db7f2c487ce4cae9c9698bac585b'\|\|CIPH+TAG\|\|h'818344a101381aa143455f565832a120a5010202442edb61f92001215820acbee6672a28340affce41c721901ebd7868231bd1d86e41888a07822214050022f540',
which has a size of 187 bytes.
Note that by registering the label 'MAC-alg' and 'E\_V' to unsigned values the size can be reduced to 177 bytes.

### Message 3 ## {#ex-rpk3}

An example of COSE encoding for message\_3 is given in {{message3}} using CBOR's diagnostic notation.

The payload of the COSE_MAC0 is:

~~~~~~~~~~~ CBORdiag

[
  h'7ce4cae9c9698bac', / N_V /
  h'5598a57b47db7f2c', / N_U /
  h'a120a40102200121582098f50a4ff6c05861c8860d13a638ea56c3f5ad7590bbf
  bf054e1c7b4d91d628022f5', / COSE_Key E_U /
  h'8481381a810c81268104', / ALG_U /
    / [ /
      / [ -27 ], ECDH-SS + HKDF-256 /
      / [ 12 ],  AES-CCM-64-64-128 /
      / [ -7 ],  ES256 /
      / [ 4 ]    HMAC 256-64 /
    / ] /
  h'0f4907e1' / ID_V /
]

~~~~~~~~~~~

The equivalent CBOR encoding of the payload of the COSE_MAC0 is:
h'85487ce4cae9c9698bac485598a57b47db7f2c582ca120a40102200121582098f50a4ff6c05861c8860d13a638ea56c3f5ad7590bbfbf054e1c7b4d91d628022f54a8481381a810c81268104440f4907e1',
which has a size of 81 bytes. Note that these bytes are not sent in the message.

The COSE_MAC0 is:

~~~~~~~~~~~ CBORdiag

[
  h'a10104', / protected : {01:04} /             
  {}, / unprotected /
  h'85487ce4cae9c9698bac485598a57b47db7f2c582ca120a40102200121582098f
  50a4ff6c05861c8860d13a638ea56c3f5ad7590bbfbf054e1c7b4d91d628022f54a
  8481381a810c81268104440f4907e1', / payload /
  MAC / truncated 8-byte MAC /
]

~~~~~~~~~~~

The equivalent CBOR encoding of the COSE_MAC0 is:
h'8443a10104a0585185487ce4cae9c9698bac485598a57b47db7f2c582ca120a40102200121582098f50a4ff6c05861c8860d13a638ea56c3f5ad7590bbfbf054e1c7b4d91d628022f54a8481381a810c81268104440f4907e148'\|\|MAC,
which has a size of 98 bytes. Note that these bytes are not sent in the message.

The COSE_Sign1 is:

~~~~~~~~~~~ CBORdiag

[
  h'a20126474d41432d616c6704', / protected : {1:-7, 'MAC-alg':4} /
  {04:h'0f4907e1'}, / unprotected /
  h'', / detached payload /
  SIG  / 64-byte signature /
]
~~~~~~~~~~~

The equivalent CBOR encoding of the COSE_Sign1 is:
h'844ca20126474d41432d616c6704a104440f4907e1405840'\|\|SIG,
which has a size of 88 bytes.
Note that by registering the label 'MAC-alg' to unsigned values the size can be reduced to 81 bytes.

The COSE_Encrypt0 is:

~~~~~~~~~~~ CBORdiag
[
  h'a1010c', / protected : {01:12} /
  {'nonces':h'82485598a57b47db7f2c487ce4cae9c9698bac'},/unprotected /
    / 'nonces':[ /
      /  h'5598a57b47db7f2c', N_U /
      /  h'7ce4cae9c9698bac' N_V /
    / ] /
  CIPH+TAG / 88 bytes-cipher text + truncated 8-byte TAG /
]
~~~~~~~~~~~
{: #message3 title="Example of message_3"} 

The equivalent CBOR encoding of the COSE_Encrypt0 is:
h'8343a1010ca1466e6f6e6365735382485598a57b47db7f2c487ce4cae9c9698bac5860'\|\|CIPH+TAG,
which has a size of 131 bytes.
Note that by registering the labels 'MAC-alg' and 'nonces' to unsigned values the size can be reduced to 118 bytes.

## Example with Symmetric Keys (PSK) ##

In this example, the identifiers of U and V are 4 bytes.

### Message 1 ## {#ex-psk1}

An example of COSE encoding for message\_1 is given in {{message1-psk}}, using CBOR's diagnostic notation.

The message\_1 is:

~~~~~~~~~~~ CBORdiag
{
  'N_U':h'5598a57b47db7f2c',
  'E_U':h'a120a40102200121582098f50a4ff6c05861c8860d13a638ea56c3f5ad7
  590bbfbf054e1c7b4d91d628022f5', / COSE_Key E_U { /
    / ephemeral -1:{ /
    / kty 1:2, /
    / crv -1:1, /
    / x -2:h'98f50a4ff6c05861c8860d13a638ea56c3f5ad7590bbfb /
    / f054e1c7b4d91d6280', /
    / y -3:true /
    / } /
  / } /
  'KID':h'e19648b5',
  'ALG_U':h'8381381a810c8104' 
    / [ /
      / [ -27 ], ECDH-SS + HKDF-256 /
      / [ 12 ],  AES-CCM-64-64-128 /
      / [ 4 ]    HMAC 256-64 /
    / ] /  
}
~~~~~~~~~~~
{: #message1-psk title="Example of message_1"} 

The equivalent CBOR encoding of the message_1 is:
h'a4434e5f55485598a57b47db7f2c43455f55582ca120a40102200121582098f50a4ff6c05861c8860d13a638ea56c3f5ad7590bbfbf054e1c7b4d91d628022f5434b494444e19648b545414c475f55488381381a810c8104',
which has a size of 88 bytes.
Note that by registering the labels 'N\_U', 'E\_U', 'KID' and 'ALG\_U' to unsigned values the size can be reduced to 74 bytes.

### Message 2 ## {#ex-psk2}

An example of COSE encoding for message\_2 is given in {{message2-psk}} using CBOR's diagnostic notation.

The payload of the COSE_MAC0 is:

~~~~~~~~~~~ CBORdiag

[
  h'5598a57b47db7f2c', / N_U /
  h'7ce4cae9c9698bac', / N_V /
  h'a120a401022001215820acbee6672a28340affce41c721901eb
  d7868231bd1d86e41888a07822214050022f5', / COSE_Key E_V { /
    / ephemeral -1:{ /
    / kty 1:2, /
    / crv -1:1, /
    / x -2:h'acbee6672a28340affce41c721901ebd7868231bd1d /
    / 86e41888a078222140500', /
    / y -3:true /
    / } /
  / } /
  h'e19648b5', / KID /
  h'0f4907e1', / ID_V /
  h'83381a0c04' / ALG_V /
    / [ /
      /-27 , ECDH-SS + HKDF-256 /
      / 12 , AES-CCM-64-64-128 /
      / 4    HMAC 256-64 /
    / ] /  
]

~~~~~~~~~~~

The equivalent CBOR encoding of the payload of the COSE_MAC0 is:
h'86485598a57b47db7f2c487ce4cae9c9698bac582ca120a401022001215820acbee6672a28340affce41c721901ebd7868231bd1d86e41888a07822214050022f544e19648b5440f4907e14583381a0c04',
which has a size of 81 bytes. Note that these bytes are not sent in the message.

The COSE_MAC0 is:

~~~~~~~~~~~ CBORdiag

[
  h'a10104', / protected : {01:04} /             
  {}, / unprotected /
  h'86485598a57b47db7f2c487ce4cae9c9698bac582ca120a401022001215820acb
  ee6672a28340affce41c721901ebd7868231bd1d86e41888a07822214050022f544
  e19648b5440f4907e14583381a0c04', / payload /
  MAC / truncated 8-byte MAC /
]

~~~~~~~~~~~

The equivalent CBOR encoding of the COSE_MAC0 is:
h'8443a10104a0585186485598a57b47db7f2c487ce4cae9c9698bac582ca120a401022001215820acbee6672a28340affce41c721901ebd7868231bd1d86e41888a07822214050022f544e19648b5440f4907e14583381a0c0448'\|\|MAC,
which has a size of 98 bytes. Note that these bytes are not sent in the message.

The COSE_MAC is:

~~~~~~~~~~~ CBORdiag

[
  h'a10104', / protected : {01:04} /
  { / unprotected /
    'nonces':h'82485598a57b47db7f2c487ce4cae9c9698bac', / 'nonces':[/
      /  h'5598a57b47db7f2c', N_U /
      /  h'7ce4cae9c9698bac' N_V /
      / ] /
      04:h'e19648b5', / KID /
      'sid':h'0f4907e1', / ID_V /
      'AEAD-alg': 12
    },
  h'', / detached payload /
  TAG, / 8-byte truncated tag /
  [ / recipients /
    [
      h'a101381a' / protected : {1:-27} / , 
      { / unprotected /
        'E_V':h'a120a401022001215820a
        cbee6672a28340affce41c721901ebd7868231bd1
        d86e41888a07822214050022f5' / COSE_Key E_V { /
          / ephemeral -1:{ /
          / kty 1:2, /
          / crv -1:1, /
          / x -2:h'acbee6672a28340affce41c721901ebd7868231bd1d /
          / 86e41888a078222140500', /
          / y -3:true /
          / } /
        / } /
      },
      h'' / ciphertext /
    ]
  ]
]
~~~~~~~~~~~
{: #message2-psk title="Example of message_2"} 

The equivalent CBOR encoding of the COSE_MAC is:

h'8543a10104a4466e6f6e6365735382485598a57b47db7f2c487ce4cae9c9698bac0444e19648b543736964440f4907e148414541442d616c670c4048\|\|MAC\|\|818344a101381aa143455f56582ca120a401022001215820acbee6672a28340affce41c721901ebd7868231bd1d86e41888a07822214050022f540',
which has a size of 127 bytes.
Note that by registering the labels 'nonces', 'sid', 'AEAD-alg' and 'E_V' to unsigned values the size can be reduced to 107 bytes.

### Message 3 ## {#ex-psk3}

An example of COSE encoding for message\_3 is given in {{message3-psk}} using CBOR's diagnostic notation.

The payload of the COSE_MAC0 is:

~~~~~~~~~~~ CBORdiag

[
  h'5598a57b47db7f2c', / N_U /
  h'7ce4cae9c9698bac', / N_V /
  h'a120a40102200121582098f50a4ff6c05861c8860d13a638ea56c
  3f5ad7590bbfbf054e1c7b4d91d628022f5', / COSE_Key E_U /
  h'e19648b5', / KID /
  h'0f4907e1', / ID_V /
  h'8381381a810c8104' 
    / [ /
      / [ -27 ], ECDH-SS + HKDF-256 /
      / [ 12 ],  AES-CCM-64-64-128 /
      / [ 4 ]    HMAC 256-64 /
    / ] / 
]

~~~~~~~~~~~

The equivalent CBOR encoding of the payload of the COSE_MAC0 is:
h'86485598a57b47db7f2c487ce4cae9c9698bac582fa120a40102200121582098f50a4ff6c05861c8860d13a638ea56c3f5ad7590bbfbf054e1c7b4d91d628022f544e19648b5440f4907e1488381381a810c8104',
which has a size of 84 bytes. Note that these bytes are not sent in the message.

The COSE_MAC0 is:

~~~~~~~~~~~ CBORdiag

[
  h'a10104', / protected : {01:04} /             
  {}, / unprotected /
  h'86485598a57b47db7f2c487ce4cae9c9698bac582fa120a401022001215
  82098f50a4ff6c05861c8860d13a638ea56c3f5ad7590bbfbf054e1c7b4d91d6280
  22f544e19648b5440f4907e1488381381a810c8104', / payload /
  MAC / truncated 8-byte MAC /
]

~~~~~~~~~~~

The equivalent CBOR encoding of the COSE_MAC0 is:
h'8444a10104a0585486485598a57b47db7f2c487ce4cae9c9698bac582fa120a40102200121582098f50a4ff6c05861c8860d13a638ea56c3f5ad7590bbfbf054e1c7b4d91d628022f544e19648b5440f4907e1488381381a810c810448'\|\|MAC,
which has a size of 101 bytes. Note that these bytes are not sent in the message.

The COSE_MAC0 is:

~~~~~~~~~~~ CBORdiag

[
  h'a10104', / protected : {01:04} /
  { / unprotected /  
    'nonces':h'82485598a57b47db7f2c487ce4cae9c9698bac', 
    / [ /
      /  h'5598a57b47db7f2c', N_U /
      /  h'7ce4cae9c9698bac' N_V /
      / ] /
    04:h'e19648b5', / KID /
    'sid':h'dbabb666' / ID_U /
  },
  h'', / detached payload /
  MAC / truncated 8-byte MAC /
]
~~~~~~~~~~~
{: #message3-psk title="Example of message_3"} 

The equivalent CBOR encoding of the COSE_MAC0 is:
h'8443a10104a3466e6f6e6365735382485598a57b47db7f2c487ce4cae9c9698bac0444e19648b54373696444dbabb6664048'\|\|MAC,
which has a size of 58 bytes.
Note that by registering the labels 'nonces' and 'sid' to unsigned values the size can be reduced to 49 bytes.

# Implementing EDHOC with CoAP and OSCOAP # {#app-a}

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

