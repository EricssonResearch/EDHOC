// EDHOC Test Vectors
// Copyright (c) 2020, Ericsson and John Mattsson <john.mattsson@ericsson.com>
//
// This software may be distributed under the terms of the 3-Clause BSD License.

#include <iostream>
#include <iomanip>
#include <vector>
#include <sodium.h>
#include "aes.h"

using namespace std;
using vec = vector<uint8_t>;

enum KeyType { sig, sdh, psk }; 
enum HeaderAttribute { kid = 4, x5bag = 32, x5chain = 33, x5t = 34, x5u = 35 }; 
enum Correlation { corr_none, corr_12, corr_23, corr_123 }; 
enum Suite { suite_0, suite_1 }; 

enum AuxData { aux_no, aux_yes }; // Only used in this program, not from EDHOC
enum SubjectName { sub_no, sub_yes }; // Only used in this program, not from EDHOC
enum Output { full, lite }; // Only used in this program, not from EDHOC

template <typename T> 
T operator+( T a, T b ) {
    a.insert( a.end(), b.begin(), b.end() );
    return a;
}

void syntax_error( string s ) {
    cout << "Syntax Error: " << s;
    exit(-1);
}

// print an int to cout
void print( string s, int i ) {
    cout << endl << dec << s << " (int)" << endl << i << endl;    
}

void print( string s, string s2 ) {
    cout << endl << s << " (text string)" << endl << "\"" << s2 << "\"" << endl;    
}

// print a vec to cout
void print( string s, vec v ) {
    cout << endl << dec << s << " (" << v.size() << " bytes)";
    if  ( v.size() )
        cout << endl;
    for ( int i = 1; i <= v.size(); i++ ) {
        cout << hex << setfill('0') << setw( 2 ) << (int)v[i-1] << " ";        
        if ( i % 24 == 0 && i < v.size() )
            cout << endl;
    }
    cout << endl;
}

// CBOR encodes an int in the range [-256, 65535]
vec cbor( int i ) {
    if ( i < -256 || i > 65535 )
        syntax_error( "cbor( int i )" );
    if ( i < 0 )
        if ( i < -24 )      return { 0x38, (uint8_t) -(i + 1) };
        else                return { (uint8_t) (31 - i) };
    else {
        if ( i < 24 )       return { (uint8_t) i };
        else if ( i < 256 ) return { 0x18, (uint8_t) i };
        else                return { 0x19, (uint8_t) (i >> 8), (uint8_t) (i & 0xFF) };
    }
}

// CBOR encodes a bstr
 vec cbor( vec v ) {
    vec out;
    if ( v.size() < 24 )
        out = { (uint8_t)( v.size() | 0x40 ) };
    else
        out = { 0x58, (uint8_t)v.size() };

    return out + v;
}

// CBOR encodes a tstr
vec cbor( string s ) {
    vec out;
    if ( s.size() < 24 )
        out = { (uint8_t)( s.size() | 0x60 ) };
    else
        out = { 0x78, (uint8_t)s.size() };
    
    return out + vec( s.begin(), s.end() );
}

// CBOR encodes a bstr_indentifier
 vec cbor_id( vec v ) {
    if ( v.size() == 1 )
        return cbor( v[0] - 24 );
    else
        return cbor( v );
}

// Tries to compress ID_CRED_x
 vec compress_id_cred( vec v ) {
    if ( v[0] == 0xA1 && v[1] == 0x04 )
        return cbor_id( vec( v.begin() + 3, v.end() ) );
    else
        return v;
}

vec hash_sha_256( vec m, int l = 32 ) {
    vec digest( crypto_hash_sha256_BYTES );
    crypto_hash_sha256( digest.data(), m.data(), m.size() );
    digest.resize( l );
    return digest;
}

vec hmac_sha_256( vec k, vec m ) {
    vec out( crypto_auth_hmacsha256_BYTES ); 
    crypto_auth_hmacsha256_state state;
    crypto_auth_hmacsha256_init( &state, k.data(), k.size() );
    crypto_auth_hmacsha256_update( &state, m.data(), m.size() );
    crypto_auth_hmacsha256_final( &state, out.data() );
    return out;
}

vec hkdf_extract_sha_256( vec salt, vec IKM ) {
    return hmac_sha_256( salt,  IKM ); // correct that salt is key
}

// TODO: This function should be checked against another implementation
vec hkdf_expand_sha_256( vec PRK, vec info, int L ) {
    vec out, T;
    for ( int i = 0; i <= L / 32; i++ ) {
        vec m = T + info + vec{ uint8_t( i + 1 ) };
        T = hmac_sha_256( PRK, m );
        out = out + T;
    }
    out.resize( L );
    return out;
}

// TODO: This function should be checked against another implementation
vec aes_ccm_16_64_128( vec K, vec N, vec P, vec A, int tag_len ) {
    if( A.size() > (42 * 16 - 2) )
        syntax_error( "aes_ccm_16_64_128()" );
    vec C( P.size() + tag_len );
    int r = aes_ccm_ae( K.data(), 16, N.data(), tag_len, P.data(), P.size(), A.data(), A.size(), C.data(), C.data() + P.size() );
    return C;
}

vec xor_encryption( vec K, vec P ) {
    for( int i = 0; i < P.size(); ++i )
        P[i] ^= K[i];
    return P;
}

// Creates the info parameter for HKDF
template <typename T> 
vec gen_info( T AlgorithmID, int keyDataLength, vec protect, vec other ) {
    return vec{ 0x84 }
        + cbor( AlgorithmID )
        + vec{ 0x83, 0xf6, 0xf6, 0xf6 }
        + vec{ 0x83, 0xf6, 0xf6, 0xf6 }
        + vec{ 0x83 } + cbor( keyDataLength ) + cbor( protect ) + cbor( other );
}

vec random_vector( int len ) {
    vec out( len );
    for( auto& i : out )
        i = rand();
    return out;
}

std::tuple< vec, vec > X25519_key_pair() {
    vec G_X( crypto_kx_PUBLICKEYBYTES );
    vec X( crypto_kx_SECRETKEYBYTES );
    vec seed = random_vector( crypto_kx_SEEDBYTES );
    crypto_kx_seed_keypair( G_X.data(), X.data(), seed.data() );
    return std::make_tuple( X, G_X );
}

// EDHOC uses RFC 8032 notation, libsodium uses the notation from the Ed25519 paper by Bernstein
// Libsodium seed = RFC 8032 sk
// Libsodium sk = pruned SHA-512(sk) in RFC 8032
std::tuple< vec, vec > Ed25519_key_pair() {
    vec PK( crypto_sign_PUBLICKEYBYTES );
    vec SK_libsodium( crypto_sign_SECRETKEYBYTES );
    vec SK = random_vector( crypto_sign_SEEDBYTES );
    crypto_sign_seed_keypair( PK.data(), SK_libsodium.data(), SK.data() );
    return std::make_tuple( SK, PK );
}

vec X25519( vec A, vec G_B ) {
    vec G_AB( crypto_scalarmult_BYTES );
    if ( crypto_scalarmult( G_AB.data(), A.data(), G_B.data() ) == -1 )
        syntax_error( "crypto_scalarmult()" );
    return G_AB;
}

vec Ed25519( vec SK, vec M ) {
    vec signature( crypto_sign_BYTES );
    vec PK( crypto_sign_PUBLICKEYBYTES );
    vec SK_libsodium( crypto_sign_SECRETKEYBYTES );
    crypto_sign_seed_keypair( PK.data(), SK_libsodium.data(), SK.data() );
    crypto_sign_detached( signature.data(), nullptr, M.data(), M.size(), SK_libsodium.data() );
    return signature;
}

vec bstr_id() {
    int i = rand() % 49;
    if ( i == 48 )
        return vec{};
    else
        return { (uint8_t) i };
}

// TODO PSK
void test_vectors( KeyType type_I, KeyType type_R, HeaderAttribute attr_I, HeaderAttribute attr_R, Suite suite, Correlation corr,
                   AuxData auxdata, SubjectName subjectname, Output output ) {

    // METHOD_CORR and seed random number generation
    int method = 3 * type_I + type_R; // method will likely be replaced by key types in a future version
    int METHOD_CORR = 4 * method + corr;
    srand( 100 * ( 25 * METHOD_CORR + 5 * attr_I + attr_R ) + suite );

    // EDHOC and OSCORE algorithms
    int edhoc_aead_id, edhoc_tag_len;
    int oscore_aead_id, oscore_hmac_id = 5;
    if ( suite == suite_0 ) {
        edhoc_aead_id = 10;
        edhoc_tag_len = 8;
        oscore_aead_id = 10;
    }
    if ( suite == suite_1 ) {
        edhoc_aead_id = 30;
        edhoc_tag_len = 16;
        oscore_aead_id = 10;
    }

    // Ephemeral keys
    auto [ X, G_X ] = X25519_key_pair();
    auto [ Y, G_Y ] = X25519_key_pair();
    vec G_XY = X25519( X, G_Y );

    // Authentication keys
    // Only some of these keys are used depending on type_I and type_R
    auto [ R, G_R ] = X25519_key_pair();
    auto [ I, G_I ] = X25519_key_pair();
    vec G_RX = X25519( R, G_X );
    vec G_IY = X25519( I, G_Y );

    auto [ SK_R, PK_R ] = Ed25519_key_pair(); 
    auto [ SK_I, PK_I ] = Ed25519_key_pair();
    
    // PRKs
    vec salt, PRK_2e, PRK_3e2m, PRK_4x3m;
    salt = vec{};
    PRK_2e = hkdf_extract_sha_256( salt, G_XY );

    if ( type_R == sdh )
        PRK_3e2m = hkdf_extract_sha_256( PRK_2e, G_RX );
    else
        PRK_3e2m = PRK_2e;

    if ( type_I == sdh )
        PRK_4x3m = hkdf_extract_sha_256( PRK_3e2m, G_IY );
    else
        PRK_4x3m = PRK_3e2m;
        
    // Subject names
    string NAME_I, NAME_R;
    if ( subjectname == sub_yes ) {
        NAME_I = "42-50-31-FF-EF-37-32-39";
        NAME_R = "54-68-65-FF-EF-6F-31-39";
    }
    else
        NAME_I = NAME_R = "";

    // TODO real X.509 certificates
    // CRED_x and ID_CRED_x
    vec ID_CRED_I, ID_CRED_R, CRED_I, CRED_R;
    if ( attr_I == kid ) {
        if ( type_I == sig )
            CRED_I = vec{ 0xa3, 0x01, 0x01, 0x20, 0x06, 0x21 } + cbor( PK_I ) + cbor( "subject name" ) + cbor( NAME_I );
        if ( type_I == sdh )
            CRED_I = vec{ 0xa3, 0x01, 0x01, 0x20, 0x04, 0x21 } + cbor( G_I )  + cbor( "subject name" ) + cbor( NAME_I );
        ID_CRED_I = vec{ 0xa1, attr_I } + cbor( bstr_id() );
    } else {
        vec X509_R = random_vector( 100 + rand() % 50 );
        CRED_I = cbor( X509_R );
        if ( attr_I == x5bag ||  attr_I == x5chain )
            ID_CRED_I = vec{ 0xa1, attr_I } + cbor( CRED_I );
        if ( attr_I == x5t )
            ID_CRED_I = vec{ 0xa1, attr_I } + vec{ 0x82, 0x2e } + cbor( hash_sha_256( X509_R, 8 ) ); // 0x2e = -15 = SHA-256/64
        if ( attr_I == x5u )
            ID_CRED_I = vec{ 0xa1, attr_I } + vec{ 0xD8, 0x20 } + cbor ( "https://www.example.edu/3370318" );
    }

    if ( attr_R == kid ) {
        if ( type_R == sig )
            CRED_R = vec{ 0xa3, 0x01, 0x01, 0x20, 0x06, 0x21 } + cbor( PK_R ) + cbor( "subject name" ) + cbor( NAME_R );
        if ( type_R == sdh )
            CRED_R = vec{ 0xa3, 0x01, 0x01, 0x20, 0x04, 0x21 } + cbor( G_R )  + cbor( "subject name" ) + cbor( NAME_R );
        ID_CRED_R = vec{ 0xa1, attr_R } + cbor( bstr_id() );
    } else {
        vec X509_I = random_vector( 100 + rand() % 50 );
        CRED_R = cbor( X509_I );
        if ( attr_R == x5bag ||  attr_R == x5chain )
            ID_CRED_R = vec{ 0xa1, attr_R } + cbor( CRED_R );
        if ( attr_R == x5t )
            ID_CRED_R = vec{ 0xa1, attr_R } + vec{ 0x82, 0x2e } + cbor( hash_sha_256( X509_I, 8 ) ); // 0x2e = -15 = SHA-256/64
        if ( attr_R == x5u )
            ID_CRED_R = vec{ 0xa1, attr_R } + vec{ 0xD8, 0x20 } + cbor ( "https://www.example.edu/2716057" );
    }
 
    // Calculate C_I != C_R
    vec C_I, C_R;
    do {
        C_I = bstr_id();
        C_R = bstr_id();
    } while ( C_I == C_R );

    // Auxiliary data
    vec AD_1, AD_2, AD_3;
    if ( auxdata == aux_yes ) {
        string s1 = "People who don't like Comic Sans don't know anything about design.";
        string s2 = "Lindy Hoppers never die - they just swing out in Herräng.";
        string s3 = "A delayed game is eventually good, but a rushed game is forever bad.";
        AD_1 = vec( s1.begin(), s1.end() );
        AD_2 = vec( s2.begin(), s2.end() );
        AD_3 = vec( s3.begin(), s3.end() );
    }
    else
        AD_1 = AD_2 = AD_3 = vec{};

    vec message_1 = cbor( METHOD_CORR ) + cbor( suite ) + cbor( G_X ) + cbor_id( C_I ) + cbor( AD_1 );

   // message_2 ////////////////////////////////////////////////////////////////////////////

    // Calculate data_2, and TH_2
    vec data_2;
    if ( corr == corr_none || corr == corr_23 )
        data_2 = cbor_id( C_I ) + cbor( G_Y ) + cbor_id( C_R );
    else
        data_2 = cbor( G_Y ) + cbor_id( C_R );
    vec TH_2_input = message_1 + data_2;
    vec TH_2 = hash_sha_256( TH_2_input ); 

    // Calculate MAC_2
    vec P_2m = vec{};
    vec protected_2 = cbor( ID_CRED_R );
    vec external_aad_2 = cbor( cbor( TH_2 ) + CRED_R ) + cbor( AD_2 );
    vec A_2m = vec{ 0xa3 } + cbor( "Encrypt0" ) + protected_2 + external_aad_2;
    vec info_K_2m  = gen_info( edhoc_aead_id, 128,  protected_2, TH_2 );
    vec info_IV_2m = gen_info( "IV-GENERATION",   104,  protected_2, TH_2 );
    vec K_2m  = hkdf_expand_sha_256( PRK_3e2m, info_K_2m, 16 );
    vec IV_2m = hkdf_expand_sha_256( PRK_3e2m, info_IV_2m, 13 );
    vec MAC_2 = aes_ccm_16_64_128( K_2m, IV_2m, P_2m, A_2m, edhoc_tag_len );

    // Calculate Signature_or_MAC_2
    vec M_2, signature_or_MAC_2;
    if ( type_R == sig ) {
        M_2 = vec{ 0x84 } + cbor( "Signature1" ) +  protected_2 + external_aad_2 + cbor( MAC_2 );
        signature_or_MAC_2 = Ed25519( SK_R, M_2 );
    }
    else
        signature_or_MAC_2 = MAC_2;

    // Calculate CIPHERTEXT_2
    vec P_2e = compress_id_cred( ID_CRED_R ) + cbor( signature_or_MAC_2 ) + cbor( AD_2 );
    vec info_K_2e   = gen_info( "XOR-ENCRYPTION", 8 * P_2e.size(), vec{}, TH_2 );
    vec K_2e = hkdf_expand_sha_256( PRK_2e, info_K_2e, P_2e.size() );
    vec CIPHERTEXT_2 = xor_encryption( K_2e, P_2e );

    // Calculate message_2
    vec message_2 = data_2 + cbor( CIPHERTEXT_2 );

   // message_3 ////////////////////////////////////////////////////////////////////////////

    // Calculate data_3, and TH_3
    vec data_3;
    if ( corr == corr_none || corr == corr_12 )
        data_3 = cbor_id( C_R );
    else
        data_3 = vec{};
    vec TH_3_input = cbor( TH_2 ) + cbor( CIPHERTEXT_2 ) + data_3;
    vec TH_3 = hash_sha_256( TH_3_input ); 

    // Calculate MAC_3
    vec P_3m = vec{};
    vec protected_3 = cbor( ID_CRED_I );
    vec external_aad_3 = cbor( cbor( TH_3 ) + CRED_I ) + cbor( AD_3 );
    vec A_3m = vec{ 0xa3 } + cbor( "Encrypt0" ) + protected_3 + external_aad_3;
    vec info_K_3m  = gen_info( edhoc_aead_id, 128, protected_3, TH_3 );
    vec info_IV_3m = gen_info( "IV-GENERATION",   104, protected_3, TH_3 );
    vec K_3m  = hkdf_expand_sha_256( PRK_4x3m, info_K_3m,  16 );
    vec IV_3m = hkdf_expand_sha_256( PRK_4x3m, info_IV_3m, 13 );
    vec MAC_3 = aes_ccm_16_64_128( K_3m, IV_3m, P_3m, A_3m, edhoc_tag_len );

    // Calculate Signature_or_MAC_3
    vec M_3, signature_or_MAC_3;
    if ( type_I == sig ) {
        M_3 = vec{ 0x84 } + cbor( "Signature1" ) + protected_3 + external_aad_3 + cbor( MAC_3 );
        signature_or_MAC_3 = Ed25519( SK_I, M_3 );
    }
    else
        signature_or_MAC_3 = MAC_3;

    // Calculate CIPHERTEXT_3
    vec P_3ae = compress_id_cred( ID_CRED_I ) + cbor( signature_or_MAC_3 ) + cbor( AD_3 );
    vec A_3ae = vec{ 0xa3 } + cbor( "Encrypt0" ) + cbor( vec{} ) + cbor( TH_3 );
    vec info_K_3ae  = gen_info( edhoc_aead_id, 128, vec{}, TH_3 );
    vec info_IV_3ae = gen_info( "IV-GENERATION",   104, vec{}, TH_3 );
    vec K_3ae  = hkdf_expand_sha_256( PRK_3e2m, info_K_3ae,  16 );
    vec IV_3ae = hkdf_expand_sha_256( PRK_3e2m, info_IV_3ae, 13 );
    vec CIPHERTEXT_3 = aes_ccm_16_64_128( K_3ae, IV_3ae, P_3ae, A_3ae, edhoc_tag_len );

    // Calculate message_3
    vec message_3 = data_3 + cbor( CIPHERTEXT_3 );

    // OSCORE ////////////////////////////////////////////////////////////////////////////

    // Calculate TH_4
    vec TH_4_input = cbor( TH_3 ) + cbor( CIPHERTEXT_3 );
    vec TH_4 = hash_sha_256( TH_4_input ); 

    // Derive OSCORE Master Secret and Salt
    vec info_OSCORE_secret = gen_info( "OSCORE Master Secret", 128, vec{}, TH_4 );
    vec info_OSCORE_salt   = gen_info( "OSCORE Master Salt",    64, vec{}, TH_4 );
    vec OSCORE_secret = hkdf_expand_sha_256( PRK_4x3m, info_OSCORE_secret, 16 );
    vec OSCORE_salt   = hkdf_expand_sha_256( PRK_4x3m, info_OSCORE_salt,    8 );

    // Print stuff ////////////////////////////////////////////////////////////////////////////
    ///////////////////////////////////////////////////////////////////////////////////////////

    cout << endl << "---------------------------------------------------------------" << endl;
    cout << "Test Vectors for EHDOC";
    cout << endl << "---------------------------------------------------------------" << endl;

    // message_1 ////////////////////////////////////////////////////////////////////////////

    if ( output == full ) {
        print( "Initiator's Key Type", type_I );
        print( "Responder's Key Type", type_R );
        print( "method", method );
        print( "corr", corr );
        print( "METHOD_CORR (4 * method + corr)", METHOD_CORR );   
        print( "suite", suite );
    }
    print( "X (Initiator's ephemeral private key)", X );
    if ( output == full ) {
        print( "G_X (Initiator's ephemeral public key)", G_X );
        print( "Connection identifier chosen by Initiator", C_I );
        print( "AD_1", AD_1 );   
    }
    print( "message_1 (CBOR Sequence)", message_1 );

    // message_2 ////////////////////////////////////////////////////////////////////////////

    print( "Y (Responder's ephemeral private key)", Y );
    if ( output == full ) {
        print( "G_Y (Responder's ephemeral public key)", G_Y );
        print( "G_XY (ECDH shared secret)", G_XY );
        print( "salt", salt );
        print( "PRK_2e", PRK_2e );   
    }
    if ( type_I == sig )
        print( "SK_R (Responders's private authentication key)", SK_R );
    if ( type_R == sdh ) {
        print( "R (Responder's private authentication key)", R );
        if ( output == full ) {
            print( "G_R (Responder's public authentication key)", G_R );
            print( "G_RX (ECDH shared secret)", G_RX );    
        }
    }
    if ( output == full ) {
        print( "PRK_3e2m", PRK_3e2m );   
        print( "Connection identifier chosen by Responder", C_R );
        print( "data_2 (CBOR Sequence)", data_2 );
        print( "Input to calculate TH_2 (CBOR Sequence)", TH_2_input );
        print( "TH_2", TH_2 );
        print( "Responders's subject name", NAME_R );
        print( "ID_CRED_R", ID_CRED_R );
        print( "CRED_R", CRED_R );
        print( "AD_2", AD_2 );   
        print( "P_2m", P_2m );
        print( "A_2m (CBOR-encoded)", A_2m );   
        print( "info for K_2m (CBOR-encoded)", info_K_2m );   
        print( "K_2m", K_2m );   
        print( "info for IV_2m (CBOR-encoded)", info_IV_2m );   
        print( "IV_2m", IV_2m );   
        print( "MAC_2", MAC_2 );   
        print( "Signature_or_MAC_2", signature_or_MAC_2 );
        print( "P_2e (CBOR Sequence)", P_2e );   
        print( "info for K_2e (CBOR-encoded)", info_K_2e );   
        print( "K_2e", K_2e );   
        print( "CIPHERTEXT_2", CIPHERTEXT_2 );   
    }
    print( "message_2 (CBOR Sequence)", message_2 );

    // message_3 ////////////////////////////////////////////////////////////////////////////

    if ( type_I == sig )
        print( "SK_I (Initiator's private authentication key)", SK_I );
    if ( type_I == sdh ) {
            print( "I (Initiator's private authentication key)", I );
        if ( output == full ) {
            print( "G_I (Initiator's public authentication key)", G_I );
            print( "G_IY (ECDH shared secret)", G_IY );
        }
    }
    if ( output == full ) {
        print( "PRK_4x3m", PRK_4x3m );   
        print( "data_3 (CBOR Sequence)", data_3 );
        print( "Input to calculate TH_3 (CBOR Sequence)", TH_3_input );
        print( "TH_3", TH_3);
        print( "Initiator's subject name", NAME_I );
        print( "ID_CRED_I", ID_CRED_I );
        print( "CRED_I", CRED_I );
        print( "AD_3", AD_3 );   
        print( "P_3m", P_3m );   
        print( "A_3m (CBOR-encoded)", A_3m );   
        print( "info for K_3m (CBOR-encoded)", info_K_3m );   
        print( "K_3m", K_3m );   
        print( "info for IV_3m (CBOR-encoded)", info_IV_3m );   
        print( "IV_3m", IV_3m );   
        print( "MAC_3", MAC_3 );   
        print( "Signature_or_MAC_3", signature_or_MAC_3 );
        print( "P_3ae (CBOR Sequence)", P_3ae );   
        print( "A_3ae (CBOR-encoded)", A_3ae );   
        print( "info for K_3ae (CBOR-encoded)", info_K_3ae );   
        print( "K_3ae", K_3ae );   
        print( "info for IV_3ae (CBOR-encoded)", info_IV_3ae );   
        print( "IV_3ae", IV_3ae );   
        print( "CIPHERTEXT_3", CIPHERTEXT_3 );   
    }
    print( "message_3 (CBOR Sequence)", message_3 );

    // OSCORE ////////////////////////////////////////////////////////////////////////////

    if ( output == full ) {
        print( "Input to calculate TH_4 (CBOR Sequence)", TH_4_input );
        print( "TH_4", TH_4 );
        print( "info for OSCORE Master Secret (CBOR-encoded)", info_OSCORE_secret );   
        print( "OSCORE Master Secret", OSCORE_secret );
        print( "info for OSCORE Master Salt (CBOR-encoded)", info_OSCORE_salt );   
        print( "OSCORE Master Salt", OSCORE_salt );
        print( "Client's OSCORE Sender ID", C_R );
        print( "Server's OSCORE Sender ID", C_I );
        print( "OSCORE AEAD Algorithm", oscore_aead_id );
        print( "OSCORE HMAC Algorithm", oscore_hmac_id );
    }
}

int main( void ) {
    if ( sodium_init() == -1 )
        syntax_error( "sodium_init()" );

    // Four methods
    test_vectors( sig, sig, x5t,     x5t,   suite_0, corr_12,    aux_no, sub_no, full );
    test_vectors( sig, sdh, x5t,     kid,   suite_0, corr_12,    aux_no, sub_no, lite );
    test_vectors( sdh, sig, kid,     x5t,   suite_0, corr_12,    aux_no, sub_no, lite );
    test_vectors( sdh, sdh, kid,     kid,   suite_0, corr_12,    aux_no, sub_no, full );

    // All header attributes for sig and sdh
    test_vectors( sig, sig, x5u,     x5bag, suite_0, corr_12,    aux_no, sub_no, lite );
    test_vectors( sig, sig, x5chain, kid,   suite_0, corr_12,    aux_no, sub_no, lite );
    test_vectors( sdh, sdh, x5u,     x5bag, suite_0, corr_12,    aux_no, sub_no, lite );
    test_vectors( sdh, sdh, x5chain, x5t,   suite_0, corr_12,    aux_no, sub_no, lite );

    // Cipher suite 1
    test_vectors( sig, sig, x5t,     x5t,   suite_1, corr_12,    aux_no, sub_no, lite );
    test_vectors( sdh, sdh, kid,     kid,   suite_1, corr_12,    aux_no, sub_no, lite );

    // All correlation
    test_vectors( sdh, sdh, kid,     kid,    suite_0, corr_none, aux_no, sub_no, lite );
    test_vectors( sdh, sdh, kid,     kid,    suite_0, corr_23,   aux_no, sub_no, lite );
    test_vectors( sdh, sdh, kid,     kid,    suite_0, corr_123,  aux_no, sub_no, lite );

    // Auxileary data
    test_vectors( sdh, sdh, kid,     kid,    suite_0, corr_12,   aux_yes, sub_no, lite );

    // Subject name
    test_vectors( sdh, sdh, kid,     kid,    suite_0, corr_12,   aux_yes, sub_yes, lite );
}