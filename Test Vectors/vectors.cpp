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

// Concatenates two vectors
template <typename T> 
T operator+( T a, T b ) {
    a.insert( a.end(), b.begin(), b.end() );
    return a;
}

// Fatal error
void syntax_error( string s ) {
    cout << "Syntax Error: " << s;
    exit(-1);
}

// Print an int to cout
void print( string s, int i ) {
    cout << endl << dec << s << " (int)" << endl << i << endl;    
}

// Print a string to cout
void print( string s, string s2 ) {
    cout << endl << s << " (text string)" << endl << "\"" << s2 << "\"" << endl;    
}

// Print a vec to cout
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

// Helper funtion for CBOR encoding
vec cbor_unsigned_with_type( uint8_t type, int i ) {
    type = type << 5;
    if ( i < 0 || i > 0xFFFF )
        syntax_error( "cbor_unsigned_with_type()" );
    if ( i < 24 )
        return { (uint8_t) (type | i) };
    else if ( i < 0x100 )
        return { (uint8_t) (type | 0x18), (uint8_t) i };
    else
        return { (uint8_t) (type | 0x19), (uint8_t) (i >> 8), (uint8_t) (i & 0xFF) };
}

// CBOR encodes an int
vec cbor( int i ) {
    if ( i < 0 )
        return cbor_unsigned_with_type( 1, -(i + 1) ); 
    else
	    return cbor_unsigned_with_type( 0, i ); 
}

// CBOR encodes a bstr
 vec cbor( vec v ) {
    return cbor_unsigned_with_type( 2, v.size() ) + v;
}

// CBOR encodes a tstr
vec cbor( string s ) {
    return cbor_unsigned_with_type( 3, s.size() ) + vec( s.begin(), s.end() );
}

// CBOR encodes a bstr_indentifier
 vec cbor_id( vec v ) {
    if ( v.size() == 1 )
        return cbor( v[0] - 24 );
    else
        return cbor( v );
}

// CBOR encodes AD
 vec cbor_AD( vec v ) {
    if ( v.size() == 0 )
        return v;
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

// Tries to compress SUTES_I
// Only supports suites in the range [-24, 23]
 vec compress_suites( vec v ) {
    if ( v[1] == v[2] )
        return cbor( v[1] );
    else
        return v;
}

// Calculates the hash of m
vec H( int alg, vec m ) {
    if ( alg != -15 && alg != -16 )
        syntax_error( "hash()" );
    vec digest( crypto_hash_sha256_BYTES );
    crypto_hash_sha256( digest.data(), m.data(), m.size() );
    if ( alg == -15 )
        digest.resize( 8 );
    return digest;
}

vec hmac( int alg, vec k, vec m ) {
    if ( alg != -16 )
        syntax_error( "hmac()" );
    vec out( crypto_auth_hmacsha256_BYTES ); 
    crypto_auth_hmacsha256_state state;
    crypto_auth_hmacsha256_init( &state, k.data(), k.size() );
    crypto_auth_hmacsha256_update( &state, m.data(), m.size() );
    crypto_auth_hmacsha256_final( &state, out.data() );
    return out;
}

vec hkdf_extract( int alg, vec salt, vec IKM ) {
    return hmac( alg, salt, IKM ); // correct that salt is key
}

// TODO: This function should be checked against another implementation
vec hkdf_expand( int alg, vec PRK, vec info, int L ) {
    vec out, T;
    for ( int i = 0; i <= L / 32; i++ ) {
        vec m = T + info + vec{ uint8_t( i + 1 ) };
        T = hmac( alg, PRK, m );
        out = out + T;
    }
    out.resize( L );
    return out;
}

// TODO: This function should be checked against another implementation
vec AEAD( int alg, vec K, vec N, vec P, vec A ) {
    if ( alg != 10 && alg != 30 )
        syntax_error( "AEAD()" );
    if( A.size() > (42 * 16 - 2) )
        syntax_error( "AEAD()" );
    int tag_length = ( alg == 10 ) ? 8 : 16;
    vec C( P.size() + tag_length );
    int r = aes_ccm_ae( K.data(), 16, N.data(), tag_length, P.data(), P.size(), A.data(), A.size(), C.data(), C.data() + P.size() );
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

// Generates a key pair
std::tuple< vec, vec > gen_key_pair( int curve ) {
    if ( curve != 4 && curve != 6 )
        syntax_error( "gen_key_pair()" );
    if ( curve == 4 ) {
        vec G_X( crypto_kx_PUBLICKEYBYTES );
        vec X( crypto_kx_SECRETKEYBYTES );
        vec seed = random_vector( crypto_kx_SEEDBYTES );
        crypto_kx_seed_keypair( G_X.data(), X.data(), seed.data() );
        return std::make_tuple( X, G_X );
    }
    else {
        // EDHOC uses RFC 8032 notation, libsodium uses the notation from the Ed25519 paper by Bernstein
        // Libsodium seed = RFC 8032 sk, Libsodium sk = pruned SHA-512(sk) in RFC 8032
        vec PK( crypto_sign_PUBLICKEYBYTES );
        vec SK_libsodium( crypto_sign_SECRETKEYBYTES );
        vec SK = random_vector( crypto_sign_SEEDBYTES );
        crypto_sign_seed_keypair( PK.data(), SK_libsodium.data(), SK.data() );
        return std::make_tuple( SK, PK );
    }
}

vec shared_secret( int curve, vec A, vec G_B ) {
    if ( curve != 4 )
        syntax_error( "shared_secret()" );
    vec G_AB( crypto_scalarmult_BYTES );
    if ( crypto_scalarmult( G_AB.data(), A.data(), G_B.data() ) == -1 )
        syntax_error( "crypto_scalarmult()" );
    return G_AB;
}

vec sign( int alg, int curve, vec SK, vec M ) {
    if ( alg != -8 || curve != 6 )
        syntax_error( "sign()" );
    vec signature( crypto_sign_BYTES );
    vec PK( crypto_sign_PUBLICKEYBYTES );
    vec SK_libsodium( crypto_sign_SECRETKEYBYTES );
    crypto_sign_seed_keypair( PK.data(), SK_libsodium.data(), SK.data() );
    crypto_sign_detached( signature.data(), nullptr, M.data(), M.size(), SK_libsodium.data() );
    return signature;
}

vec bstr_id( bool long_id ) {
    if ( long_id == true )
        return random_vector( 2 + rand() % 2 );
    else {
        int i = rand() % 49;
        if ( i == 48 )
            return vec{};
        else
            return { (uint8_t) i };
    }
}

// TODO PSK
// TODO error message with SUITES_V
// TODO real X.509 certificates
// TODO other COSE algorithms like ECDSA, P-256, SHA-384, P-384, AES-GCM, ChaCha20-Poly1305
void test_vectors( KeyType type_I, KeyType type_R, HeaderAttribute attr_I, HeaderAttribute attr_R, Suite selected_suite, Correlation corr,
                   bool auxdata, bool subjectname, bool long_id, bool full_output ) {

    // METHOD_CORR and seed random number generation
    int method = 3 * type_I + type_R; // method will likely be replaced by key types in a future version
    int METHOD_CORR = 4 * method + corr;
    srand( 100 * ( 25 * METHOD_CORR + 5 * attr_I + attr_R ) + selected_suite );

    // EDHOC and OSCORE algorithms
    vec preferred_suites = vec{ 0x00, 0x01 };
    vec SUITES_I = vec{ 0x83 } + vec{ selected_suite } + preferred_suites;
    int edhoc_aead_alg, edhoc_hash_alg, edhoc_ecdh_curve, edhoc_sign_alg, edhoc_sign_curve, oscore_aead_alg, oscore_hash_alg;
    if ( selected_suite == suite_0 ) {
        edhoc_aead_alg = 10;
        edhoc_hash_alg = -16;
        edhoc_ecdh_curve = 4;
        edhoc_sign_alg = -8;
        edhoc_sign_curve = 6;
        oscore_aead_alg = 10;
        oscore_hash_alg = -16;
    }
    if ( selected_suite == suite_1 ) {
        edhoc_aead_alg = 30;
        edhoc_hash_alg = -16;
        edhoc_ecdh_curve = 4;
        edhoc_sign_alg = -8;
        edhoc_sign_curve = 6;
        oscore_aead_alg = 10;
        oscore_hash_alg = -16;
    }

    // Ephemeral keys
    auto [ X, G_X ] = gen_key_pair( edhoc_ecdh_curve );
    auto [ Y, G_Y ] = gen_key_pair( edhoc_ecdh_curve );
    vec G_XY = shared_secret( edhoc_ecdh_curve, X, G_Y );

    // Authentication keys
    // Only some of these keys are used depending on type_I and type_R
    auto [ R, G_R ] = gen_key_pair( edhoc_ecdh_curve );
    auto [ I, G_I ] = gen_key_pair( edhoc_ecdh_curve );
    vec G_RX = shared_secret( edhoc_ecdh_curve, R, G_X );
    vec G_IY = shared_secret( edhoc_ecdh_curve, I, G_Y );
    auto [ SK_R, PK_R ] = gen_key_pair( edhoc_sign_curve );
    auto [ SK_I, PK_I ] = gen_key_pair( edhoc_sign_curve );
    
    // PRKs
    vec salt, PRK_2e, PRK_3e2m, PRK_4x3m;
    salt = vec{};
    PRK_2e = hkdf_extract( edhoc_hash_alg, salt, G_XY );

    if ( type_R == sdh )
        PRK_3e2m = hkdf_extract( edhoc_hash_alg, PRK_2e, G_RX );
    else
        PRK_3e2m = PRK_2e;

    if ( type_I == sdh )
        PRK_4x3m = hkdf_extract( edhoc_hash_alg, PRK_3e2m, G_IY );
    else
        PRK_4x3m = PRK_3e2m;
        
    // Subject names
    string NAME_I, NAME_R;
    if ( subjectname == true ) {
        NAME_I = "42-50-31-FF-EF-37-32-39";
        NAME_R = "example.edu";
    }
    else
        NAME_I = NAME_R = "";

    // CRED_x and ID_CRED_x
    vec ID_CRED_I, ID_CRED_R, CRED_I, CRED_R;
    if ( attr_I == kid ) {
        if ( type_I == sig )
            CRED_I = vec{ 0xa3, 0x01, 0x01, 0x20, 0x06, 0x21 } + cbor( PK_I ) + cbor( "subject name" ) + cbor( NAME_I );
        if ( type_I == sdh )
            CRED_I = vec{ 0xa3, 0x01, 0x01, 0x20, 0x04, 0x21 } + cbor( G_I )  + cbor( "subject name" ) + cbor( NAME_I );
        ID_CRED_I = vec{ 0xa1, attr_I } + cbor( bstr_id( long_id ) );
    } else {
        vec X509_R = random_vector( 100 + rand() % 50 );
        CRED_I = cbor( X509_R );
        if ( attr_I == x5bag ||  attr_I == x5chain )
            ID_CRED_I = vec{ 0xa1, 0x18, attr_I } + cbor( CRED_I );
        if ( attr_I == x5t )
            ID_CRED_I = vec{ 0xa1, 0x18, attr_I } + vec{ 0x82, 0x2e } + cbor( H( -15, X509_R ) ); // 0x2e = -15 = SHA-256/64
        if ( attr_I == x5u )
            ID_CRED_I = vec{ 0xa1, 0x18, attr_I } + vec{ 0xD8, 0x20 } + cbor ( "https://example.edu/3370318" );
    }

    if ( attr_R == kid ) {
        if ( type_R == sig )
            CRED_R = vec{ 0xa3, 0x01, 0x01, 0x20, 0x06, 0x21 } + cbor( PK_R ) + cbor( "subject name" ) + cbor( NAME_R );
        if ( type_R == sdh )
            CRED_R = vec{ 0xa3, 0x01, 0x01, 0x20, 0x04, 0x21 } + cbor( G_R )  + cbor( "subject name" ) + cbor( NAME_R );
        ID_CRED_R = vec{ 0xa1, attr_R } + cbor( bstr_id( long_id ) );
    } else {
        vec X509_I = random_vector( 100 + rand() % 50 );
        CRED_R = cbor( X509_I );
        if ( attr_R == x5bag ||  attr_R == x5chain )
            ID_CRED_R = vec{ 0xa1, 0x18, attr_R } + cbor( CRED_R );
        if ( attr_R == x5t )
            ID_CRED_R = vec{ 0xa1, 0x18, attr_R } + vec{ 0x82, 0x2e } + cbor( H( -15, X509_I ) ); // 0x2e = -15 = SHA-256/64
        if ( attr_R == x5u )
            ID_CRED_R = vec{ 0xa1, 0x18, attr_R } + vec{ 0xD8, 0x20 } + cbor ( "https://example.edu/2716057" );
    }
 
    // Calculate C_I != C_R
    vec C_I, C_R;
    do {
        C_I = bstr_id( long_id );
        C_R = bstr_id( long_id );
    } while ( C_I == C_R );

    // Auxiliary data
    vec AD_1, AD_2, AD_3;
    if ( auxdata == true ) {
        string s1 = "People who don't like Comic Sans don't know anything about design.";
        string s2 = "Lindy Hoppers never die - they just swing out in Herräng.";
        string s3 = "A delayed game is eventually good, but a rushed game is forever bad.";
        AD_1 = cbor( vec( s1.begin(), s1.end() ) );
        AD_2 = cbor( vec( s2.begin(), s2.end() ) );
        AD_3 = cbor( vec( s3.begin(), s3.end() ) );
    }
    else
        AD_1 = AD_2 = AD_3 = vec{};
 
    vec message_1 = cbor( METHOD_CORR ) + compress_suites( SUITES_I ) + cbor( G_X ) + cbor_id( C_I ) + cbor_AD( AD_1 );

   // message_2 ////////////////////////////////////////////////////////////////////////////

    // Calculate data_2, and TH_2
    vec data_2;
    if ( corr == corr_none || corr == corr_23 )
        data_2 = cbor_id( C_I ) + cbor( G_Y ) + cbor_id( C_R );
    else
        data_2 = cbor( G_Y ) + cbor_id( C_R );
    vec TH_2_input = message_1 + data_2;
    vec TH_2 = H( edhoc_hash_alg, TH_2_input ); 

    // Calculate MAC_2
    vec P_2m = vec{};
    vec protected_2 = cbor( ID_CRED_R );
    vec external_aad_2 = cbor( cbor( TH_2 ) + CRED_R ) + cbor_AD( AD_2 );
    vec A_2m = vec{ 0xa3 } + cbor( "Encrypt0" ) + protected_2 + external_aad_2;
    vec info_K_2m  = gen_info( edhoc_aead_alg, 128,  protected_2, TH_2 );
    vec info_IV_2m = gen_info( "IV-GENERATION",   104,  protected_2, TH_2 );
    vec K_2m  = hkdf_expand( edhoc_hash_alg, PRK_3e2m, info_K_2m, 16 );
    vec IV_2m = hkdf_expand( edhoc_hash_alg, PRK_3e2m, info_IV_2m, 13 );
    vec MAC_2 = AEAD( edhoc_aead_alg, K_2m, IV_2m, P_2m, A_2m );

    // Calculate Signature_or_MAC_2
    vec M_2, signature_or_MAC_2;
    if ( type_R == sig ) {
        M_2 = vec{ 0x84 } + cbor( "Signature1" ) +  protected_2 + external_aad_2 + cbor( MAC_2 );
        signature_or_MAC_2 = sign( edhoc_sign_alg, edhoc_sign_curve, SK_R, M_2 );
    }
    else
        signature_or_MAC_2 = MAC_2;

    // Calculate CIPHERTEXT_2
    vec P_2e = compress_id_cred( ID_CRED_R ) + cbor( signature_or_MAC_2 ) + cbor_AD( AD_2 );
    vec info_K_2e   = gen_info( "XOR-ENCRYPTION", 8 * P_2e.size(), vec{}, TH_2 );
    vec K_2e = hkdf_expand( edhoc_hash_alg, PRK_2e, info_K_2e, P_2e.size() );
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
    vec TH_3 = H( edhoc_hash_alg, TH_3_input ); 

    // Calculate MAC_3
    vec P_3m = vec{};
    vec protected_3 = cbor( ID_CRED_I );
    vec external_aad_3 = cbor( cbor( TH_3 ) + CRED_I ) + cbor_AD( AD_3 );
    vec A_3m = vec{ 0xa3 } + cbor( "Encrypt0" ) + protected_3 + external_aad_3;
    vec info_K_3m  = gen_info( edhoc_aead_alg, 128, protected_3, TH_3 );
    vec info_IV_3m = gen_info( "IV-GENERATION",   104, protected_3, TH_3 );
    vec K_3m  = hkdf_expand( edhoc_hash_alg, PRK_4x3m, info_K_3m,  16 );
    vec IV_3m = hkdf_expand( edhoc_hash_alg, PRK_4x3m, info_IV_3m, 13 );
    vec MAC_3 = AEAD( edhoc_aead_alg, K_3m, IV_3m, P_3m, A_3m );

    // Calculate Signature_or_MAC_3
    vec M_3, signature_or_MAC_3;
    if ( type_I == sig ) {
        M_3 = vec{ 0x84 } + cbor( "Signature1" ) + protected_3 + external_aad_3 + cbor( MAC_3 );
        signature_or_MAC_3 = sign( edhoc_sign_alg, edhoc_sign_curve, SK_I, M_3 );
    }
    else
        signature_or_MAC_3 = MAC_3;

    // Calculate CIPHERTEXT_3
    vec P_3ae = compress_id_cred( ID_CRED_I ) + cbor( signature_or_MAC_3 ) + cbor_AD( AD_3 );
    vec A_3ae = vec{ 0xa3 } + cbor( "Encrypt0" ) + cbor( vec{} ) + cbor( TH_3 );
    vec info_K_3ae  = gen_info( edhoc_aead_alg, 128, vec{}, TH_3 );
    vec info_IV_3ae = gen_info( "IV-GENERATION",   104, vec{}, TH_3 );
    vec K_3ae  = hkdf_expand( edhoc_hash_alg, PRK_3e2m, info_K_3ae,  16 );
    vec IV_3ae = hkdf_expand( edhoc_hash_alg, PRK_3e2m, info_IV_3ae, 13 );
    vec CIPHERTEXT_3 = AEAD( edhoc_aead_alg, K_3ae, IV_3ae, P_3ae, A_3ae );

    // Calculate message_3
    vec message_3 = data_3 + cbor( CIPHERTEXT_3 );

    // OSCORE ////////////////////////////////////////////////////////////////////////////

    // Calculate TH_4
    vec TH_4_input = cbor( TH_3 ) + cbor( CIPHERTEXT_3 );
    vec TH_4 = H( edhoc_hash_alg, TH_4_input ); 

    // Derive OSCORE Master Secret and Salt
    vec info_OSCORE_secret = gen_info( "OSCORE Master Secret", 128, vec{}, TH_4 );
    vec info_OSCORE_salt   = gen_info( "OSCORE Master Salt",    64, vec{}, TH_4 );
    vec OSCORE_secret = hkdf_expand( edhoc_hash_alg, PRK_4x3m, info_OSCORE_secret, 16 );
    vec OSCORE_salt   = hkdf_expand( edhoc_hash_alg, PRK_4x3m, info_OSCORE_salt,    8 );

    // Print stuff ////////////////////////////////////////////////////////////////////////////
    ///////////////////////////////////////////////////////////////////////////////////////////

    cout << endl << "---------------------------------------------------------------" << endl;
    cout << "Test Vectors for EHDOC";
    cout << endl << "---------------------------------------------------------------" << endl;

    // message_1 ////////////////////////////////////////////////////////////////////////////

    if ( full_output == true ) {
        print( "Initiator's Key Type", type_I );
        print( "Responder's Key Type", type_R );
        print( "method", method );
        print( "corr", corr );
        print( "METHOD_CORR (4 * method + corr)", METHOD_CORR );   
        print( "Selected Cipher Suite", selected_suite );
        print( "Preferred Cipher Suites", preferred_suites );
        print( "Uncompressed SUITES_I", SUITES_I );
    }
    print( "X (Initiator's ephemeral private key)", X );
    if ( full_output == true ) {
        print( "G_X (Initiator's ephemeral public key)", G_X );
        print( "Connection identifier chosen by Initiator", C_I );
        print( "AD_1", AD_1 );   
    }
    print( "message_1 (CBOR Sequence)", message_1 );

    // message_2 ////////////////////////////////////////////////////////////////////////////

    print( "Y (Responder's ephemeral private key)", Y );
    if ( full_output == true ) {
        print( "G_Y (Responder's ephemeral public key)", G_Y );
        print( "G_XY (ECDH shared secret)", G_XY );
        print( "salt", salt );
        print( "PRK_2e", PRK_2e );   
    }
    if ( type_I == sig )
        print( "SK_R (Responders's private authentication key)", SK_R );
    if ( type_R == sdh ) {
        print( "R (Responder's private authentication key)", R );
        if ( full_output == true ) {
            print( "G_R (Responder's public authentication key)", G_R );
            print( "G_RX (ECDH shared secret)", G_RX );    
        }
    }
    if ( full_output == true ) {
        print( "PRK_3e2m", PRK_3e2m );   
        print( "Connection identifier chosen by Responder", C_R );
        print( "data_2 (CBOR Sequence)", data_2 );
        print( "Input to calculate TH_2 (CBOR Sequence)", TH_2_input );
        print( "TH_2", TH_2 );
        print( "Responders's subject name", NAME_R );
        print( "ID_CRED_R", ID_CRED_R );
        print( "CRED_R", CRED_R );
        print( "AD_2 ", AD_2 );   
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
        if ( full_output == true ) {
            print( "G_I (Initiator's public authentication key)", G_I );
            print( "G_IY (ECDH shared secret)", G_IY );
        }
    }
    if ( full_output == true ) {
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

    if ( full_output == true ) {
        print( "Input to calculate TH_4 (CBOR Sequence)", TH_4_input );
        print( "TH_4", TH_4 );
        print( "info for OSCORE Master Secret (CBOR-encoded)", info_OSCORE_secret );   
        print( "OSCORE Master Secret", OSCORE_secret );
        print( "info for OSCORE Master Salt (CBOR-encoded)", info_OSCORE_salt );   
        print( "OSCORE Master Salt", OSCORE_salt );
        print( "Client's OSCORE Sender ID", C_R );
        print( "Server's OSCORE Sender ID", C_I );
        print( "OSCORE AEAD Algorithm", oscore_aead_alg );
        print( "OSCORE Hash Algorithm", oscore_hash_alg );
    }
}

int main( void ) {
    if ( sodium_init() == -1 )
        syntax_error( "sodium_init()" );

    // Full output
    test_vectors( sig, sig, x5t,     x5t,   suite_0, corr_12,    false, false, false, true );
    test_vectors( sdh, sdh, kid,     kid,   suite_0, corr_12,    false, false, false, true );

    // Different key types
    test_vectors( sig, sdh, x5t,     kid,   suite_0, corr_12,    false, false, false, false );
    test_vectors( sdh, sig, kid,     x5t,   suite_0, corr_12,    false, false, false, false );

    // All header attributes for sig and sdh
    test_vectors( sig, sig, x5u,     x5bag, suite_0, corr_12,    false, false, false, false );
    test_vectors( sig, sig, x5chain, kid,   suite_0, corr_12,    false, false, false, false );
    test_vectors( sdh, sdh, x5u,     x5bag, suite_0, corr_12,    false, false, false, false );
    test_vectors( sdh, sdh, x5chain, x5t,   suite_0, corr_12,    false, false, false, false );

    // Cipher suite nr. 1 and non-compressed SUITES_I
    test_vectors( sig, sig, x5t,     x5t,   suite_1, corr_12,    false, false, false, false );
    test_vectors( sdh, sdh, kid,     kid,   suite_1, corr_12,    false, false, false, false );

    // All other correlations
    test_vectors( sdh, sdh, kid,     kid,    suite_0, corr_none, false, false, false, false );
    test_vectors( sdh, sdh, kid,     kid,    suite_0, corr_23,   false, false, false, false );
    test_vectors( sdh, sdh, kid,     kid,    suite_0, corr_123,  false, false, false, false );

    // Auxileary data
    test_vectors( sdh, sdh, kid,     kid,    suite_0, corr_12,   true, false, false, false );

    // Subject names
    test_vectors( sdh, sdh, kid,     kid,    suite_0, corr_12,   false, true, false, false );

    // Long non-compressed bstr_identifiers
    test_vectors( sdh, sdh, kid,     kid,    suite_0, corr_12,   false, false, true, false );
}
