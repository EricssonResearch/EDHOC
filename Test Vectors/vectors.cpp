// EDHOC Test Vectors
// Copyright (c) 2019, Ericsson and John Mattsson <john.mattsson@ericsson.com>
//
// This software may be distributed under the terms of the 3-Clause BSD License.

#include <iostream>
#include <iomanip>
#include <cstdint>
#include <vector>
#include <cstring>

#include <sodium.h>

#include "aes.h"

using namespace std;

// Concatenates a to the end of v (may not work if a = v)
void vector_append( vector<uint8_t> &v, vector<uint8_t> a ) {
    v.reserve( 1000 ); // big so that iterators are stable during insert
    v.insert( v.end(), a.begin(), a.end() );
}

// print a vector to cout
void print_vector( string s, vector<uint8_t> v ) {
    cout << endl << dec << s << " (" << v.size() << " bytes)" << endl;    
    for ( auto i : v )
        cout << hex << setfill('0') << setw(2) << (int)i << " ";
    cout << endl;
}

// print an int to cout
void print_int( string s, int i ) {
    cout << endl << dec << s << endl << i << endl;    
}

// print a line to cout
void print_line() {
    cout << endl << "---------------------------------------------------------------" << endl;
}

// print a CDDL int to cout
void print_cddl_int( int i ) {
    cout << dec << "  " << i << "," << endl;
}

// print a bstr to cout
void print_cddl_bstr( vector<uint8_t> v ) {
    cout << "  h'";
    for ( auto i : v )
        cout << hex << setfill('0') << setw(2) << (int)i;
    cout << "'," << endl;
}

// CBOR encodes an uint8_t
vector<uint8_t> cbor_uint8( uint8_t i ) {
    if ( i < 24 )
        return { i };
    else
        return { 0x18, i };
}

// CBOR encodes a bstr
vector<uint8_t> cbor_bstr( vector<uint8_t> v ) {
    vector<uint8_t> out;
    if ( v.size() < 24 )
        out = { (uint8_t)( v.size() | 0x40 ) };
    else
        out = { 0x58, (uint8_t)v.size() };

    vector_append( out, v );
    return out;
}

// CBOR encodes a tstr
vector<uint8_t> cbor_tstr( string s ) {
    vector<uint8_t> out;
    if ( s.size() < 24 )
        out = { (uint8_t)( s.size() | 0x60 ) };
    else
        out = { 0x78, (uint8_t)s.size() };
    
    vector_append( out, vector<uint8_t>( s.begin(), s.end() ) );
    return out;
}

// wrapper for crypto_hash_sha_256
vector<uint8_t> hash_sha_256( vector<uint8_t> m ) {
    vector<uint8_t> digest( crypto_hash_sha256_BYTES );
    crypto_hash_sha256( digest.data(), m.data(), m.size() );
    return digest;
}

// wrapper as crypto_auth_hmac_sha_256 does not suppport variable key lengths
vector<uint8_t> hmac_sha_256( vector<uint8_t> k,  vector<uint8_t> m ) {
    vector<uint8_t> out( crypto_auth_hmacsha256_BYTES ); 
    crypto_auth_hmacsha256_state state;
    crypto_auth_hmacsha256_init( &state, k.data(), k.size() );
    crypto_auth_hmacsha256_update( &state, m.data(), m.size() );
    crypto_auth_hmacsha256_final( &state, out.data() );
    return out;
}

vector<uint8_t> hkdf_extract_sha_256( vector<uint8_t> salt, vector<uint8_t> IKM ) {
    return hmac_sha_256( salt,  IKM ); // correct that salt is key
}

// Only works for L <= 32
vector<uint8_t> hkdf_expand_sha_256( vector<uint8_t> PRK, vector<uint8_t> info, int L ) {
    vector<uint8_t> m( info );
    m.push_back( 0x01 );
    vector<uint8_t> out = hmac_sha_256( PRK, m );
    out.resize( L );
    return out;
}

vector<uint8_t> aes_ccm_16_64_128( vector<uint8_t> K, vector<uint8_t> N, vector<uint8_t> P, vector<uint8_t> A ) {
    vector<uint8_t> C( P.size() + 8 );
    int r = aes_ccm_ae( K.data(), 16, N.data(), 8, P.data(), P.size(), A.data(), A.size(), C.data(), C.data() + P.size() );
    return C;
}

// Creates the info parameter for HKDF
vector<uint8_t> gen_info( vector<uint8_t> AlgorithmID_CBOR, int keyDataLength, vector<uint8_t> other )
{
    vector<uint8_t> info { 0x84 }; // CBOR array of length 4
    vector_append( info, AlgorithmID_CBOR );
    vector_append( info, { 0x83, 0xf6, 0xf6, 0xf6 } ); // CBOR encoding of [ null, null, null ]
    vector_append( info, { 0x83, 0xf6, 0xf6, 0xf6 } ); // CBOR encoding of [ null, null, null ]
    info.push_back( 0x83 ); // CBOR array of length 3
    vector_append( info, cbor_uint8( keyDataLength ) ); // keyDataLength is in bits
    vector_append( info, cbor_bstr( { } ) ); // empty bstr 
    vector_append( info, cbor_bstr( other ) ); // other = TH_i
    return info;
}

void psk_vectors( void )
{
    print_line();
    cout << "Test Vectors for EDHOC Authenticated with PSK";
    print_line();

    // Pre-shared stuff ////////////////////////////////////////////////////////////////////////////

    vector<uint8_t> PSK( 16 );  // 16 bytes = 128 bit security
    vector<uint8_t> PSK_seed( randombytes_SEEDBYTES, 0 ); 
    randombytes_buf_deterministic( PSK.data(), PSK.size(), PSK_seed.data() );
    vector<uint8_t> kid { 0xa1 };
    vector<uint8_t> ID_PSK = cbor_bstr( kid );

    /* Print */
    print_vector( "Pre-shared Key (PSK)", PSK );
    print_vector( "kid value to identify PSK", kid );    

    cout << endl;
    cout << "COSE header_map =" << endl;
    cout << "{" << endl;
    cout << "  4:";
    print_cddl_bstr( kid );
    cout << "}" << endl;

    cout << endl << "The header_map contains a single 'kid' parameter, so ID_PSK is a CBOR bstr)" << endl;

    print_vector( "ID_PSK (CBOR-encoded)", ID_PSK );

    print_line();

    // message_1 ////////////////////////////////////////////////////////////////////////////

    // Generate the Party U's ephemeral key pair
    vector<uint8_t> U_kx_pk( crypto_kx_PUBLICKEYBYTES );
    vector<uint8_t> U_kx_sk( crypto_kx_SECRETKEYBYTES );
    vector<uint8_t> U_kx_seed( crypto_kx_SEEDBYTES, 1 ); ;
    crypto_kx_seed_keypair( U_kx_pk.data(), U_kx_sk.data(), U_kx_seed.data() );

    // Other parameters
    uint8_t method = 1; // Symmetric
    uint8_t corr = 1; // Party U is CoAP client
    uint8_t TYPE = 4 * method + corr;
    uint8_t suite = 0; // [ 10, -27, 4, -8, 6 ] AES-CCM-16-64-128, ECDH-SS + HKDF-256, X25519, EdDSA, Ed25519
    int aead_algorithm_id = 10;
    int hkdf_algorithm_id = -27;
    vector<uint8_t> C_U { 0xc1 };

    // Calculate message_1
    vector<uint8_t> message_1;
    vector_append( message_1, cbor_uint8( TYPE ) ); 
    vector_append( message_1, cbor_uint8( suite ) ); 
    vector_append( message_1, cbor_bstr( U_kx_pk ) ); 
    vector_append( message_1, cbor_bstr( C_U ) ); 
    vector_append( message_1, cbor_bstr( kid ) ); // ID_PSK contains a single 'kid' parameter, so only bstr is used

    // Print
    print_int( "method (Symmetric Authentication)", method );
    print_int( "corr (Party U is CoAP client)", corr );
    print_int( "TYPE (4 * method + corr)", TYPE );   
    print_int( "suite", suite );
    print_vector( "Party U's ephemeral private key", U_kx_sk );
    print_vector( "Party U's ephemeral public key (value of X_U)", U_kx_pk );
    print_vector( "Connection identifier chosen by U (value of C_U)", C_U );

    cout << endl;
    cout << "message_1 =" << endl;
    cout << "(" << endl;
    print_cddl_int( TYPE );
    print_cddl_int( suite );
    print_cddl_bstr( U_kx_pk );
    print_cddl_bstr( C_U );
    print_cddl_bstr( kid ); // ID_PSK contains a single 'kid' parameter, so only bstr is used
    cout << ")" << endl;

    print_vector( "message_1 (CBOR Sequence)", message_1 );

    print_line();

    // message_2 ////////////////////////////////////////////////////////////////////////////

    /* Generate the Party V's ephemeral key pair */
    vector<uint8_t> V_kx_pk( crypto_kx_PUBLICKEYBYTES );
    vector<uint8_t> V_kx_sk( crypto_kx_SECRETKEYBYTES );
    vector<uint8_t> V_kx_seed( crypto_kx_SEEDBYTES, 2 ); ;
    crypto_kx_seed_keypair( V_kx_pk.data(), V_kx_sk.data(), V_kx_seed.data() );

    // Other parameters
    vector<uint8_t> C_V { 0xc2 };

    // Calculate data_2
    vector<uint8_t> data_2;
    vector_append( data_2, cbor_bstr( V_kx_pk ) ); 
    vector_append( data_2, cbor_bstr( C_V ) ); 

    // Calculate TH_2
    vector<uint8_t> TH_2_input;
    vector_append( TH_2_input, message_1 );
    vector_append( TH_2_input, data_2 );
    vector<uint8_t> TH_2 = hash_sha_256( TH_2_input );

    // Calculate ECDH shared secret
    vector<uint8_t> shared_secret( crypto_scalarmult_BYTES );
    if ( crypto_scalarmult( shared_secret.data(), V_kx_sk.data(), U_kx_pk.data() ) == -1 ) {
        cout << "crypto_scalarmult error";
        return;
    }

    // Derive key and IV
    vector<uint8_t> salt( PSK );
    vector<uint8_t> PRK = hkdf_extract_sha_256( salt, shared_secret );
    vector<uint8_t> info_K_2 = gen_info( cbor_uint8( aead_algorithm_id ), 128, TH_2 );
    vector<uint8_t> K_2 = hkdf_expand_sha_256( PRK, info_K_2, 16 );
    vector<uint8_t> info_IV_2 = gen_info( cbor_tstr( "IV-GENERATION" ), 104, TH_2 );
    vector<uint8_t> IV_2 = hkdf_expand_sha_256( PRK, info_IV_2, 13 );

    // Calculate ciphertext
    vector<uint8_t> P_2; // empty byte string
    vector<uint8_t> A_2 = { 0x83 }; // CBOR array of length 3
    vector_append( A_2, cbor_tstr( "Encrypt0" ) );
    vector_append( A_2, cbor_bstr( { } ) ); // empty bstr 
    vector_append( A_2, cbor_bstr( TH_2 ) );
    vector<uint8_t> C_2 = aes_ccm_16_64_128( K_2, IV_2, P_2, A_2 );

    // Calculate message_2
    vector<uint8_t> message_2;
    vector_append( message_2, data_2 );
    vector_append( message_2, cbor_bstr( C_2 ) ); 

    // Print
    print_vector( "Party V's ephemeral private key", V_kx_sk );
    print_vector( "Party V's ephemeral public key (value of X_V)", V_kx_pk );
    print_vector( "ECDH shared secret", shared_secret );
    print_vector( "salt", salt );
    print_vector( "PRK", PRK );   
    print_vector( "Connection identifier chosen by V (value of C_V)", C_V );

    cout << endl;
    cout << "data_2 =" << endl;
    cout << "(" << endl;
    print_cddl_bstr( V_kx_pk );
    print_cddl_bstr( C_V );
    cout << ")" << endl;

    print_vector( "data_2 (CBOR Sequence)", data_2 );
    print_vector( "Input to SHA-256 to calculate TH_2 ( message_1, data_2 ) (CBOR Sequence)", TH_2_input );
    print_vector( "TH_2 (CBOR-encoded)",  cbor_bstr( TH_2 ) );

    cout << endl;
    cout << "COSE_KDF_Context =" << endl;
    cout << "[" << endl;
    print_cddl_int( aead_algorithm_id );
    cout << "  [ null, null, null ]," << endl;
    cout << "  [ null, null, null ]," << endl;
    cout << "  [ 128, h'', h'";
    for ( auto i : TH_2 )
        cout << hex << setfill('0') << setw(2) << (int)i;
    cout << "' ]," << endl;
    cout << "]" << endl;

    print_vector( "info (K_2) (CBOR-encoded)", info_K_2 );   
    print_vector( "K_2", K_2 );   

    cout << endl;
    cout << "COSE_KDF_Context =" << endl;
    cout << "[" << endl;
    cout << "  \"IV-GENERATION\"," << endl;
    cout << "  [ null, null, null ]," << endl;
    cout << "  [ null, null, null ]," << endl;
    cout << "  [ 104, h'', h'";
    for ( auto i : TH_2 )
        cout << hex << setfill('0') << setw(2) << (int)i;
    cout << "' ]," << endl;
    cout << "]" << endl;

    print_vector( "info (IV_2) (CBOR-encoded)", info_IV_2 );   
    print_vector( "IV_2", IV_2 );   
    print_vector( "P_2", P_2 );   

    cout << endl;
    cout << "A_2 =" << endl;
    cout << "[" << endl;
    cout << "  \"Encrypt0\"," << endl;
    cout << "  h''," << endl;
    cout << "  h'";
    for ( auto i : TH_2 )
        cout << hex << setfill('0') << setw(2) << (int)i;
    cout << "' ]," << endl;
    cout << "]" << endl;

    print_vector( "A_2 (CBOR-encoded)", A_2 );   
    print_vector( "C_2", C_2 );   

    cout << endl;
    cout << "message_2 =" << endl;
    cout << "(" << endl;
    print_cddl_bstr( V_kx_pk );
    print_cddl_bstr( C_V );
    print_cddl_bstr( C_2 );
    cout << ")" << endl;

    print_vector( "message_2 (CBOR Sequence)", message_2 );

    print_line();

    // message_3 ////////////////////////////////////////////////////////////////////////////

    // Calculate data_3
    vector<uint8_t> data_3;
    vector_append( data_3, cbor_bstr( C_V ) );

    // Calculate TH_3
    vector<uint8_t> TH_3_input;
    vector_append( TH_3_input, cbor_bstr( TH_2 ) );
    vector_append( TH_3_input, cbor_bstr( C_2 ) );
    vector_append( TH_3_input, data_3 );
    vector<uint8_t> TH_3 = hash_sha_256( TH_3_input );

    // Derive key and IV
    vector<uint8_t> info_K_3 = gen_info( cbor_uint8( aead_algorithm_id ), 128, TH_3 );
    vector<uint8_t> K_3 = hkdf_expand_sha_256( PRK, info_K_3, 16 );
    vector<uint8_t> info_IV_3 = gen_info( cbor_tstr( "IV-GENERATION" ), 104, TH_3 );
    vector<uint8_t> IV_3 = hkdf_expand_sha_256( PRK, info_IV_3, 13 );

    // Calculate ciphertext
    vector<uint8_t> P_3; // empty byte string
    vector<uint8_t> A_3 = { 0x83 }; // CBOR array of length 3
    vector_append( A_3, cbor_tstr( "Encrypt0" ) );
    vector_append( A_3, cbor_bstr( { } ) ); // empty bstr 
    vector_append( A_3, cbor_bstr( TH_3 ) );
    vector<uint8_t> C_3 = aes_ccm_16_64_128( K_3, IV_3, P_3, A_3 );

    // Calculate message_3
    vector<uint8_t> message_3;
    vector_append( message_3, data_3 );
    vector_append( message_3, cbor_bstr( C_3 ) );

    // Print
    cout << endl;
    cout << "data_3 =" << endl;
    cout << "(" << endl;
    print_cddl_bstr( C_V );
    cout << ")" << endl;

    print_vector( "data_3 (CBOR Sequence)", data_3 );
    print_vector( "Input to SHA-256 to calculate TH_3 ( TH_2, CIPHERTEXT_2, data_3 ) (CBOR Sequence)", TH_3_input );
    print_vector( "TH_3 (CBOR-encoded)", cbor_bstr( TH_3 ) );

    cout << endl;
    cout << "COSE_KDF_Context =" << endl;
    cout << "[" << endl;
    print_cddl_int( aead_algorithm_id );
    cout << "  [ null, null, null ]," << endl;
    cout << "  [ null, null, null ]," << endl;
    cout << "  [ 128, h'', h'";
    for ( auto i : TH_3 )
        cout << hex << setfill('0') << setw(2) << (int)i;
    cout << "' ]," << endl;
    cout << "]" << endl;

    print_vector( "info (K_3) (CBOR-encoded)", info_K_3 );   
    print_vector( "K_3", K_3 );   

    cout << endl;
    cout << "COSE_KDF_Context =" << endl;
    cout << "[" << endl;
    cout << "  \"IV-GENERATION\"," << endl;
    cout << "  [ null, null, null ]," << endl;
    cout << "  [ null, null, null ]," << endl;
    cout << "  [ 104, h'', h'";
    for ( auto i : TH_3 )
        cout << hex << setfill('0') << setw(2) << (int)i;
    cout << "' ]," << endl;
    cout << "]" << endl;

    print_vector( "info (IV_3) (CBOR-encoded)", info_IV_3 );   
    print_vector( "IV_3", IV_3 );   

    cout << endl;
    cout << "A_3 =" << endl;
    cout << "[" << endl;
    cout << "  \"Encrypt0\"," << endl;
    cout << "  h''," << endl;
    cout << "  h'";
    for ( auto i : TH_3 )
        cout << hex << setfill('0') << setw(2) << (int)i;
    cout << "' ]," << endl;
    cout << "]" << endl;

    print_vector( "A_3 (CBOR-encoded)", A_3 );   
    print_vector( "P_3", P_3 );   
    print_vector( "C_3", C_3 );   

    cout << endl;
    cout << "message_3 =" << endl;
    cout << "(" << endl;
    print_cddl_bstr( C_V );
    print_cddl_bstr( C_3 );
    cout << ")" << endl;

    print_vector( "message_3 (CBOR Sequence)", message_3 );

    print_line();

    // OSCORE ////////////////////////////////////////////////////////////////////////////

    // Calculate TH_4
    vector<uint8_t> TH_4_input;
    vector_append( TH_4_input, cbor_bstr( TH_3 ) );
    vector_append( TH_4_input, cbor_bstr( C_3 ) );
    vector<uint8_t> TH_4 = hash_sha_256( TH_4_input );

    // Derive OSCORE Master Secret and Salt
    vector<uint8_t> info_OSCORE_secret = gen_info( cbor_tstr( "OSCORE Master Secret" ), 128, TH_4 );
    vector<uint8_t> OSCORE_secret = hkdf_expand_sha_256( PRK,  info_OSCORE_secret, 16 );
    vector<uint8_t> info_OSCORE_salt = gen_info( cbor_tstr( "OSCORE Master Salt" ), 64, TH_4 );
    vector<uint8_t> OSCORE_salt = hkdf_expand_sha_256( PRK, info_OSCORE_salt, 8 );

    // Print
    print_vector( "Input to SHA-256 to calculate TH_4 ( TH_3, CIPHERTEXT_3 ) (CBOR Sequence)", TH_4_input );

    print_vector( "TH_4 (CBOR-encoded)", cbor_bstr( TH_4 ) );

    cout << endl;
    cout << "COSE_KDF_Context =" << endl;
    cout << "[" << endl;
    cout << "  \"OSCORE Master Secret\"," << endl;
    cout << "  [ null, null, null ]," << endl;
    cout << "  [ null, null, null ]," << endl;
    cout << "  [ 128, h'', h'";
    for ( auto i : TH_4 )
        cout << hex << setfill('0') << setw(2) << (int)i;
    cout << "' ]," << endl;
    cout << "]" << endl;

    print_vector( "info (OSCORE Master Secret) (CBOR-encoded)", info_OSCORE_secret );   

    print_vector( "OSCORE Master Secret", OSCORE_secret );

    cout << endl;
    cout << "COSE_KDF_Context =" << endl;
    cout << "[" << endl;
    cout << "  \"OSCORE Master Salt\"," << endl;
    cout << "  [ null, null, null ]," << endl;
    cout << "  [ null, null, null ]," << endl;
    cout << "  [ 64, h'', h'";
    for ( auto i : TH_4 )
        cout << hex << setfill('0') << setw(2) << (int)i;
    cout << "' ]," << endl;
    cout << "]" << endl;

    print_vector( "info (OSCORE Master Salt) (CBOR-encoded)", info_OSCORE_salt );   

    print_vector( "OSCORE Master Salt", OSCORE_salt );

    print_vector( "Client's OSCORE Sender ID", C_V );

    print_vector( "Server's OSCORE Sender ID", C_U );

    print_int( "AEAD Algorithm", aead_algorithm_id );

    print_int( "HKDF Algorithm", hkdf_algorithm_id );
}

void rpk_vectors( void )
{
    print_line();
    cout << "Test Vectors for EDHOC Authenticated with RPK";
    print_line();

    // Pre-shared stuff ////////////////////////////////////////////////////////////////////////////

    // This uses RFC 8032 notation, libsodium uses the notation from the Ed25519 paper by Bernstein
    // Libsodium seed = RFC 8032 sk
    // Libsodium sk = pruned SHA-512(sk) in RFC 8032

    // The content and ordering of COSE_KEY is not specified in draft-selander-ace-cose-ecdhe-13
    // Suggested Content: Only labels 1 (kty), -1 (EC identifier), -2 (x-coordinate), -3 (y-coordinate only in EC2)
    // Suggested Order: decreasing

    // Generate Party U's authentication key pair
    vector<uint8_t> U_sign_pk( crypto_sign_PUBLICKEYBYTES );
    vector<uint8_t> U_sign_sk_libsodium( crypto_sign_SECRETKEYBYTES );
    vector<uint8_t> U_sign_sk(crypto_sign_SEEDBYTES );
    vector<uint8_t> U_sign_seed( randombytes_SEEDBYTES, 4 ); 
    randombytes_buf_deterministic( U_sign_sk.data(), U_sign_sk.size(), U_sign_seed.data() );
    crypto_sign_seed_keypair( U_sign_pk.data(), U_sign_sk_libsodium.data(), U_sign_sk.data() );

    vector<uint8_t> kid_U { 0xa2 };
    vector<uint8_t> ID_CRED_U_CBOR = { 0xa1, 0x04 }; // CBOR map(1), label = 4
    vector_append( ID_CRED_U_CBOR, cbor_bstr( kid_U ) );
    vector<uint8_t> CRED_U_CBOR { 0xa3, 0x01, 0x01, 0x20, 0x06, 0x21,  }; // CBOR map(3), 1, 1, -1, 6, -2
    vector_append( CRED_U_CBOR, cbor_bstr( U_sign_pk ) );

    // Generate Party V's authentication key pair
    vector<uint8_t> V_sign_pk( crypto_sign_PUBLICKEYBYTES );
    vector<uint8_t> V_sign_sk_libsodium( crypto_sign_SECRETKEYBYTES );
    vector<uint8_t> V_sign_sk(crypto_sign_SEEDBYTES );
    vector<uint8_t> V_sign_seed( randombytes_SEEDBYTES, 5 ); 
    randombytes_buf_deterministic( V_sign_sk.data(), V_sign_sk.size(), V_sign_seed.data() );
    crypto_sign_seed_keypair( V_sign_pk.data(), V_sign_sk_libsodium.data(), V_sign_sk.data() );

    vector<uint8_t> kid_V { 0xa3 };
    vector<uint8_t> ID_CRED_V_CBOR = { 0xa1, 0x04 }; // CBOR map(1) label = 4
    vector_append( ID_CRED_V_CBOR, cbor_bstr( kid_V ) );
    vector<uint8_t> CRED_V_CBOR { 0xa3, 0x01, 0x01, 0x20, 0x06, 0x21,  }; // CBOR map(3), 1, 1, -1, 6, -2
    vector_append( CRED_V_CBOR, cbor_bstr( V_sign_pk ) );

    /* Print */
    print_vector( "Party U's private authentication key", U_sign_sk );
    print_vector( "Party U's public authentication key", U_sign_pk );
    print_vector( "kid value to identify U's public authentication key", kid_U );

    cout << endl;
    cout << "ID_CRED_U =" << endl;
    cout << "{" << endl;
    cout << "  4:";
    print_cddl_bstr( kid_U );
    cout << "}" << endl;

    cout << endl << "The header_map contains a single 'kid' parameter, so ID_CRED_U is encoded as a CBOR bstr in the plaintext)" << endl;

    print_vector( "ID_CRED_U (in protected header) (CBOR-encoded)",  ID_CRED_U_CBOR );

    print_vector( "ID_CRED_U (in plaintext) (CBOR-encoded)", cbor_bstr( kid_U ) );

    cout << endl;
    cout << "CRED_U =" << endl;
    cout << "{" << endl;
    cout << "  1:  1," << endl;
    cout << " -1:  6," << endl;
    cout << " -2:  h'";
    for ( auto i : U_sign_pk )
        cout << hex << setfill('0') << setw(2) << (int)i;
    cout << "'," << endl << "}" << endl;

    print_vector( "CRED_U (COSE_KEY) (CBOR-encoded)", CRED_U_CBOR );

    print_vector( "Party V's private authentication key", V_sign_sk );
    print_vector( "Party V's public authentication key", V_sign_pk );
    print_vector( "kid value to identify V's public authentication key", kid_V );

    cout << endl;
    cout << "ID_CRED_V =" << endl;
    cout << "{" << endl;
    cout << "  4:";
    print_cddl_bstr( kid_V );
    cout << "}" << endl;

    cout << endl << "The header_map contains a single 'kid' parameter, so ID_CRED_V is encoded as a CBOR bstr in the plaintext)" << endl;

    print_vector( "ID_CRED_V (encoding in protected header) (CBOR-encoded)",  ID_CRED_V_CBOR );

    print_vector( "ID_CRED_V (encoding in plaintext) (CBOR-encoded)", cbor_bstr( kid_V ) );

    cout << endl;
    cout << "CRED_V =" << endl;
    cout << "{" << endl;
    cout << "  1:  1," << endl;
    cout << " -1:  6," << endl;
    cout << " -2:  h'";
    for ( auto i : V_sign_pk )
        cout << hex << setfill('0') << setw(2) << (int)i;
    cout << "'," << endl << "}" << endl;

    print_vector( "CRED_V (COSE_KEY) (CBOR-encoded)", CRED_V_CBOR );

    print_line();

    // message_1 ////////////////////////////////////////////////////////////////////////////

    // Generate the Party U's ephemeral key pair
    vector<uint8_t> U_kx_pk( crypto_kx_PUBLICKEYBYTES );
    vector<uint8_t> U_kx_sk( crypto_kx_SECRETKEYBYTES );
    vector<uint8_t> U_kx_seed( crypto_kx_SEEDBYTES, 6 ); ;
    crypto_kx_seed_keypair( U_kx_pk.data(), U_kx_sk.data(), U_kx_seed.data() );

    // Other parameters
    uint8_t method = 0; // Asymmetric
    uint8_t corr = 1; // Party U is CoAP client
    uint8_t TYPE = 4 * method + corr;
    uint8_t suite = 0; // [ 10, -27, 4, -8, 6 ] AES-CCM-16-64-128, ECDH-SS + HKDF-256, X25519, EdDSA, Ed25519
    int aead_algorithm_id = 10;
    int hkdf_algorithm_id = -27;
    vector<uint8_t> C_U { 0xc3 };

    // Calculate message_1
    vector<uint8_t> message_1;
    vector_append( message_1, cbor_uint8( TYPE ) ); 
    vector_append( message_1, cbor_uint8( suite ) ); 
    vector_append( message_1, cbor_bstr( U_kx_pk ) ); 
    vector_append( message_1, cbor_bstr( C_U ) ); 

    // Print
    print_int( "method (Asymmetric Authentication)", method );
    print_int( "corr (Party U is CoAP client)", corr );
    print_int( "TYPE (4 * method + corr)", TYPE );   
    print_int( "suite", suite );
    print_vector( "Party U's ephemeral private key", U_kx_sk );
    print_vector( "Party U's ephemeral public key (value of X_U)", U_kx_pk );
    print_vector( "Connection identifier chosen by U (value of C_U)", C_U );

    cout << endl;
    cout << "message_1 =" << endl;
    cout << "(" << endl;
    print_cddl_int( TYPE );
    print_cddl_int( suite );
    print_cddl_bstr( U_kx_pk );
    print_cddl_bstr( C_U );
    cout << ")" << endl;

    print_vector( "message_1 (CBOR Sequence)", message_1 );

    print_line();

    // message_2 ////////////////////////////////////////////////////////////////////////////

    /* Generate the Party V's ephemeral key pair */
    vector<uint8_t> V_kx_pk( crypto_kx_PUBLICKEYBYTES );
    vector<uint8_t> V_kx_sk( crypto_kx_SECRETKEYBYTES );
    vector<uint8_t> V_kx_seed( crypto_kx_SEEDBYTES, 7 ); ;
    crypto_kx_seed_keypair( V_kx_pk.data(), V_kx_sk.data(), V_kx_seed.data() );

    // Other parameters
    vector<uint8_t> C_V { 0xc4 };

    // Calculate data_2
    vector<uint8_t> data_2;
    vector_append( data_2, cbor_bstr( V_kx_pk ) ); 
    vector_append( data_2, cbor_bstr( C_V ) ); 

    // Calculate TH_2
    vector<uint8_t> TH_2_input;
    vector_append( TH_2_input, message_1 );
    vector_append( TH_2_input, data_2 );
    vector<uint8_t> TH_2 = hash_sha_256( TH_2_input );

    // Calculate ECDH shared secret
    vector<uint8_t> shared_secret( crypto_scalarmult_BYTES );
    if ( crypto_scalarmult( shared_secret.data(), V_kx_sk.data(), U_kx_pk.data() ) == -1 ) {
        cout << "crypto_scalarmult error";
        return;
    }

    // Calculate signature
    vector<uint8_t> message_V { 0x84 }; // CBOR array of length 4
    vector_append( message_V, cbor_tstr( "Signature1" ) );
    vector_append( message_V, cbor_bstr( ID_CRED_V_CBOR ) );
    vector_append( message_V, cbor_bstr( TH_2 ) );
    vector_append( message_V, CRED_V_CBOR );
    vector<uint8_t> signature_V( crypto_sign_BYTES );
    crypto_sign_detached( signature_V.data(), nullptr, message_V.data(), message_V.size(), V_sign_sk_libsodium.data() );

    // Derive key and IV
    vector<uint8_t> salt; // empty byte string;
    vector<uint8_t> PRK = hkdf_extract_sha_256( salt, shared_secret );
    vector<uint8_t> info_K_2 = gen_info( cbor_uint8( aead_algorithm_id ), 128, TH_2 );
    vector<uint8_t> K_2 = hkdf_expand_sha_256( PRK, info_K_2, 16 );
    vector<uint8_t> info_IV_2 = gen_info( cbor_tstr( "IV-GENERATION" ), 104, TH_2 );
    vector<uint8_t> IV_2 = hkdf_expand_sha_256( PRK, info_IV_2, 13 );

    // Calculate ciphertext
    vector<uint8_t> P_2;
    vector_append( P_2, cbor_bstr( kid_V ) ); // ID_CRED_V contains a single 'kid' parameter, so only bstr is used
    vector_append( P_2, cbor_bstr( signature_V ) );
    vector<uint8_t> A_2 = { 0x83 }; // CBOR array of length 3
    vector_append( A_2, cbor_tstr( "Encrypt0" ) );
    vector_append( A_2, cbor_bstr( { } ) ); // empty bstr 
    vector_append( A_2, cbor_bstr( TH_2 ) );
    vector<uint8_t> C_2 = aes_ccm_16_64_128( K_2, IV_2, P_2, A_2 );

    // Calculate message_2
    vector<uint8_t> message_2;
    vector_append( message_2, data_2 );
    vector_append( message_2, cbor_bstr( C_2 ) ); 

    // Print
    print_vector( "Party V's ephemeral private key", V_kx_sk );
    print_vector( "Party V's ephemeral public key (value of X_V)", V_kx_pk );
    print_vector( "ECDH shared secret", shared_secret );
    print_vector( "salt", salt );   
    print_vector( "PRK", PRK );   
    print_vector( "Connection identifier chosen by V (value of C_V)", C_V );

    cout << endl;
    cout << "data_2 =" << endl;
    cout << "(" << endl;
    print_cddl_bstr( V_kx_pk );
    print_cddl_bstr( C_V );
    cout << ")" << endl;

    print_vector( "data_2 (CBOR Sequence)", data_2 );
    print_vector( "Input to SHA-256 to calculate TH_2 ( message_1, data_2 ) (CBOR Sequence)", TH_2_input );
    print_vector( "TH_2 (CBOR-encoded)", cbor_bstr( TH_2 ) );

    cout << endl;
    cout << "M_V =" << endl;
    cout << "[" << endl;
    cout << "  \"Signature1\"," << endl;
    cout << "  << { 4: h'";
    for ( auto i : kid_V )
        cout << hex << setfill('0') << setw(2) << (int)i;
    cout << "' } >>," << endl;
    print_cddl_bstr( TH_2 );
    cout << "  {" << endl;
    cout << "    1:  1," << endl;
    cout << "   -1:  6," << endl;
    cout << "   -2:  h'";
    for ( auto i : V_sign_pk )
        cout << hex << setfill('0') << setw(2) << (int)i;
    cout << "'," << endl << "  }," << endl;
    cout << "]" << endl;

    print_vector( "M_V (message to be signed with Ed25519) (CBOR-encoded)", message_V );
    print_vector( "V's signature", signature_V );

    cout << endl;
    cout << "COSE_KDF_Context =" << endl;
    cout << "[" << endl;
    print_cddl_int( aead_algorithm_id );
    cout << "  [ null, null, null ]," << endl;
    cout << "  [ null, null, null ]," << endl;
    cout << "  [ 128, h'', h'";
    for ( auto i : TH_2 )
        cout << hex << setfill('0') << setw(2) << (int)i;
    cout << "' ]," << endl;
    cout << "]" << endl;

    print_vector( "info (K_2) (CBOR-encoded)", info_K_2 );   
    print_vector( "K_2", K_2 );   

    cout << endl;
    cout << "COSE_KDF_Context =" << endl;
    cout << "[" << endl;
    cout << "  \"IV-GENERATION\"," << endl;
    cout << "  [ null, null, null ]," << endl;
    cout << "  [ null, null, null ]," << endl;
    cout << "  [ 104, h'', h'";
    for ( auto i : TH_2 )
        cout << hex << setfill('0') << setw(2) << (int)i;
    cout << "' ]," << endl;
    cout << "]" << endl;

    print_vector( "info (IV_2) (CBOR-encoded)", info_IV_2 );   
    print_vector( "IV_2", IV_2 );   
    print_vector( "P_2", P_2 );   

    cout << endl;
    cout << "A_2 =" << endl;
    cout << "[" << endl;
    cout << "  \"Encrypt0\"," << endl;
    cout << "  h''," << endl;
    cout << "  h'";
    for ( auto i : TH_2 )
        cout << hex << setfill('0') << setw(2) << (int)i;
    cout << "' ]," << endl;
    cout << "]" << endl;

    print_vector( "A_2 (CBOR-encoded)", A_2 );   
    print_vector( "C_2", C_2 );   

    cout << endl;
    cout << "message_2 =" << endl;
    cout << "(" << endl;
    print_cddl_bstr( V_kx_pk );
    print_cddl_bstr( C_V );
    print_cddl_bstr( C_2 );
    cout << ")" << endl;

    print_vector( "message_2 (CBOR Sequence)", message_2 );

    print_line();

    // message_3 ////////////////////////////////////////////////////////////////////////////

    // Calculate data_3
    vector<uint8_t> data_3;
    vector_append( data_3, cbor_bstr( C_V ) );

    // Calculate TH_3
    vector<uint8_t> TH_3_input;
    vector_append( TH_3_input, cbor_bstr( TH_2 ) );
    vector_append( TH_3_input, cbor_bstr( C_2 ) );
    vector_append( TH_3_input, data_3 );
    vector<uint8_t> TH_3 = hash_sha_256( TH_3_input );

    // Calculate signature
    vector<uint8_t> message_U { 0x84 }; // CBOR array of length 4
    vector_append( message_U, cbor_tstr( "Signature1" ) );
    vector_append( message_U, cbor_bstr( ID_CRED_U_CBOR ) );
    vector_append( message_U, cbor_bstr( TH_3 ) );
    vector_append( message_U, CRED_U_CBOR );
    vector<uint8_t> signature_U( crypto_sign_BYTES );
    crypto_sign_detached( signature_U.data(), nullptr, message_U.data(), message_U.size(), U_sign_sk_libsodium.data() );

    // Derive key and IV
    vector<uint8_t> info_K_3 = gen_info( cbor_uint8( aead_algorithm_id ), 128, TH_3 );
    vector<uint8_t> K_3 = hkdf_expand_sha_256( PRK, info_K_3, 16 );
    vector<uint8_t> info_IV_3 = gen_info( cbor_tstr( "IV-GENERATION" ), 104, TH_3 );
    vector<uint8_t> IV_3 = hkdf_expand_sha_256( PRK, info_IV_3, 13 );

    // Calculate ciphertext
    vector<uint8_t> P_3;
    vector_append( P_3, cbor_bstr( kid_U ) ); // ID_CRED_U contains a single 'kid' parameter, so only bstr is used
    vector_append( P_3, cbor_bstr( signature_U ) );
    vector<uint8_t> A_3 = { 0x83 }; // CBOR array of length 3
    vector_append( A_3, cbor_tstr( "Encrypt0" ) );
    vector_append( A_3, cbor_bstr( { } ) ); // empty bstr 
    vector_append( A_3, cbor_bstr( TH_3 ) );
    vector<uint8_t> C_3 = aes_ccm_16_64_128( K_3, IV_3, P_3, A_3 );

    // Calculate message_3
    vector<uint8_t> message_3;
    vector_append( message_3, data_3 );
    vector_append( message_3, cbor_bstr( C_3 ) );

    // Print
    cout << endl;
    cout << "data_3 =" << endl;
    cout << "(" << endl;
    print_cddl_bstr( C_V );
    cout << ")" << endl;

    print_vector( "data_3 (CBOR Sequence)", data_3 );
    print_vector( "Input to SHA-256 to calculate TH_3 ( TH_2, CIPHERTEXT_2, data_3 ) (CBOR Sequence)", TH_3_input );
    print_vector( "TH_3 (CBOR-encoded)", cbor_bstr( TH_3 ) );

    cout << endl;
    cout << "M_U =" << endl;
    cout << "[" << endl;
    cout << "  \"Signature1\"," << endl;
    cout << "  << { 4: h'";
    for ( auto i : kid_U )
        cout << hex << setfill('0') << setw(2) << (int)i;
    cout << "' } >>," << endl;
    print_cddl_bstr( TH_3 );
    cout << "  {" << endl;
    cout << "    1:  1," << endl;
    cout << "   -1:  6," << endl;
    cout << "   -2:  h'";
    for ( auto i : U_sign_pk )
        cout << hex << setfill('0') << setw(2) << (int)i;
    cout << "'," << endl << "  }," << endl;
    cout << "]" << endl;

    print_vector( "M_U (message to be signed with Ed25519) (CBOR-encoded)", message_U );
    print_vector( "U's signature", signature_U );

    cout << endl;
    cout << "COSE_KDF_Context =" << endl;
    cout << "[" << endl;
    print_cddl_int( aead_algorithm_id );
    cout << "  [ null, null, null ]," << endl;
    cout << "  [ null, null, null ]," << endl;
    cout << "  [ 128, h'', h'";
    for ( auto i : TH_3 )
        cout << hex << setfill('0') << setw(2) << (int)i;
    cout << "' ]," << endl;
    cout << "]" << endl;

    print_vector( "info (K_3) (CBOR-encoded)", info_K_3 );   
    print_vector( "K_3", K_3 );   

    cout << endl;
    cout << "COSE_KDF_Context =" << endl;
    cout << "[" << endl;
    cout << "  \"IV-GENERATION\"," << endl;
    cout << "  [ null, null, null ]," << endl;
    cout << "  [ null, null, null ]," << endl;
    cout << "  [ 104, h'', h'";
    for ( auto i : TH_3 )
        cout << hex << setfill('0') << setw(2) << (int)i;
    cout << "' ]," << endl;
    cout << "]" << endl;

    print_vector( "info (IV_3) (CBOR-encoded)", info_IV_3 );   
    print_vector( "IV_3", IV_3 );   

    cout << endl;
    cout << "A_3 =" << endl;
    cout << "[" << endl;
    cout << "  \"Encrypt0\"," << endl;
    cout << "  h''," << endl;
    cout << "  h'";
    for ( auto i : TH_3 )
        cout << hex << setfill('0') << setw(2) << (int)i;
    cout << "' ]," << endl;
    cout << "]" << endl;

    print_vector( "A_3 (CBOR-encoded)", A_3 );   
    print_vector( "P_3", P_3 );   
    print_vector( "C_3", C_3 );   

    cout << endl;
    cout << "message_3 =" << endl;
    cout << "(" << endl;
    print_cddl_bstr( C_V );
    print_cddl_bstr( C_3 );
    cout << ")" << endl;

    print_vector( "message_3 (CBOR Sequence)", message_3 );

    print_line();

    // OSCORE ////////////////////////////////////////////////////////////////////////////

    // Calculate TH_4
    vector<uint8_t> TH_4_input;
    vector_append( TH_4_input, cbor_bstr( TH_3 ) );
    vector_append( TH_4_input, cbor_bstr( C_3 ) );
    vector<uint8_t> TH_4 = hash_sha_256( TH_4_input );

    // Derive OSCORE Master Secret and Salt
    vector<uint8_t> info_OSCORE_secret = gen_info( cbor_tstr( "OSCORE Master Secret" ), 128, TH_4 );
    vector<uint8_t> OSCORE_secret = hkdf_expand_sha_256( PRK,  info_OSCORE_secret, 16 );
    vector<uint8_t> info_OSCORE_salt = gen_info( cbor_tstr( "OSCORE Master Salt" ), 64, TH_4 );
    vector<uint8_t> OSCORE_salt = hkdf_expand_sha_256( PRK, info_OSCORE_salt, 8 );

    // Print
    print_vector( "Input to SHA-256 to calculate TH_4 ( TH_3, CIPHERTEXT_3 ) (CBOR Sequence)", TH_4_input );

    print_vector( "TH_4 (CBOR-encoded)", cbor_bstr( TH_4 ) );

    cout << endl;
    cout << "COSE_KDF_Context =" << endl;
    cout << "[" << endl;
    cout << "  \"OSCORE Master Secret\"," << endl;
    cout << "  [ null, null, null ]," << endl;
    cout << "  [ null, null, null ]," << endl;
    cout << "  [ 128, h'', h'";
    for ( auto i : TH_4 )
        cout << hex << setfill('0') << setw(2) << (int)i;
    cout << "' ]," << endl;
    cout << "]" << endl;

    print_vector( "info (OSCORE Master Secret) (CBOR-encoded)", info_OSCORE_secret );   

    print_vector( "OSCORE Master Secret", OSCORE_secret );

    cout << endl;
    cout << "COSE_KDF_Context =" << endl;
    cout << "[" << endl;
    cout << "  \"OSCORE Master Salt\"," << endl;
    cout << "  [ null, null, null ]," << endl;
    cout << "  [ null, null, null ]," << endl;
    cout << "  [ 64, h'', h'";
    for ( auto i : TH_4 )
        cout << hex << setfill('0') << setw(2) << (int)i;
    cout << "' ]," << endl;
    cout << "]" << endl;

    print_vector( "info (OSCORE Master Salt) (CBOR-encoded)", info_OSCORE_salt );   

    print_vector( "OSCORE Master Salt", OSCORE_salt );

    print_vector( "Client's OSCORE Sender ID", C_V );

    print_vector( "Server's OSCORE Sender ID", C_U );

    print_int( "AEAD Algorithm", aead_algorithm_id );

    print_int( "HKDF Algorithm", hkdf_algorithm_id );
}

int main( void )
{
    // Initiate Sodium
    if ( sodium_init() == -1 ) {
        cout << "The libsodoum library couldn't be initialized";
        return 1;
    }

    psk_vectors();
    rpk_vectors();
}
