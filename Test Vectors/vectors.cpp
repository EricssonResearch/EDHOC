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

// CBOR encodes a bstr_indentifier
vector<uint8_t> cbor_bstr_id( vector<uint8_t> v ) {
    if ( v.size() == 1 ) {
        int i = v[0] - 24;
        if ( i < 0 )
            return { (uint8_t)(31 - i) };
        else
            return cbor_uint8( i );
    }
    else
        return cbor_bstr(v);
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

vector<uint8_t> hkdf_expand_sha_256( vector<uint8_t> PRK, vector<uint8_t> info, int L ) {
    vector<uint8_t> out;
    vector<uint8_t> T( { } );
    for ( int i = 0; i <= L / 32; i++ ) {
        vector<uint8_t> m( T );
        vector_append( m, info );
        m.push_back( uint8_t( i + 1 ) );
        T = hmac_sha_256( PRK, m );
        vector_append( out, T );
    }
    out.resize( L );
    return out;
}

vector<uint8_t> aes_ccm_16_64_128( vector<uint8_t> K, vector<uint8_t> N, vector<uint8_t> P, vector<uint8_t> A ) {
    vector<uint8_t> C( P.size() + 8 );
    int r = aes_ccm_ae( K.data(), 16, N.data(), 8, P.data(), P.size(), A.data(), A.size(), C.data(), C.data() + P.size() );
    return C;
}

vector<uint8_t> xor_encryption( vector<uint8_t> K, vector<uint8_t> P ) {
    vector<uint8_t> C( P );
    for( int i = 0; i < C.size(); ++i )
        C[i] ^= K[i];
    return C;
}

// Creates the info parameter for HKDF
vector<uint8_t> gen_info( vector<uint8_t> AlgorithmID_CBOR, int keyDataLength, vector<uint8_t> protect, vector<uint8_t> other )
{
    vector<uint8_t> info { 0x84 }; // CBOR array of length 4
    vector_append( info, AlgorithmID_CBOR );
    vector_append( info, { 0x83, 0xf6, 0xf6, 0xf6 } ); // CBOR encoding of [ null, null, null ]
    vector_append( info, { 0x83, 0xf6, 0xf6, 0xf6 } ); // CBOR encoding of [ null, null, null ]
    info.push_back( 0x83 ); // CBOR array of length 3
    vector_append( info, cbor_uint8( keyDataLength ) ); // keyDataLength is in bits
    vector_append( info, cbor_bstr( protect ) );
    vector_append( info, cbor_bstr( other ) ); // other = TH_i
    return info;
}

void sig_sig_vectors( void )
{
    ///////////////////////////////////////////////////////////////////////////////////////////
    // Calculate stuff ////////////////////////////////////////////////////////////////////////
    ///////////////////////////////////////////////////////////////////////////////////////////

    // This uses RFC 8032 notation, libsodium uses the notation from the Ed25519 paper by Bernstein
    // Libsodium seed = RFC 8032 sk
    // Libsodium sk = pruned SHA-512(sk) in RFC 8032

    // Pre-shared stuff ////////////////////////////////////////////////////////////////////////////

    // Generate Party Initiator's COSE_Key
    vector<uint8_t> I_auth_pk( crypto_sign_PUBLICKEYBYTES );
    vector<uint8_t> I_auth_sk_libsodium( crypto_sign_SECRETKEYBYTES );
    vector<uint8_t> I_auth_sk(crypto_sign_SEEDBYTES );
    vector<uint8_t> I_auth_seed( randombytes_SEEDBYTES, 4 ); 
    randombytes_buf_deterministic( I_auth_sk.data(), I_auth_sk.size(), I_auth_seed.data() );
    crypto_sign_seed_keypair( I_auth_pk.data(), I_auth_sk_libsodium.data(), I_auth_sk.data() );
    vector<uint8_t> kid_I { 0x2a };

    // Generate Party Responders's COSE_Key
    vector<uint8_t> R_auth_pk( crypto_sign_PUBLICKEYBYTES );
    vector<uint8_t> R_auth_sk_libsodium( crypto_sign_SECRETKEYBYTES );
    vector<uint8_t> R_auth_sk(crypto_sign_SEEDBYTES );
    vector<uint8_t> R_auth_seed( randombytes_SEEDBYTES, 5 ); 
    randombytes_buf_deterministic( R_auth_sk.data(), R_auth_sk.size(), R_auth_seed.data() );
    crypto_sign_seed_keypair( R_auth_pk.data(), R_auth_sk_libsodium.data(), R_auth_sk.data() );
    vector<uint8_t> kid_R { 0x2b };
 
    uint8_t method = 0; // Signature + Signature

   // message_1 ////////////////////////////////////////////////////////////////////////////

    // Generate Initiator's ephemeral key pair
    vector<uint8_t> I_kx_pk( crypto_kx_PUBLICKEYBYTES );
    vector<uint8_t> I_kx_sk( crypto_kx_SECRETKEYBYTES );
    vector<uint8_t> I_kx_seed( crypto_kx_SEEDBYTES, 6 ); ;
    crypto_kx_seed_keypair( I_kx_pk.data(), I_kx_sk.data(), I_kx_seed.data() );

    // Other parameters
    uint8_t corr = 1; // Responder can correlate message_1 and message_2
    uint8_t METHOD_CORR = 4 * method + corr;
    uint8_t suite = 0; // ( 10, 5, 4, -8, 6, 10, 5 ) AES-CCM-16-64-128, HMAC 256/256, X25519, EdDSA, Ed25519, AES-CCM-16-64-128, HMAC 256/256
    int aead_algorithm_id = 10;
    int hmac_algorithm_id = 5;
    vector<uint8_t> C_I { 0x0a };

    // Calculate message_1
    vector<uint8_t> message_1;
    vector_append( message_1, cbor_uint8( METHOD_CORR ) ); 
    vector_append( message_1, cbor_uint8( suite ) ); 
    vector_append( message_1, cbor_bstr( I_kx_pk ) ); 
    vector_append( message_1, cbor_bstr_id( C_I ) ); 

   // message_2 ////////////////////////////////////////////////////////////////////////////

    // Generate Responder's ephemeral key pair
    vector<uint8_t> R_kx_pk( crypto_kx_PUBLICKEYBYTES );
    vector<uint8_t> R_kx_sk( crypto_kx_SECRETKEYBYTES );
    vector<uint8_t> R_kx_seed( crypto_kx_SEEDBYTES, 7 ); ;
    crypto_kx_seed_keypair( R_kx_pk.data(), R_kx_sk.data(), R_kx_seed.data() );

    // Derive PRK_2e
    vector<uint8_t> G_XY( crypto_scalarmult_BYTES );
    if ( crypto_scalarmult( G_XY.data(), R_kx_sk.data(), I_kx_pk.data() ) == -1 ) {
        cout << "crypto_scalarmult error";
        return;
    }
    vector<uint8_t> salt; // empty byte string;
    vector<uint8_t> PRK_2e = hkdf_extract_sha_256( salt, G_XY );

    // Derive PRK_3e2m
    vector<uint8_t> PRK_3e2m = PRK_2e;

    // Other parameters
    vector<uint8_t> C_R { 0x0b };

    // Calculate data_2
    vector<uint8_t> data_2;
    vector_append( data_2, cbor_bstr( R_kx_pk ) ); 
    vector_append( data_2, cbor_bstr_id( C_R ) ); 

    // Calculate TH_2
    vector<uint8_t> TH_2_input;
    vector_append( TH_2_input, message_1 );
    vector_append( TH_2_input, data_2 );
    vector<uint8_t> TH_2 = hash_sha_256( TH_2_input ); 

    // Calculate ID_CRED_R and CRED_R
    vector<uint8_t> ID_CRED_R = { 0xa1, 0x04 }; // CBOR map(1) label = 4
    vector_append( ID_CRED_R, cbor_bstr( kid_R ) );
    vector<uint8_t> CRED_R { 0xa3, 0x01, 0x01, 0x20, 0x06, 0x21,  }; // CBOR map(3), 1, 1, -1, 6, -2
    vector_append( CRED_R, cbor_bstr( R_auth_pk ) );

    // Calculate MAC_2
    vector<uint8_t> P_2m; // empty byte string
    vector<uint8_t> A_2m = { 0x83 }; // CBOR array of length 3
    vector_append( A_2m, cbor_tstr( "Encrypt0" ) );
    vector_append( A_2m, cbor_bstr( ID_CRED_R ) ); // << ID_CRED_R >>
    vector<uint8_t> external_aad_2 = { CRED_R };
    vector_append( external_aad_2, cbor_bstr( TH_2 ) );
    vector_append( A_2m, cbor_bstr( external_aad_2 ) ); // << CRED_R, TH_2 >>

    vector<uint8_t> info_K_2m = gen_info( cbor_uint8( aead_algorithm_id ), 128, cbor_bstr( ID_CRED_R ), TH_2 );
    vector<uint8_t> K_2m = hkdf_expand_sha_256( PRK_3e2m, info_K_2m, 16 );
    vector<uint8_t> info_IV_2m = gen_info( cbor_tstr( "IV-GENERATION" ), 104, cbor_bstr( ID_CRED_R ), TH_2 );
    vector<uint8_t> IV_2m = hkdf_expand_sha_256( PRK_3e2m, info_IV_2m, 13 );

    vector<uint8_t> MAC_2 = aes_ccm_16_64_128( K_2m, IV_2m, P_2m, A_2m );

    // Calculate Signature_or_MAC_2
    vector<uint8_t> M_2 { 0x84 }; // CBOR array of length 4
    vector_append( M_2, cbor_tstr( "Signature1" ) );
    vector_append( M_2, cbor_bstr( ID_CRED_R ) );
    vector_append( M_2, cbor_bstr( external_aad_2 ) );
    vector_append( M_2, cbor_bstr( MAC_2 ) );

    vector<uint8_t> signature_or_MAC_2( crypto_sign_BYTES );
    crypto_sign_detached( signature_or_MAC_2.data(), nullptr, M_2.data(), M_2.size(), R_auth_sk_libsodium.data() );

    // Calculate CIPHERTEXT_2
    vector<uint8_t> P_2e;
    vector_append( P_2e, cbor_bstr_id( kid_R ) ); 
    vector_append( P_2e, cbor_bstr( signature_or_MAC_2 ) );

    vector<uint8_t> info_K_2e = gen_info( cbor_tstr( "XOR-ENCRYPTION" ), 8 * P_2e.size(), { }, TH_2 );
    vector<uint8_t> K_2e = hkdf_expand_sha_256( PRK_2e, info_K_2e, P_2e.size() );
 
    vector<uint8_t> CIPHERTEXT_2 = xor_encryption( K_2e, P_2e );

    // Calculate message_2
    vector<uint8_t> message_2;
    vector_append( message_2, data_2 );
    vector_append( message_2, cbor_bstr( CIPHERTEXT_2 ) ); 

   // message_3 ////////////////////////////////////////////////////////////////////////////

    // Derive PRK_4x3m
    vector<uint8_t> PRK_4x3m = PRK_3e2m;

    // Calculate data_3
    vector<uint8_t> data_3;
    vector_append( data_3, cbor_bstr_id( C_R ) ); 

    // Calculate TH_3
    vector<uint8_t> TH_3_input;
    vector_append( TH_3_input, cbor_bstr( TH_2 ) );
    vector_append( TH_3_input, cbor_bstr( CIPHERTEXT_2 ) );
    vector_append( TH_3_input, data_3 );
    vector<uint8_t> TH_3 = hash_sha_256( TH_3_input );

    // Calculate ID_CRED_I and CRED_I
    vector<uint8_t> ID_CRED_I = { 0xa1, 0x04 }; // CBOR map(1), label = 4
    vector_append( ID_CRED_I, cbor_bstr( kid_I ) );
    vector<uint8_t> CRED_I { 0xa3, 0x01, 0x01, 0x20, 0x06, 0x21,  }; // CBOR map(3), 1, 1, -1, 6, -2
    vector_append( CRED_I, cbor_bstr( I_auth_pk ) );

    // Calculate MAC_3
    vector<uint8_t> P_3m; // empty byte string
    vector<uint8_t> A_3m = { 0x83 }; // CBOR array of length 3
    vector_append( A_3m, cbor_tstr( "Encrypt0" ) );
    vector_append( A_3m, cbor_bstr( ID_CRED_I ) ); // << ID_CRED_I >>
    vector<uint8_t> external_aad_3 = { CRED_I }; 
    vector_append( external_aad_3, cbor_bstr( TH_3 ) );
    vector_append( A_3m, cbor_bstr( external_aad_3 ) ); // << CRED_I, TH_3 >>

    vector<uint8_t> info_K_3m = gen_info( cbor_uint8( aead_algorithm_id ), 128, cbor_bstr( ID_CRED_I ), TH_3 );
    vector<uint8_t> K_3m = hkdf_expand_sha_256( PRK_4x3m, info_K_3m, 16 );
    vector<uint8_t> info_IV_3m = gen_info( cbor_tstr( "IV-GENERATION" ), 104, cbor_bstr( ID_CRED_I ), TH_3 );
    vector<uint8_t> IV_3m = hkdf_expand_sha_256( PRK_4x3m, info_IV_3m, 13 );

    vector<uint8_t> MAC_3 = aes_ccm_16_64_128( K_3m, IV_3m, P_3m, A_3m );

    // Calculate Signature_or_MAC_3
    vector<uint8_t> M_3 { 0x84 }; // CBOR array of length 4
    vector_append( M_3, cbor_tstr( "Signature1" ) );
    vector_append( M_2, cbor_bstr( ID_CRED_I ) );
    vector_append( M_2, cbor_bstr( external_aad_3 ) );
    vector_append( M_2, cbor_bstr( MAC_3 ) );

    vector<uint8_t> signature_or_MAC_3( crypto_sign_BYTES );
    crypto_sign_detached( signature_or_MAC_3.data(), nullptr, M_3.data(), M_3.size(), I_auth_sk_libsodium.data() );

    // Calculate CIPHERTEXT_3
    vector<uint8_t> P_3ae;
    vector_append( P_3ae, cbor_bstr_id( kid_I ) );
    vector_append( P_3ae, cbor_bstr( signature_or_MAC_3 ) );
    vector<uint8_t> A_3ae = { 0x83 }; // CBOR array of length 3
    vector_append( A_3ae, cbor_tstr( "Encrypt0" ) );
    vector_append( A_3ae, cbor_bstr( { } ) ); // empty bstr 
    vector_append( A_3ae, cbor_bstr( TH_3 ) );

    vector<uint8_t> info_K_3ae = gen_info( cbor_uint8( aead_algorithm_id ), 128, { }, TH_3 );
    vector<uint8_t> K_3ae = hkdf_expand_sha_256( PRK_3e2m, info_K_3ae, 16 );
    vector<uint8_t> info_IV_3ae = gen_info( cbor_tstr( "IV-GENERATION" ), 104, { }, TH_3 );
    vector<uint8_t> IV_3ae = hkdf_expand_sha_256( PRK_3e2m, info_IV_3ae, 13 );

    vector<uint8_t> CIPHERTEXT_3 = aes_ccm_16_64_128( K_3ae, IV_3ae, P_3ae, A_3ae );

    // Calculate message_3
    vector<uint8_t> message_3;
    vector_append( message_3, data_3 );
    vector_append( message_3, cbor_bstr( CIPHERTEXT_3 ) ); 

    // OSCORE ////////////////////////////////////////////////////////////////////////////

    // Calculate TH_4
    vector<uint8_t> TH_4_input;
    vector_append( TH_4_input, cbor_bstr( TH_3 ) );
    vector_append( TH_4_input, cbor_bstr( CIPHERTEXT_3 ) );
    vector<uint8_t> TH_4 = hash_sha_256( TH_4_input );

    // Derive OSCORE Master Secret and Salt
    vector<uint8_t> info_OSCORE_secret = gen_info( cbor_tstr( "OSCORE Master Secret" ), 128, { }, TH_4 );
    vector<uint8_t> OSCORE_secret = hkdf_expand_sha_256( PRK_4x3m,  info_OSCORE_secret, 16 );
    vector<uint8_t> info_OSCORE_salt = gen_info( cbor_tstr( "OSCORE Master Salt" ), 64, { }, TH_4 );
    vector<uint8_t> OSCORE_salt = hkdf_expand_sha_256( PRK_4x3m, info_OSCORE_salt, 8 );

    ///////////////////////////////////////////////////////////////////////////////////////////
    // Print stuff ////////////////////////////////////////////////////////////////////////////
    ///////////////////////////////////////////////////////////////////////////////////////////

    print_line();
    cout << "Test Vectors for EDHOC Authenticated with Signature (RPK) + Signature (RPK)";
    print_line();

    // Pre-shared stuff ////////////////////////////////////////////////////////////////////////////

    cout << endl;
    cout << "Initiator COSE_Key =" << endl;
    cout << "{" << endl;
    cout << "   2:";
    print_cddl_bstr( kid_I );
    cout << "   1:";
    print_cddl_int( 1 );
    cout << "  -1:";
    print_cddl_int( 6 );
    cout << "  -2:";
    print_cddl_bstr( I_auth_pk );
    cout << "  -4:";
    print_cddl_bstr( I_auth_sk );
    cout << "}" << endl;

    cout << endl;
    cout << "Responder COSE_Key =" << endl;
    cout << "{" << endl;
    cout << "   2:";
    print_cddl_bstr( kid_R );
    cout << "   1:";
    print_cddl_int( 1 );
    cout << "  -1:";
    print_cddl_int( 6 );
    cout << "  -2:";
    print_cddl_bstr( R_auth_pk );
    cout << "  -4:";
    print_cddl_bstr( R_auth_sk );
    cout << "}" << endl;

    print_int( "method (Signature + Singature)", method );
    print_line();

    // message_1 ////////////////////////////////////////////////////////////////////////////

    print_int( "corr (Initiator can correlate message_1 and message_2)", corr );
    print_int( "METHOD_CORR (4 * method + corr)", METHOD_CORR );   
    print_int( "suite", suite );
    print_vector( "X (Initiator's ephemeral private key)", I_kx_sk );
    print_vector( "G_X (Initiator's ephemeral public key)", I_kx_pk );
    print_vector( "Connection identifier chosen by Initiator", C_I );
    print_vector( "message_1 (CBOR Sequence)", message_1 );
    print_line();

    // message_2 ////////////////////////////////////////////////////////////////////////////

    print_vector( "Y (Responder's ephemeral private key)", R_kx_sk );
    print_vector( "G_Y (Responder's ephemeral public key)", R_kx_pk );
    print_vector( "G_XY (ECDH shared secret)", G_XY );
    print_vector( "salt", salt );
    print_vector( "PRK_2e", PRK_2e );   
    print_vector( "PRK_3e2m", PRK_3e2m );   
    print_vector( "Connection identifier chosen by Responder", C_R );
    print_vector( "data_2 (CBOR Sequence)", data_2 );
    print_vector( "Input to SHA-256 to calculate TH_2 ( message_1, data_2 ) (CBOR Sequence)", TH_2_input );
    print_vector( "TH_2",  TH_2 );
    print_vector( "P_2m", P_2m );
    print_vector( "A_2m (CBOR-encoded)", A_2m );   
    print_vector( "info for K_2m (CBOR-encoded)", info_K_2m );   
    print_vector( "K_2m", K_2m );   
    print_vector( "info for IV_2m (CBOR-encoded)", info_IV_2m );   
    print_vector( "IV_2m", IV_2m );   
    print_vector( "MAC_2", MAC_2 );   
    print_vector( "M_2 (message to be signed by Responder) (CBOR-encoded)", M_2 );
    print_vector( "Signature_or_MAC_2", signature_or_MAC_2 );
    print_vector( "P_2e", P_2e );   
    print_vector( "info for K_2e (CBOR-encoded)", info_K_2e );   
    print_vector( "K_2e", K_2e );   
    print_vector( "CIPHERTEXT_2", CIPHERTEXT_2 );   
    print_vector( "message_2 (CBOR Sequence)", message_2 );
    print_line();

    // message_3 ////////////////////////////////////////////////////////////////////////////

    print_vector( "PRK_4x3m", PRK_4x3m );
    print_vector( "data_3 (CBOR Sequence)", data_3 );
    print_vector( "Input to SHA-256 to calculate TH_3 ( TH_2, CIPHERTEXT_2, data_3 ) (CBOR Sequence)", TH_3_input );
    print_vector( "TH_3", TH_3);
    print_vector( "P_3m", P_3m );   
    print_vector( "A_3m (CBOR-encoded)", A_3m );   
    print_vector( "info for K_3m (CBOR-encoded)", info_K_3m );   
    print_vector( "K_3m", K_3m );   
    print_vector( "info for IV_3m (CBOR-encoded)", info_IV_3m );   
    print_vector( "IV_3m", IV_3m );   
    print_vector( "MAC_3", MAC_3 );   
    print_vector( "M_3 (message to be signed by Initiator) (CBOR-encoded)", M_3 );
    print_vector( "Signature_or_MAC_2", signature_or_MAC_2 );
    print_vector( "P_3ae", P_3ae );   
    print_vector( "A_3ae (CBOR-encoded)", A_3ae );   
    print_vector( "info for K_3ae (CBOR-encoded)", info_K_3ae );   
    print_vector( "K_3ae", K_3ae );   
    print_vector( "info for IV_3ae (CBOR-encoded)", info_IV_3ae );   
    print_vector( "IV_3ae", IV_3ae );   
    print_vector( "CIPHERTEXT_3", CIPHERTEXT_3 );   
    print_vector( "message_3 (CBOR Sequence)", message_3 );
    print_line();

    // OSCORE ////////////////////////////////////////////////////////////////////////////

    print_vector( "Input to SHA-256 to calculate TH_4 ( TH_3, CIPHERTEXT_3 ) (CBOR Sequence)", TH_4_input );
    print_vector( "TH_4", TH_4 );
    print_vector( "info for OSCORE Master Secret (CBOR-encoded)", info_OSCORE_secret );   
    print_vector( "OSCORE Master Secret", OSCORE_secret );
    print_vector( "info for OSCORE Master Salt (CBOR-encoded)", info_OSCORE_salt );   
    print_vector( "OSCORE Master Salt", OSCORE_salt );
    print_vector( "Client's OSCORE Sender ID", C_R );
    print_vector( "Server's OSCORE Sender ID", C_I );
    print_int( "AEAD Algorithm", aead_algorithm_id );
    print_int( "HMAC Algorithm", hmac_algorithm_id );
}

void sdh_sdh_vectors( void )
{
    ///////////////////////////////////////////////////////////////////////////////////////////
    // Calculate stuff ////////////////////////////////////////////////////////////////////////
    ///////////////////////////////////////////////////////////////////////////////////////////

    // Pre-shared stuff ////////////////////////////////////////////////////////////////////////////

    // Generate Party Initiator's COSE_Key
    vector<uint8_t> I_auth_pk( crypto_kx_PUBLICKEYBYTES );
    vector<uint8_t> I_auth_sk( crypto_kx_SECRETKEYBYTES );
    vector<uint8_t> I_auth_seed( crypto_kx_SEEDBYTES, 12 ); ;
    crypto_kx_seed_keypair( I_auth_pk.data(), I_auth_sk.data(), I_auth_seed.data() );
    vector<uint8_t> kid_I { 0x21 };

    // Generate Party Responders's COSE_Key
    vector<uint8_t> R_auth_pk( crypto_kx_PUBLICKEYBYTES );
    vector<uint8_t> R_auth_sk( crypto_kx_SECRETKEYBYTES );
    vector<uint8_t> R_auth_seed( crypto_kx_SEEDBYTES, 12 ); ;
    crypto_kx_seed_keypair( R_auth_pk.data(), R_auth_sk.data(), R_auth_seed.data() );
    vector<uint8_t> kid_R { 0x22 };
 
    uint8_t method = 3; // Static DH + Static DH

   // message_1 ////////////////////////////////////////////////////////////////////////////

    // Generate Initiator's ephemeral key pair
    vector<uint8_t> I_kx_pk( crypto_kx_PUBLICKEYBYTES );
    vector<uint8_t> I_kx_sk( crypto_kx_SECRETKEYBYTES );
    vector<uint8_t> I_kx_seed( crypto_kx_SEEDBYTES, 6 ); ;
    crypto_kx_seed_keypair( I_kx_pk.data(), I_kx_sk.data(), I_kx_seed.data() );

    // Other parameters
    uint8_t corr = 1; // Responder can correlate message_1 and message_2
    uint8_t METHOD_CORR = 4 * method + corr;
    uint8_t suite = 0; // ( 10, 5, 4, -8, 6, 10, 5 ) AES-CCM-16-64-128, HMAC 256/256, X25519, EdDSA, Ed25519, AES-CCM-16-64-128, HMAC 256/256
    int aead_algorithm_id = 10;
    int hmac_algorithm_id = 5;
    vector<uint8_t> C_I { 0x01 };

    // Calculate message_1
    vector<uint8_t> message_1;
    vector_append( message_1, cbor_uint8( METHOD_CORR ) ); 
    vector_append( message_1, cbor_uint8( suite ) ); 
    vector_append( message_1, cbor_bstr( I_kx_pk ) ); 
    vector_append( message_1, cbor_bstr_id( C_I ) ); 

   // message_2 ////////////////////////////////////////////////////////////////////////////

    // Generate Responder's ephemeral key pair
    vector<uint8_t> R_kx_pk( crypto_kx_PUBLICKEYBYTES );
    vector<uint8_t> R_kx_sk( crypto_kx_SECRETKEYBYTES );
    vector<uint8_t> R_kx_seed( crypto_kx_SEEDBYTES, 7 ); ;
    crypto_kx_seed_keypair( R_kx_pk.data(), R_kx_sk.data(), R_kx_seed.data() );

    // Derive PRK_2e
    vector<uint8_t> G_XY( crypto_scalarmult_BYTES );
    if ( crypto_scalarmult( G_XY.data(), R_kx_sk.data(), I_kx_pk.data() ) == -1 ) {
        cout << "crypto_scalarmult error";
        return;
    }
    vector<uint8_t> salt; // empty byte string;
    vector<uint8_t> PRK_2e = hkdf_extract_sha_256( salt, G_XY );

    // Derive PRK_3e2m
    vector<uint8_t> G_RX( crypto_scalarmult_BYTES );
    if ( crypto_scalarmult( G_RX.data(), R_auth_sk.data(), I_kx_pk.data() ) == -1 ) {
        cout << "crypto_scalarmult error";
        return;
    }
    vector<uint8_t> PRK_3e2m = hkdf_extract_sha_256( PRK_2e, G_RX );

    // Other parameters
    vector<uint8_t> C_R { 0x02 };

    // Calculate data_2
    vector<uint8_t> data_2;
    vector_append( data_2, cbor_bstr( R_kx_pk ) ); 
    vector_append( data_2, cbor_bstr_id( C_R ) ); 

    // Calculate TH_2
    vector<uint8_t> TH_2_input;
    vector_append( TH_2_input, message_1 );
    vector_append( TH_2_input, data_2 );
    vector<uint8_t> TH_2 = hash_sha_256( TH_2_input );

    // Calculate ID_CRED_R and CRED_R
    vector<uint8_t> ID_CRED_R = { 0xa1, 0x04 }; // CBOR map(1) label = 4
    vector_append( ID_CRED_R, cbor_bstr( kid_R ) );
    vector<uint8_t> CRED_R { 0xa3, 0x01, 0x01, 0x20, 0x04, 0x21,  }; // CBOR map(3), 1, 1, -1, 4, -2
    vector_append( CRED_R, cbor_bstr( R_auth_pk ) );

    // Calculate MAC_2
    vector<uint8_t> P_2m; // empty byte string
    vector<uint8_t> A_2m = { 0x83 }; // CBOR array of length 3
    vector_append( A_2m, cbor_tstr( "Encrypt0" ) );
    vector_append( A_2m, cbor_bstr( ID_CRED_R ) ); // << ID_CRED_R >>
    vector<uint8_t> external_aad_2 = { CRED_R };
    vector_append( external_aad_2, cbor_bstr( TH_2 ) );
    vector_append( A_2m, cbor_bstr( external_aad_2 ) ); // << CRED_R, TH_2 >>

    vector<uint8_t> info_K_2m = gen_info( cbor_uint8( aead_algorithm_id ), 128, cbor_bstr( ID_CRED_R ), TH_2 );
    vector<uint8_t> K_2m = hkdf_expand_sha_256( PRK_3e2m, info_K_2m, 16 );
    vector<uint8_t> info_IV_2m = gen_info( cbor_tstr( "IV-GENERATION" ), 104, cbor_bstr( ID_CRED_R ), TH_2 );
    vector<uint8_t> IV_2m = hkdf_expand_sha_256( PRK_3e2m, info_IV_2m, 13 );

    vector<uint8_t> MAC_2 = aes_ccm_16_64_128( K_2m, IV_2m, P_2m, A_2m );

    // Calculate Signature_or_MAC_2
    vector<uint8_t> signature_or_MAC_2 = MAC_2;

    // Calculate CIPHERTEXT_2
    vector<uint8_t> P_2e;
    vector_append( P_2e, cbor_bstr_id( kid_R ) ); 
    vector_append( P_2e, cbor_bstr( signature_or_MAC_2 ) );

    vector<uint8_t> info_K_2e = gen_info( cbor_tstr( "XOR-ENCRYPTION" ), 8 * P_2e.size(), { }, TH_2 );
    vector<uint8_t> K_2e = hkdf_expand_sha_256( PRK_2e, info_K_2e, P_2e.size() );
 
    vector<uint8_t> CIPHERTEXT_2 = xor_encryption( K_2e, P_2e );

    // Calculate message_2
    vector<uint8_t> message_2;
    vector_append( message_2, data_2 );
    vector_append( message_2, cbor_bstr( CIPHERTEXT_2 ) ); 

   // message_3 ////////////////////////////////////////////////////////////////////////////

    // Derive PRK_4x3m
    vector<uint8_t> G_IY( crypto_scalarmult_BYTES );
    if ( crypto_scalarmult( G_IY.data(), I_auth_sk.data(), R_kx_pk.data() ) == -1 ) {
        cout << "crypto_scalarmult error";
        return;
    }
    vector<uint8_t> PRK_4x3m = hkdf_extract_sha_256( PRK_3e2m, G_IY );

    // Calculate data_3
    vector<uint8_t> data_3;
    vector_append( data_3, cbor_bstr_id( C_R ) ); 

    // Calculate TH_3
    vector<uint8_t> TH_3_input;
    vector_append( TH_3_input, cbor_bstr( TH_2 ) );
    vector_append( TH_3_input, cbor_bstr( CIPHERTEXT_2 ) );
    vector_append( TH_3_input, data_3 );
    vector<uint8_t> TH_3 = hash_sha_256( TH_3_input );

    // Calculate ID_CRED_I and CRED_I
    vector<uint8_t> ID_CRED_I = { 0xa1, 0x04 }; // CBOR map(1), label = 4
    vector_append( ID_CRED_I, cbor_bstr( kid_I ) );
    vector<uint8_t> CRED_I { 0xa3, 0x01, 0x01, 0x20, 0x04, 0x21,  }; // CBOR map(3), 1, 1, -1, 4, -2
    vector_append( CRED_I, cbor_bstr( I_auth_pk ) );

    // Calculate MAC_3
    vector<uint8_t> P_3m; // empty byte string
    vector<uint8_t> A_3m = { 0x83 }; // CBOR array of length 3
    vector_append( A_3m, cbor_tstr( "Encrypt0" ) );
    vector_append( A_3m, cbor_bstr( ID_CRED_I ) ); // << ID_CRED_I >>
    vector<uint8_t> external_aad_3 = { CRED_I }; 
    vector_append( external_aad_3, cbor_bstr( TH_3 ) );
    vector_append( A_3m, cbor_bstr( external_aad_3 ) ); // << CRED_I, TH_3 >>

    vector<uint8_t> info_K_3m = gen_info( cbor_uint8( aead_algorithm_id ), 128, cbor_bstr( ID_CRED_I ), TH_3 );
    vector<uint8_t> K_3m = hkdf_expand_sha_256( PRK_4x3m, info_K_3m, 16 );
    vector<uint8_t> info_IV_3m = gen_info( cbor_tstr( "IV-GENERATION" ), 104, cbor_bstr( ID_CRED_I ), TH_3 );
    vector<uint8_t> IV_3m = hkdf_expand_sha_256( PRK_4x3m, info_IV_3m, 13 );

    vector<uint8_t> MAC_3 = aes_ccm_16_64_128( K_3m, IV_3m, P_3m, A_3m );

    // Calculate Signature_or_MAC_3
    vector<uint8_t> signature_or_MAC_3 = MAC_3;

    // Calculate CIPHERTEXT_3
    vector<uint8_t> P_3ae;
    vector_append( P_3ae, cbor_bstr_id( kid_I ) );
    vector_append( P_3ae, cbor_bstr( signature_or_MAC_3 ) );
    vector<uint8_t> A_3ae = { 0x83 }; // CBOR array of length 3
    vector_append( A_3ae, cbor_tstr( "Encrypt0" ) );
    vector_append( A_3ae, cbor_bstr( { } ) ); // empty bstr 
    vector_append( A_3ae, cbor_bstr( TH_3 ) );

    vector<uint8_t> info_K_3ae = gen_info( cbor_uint8( aead_algorithm_id ), 128, { }, TH_3 );
    vector<uint8_t> K_3ae = hkdf_expand_sha_256( PRK_3e2m, info_K_3ae, 16 );
    vector<uint8_t> info_IV_3ae = gen_info( cbor_tstr( "IV-GENERATION" ), 104, { }, TH_3 );
    vector<uint8_t> IV_3ae = hkdf_expand_sha_256( PRK_3e2m, info_IV_3ae, 13 );

    vector<uint8_t> CIPHERTEXT_3 = aes_ccm_16_64_128( K_3ae, IV_3ae, P_3ae, A_3ae );

    // Calculate message_3
    vector<uint8_t> message_3;
    vector_append( message_3, data_3 );
    vector_append( message_3, cbor_bstr( CIPHERTEXT_3 ) ); 

    // OSCORE ////////////////////////////////////////////////////////////////////////////

    // Calculate TH_4
    vector<uint8_t> TH_4_input;
    vector_append( TH_4_input, cbor_bstr( TH_3 ) );
    vector_append( TH_4_input, cbor_bstr( CIPHERTEXT_3 ) );
    vector<uint8_t> TH_4 = hash_sha_256( TH_4_input );

    // Derive OSCORE Master Secret and Salt
    vector<uint8_t> info_OSCORE_secret = gen_info( cbor_tstr( "OSCORE Master Secret" ), 128, { }, TH_4 );
    vector<uint8_t> OSCORE_secret = hkdf_expand_sha_256( PRK_4x3m,  info_OSCORE_secret, 16 );
    vector<uint8_t> info_OSCORE_salt = gen_info( cbor_tstr( "OSCORE Master Salt" ), 64, { }, TH_4 );
    vector<uint8_t> OSCORE_salt = hkdf_expand_sha_256( PRK_4x3m, info_OSCORE_salt, 8 );

    ///////////////////////////////////////////////////////////////////////////////////////////
    // Print stuff ////////////////////////////////////////////////////////////////////////////
    ///////////////////////////////////////////////////////////////////////////////////////////

    print_line();
    cout << "Test Vectors for EDHOC Authenticated with Static DH (RPK) + Static DH (RPK)";
    print_line();

    // Pre-shared stuff ////////////////////////////////////////////////////////////////////////////

    cout << endl;
    cout << "Initiator COSE_Key =" << endl;
    cout << "{" << endl;
    cout << "   2:";
    print_cddl_bstr( kid_I );
    cout << "   1:";
    print_cddl_int( 1 );
    cout << "  -1:";
    print_cddl_int( 4 );
    cout << "  -2:";
    print_cddl_bstr( I_auth_pk );
    cout << "  -4:";
    print_cddl_bstr( I_auth_sk );
    cout << "}" << endl;

    cout << endl;
    cout << "Responder COSE_Key =" << endl;
    cout << "{" << endl;
    cout << "   2:";
    print_cddl_bstr( kid_R );
    cout << "   1:";
    print_cddl_int( 1 );
    cout << "  -1:";
    print_cddl_int( 4 );
    cout << "  -2:";
    print_cddl_bstr( R_auth_pk );
    cout << "  -4:";
    print_cddl_bstr( R_auth_sk );
    cout << "}" << endl;

    print_int( "method (Static DH + Static DH)", method );
    print_line();

    // message_1 ////////////////////////////////////////////////////////////////////////////

    print_int( "corr (Initiator can correlate message_1 and message_2)", corr );
    print_int( "METHOD_CORR (4 * method + corr)", METHOD_CORR );   
    print_int( "suite", suite );
    print_vector( "X (Initiator's ephemeral private key)", I_kx_sk );
    print_vector( "G_X (Initiator's ephemeral public key)", I_kx_pk );
    print_vector( "Connection identifier chosen by Initiator", C_I );
    print_vector( "message_1 (CBOR Sequence)", message_1 );
    print_line();

    // message_2 ////////////////////////////////////////////////////////////////////////////

    print_vector( "Y (Responder's ephemeral private key)", R_kx_sk );
    print_vector( "G_Y (Responder's ephemeral public key)", R_kx_pk );
    print_vector( "G_XY (ECDH shared secret)", G_XY );
    print_vector( "salt", salt );
    print_vector( "PRK_2e", PRK_2e );   
    print_vector( "G_RX (ECDH shared secret)", G_RX );
    print_vector( "PRK_3e2m", PRK_3e2m );   
    print_vector( "Connection identifier chosen by Responder", C_R );
    print_vector( "data_2 (CBOR Sequence)", data_2 );
    print_vector( "Input to SHA-256 to calculate TH_2 ( message_1, data_2 ) (CBOR Sequence)", TH_2_input );
    print_vector( "TH_2",  TH_2 );
    print_vector( "P_2m", P_2m );
    print_vector( "A_2m (CBOR-encoded)", A_2m );   
    print_vector( "info for K_2m (CBOR-encoded)", info_K_2m );   
    print_vector( "K_2m", K_2m );   
    print_vector( "info for IV_2m (CBOR-encoded)", info_IV_2m );   
    print_vector( "IV_2m", IV_2m );   
    print_vector( "MAC_2", MAC_2 );   
    print_vector( "Signature_or_MAC_2", signature_or_MAC_2 );
    print_vector( "P_2e", P_2e );   
    print_vector( "info for K_2e (CBOR-encoded)", info_K_2e );   
    print_vector( "K_2e", K_2e );   
    print_vector( "CIPHERTEXT_2", CIPHERTEXT_2 );   
    print_vector( "message_2 (CBOR Sequence)", message_2 );
    print_line();

    // message_3 ////////////////////////////////////////////////////////////////////////////

    print_vector( "G_IY (ECDH shared secret)", G_IY );
    print_vector( "PRK_4x3m", PRK_4x3m );   
    print_vector( "data_3 (CBOR Sequence)", data_3 );
    print_vector( "Input to SHA-256 to calculate TH_3 ( TH_2, CIPHERTEXT_2, data_3 ) (CBOR Sequence)", TH_3_input );
    print_vector( "TH_3", TH_3);
    print_vector( "P_3m", P_3m );   
    print_vector( "A_3m (CBOR-encoded)", A_3m );   
    print_vector( "info for K_3m (CBOR-encoded)", info_K_3m );   
    print_vector( "K_3m", K_3m );   
    print_vector( "info for IV_3m (CBOR-encoded)", info_IV_3m );   
    print_vector( "IV_3m", IV_3m );   
    print_vector( "MAC_3", MAC_3 );   
    print_vector( "Signature_or_MAC_2", signature_or_MAC_2 );
    print_vector( "P_3ae", P_3ae );   
    print_vector( "A_3ae (CBOR-encoded)", A_3ae );   
    print_vector( "info for K_3ae (CBOR-encoded)", info_K_3ae );   
    print_vector( "K_3ae", K_3ae );   
    print_vector( "info for IV_3ae (CBOR-encoded)", info_IV_3ae );   
    print_vector( "IV_3ae", IV_3ae );   
    print_vector( "CIPHERTEXT_3", CIPHERTEXT_3 );   
    print_vector( "message_3 (CBOR Sequence)", message_3 );
    print_line();

    // OSCORE ////////////////////////////////////////////////////////////////////////////

    print_vector( "Input to SHA-256 to calculate TH_4 ( TH_3, CIPHERTEXT_3 ) (CBOR Sequence)", TH_4_input );
    print_vector( "TH_4", TH_4 );
    print_vector( "info for OSCORE Master Secret (CBOR-encoded)", info_OSCORE_secret );   
    print_vector( "OSCORE Master Secret", OSCORE_secret );
    print_vector( "info for OSCORE Master Salt (CBOR-encoded)", info_OSCORE_salt );   
    print_vector( "OSCORE Master Salt", OSCORE_salt );
    print_vector( "Client's OSCORE Sender ID", C_R );
    print_vector( "Server's OSCORE Sender ID", C_I );
    print_int( "AEAD Algorithm", aead_algorithm_id );
    print_int( "HMAC Algorithm", hmac_algorithm_id );
}

void psk_psk_vectors( void )
{
    ///////////////////////////////////////////////////////////////////////////////////////////
    // Calculate stuff ////////////////////////////////////////////////////////////////////////
    ///////////////////////////////////////////////////////////////////////////////////////////

    // Pre-shared stuff ////////////////////////////////////////////////////////////////////////////

    // Generate Shared COSE_Key
    vector<uint8_t> PSK( 16 );  // 16 bytes = 128 bit security
    vector<uint8_t> PSK_seed( randombytes_SEEDBYTES, 0 ); 
    randombytes_buf_deterministic( PSK.data(), PSK.size(), PSK_seed.data() );
    vector<uint8_t> kid_psk { 0x2c };

    uint8_t method = 4; // PSK + PSK
 
    // message_1 ////////////////////////////////////////////////////////////////////////////

    // Generate Initiator's ephemeral key pair
    vector<uint8_t> I_kx_pk( crypto_kx_PUBLICKEYBYTES );
    vector<uint8_t> I_kx_sk( crypto_kx_SECRETKEYBYTES );
    vector<uint8_t> I_kx_seed( crypto_kx_SEEDBYTES, 1 ); ;
    crypto_kx_seed_keypair( I_kx_pk.data(), I_kx_sk.data(), I_kx_seed.data() );

    // Other parameters
    uint8_t corr = 1; // Responder can correlate message_1 and message_2
    uint8_t METHOD_CORR = 4 * method + corr;
    uint8_t suite = 0; // ( 10, 5, 4, -8, 6, 10, 5 ) AES-CCM-16-64-128, HMAC 256/256, X25519, EdDSA, Ed25519, AES-CCM-16-64-128, HMAC 256/256
    int aead_algorithm_id = 10;
    int hmac_algorithm_id = 5;
    vector<uint8_t> C_I { 0x0c };

    // Calculate message_1
    vector<uint8_t> message_1;
    vector_append( message_1, cbor_uint8( METHOD_CORR ) ); 
    vector_append( message_1, cbor_uint8( suite ) ); 
    vector_append( message_1, cbor_bstr( I_kx_pk ) ); 
    vector_append( message_1, cbor_bstr_id( C_I ) ); 
    vector_append( message_1, cbor_bstr_id( kid_psk ) );
 
    // message_2 ////////////////////////////////////////////////////////////////////////////

    // Generate Responder's ephemeral key pair
    vector<uint8_t> R_kx_pk( crypto_kx_PUBLICKEYBYTES );
    vector<uint8_t> R_kx_sk( crypto_kx_SECRETKEYBYTES );
    vector<uint8_t> R_kx_seed( crypto_kx_SEEDBYTES, 2 ); ;
    crypto_kx_seed_keypair( R_kx_pk.data(), R_kx_sk.data(), R_kx_seed.data() );

    // Derive PRK_2e
    vector<uint8_t> G_XY( crypto_scalarmult_BYTES );
    if ( crypto_scalarmult( G_XY.data(), R_kx_sk.data(), I_kx_pk.data() ) == -1 ) {
        cout << "crypto_scalarmult error";
        return;
    }
    vector<uint8_t> salt; // empty byte string;
    vector<uint8_t> PRK_2e = hkdf_extract_sha_256( salt, G_XY );

    // Derive PRK_3e2m
    vector<uint8_t> PRK_3e2m = PRK_2e;

    // Other parameters
    vector<uint8_t> C_R { 0x0d };

    // Calculate data_2
    vector<uint8_t> data_2;
    vector_append( data_2, cbor_bstr( R_kx_pk ) ); 
    vector_append( data_2, cbor_bstr_id( C_R ) ); 

    // Calculate TH_2
    vector<uint8_t> TH_2_input;
    vector_append( TH_2_input, message_1 );
    vector_append( TH_2_input, data_2 );
    vector<uint8_t> TH_2 = hash_sha_256( TH_2_input );
 
   // Calculate CIPHERTEXT_2
    vector<uint8_t> info_K_2ae = gen_info( cbor_uint8( aead_algorithm_id ), 128, { }, TH_2 );
    vector<uint8_t> K_2ae = hkdf_expand_sha_256( PRK_2e, info_K_2ae, 16 );
    vector<uint8_t> info_IV_2ae = gen_info( cbor_tstr( "IV-GENERATION" ), 104, { }, TH_2 );
    vector<uint8_t> IV_2ae = hkdf_expand_sha_256( PRK_2e, info_IV_2ae, 13 );

    vector<uint8_t> P_2ae; // empty byte string
    vector<uint8_t> A_2ae = { 0x83 }; // CBOR array of length 3
    vector_append( A_2ae, cbor_tstr( "Encrypt0" ) );
    vector_append( A_2ae, cbor_bstr( { } ) ); // empty bstr 
    vector_append( A_2ae, cbor_bstr( TH_2 ) );
 
    vector<uint8_t> CIPHERTEXT_2 = aes_ccm_16_64_128( K_2ae, IV_2ae, P_2ae, A_2ae );

    // Calculate message_2
    vector<uint8_t> message_2;
    vector_append( message_2, data_2 );
    vector_append( message_2, cbor_bstr( CIPHERTEXT_2 ) ); 

    // message_3 ////////////////////////////////////////////////////////////////////////////

    // Derive PRK_4x3m
    vector<uint8_t> PRK_4x3m = PRK_3e2m;

    // Calculate data_3
    vector<uint8_t> data_3;
    vector_append( data_3, cbor_bstr_id( C_R ) );

    // Calculate TH_3
    vector<uint8_t> TH_3_input;
    vector_append( TH_3_input, cbor_bstr( TH_2 ) );
    vector_append( TH_3_input, cbor_bstr( CIPHERTEXT_2 ) );
    vector_append( TH_3_input, data_3 );
    vector<uint8_t> TH_3 = hash_sha_256( TH_3_input );

    // Calculate CIPHERTEXT_3
    vector<uint8_t> info_K_3ae = gen_info( cbor_uint8( aead_algorithm_id ), 128, { }, TH_3 );
    vector<uint8_t> K_3ae = hkdf_expand_sha_256( PRK_3e2m, info_K_3ae, 16 );
    vector<uint8_t> info_IV_3ae = gen_info( cbor_tstr( "IV-GENERATION" ), 104, { }, TH_3 );
    vector<uint8_t> IV_3ae = hkdf_expand_sha_256( PRK_3e2m, info_IV_3ae, 13 );

    vector<uint8_t> P_3ae; // empty byte string
    vector<uint8_t> A_3ae = { 0x83 }; // CBOR array of length 3
    vector_append( A_3ae, cbor_tstr( "Encrypt0" ) );
    vector_append( A_3ae, cbor_bstr( { } ) ); // empty bstr 
    vector_append( A_3ae, cbor_bstr( TH_3 ) );

    vector<uint8_t> CIPHERTEXT_3 = aes_ccm_16_64_128( K_3ae, IV_3ae, P_3ae, A_3ae );

    // Calculate message_3
    vector<uint8_t> message_3;
    vector_append( message_3, data_3 );
    vector_append( message_3, cbor_bstr( CIPHERTEXT_3 ) );

    // OSCORE ////////////////////////////////////////////////////////////////////////////

    // Calculate TH_4
    vector<uint8_t> TH_4_input;
    vector_append( TH_4_input, cbor_bstr( TH_3 ) );
    vector_append( TH_4_input, cbor_bstr( CIPHERTEXT_3 ) );
    vector<uint8_t> TH_4 = hash_sha_256( TH_4_input );

    // Derive OSCORE Master Secret and Salt
    vector<uint8_t> info_OSCORE_secret = gen_info( cbor_tstr( "OSCORE Master Secret" ), 128, { }, TH_4 );
    vector<uint8_t> OSCORE_secret = hkdf_expand_sha_256( PRK_4x3m,  info_OSCORE_secret, 16 );
    vector<uint8_t> info_OSCORE_salt = gen_info( cbor_tstr( "OSCORE Master Salt" ), 64, { }, TH_4 );
    vector<uint8_t> OSCORE_salt = hkdf_expand_sha_256( PRK_4x3m, info_OSCORE_salt, 8 );

    ///////////////////////////////////////////////////////////////////////////////////////////
    // Print stuff ////////////////////////////////////////////////////////////////////////////
    ///////////////////////////////////////////////////////////////////////////////////////////

    print_line();
    cout << "Test Vectors for EDHOC Authenticated with PSK + PSK";
    print_line();

    // Pre-shared stuff ////////////////////////////////////////////////////////////////////////////

    cout << endl;
    cout << "Shared COSE_Key =" << endl;
    cout << "{" << endl;
    cout << "   2:";
    print_cddl_bstr( kid_psk );
    cout << "  -1:";
    print_cddl_bstr( PSK );
    cout << "}" << endl;

    print_int( "method (PSK + PSK)", method );
    print_line();

    // message_1 ////////////////////////////////////////////////////////////////////////////

    print_int( "corr (Initiator can correlate message_1 and message_2)", corr );
    print_int( "METHOD_CORR (4 * method + corr)", METHOD_CORR );   
    print_int( "suite", suite );
    print_vector( "X (Initiator's ephemeral private key)", I_kx_sk );
    print_vector( "G_X (Initiator's ephemeral public key)", I_kx_pk );
    print_vector( "Connection identifier chosen by Initiator", C_I );
    print_vector( "message_1 (CBOR Sequence)", message_1 );
    print_line();

    // message_2 ////////////////////////////////////////////////////////////////////////////

    print_vector( "Y (Responder's ephemeral private key)", R_kx_sk );
    print_vector( "G_Y (Responder's ephemeral public key)", R_kx_pk );
    print_vector( "G_XY (ECDH shared secret)", G_XY );
    print_vector( "salt", salt );
    print_vector( "PRK_2e", PRK_2e );   
    print_vector( "PRK_3e2m", PRK_3e2m );   
    print_vector( "Connection identifier chosen by Responder", C_R );
    print_vector( "data_2 (CBOR Sequence)", data_2 );
    print_vector( "Input to SHA-256 to calculate TH_2 ( message_1, data_2 ) (CBOR Sequence)", TH_2_input );
    print_vector( "TH_2",  TH_2 );
    print_vector( "P_2ae", P_2ae );   
    print_vector( "A_2ae (CBOR-encoded)", A_2ae );   
    print_vector( "info for K_2ae (CBOR-encoded)", info_K_2ae );   
    print_vector( "K_2ae", K_2ae );   
    print_vector( "info for IV_2ae (CBOR-encoded)", info_IV_2ae );   
    print_vector( "IV_2ae", IV_2ae );   
    print_vector( "CIPHERTEXT_2", CIPHERTEXT_2 );   
    print_vector( "message_2 (CBOR Sequence)", message_2 );
    print_line();

    // message_3 ////////////////////////////////////////////////////////////////////////////

    print_vector( "PRK_4x3m", PRK_4x3m );   
    print_vector( "data_3 (CBOR Sequence)", data_3 );
    print_vector( "Input to SHA-256 to calculate TH_3 ( TH_2, CIPHERTEXT_2, data_3 ) (CBOR Sequence)", TH_3_input );
    print_vector( "TH_3", TH_3);
    print_vector( "P_3ae", P_3ae );   
    print_vector( "A_3ae (CBOR-encoded)", A_3ae );   
    print_vector( "info for K_3ae (CBOR-encoded)", info_K_3ae );   
    print_vector( "K_3ae", K_3ae );   
    print_vector( "info for IV_3ae (CBOR-encoded)", info_IV_3ae );   
    print_vector( "IV_3ae", IV_3ae );   
    print_vector( "CIPHERTEXT_3", CIPHERTEXT_3 );   
    print_vector( "message_3 (CBOR Sequence)", message_3 );
    print_line();

    // OSCORE ////////////////////////////////////////////////////////////////////////////

    print_vector( "Input to SHA-256 to calculate TH_4 ( TH_3, CIPHERTEXT_3 ) (CBOR Sequence)", TH_4_input );
    print_vector( "TH_4", TH_4 );
    print_vector( "info for OSCORE Master Secret (CBOR-encoded)", info_OSCORE_secret );   
    print_vector( "OSCORE Master Secret", OSCORE_secret );
    print_vector( "info for OSCORE Master Salt (CBOR-encoded)", info_OSCORE_salt );   
    print_vector( "OSCORE Master Salt", OSCORE_salt );
    print_vector( "Client's OSCORE Sender ID", C_R );
    print_vector( "Server's OSCORE Sender ID", C_I );
    print_int( "AEAD Algorithm", aead_algorithm_id );
    print_int( "HMAC Algorithm", hmac_algorithm_id );
}

int main( void )
{
    // Initiate Sodium
    if ( sodium_init() == -1 ) {
        cout << "The libsodoum library couldn't be initialized";
        return 1;
    }

    sig_sig_vectors();
    sdh_sdh_vectors();
    psk_psk_vectors();
}