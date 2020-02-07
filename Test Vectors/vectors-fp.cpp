// EDHOC Test Vectors
// Copyright (c) 2019, Ericsson - John Mattsson <john.mattsson@ericsson.com> and 
// Francesca Palombini <francesca.palombini@ericsson.com>
//
// This software may be distributed under the terms of the 3-Clause BSD License.

#include <iostream>
#include <iomanip>
#include <cstdint>
#include <vector>
#include <cstring>

#include <string>
#include <sstream>

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

// returns a string from vector
string vector_to_string( vector<uint8_t> v ) {
    string s;
    for ( int i = 0; i < v.size(); ++i ) {
        ostringstream ss;
        ss << hex << setfill('0') << setw(2) << (int)v[i];
        if(i % 24 == 0 and i > 1) //column 75 to the line
            ss << endl;
        else
            ss << " ";
        s += ss.str();
    }
    return s;
}

// print an int to cout
void print_int( string s, int i ) {
    cout << endl << dec << s << endl << i << endl;    
}

// print a line to cout
void print_line() {
    cout << endl << "---------------------------------------------------------------" << endl;
}

// print a md figure to cout
void print_fig( string title, string s ) {
    cout << endl << "~~~~~~~~~~~~~~~~~~~~~~~" << endl << title << endl << s << endl << "~~~~~~~~~~~~~~~~~~~~~~~" << endl <<endl;
}

// returns a string tabbed of 2 spaces for each return
string tab( string s ){
    string r;
    for (auto i : s){
        if (i == '\n')
            r += "\n  ";
        else
            r += i;
    }
    return r;
}

// remove extra whitespaces in a string
string remove_extra_whitespaces(string &input)
{
    string output;  
    unique_copy (input.begin(), input.end(), back_insert_iterator<string>(output), [](char x,char y){ return isspace(x) && isspace(y);});  
    return output;
}

// removes returns carriages and extra white spaces in a string
string line ( string s ){
    string r;
    for ( int i = 0; i < s.size(); ++i ) {
        if (s[i] == '\n')
            r += " ";
        else
            r += s[i];
    }
    return remove_extra_whitespaces(r);
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


string vector_to_cddl_bstr( vector<uint8_t> v ) {
    string s;
    s += "h'";
    for ( int i = 0; i < v.size(); ++i ) {
        ostringstream ss;
        ss << hex << setfill('0') << setw(2) << (int)v[i];
        if( i % 34 == 0 and i > 1 ) //column 75 to the line
            ss << endl;
        s += ss.str();
    }
    s += "'";
    return s;
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

// Returns the info string for HKDF
string info_string( string id, int keyDataLength, vector<uint8_t> other )
{
    string s;
    s = "[\n  " + id + ", \n  [ null, null, null ], \n  [ null, null, null ], \n  [ " + to_string(keyDataLength) + ", h'', " + vector_to_cddl_bstr(other) + "]\n]";
    return s;
}

string enc_string( vector<uint8_t> ext_aad )
{
    string s;
    s = "[\n  \"Encrypt0\",\n  h'',\n  " + vector_to_cddl_bstr(ext_aad) + "\n]";
    return s;
}

void psk_vectors( void )
{

    print_line();


    //OLD

    /*
    print_line();
    cout << "Test Vectors for EDHOC Authenticated with PSK";
    print_line();

    // Pre-shared stuff ////////////////////////////////////////////////////////////////////////////

    vector<uint8_t> PSK( 16 );  // 16 bytes = 128 bit security
    vector<uint8_t> PSK_seed( randombytes_SEEDBYTES, 0 ); 
    randombytes_buf_deterministic( PSK.data(), PSK.size(), PSK_seed.data() );
    vector<uint8_t> kid { 0xa1 };
    vector<uint8_t> ID_PSK = cbor_bstr( kid );

    // Print 
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
    uint8_t suite = 0; // [ 10, 5, 4, -8, 6 ] AES-CCM-16-64-128, HMAC 256/256, X25519, EdDSA, Ed25519
    int aead_algorithm_id = 10;
    int hmac_algorithm_id = 5;
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

    // Generate the Party V's ephemeral key pair 
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
    cout << "'," << endl;
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
    cout << "'," << endl;
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

    print_int( "HMAC Algorithm", hmac_algorithm_id );

    */
}

void rpk_vectors( void )
{
    // print_line();
    // cout << "Test Vectors for EDHOC Authenticated with RPK";
    // print_line();

    cout << endl << "## Test Vectors for EDHOC Authenticated with Signature Keys (RPK)" << endl; 
    cout << endl;
    cout << "EDHOC with signature authentication is used:" << endl;

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

    // Other parameters
    uint8_t method = 0; // Asymmetric
    uint8_t corr = 1; // Party U is CoAP client
    uint8_t TYPE = 4 * method + corr;
    uint8_t suite = 0; // [ 10, 5, 4, -8, 6 ] AES-CCM-16-64-128, HMAC 256/256, X25519, EdDSA, Ed25519
    int aead_algorithm_id = 10;
    int hmac_algorithm_id = 5;
    vector<uint8_t> C_U { 0xc3 };


    // Print
    print_fig( "method (Signature Authentication)", to_string(method) );

    cout << "CoaP is used as transport and Party U is CoAP client:" << endl;
    
    print_fig( "corr (Party U can correlate message_1 and message_2)", to_string(corr) );
    
    cout << "No unprotected opaque auxiliary data is sent in the message exchanges." << endl;
    cout << endl;
    cout << "The pre-defined Cipher Suite 0 is in place both on Party U and Party V, see {{cipher-suites}}." << endl;
    cout << endl;

    // Input for Party U //////////////////////////////////////////////
    cout << "### Input for Party U {#rpk-tv-input-u}" << endl;

    cout << endl;
    cout << "The following are the parameters that are set in Party U before the first message exchange." << endl;

    print_fig("Party U's private authentication key (" + to_string(U_sign_sk.size()) + " bytes)" , vector_to_string(U_sign_sk));

    print_fig("Party U's public authentication key (" + to_string(U_sign_pk.size()) + " bytes)" , vector_to_string(U_sign_pk));

    print_fig("kid value to identify U's public authentication key (" + to_string(kid_U.size()) + " bytes)" , vector_to_string(kid_U));

    cout << "This test vector uses COSE_Key objects to store the raw public keys. Moreover, EC2 keys with curve Ed25519 are used. That is in agreement with the Cipher Suite " << to_string(suite) << "." << endl;

    print_fig("CRED_U =", "<< {\n  1:  1,\n -1:  6,\n -2:  " + vector_to_cddl_bstr( U_sign_pk ) + "\n} >>");

    print_fig("CRED_U (bstr-wrapped COSE_Key) (CBOR-encoded) (" + to_string(cbor_bstr(CRED_U_CBOR).size()) + " bytes)" , vector_to_string( cbor_bstr(CRED_U_CBOR)) + "\n" );

    cout << "Because COSE_Keys are used, and because kid = " << vector_to_cddl_bstr( kid_U ) <<":";

    print_fig("ID_CRED_U =" , "{ \n  4:  " + vector_to_cddl_bstr( kid_U ) + "\n}" );

    cout << "Note that since the map for ID_CRED_U contains a single 'kid' parameter, ID_CRED_U is used when transported in the protected header of the COSE Object, but only the kid_value_U is used when added to the plaintext (see {{asym-msg3-proc}}):" << endl;

    print_fig("ID_CRED_U (in protected header) (CBOR-encoded) (" + to_string(ID_CRED_U_CBOR.size()) + " bytes)" , vector_to_string( ID_CRED_U_CBOR ) );
    
    print_fig("kid_value_U (in plaintext) (CBOR-encoded) (" + to_string(cbor_bstr(kid_U).size()) + " bytes)" , vector_to_string( cbor_bstr(kid_U) ) );

    // Input for Party V //////////////////////////////////////////////
    cout << "### Input for Party V {#rpk-tv-input-v}" << endl;

    cout << endl;
    cout << "The following are the parameters that are set in Party V before the first message exchange." << endl;

    print_fig("Party V's private authentication key (" + to_string(V_sign_sk.size()) + " bytes)" , vector_to_string(V_sign_sk));

    print_fig("Party V's public authentication key (" + to_string(V_sign_pk.size()) + " bytes)" , vector_to_string(V_sign_pk));

    print_fig("kid value to identify V's public authentication key (" + to_string(kid_V.size()) + " bytes)" , vector_to_string(kid_V));

    cout << "This test vector uses COSE_Key objects to store the raw public keys. Moreover, EC2 keys with curve Ed25519 are used. That is in agreement with the Cipher Suite " << to_string(suite) << "." << endl;

    string cred_v_str = "<< {\n  1:  1,\n -1:  6,\n -2:  " + vector_to_cddl_bstr( V_sign_pk ) + "\n} >>";
    print_fig("CRED_V =" , cred_v_str );

    print_fig("CRED_V (bstr-wrapped COSE_Key) (CBOR-encoded) (" + to_string(cbor_bstr(CRED_V_CBOR).size()) + " bytes)" , vector_to_string( cbor_bstr(CRED_V_CBOR)) + "\n" );

    cout << "Because COSE_Keys are used, and because kid = " << vector_to_cddl_bstr( kid_V ) <<":";

    string id_cred_v_str = "{ \n  4:  " + vector_to_cddl_bstr( kid_V ) + "\n}";
    print_fig("ID_CRED_V =" , id_cred_v_str );

    cout << "Note that since the map for ID_CRED_U contains a single 'kid' parameter, ID_CRED_U is used when transported in the protected header of the COSE Object, but only the kid_value_V is used when added to the plaintext (see {{asym-msg3-proc}}):" << endl;

    print_fig("ID_CRED_V (in protected header) (CBOR-encoded) (" + to_string(ID_CRED_V_CBOR.size()) + " bytes)" , vector_to_string( ID_CRED_V_CBOR ) );
    
    print_fig("kid_value_V (in plaintext) (CBOR-encoded) (" + to_string(cbor_bstr(kid_V).size()) + " bytes)" , vector_to_string( cbor_bstr(kid_V) ) );


    // message_1 ////////////////////////////////////////////////////////////////////////////

    // Generate the Party U's ephemeral key pair
    vector<uint8_t> U_kx_pk( crypto_kx_PUBLICKEYBYTES );
    vector<uint8_t> U_kx_sk( crypto_kx_SECRETKEYBYTES );
    vector<uint8_t> U_kx_seed( crypto_kx_SEEDBYTES, 6 ); ;
    crypto_kx_seed_keypair( U_kx_pk.data(), U_kx_sk.data(), U_kx_seed.data() );


    // Calculate message_1
    vector<uint8_t> message_1;
    vector_append( message_1, cbor_uint8( TYPE ) ); 
    vector_append( message_1, cbor_uint8( suite ) ); 
    vector_append( message_1, cbor_bstr( U_kx_pk ) ); 
    vector_append( message_1, cbor_bstr( C_U ) ); 

    // Print //////////////////////////////////////////////
    cout << "### Message 1 {#tv-rpk-1}" << endl << endl;
    cout << "From the input parameters (in {{rpk-tv-input-u}}):" << endl;

    print_fig("TYPE (4 * method + corr)" , to_string(TYPE));
    print_fig("suite", to_string(suite));
    print_fig("SUITES_U : suite", to_string(suite));
    print_fig("Party U's ephemeral private key (" + to_string(U_kx_sk .size()) + " bytes)", vector_to_string(U_kx_sk));
    print_fig("G_X (X-coordinate of the ephemeral public key of Party U) (" + to_string(U_kx_pk .size()) + " bytes)", vector_to_string(U_kx_pk));
    print_fig("C_U (Connection identifier chosen by U) (" + to_string(C_U.size()) + " bytes)", vector_to_string(C_U));

    cout << "No AD_1 is provided, so AD_1 is absent from message_1." << endl << endl;
    cout << "Message_1 is constructed, as the CBOR Sequence of the CBOR data items above." << endl;

    print_fig("message_1 =" , "(\n  " + to_string(TYPE) + ",\n  " + to_string(suite) + ",\n  " + vector_to_cddl_bstr(U_kx_pk) + ",\n  " + vector_to_cddl_bstr(C_U) + "\n)");

    print_fig("message_1 (CBOR Sequence) (" + to_string(message_1.size()) + " bytes)", vector_to_string(message_1) );

    // message_2 ////////////////////////////////////////////////////////////////////////////

    // Generate the Party V's ephemeral key pair 
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

    // Print //////////////////////////////////////////////

    cout << "### Message 2 {#tv-rpk-2}" << endl << endl;

    cout << "Since TYPE mod 4 equals " + to_string(TYPE) + ", C_U is omitted from data_2." << endl << endl;

    print_fig("Party V's ephemeral private key (" + to_string(V_kx_sk .size()) + " bytes)", vector_to_string(V_kx_sk));
    print_fig("G_Y (X-coordinate of the ephemeral public key of Party V) (" + to_string(V_kx_pk .size()) + " bytes)", vector_to_string(V_kx_pk));
    print_fig("C_V (Connection identifier chosen by V) (" + to_string(C_V.size()) + " bytes)", vector_to_string(C_V));

    cout << "Data_2 is constructed, as the CBOR Sequence of the CBOR data items above." << endl << endl;

    print_fig("data_2 =", "(\n  " + vector_to_cddl_bstr(V_kx_pk) + ",\n  " + vector_to_cddl_bstr(C_V) + "\n)");
    print_fig("data_2 (CBOR Sequence) (" + to_string(data_2.size()) + " bytes)", vector_to_string(data_2));

    cout << "From data_2 and message_1 (from {{tv-rpk-1}}), compute the input to the transcript hash TH_2 = H( message_1, data_2 ), as a CBOR Sequence of these 2 data items." << endl << endl;

    print_fig("( message_1, data_2 ) (CBOR Sequence) (" + to_string(TH_2_input.size()) + " bytes)" , vector_to_string(TH_2_input));

    cout << "And from there, compute the transcript hash TH_2 = SHA-256( message_1, data_2 )" << endl << endl;

    print_fig("TH_2 value (" + to_string(TH_2.size()) + " bytes)" , vector_to_string(TH_2));

    cout << "When encoded as a CBOR bstr, that gives:" << endl << endl;

    print_fig("TH_2 (CBOR-encoded) (" + to_string(cbor_bstr(TH_2).size()) + " bytes)" , vector_to_string(cbor_bstr(TH_2)));

    // Calculate signature
    vector<uint8_t> message_V { 0x84 }; // CBOR array of length 4
    vector_append( message_V, cbor_tstr( "Signature1" ) );
    vector_append( message_V, cbor_bstr( ID_CRED_V_CBOR ) );
    vector_append( message_V, cbor_bstr( TH_2 ) );
    vector_append( message_V, cbor_bstr( CRED_V_CBOR ) );
    vector<uint8_t> signature_V( crypto_sign_BYTES );
    crypto_sign_detached( signature_V.data(), nullptr, message_V.data(), message_V.size(), V_sign_sk_libsodium.data() );

     // Print //////////////////////////////////////////////

    cout << "#### Signature Computation {#tv-rpk-2-sign}" << endl << endl;

    cout << "COSE_Sign1 is computed with the following parameters. From {{rpk-tv-input-v}}:" << endl << endl;
    cout << "* protected = bstr .cbor ID_CRED_V " << endl << endl;
    cout << "* payload = CRED_V" << endl << endl;
    cout << "And from {{tv-rpk-2}}:" << endl << endl;
    cout << "* external_aad = TH_2" << endl << endl;
    cout << "The Sig_structure M_V to be signed is: \\[ \"Signature1\", << ID_CRED_V >>, TH_2, CRED_V \\] , as defined in {{asym-msg2-proc}}:" << endl << endl;

    print_fig("M_V =" , "[\n  \"Signature1\",\n  << " + line(id_cred_v_str) + " >>,\n  " + vector_to_cddl_bstr(TH_2) + ",\n  "+ tab(cred_v_str) + "\n]");

    cout << "Which encodes to the following byte string ToBeSigned:" << endl;

    print_fig("M_V (message to be signed with Ed25519) (CBOR-encoded) (" + to_string(message_V.size()) + " bytes)", vector_to_string(message_V));

    cout << "The message is signed using the private authentication key of V, and produces the following signature:" << endl;

    print_fig("V's signature (" + to_string(signature_V.size()) + " bytes)", vector_to_string(signature_V));


    // Derive key and IV
    vector<uint8_t> salt; // empty byte string;
    vector<uint8_t> PRK = hkdf_extract_sha_256( salt, shared_secret );
    vector<uint8_t> info_K_2 = gen_info( cbor_uint8( aead_algorithm_id ), 128, TH_2 );
    vector<uint8_t> K_2 = hkdf_expand_sha_256( PRK, info_K_2, 16 );
    vector<uint8_t> info_IV_2 = gen_info( cbor_tstr( "IV-GENERATION" ), 104, TH_2 );
    vector<uint8_t> IV_2 = hkdf_expand_sha_256( PRK, info_IV_2, 13 );

    // Print //////////////////////////////////////////////

    cout << "#### Key and Nonce Computation {#tv-rpk-2-key}" << endl << endl;

    cout << "The key and nonce for calculating the ciphertext are calculated as follows, as specified in {{key-der}}." << endl << endl;
    cout << "HKDF SHA-256 is the HKDF used (as defined by cipher suite 0)." << endl << endl;
    cout << "PRK = HMAC-SHA-256(salt, G_XY)" << endl << endl;
    cout << "Since this is the asymmetric case, salt is the empty byte string." << endl << endl;
    cout << "G_XY is the shared secret, and since the curve25519 is used, the ECDH shared secret is the output of the X25519 function." << endl;

    print_fig("G_XY (" + to_string(shared_secret.size()) + " bytes)", vector_to_string(shared_secret));

    cout << "From there, PRK is computed:" << endl;

    print_fig("PRK (" + to_string(PRK.size()) + " bytes)", vector_to_string(PRK));

    cout << "Key K_2 is the output of HKDF-Expand(PRK, info, L)." << endl << endl;
    cout << "info is defined as follows:" << endl;

    print_fig("info for K_2", info_string(to_string(aead_algorithm_id), 128, TH_2));

    cout << "Which as a CBOR encoded data item is:" << endl;

    print_fig("info (K_2) (CBOR-encoded) (" + to_string(info_K_2.size()) + " bytes)", vector_to_string(info_K_2));

    cout << "L is the length of K_2, so " + to_string(K_2.size()) + " bytes." << endl << endl;

    cout << "From these parameters, K_2 is computed:" << endl;

    print_fig("K_2 (" + to_string(K_2.size()) + " bytes)", vector_to_string(K_2));

    cout << "Nonce IV_2 is the output of HKDF-Expand(PRK, info, L)." << endl << endl;

    cout << "info is defined as follows:" << endl;

    print_fig("info for IV_2", info_string("\"IV-GENERATION\"", 104, TH_2));

    cout << "Which as a CBOR encoded data item is:" << endl;

    print_fig("info (IV_2) (CBOR-encoded) (" + to_string(info_IV_2.size()) + " bytes)", vector_to_string(info_IV_2));
   
    cout << "L is the length of IV_2, so " + to_string(IV_2.size()) + " bytes." << endl << endl;

    cout << "From these parameters, IV_2 is computed:" << endl;

    print_fig("IV_2 (" + to_string(IV_2.size()) + " bytes)", vector_to_string(IV_2));


    // Calculate ciphertext
    vector<uint8_t> P_2;
    vector_append( P_2, cbor_bstr( kid_V ) ); // ID_CRED_V contains a single 'kid' parameter, so only bstr is used
    vector_append( P_2, cbor_bstr( signature_V ) );
    vector<uint8_t> A_2 = { 0x83 }; // CBOR array of length 3
    vector_append( A_2, cbor_tstr( "Encrypt0" ) );
    vector_append( A_2, cbor_bstr( { } ) ); // empty bstr 
    vector_append( A_2, cbor_bstr( TH_2 ) );
    vector<uint8_t> C_2 = aes_ccm_16_64_128( K_2, IV_2, P_2, A_2 );

    // Print //////////////////////////////////////////////

    cout << "#### Ciphertext Computation {#tv-rpk-2-ciph}" << endl << endl;

    cout << "COSE_Encrypt0 is computed with the following parameters. Note that AD_2 is omitted." << endl << endl;
    cout << "* empty protected header" << endl << endl;
    cout << "* external_aad = TH_2" << endl << endl;
    cout << "* plaintext = CBOR Sequence of the items kid_value_V, signature, in this order." << endl << endl;
    cout << "with kid_value_V taken from {{rpk-tv-input-v}}, and signature as calculated in {{tv-rpk-2-sign}}." << endl << endl;
    cout << "The plaintext is the following:" << endl ;

    print_fig("P_2 (" + to_string(P_2.size()) + " bytes)" , vector_to_string(P_2));

    cout << "From the parameters above, the Enc_structure A_2 is computed." << endl;

    print_fig("A_2 =" , enc_string(TH_2));

    cout << "Which encodes to the following byte string to be used as Additional Authenticated Data:" << endl;

    print_fig("A_2 (CBOR-encoded) (" + to_string(A_2.size()) + " bytes)", vector_to_string (A_2));


    cout << "The key and nonce used are defined in {{tv-rpk-2-key}}:" << endl << endl;

    cout << "* key = K_2" << endl << endl;

    cout << "* nonce = IV_2" << endl << endl;

    cout << "Using the parameters above, the ciphertext CIPHERTEXT_2 can be computed:" << endl;

    print_fig("CIPHERTEXT_2 (" + to_string(C_2.size()) + " bytes)", vector_to_string (C_2));


    // Calculate message_2
    vector<uint8_t> message_2;
    vector_append( message_2, data_2 );
    vector_append( message_2, cbor_bstr( C_2 ) ); 

    // Print //////////////////////////////////////////////

    cout << "#### message_2" << endl << endl;

    cout << "From the parameter computed in {{tv-rpk-2}} and {{tv-rpk-2-ciph}}, message_2 is computed, as the CBOR Sequence of the following items: (G_Y, C_V, CIPHERTEXT_2)." << endl << endl;

    print_fig("message_2 =" , "(\n  " + vector_to_cddl_bstr(V_kx_pk) + ",\n  " + vector_to_cddl_bstr(C_V) + ",\n  " + vector_to_cddl_bstr(C_2) + "\n)");

    cout << "Which encodes to the following byte string:" << endl;

    print_fig("message_2 (CBOR Sequence) (" + to_string(message_2.size()) + " bytes)", vector_to_string (message_2));


/*

    //OLD
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
    uint8_t suite = 0; // [ 10, 5, 4, -8, 6 ] AES-CCM-16-64-128, HMAC 256/256, X25519, EdDSA, Ed25519
    int aead_algorithm_id = 10;
    int hmac_algorithm_id = 5;
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

    // Generate the Party V's ephemeral key pair 
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
    vector_append( message_V, cbor_bstr( CRED_V_CBOR ) );
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
    cout << "  << {" << endl;
    cout << "    1:  1," << endl;
    cout << "   -1:  6," << endl;
    cout << "   -2:  h'";
    for ( auto i : V_sign_pk )
        cout << hex << setfill('0') << setw(2) << (int)i;
    cout << "'," << endl << "  } >>," << endl;
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
    cout << "'," << endl;
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
    vector_append( message_U, cbor_bstr( CRED_U_CBOR ) );
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
    cout << "  << {" << endl;
    cout << "    1:  1," << endl;
    cout << "   -1:  6," << endl;
    cout << "   -2:  h'";
    for ( auto i : U_sign_pk )
        cout << hex << setfill('0') << setw(2) << (int)i;
    cout << "'," << endl << "  } >>," << endl;
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
    cout << "'," << endl;
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

    print_int( "HMAC Algorithm", hmac_algorithm_id );

*/
}

int main( void )
{
    // Initiate Sodium
    if ( sodium_init() == -1 ) {
        cout << "The libsodoum library couldn't be initialized";
        return 1;
    }

    /* Test vectors intro */

    cout << endl << endl << "# Test Vectors {#vectors}" << endl << endl << "This appendix provides detailed test vectors to ease implementation and ensure interoperability. In addition to hexadecimal, all CBOR data items and sequences are given in CBOR diagnostic notation. The test vectors use 1 byte key identifiers, 1 byte connection IDs, and the default mapping to CoAP where Party U is CoAP client (this means that corr = 1). " << endl;
    //TODO: extract length from connection IDs and key identifiers

    rpk_vectors();
    psk_vectors();
}
