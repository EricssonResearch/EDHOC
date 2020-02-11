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

#define COLUMN 72

// Concatenates a to the end of v (may not work if a = v)
void vector_append( vector<uint8_t> &v, vector<uint8_t> a ) {
    v.reserve( 1000 ); // big so that iterators are stable during insert
    v.insert( v.end(), a.begin(), a.end() );
}

// returns a string from vector
string vector_to_string( vector<uint8_t> v ) {
    string s;
    for ( int i = 1; i < v.size() + 1; ++i ) {
        ostringstream ss;
        ss << hex << setfill('0') << setw(2) << (int)v[i - 1];
        if(i % (COLUMN / 3) == 0) //column 75 to the line
            ss << endl;
        else
            ss << " ";
        s += ss.str();
    }
    return s;
}


// print a md figure to cout
void print_fig( string title, string s ) {
    cout << endl << "~~~~~~~~~~~~~~~~~~~~~~~" << endl << title << endl << s << endl << "~~~~~~~~~~~~~~~~~~~~~~~" << endl <<endl;
}

void print_fig_with_bytes( string title, vector<uint8_t> v ) {
    string s = title + " (" + to_string(v.size());
    if (v.size() == 1)
        s += " byte)";
    else
        s += " bytes)";
    print_fig(s, vector_to_string(v));
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

// returns a cddl bstr from vector
string vector_to_cddl_bstr_old( vector<uint8_t> v ) {
    string s;
    s += "h'";
    for ( int i = 0; i < v.size(); ++i ) {
        ostringstream ss;
        ss << hex << setfill('0') << setw(2) << (int)v[i];
        s += ss.str();
    }
    s += "'";
    return s;
}

// returns a cddl bstr from vector
string vector_to_cddl_bstr( vector<uint8_t> v , int spaces ) {
    string s;
    s += "h'";
    int column;
    for ( int i = 1; i < v.size() + 1; ++i ) {
        ostringstream ss;
        ss << hex << setfill('0') << setw(2) << (int)v[i - 1];
        if( i * 2 % (COLUMN - spaces) == 0) //to the line
            ss << endl << string(spaces, ' ');
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
    s = "[\n  " + id + ",\n  [ null, null, null ],\n  [ null, null, null ],\n  [ " + to_string(keyDataLength) + ", h'', " + vector_to_cddl_bstr(other, 16) + "]\n]";
    return s;
}

// Returns the enc structure as string
string enc_string( vector<uint8_t> prot, vector<uint8_t> ext_aad )
{
    string s;
    s = "[\n  \"Encrypt0\",\n  " + vector_to_cddl_bstr(prot, 4) +  ",\n  " + vector_to_cddl_bstr(ext_aad, 4) + "\n]";
    return s;
}

void psk_vectors( void )
{

    cout << "## Test Vectors for EDHOC Authenticated with Symmetric Keys (PSK)" << endl << endl;

    // Pre-shared stuff ////////////////////////////////////////////////////////////////////////////

    vector<uint8_t> PSK( 16 );  // 16 bytes = 128 bit security
    vector<uint8_t> PSK_seed( randombytes_SEEDBYTES, 0 ); 
    randombytes_buf_deterministic( PSK.data(), PSK.size(), PSK_seed.data() );
    vector<uint8_t> kid { 0xa1 };
    vector<uint8_t> ID_PSK = cbor_bstr( kid );
    vector<uint8_t> ID_PSK_CBOR { 0xa1, 0x04 }; //fp: added for printing
    vector_append( ID_PSK_CBOR, ID_PSK ); //fp: added for printing

    // Other parameters
    uint8_t method = 1; // Symmetric
    uint8_t corr = 1; // Party U is CoAP client
    uint8_t TYPE = 4 * method + corr;
    uint8_t suite = 0; // [ 10, 5, 4, -8, 6 ] AES-CCM-16-64-128, HMAC 256/256, X25519, EdDSA, Ed25519
    int aead_algorithm_id = 10;
    int hmac_algorithm_id = 5;
    vector<uint8_t> C_U { 0xc1 };

    // Print //////////////////////////////////////////////

    cout << "Symmetric EDHOC is used:" << endl;

    print_fig( "method (Symmetric Authentication)", to_string(method) );

    cout << "CoaP is used as transport and Party U is CoAP client:" << endl;
    
    print_fig( "corr (Party U can correlate message_1 and message_2)", to_string(corr) );
    
    cout << "No unprotected opaque auxiliary data is sent in the message exchanges." << endl;
    cout << endl;
    cout << "The pre-defined Cipher Suite 0 is in place both on Party U and Party V, see {{cipher-suites}}." << endl;
    cout << endl;


    // Generate the Party U's ephemeral key pair
    vector<uint8_t> U_kx_pk( crypto_kx_PUBLICKEYBYTES );
    vector<uint8_t> U_kx_sk( crypto_kx_SECRETKEYBYTES );
    vector<uint8_t> U_kx_seed( crypto_kx_SEEDBYTES, 1 ); ;
    crypto_kx_seed_keypair( U_kx_pk.data(), U_kx_sk.data(), U_kx_seed.data() );

    // Print //////////////////////////////////////////////

    cout << "### Input for Party U {#psk-tv-input-u}" << endl << endl;

    cout << "The following are the parameters that are set in Party U before the first message exchange." << endl;

    print_fig_with_bytes("Party U's ephemeral private key" , U_kx_sk);

    print_fig_with_bytes("Party U's ephemeral public key (value of G_X)" , U_kx_pk);

    print_fig_with_bytes("Connection identifier chosen by U (value of C_U)" , C_U);

    print_fig_with_bytes("Pre-shared Key (PSK)" , PSK);

    print_fig_with_bytes("kid value to identify PSK" , kid);

    cout << "So ID_PSK is defined as the following:" << endl;

    print_fig( "ID_PSK =" , "{\n  4:" + vector_to_cddl_bstr(kid, 6) + "\n}");

    cout << "This test vector uses COSE_Key objects to store the pre-shared key." << endl << endl;

    cout << "Note that since the map for ID_PSK contains a single 'kid' parameter, ID_PSK is used when transported in the protected header of the COSE Object, but only the kid_value is used when added to the plaintext (see {{sym-overview}}):" << endl;

    print_fig_with_bytes("ID_PSK (in protected header) (CBOR-encoded)" , ID_PSK_CBOR);

    print_fig_with_bytes("kid_value (in plaintext) (CBOR-encoded)" , ID_PSK);


    // Generate the Party V's ephemeral key pair 
    vector<uint8_t> V_kx_pk( crypto_kx_PUBLICKEYBYTES );
    vector<uint8_t> V_kx_sk( crypto_kx_SECRETKEYBYTES );
    vector<uint8_t> V_kx_seed( crypto_kx_SEEDBYTES, 2 ); ;
    crypto_kx_seed_keypair( V_kx_pk.data(), V_kx_sk.data(), V_kx_seed.data() );

    // Other parameters
    vector<uint8_t> C_V { 0xc2 };

    // Print //////////////////////////////////////////////

    cout << "### Input for Party V {#psk-tv-input-v}" << endl << endl;

    cout << "The following are the parameters that are set in Party V before the first message exchange." << endl;

    print_fig_with_bytes("Party V's ephemeral private key" , V_kx_sk);

    print_fig_with_bytes("Party V's ephemeral public key (value of G_Y)" , V_kx_pk);

    print_fig_with_bytes("Connection identifier chosen by V (value of C_V)" , C_V);

    print_fig_with_bytes("Pre-shared Key (PSK)" , PSK);

    print_fig_with_bytes("kid value to identify PSK" , kid);

    cout << "So ID_PSK is defined as the following:" << endl;

    print_fig( "ID_PSK =" , "{\n  4:" + vector_to_cddl_bstr(kid, 6) + "\n}");

    cout << "This test vector uses COSE_Key objects to store the pre-shared key." << endl << endl;

    cout << "Note that since the map for ID_PSK contains a single 'kid' parameter, ID_PSK is used when transported in the protected header of the COSE Object, but only the kid_value is used when added to the plaintext (see {{sym-overview}}):" << endl;

    print_fig_with_bytes("ID_PSK (in protected header) (CBOR-encoded)" , ID_PSK_CBOR);

    print_fig_with_bytes("kid_value (in plaintext) (CBOR-encoded)" , ID_PSK);


    // message_1 ////////////////////////////////////////////////////////////////////////////

    // Calculate message_1
    vector<uint8_t> message_1;
    vector_append( message_1, cbor_uint8( TYPE ) ); 
    vector_append( message_1, cbor_uint8( suite ) ); 
    vector_append( message_1, cbor_bstr( U_kx_pk ) ); 
    vector_append( message_1, cbor_bstr( C_U ) ); 
    vector_append( message_1, cbor_bstr( kid ) ); // ID_PSK contains a single 'kid' parameter, so only bstr is used

    // Print //////////////////////////////////////////////

    cout << "### Message 1 {#tv-psk-1}" << endl << endl;

    cout << "From the input parameters (in {{psk-tv-input-u}}):" << endl;

    print_fig("TYPE (4 * method + corr)" , to_string(TYPE));

    print_fig("suite", to_string(suite));

    print_fig("SUITES_U : suite", to_string(suite));

    print_fig_with_bytes("G_X (X-coordinate of the ephemeral public key of Party U)" , U_kx_pk);

    print_fig_with_bytes("C_U (Connection identifier chosen by U) (CBOR encoded)", cbor_bstr(C_U));

    print_fig_with_bytes("kid_value of ID_PSK (CBOR encoded)", ID_PSK);

    cout << "No UAD_1 is provided, so AD_1 is absent from message_1." << endl << endl;

    cout << "Message_1 is constructed, as the CBOR Sequence of the CBOR data items above." << endl;

    print_fig("message_1 =", "(\n  " + to_string(TYPE) + ",\n  " + to_string(suite) + ",\n  " + vector_to_cddl_bstr(U_kx_pk , 4) + ",\n  " + vector_to_cddl_bstr(C_U, 4) + ",\n  " + vector_to_cddl_bstr(kid, 4) + "\n)");

    print_fig_with_bytes("message_1 (CBOR Sequence)" , message_1);

    // message_2 ////////////////////////////////////////////////////////////////////////////

    // Calculate data_2
    vector<uint8_t> data_2;
    vector_append( data_2, cbor_bstr( V_kx_pk ) ); 
    vector_append( data_2, cbor_bstr( C_V ) ); 

    // Calculate TH_2
    vector<uint8_t> TH_2_input;
    vector_append( TH_2_input, message_1 );
    vector_append( TH_2_input, data_2 );
    vector<uint8_t> TH_2 = hash_sha_256( TH_2_input );

    // Print ////////////////////////////////////////////// 

    cout << "### Message 2 {#tv-psk-2}" << endl << endl;

    cout << "Since TYPE mod 4 equals 1, C_U is omitted from data_2." << endl;

    print_fig_with_bytes("G_Y (X-coordinate of the ephemeral public key of Party V)" , V_kx_pk);

    print_fig_with_bytes("C_V (Connection identifier chosen by V)" , C_V);

    cout << "Data_2 is constructed, as the CBOR Sequence of the CBOR data items above." << endl;

    print_fig("data_2 =" , "(\n  " + vector_to_cddl_bstr(V_kx_pk , 4) + ",\n  " + vector_to_cddl_bstr(C_V , 4) + "\n)");

    print_fig_with_bytes("data_2 (CBOR Sequence)" , data_2);
    
    cout << "From data_2 and message_1 (from {{tv-psk-1}}), compute the input to the transcript hash TH_2 = H( message_1, data_2 ), as a CBOR Sequence of these 2 data items." << endl;

    print_fig_with_bytes("( message_1, data_2 ) (CBOR Sequence)" , TH_2_input);
    
    cout << "And from there, compute the transcript hash TH_2 = SHA-256( message_1, data_2 )" << endl;

    print_fig_with_bytes("TH_2 value" , TH_2);

    cout << "When encoded as a CBOR bstr, that gives:" << endl;

    print_fig_with_bytes("TH_2 (CBOR-encoded)" , cbor_bstr(TH_2));


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

    // Print ////////////////////////////////////////////// 

    cout << "#### Key and Nonce Computation {#tv-psk-2-key}" << endl << endl;

    cout << "The key and nonce for calculating the ciphertext are calculated as follows, as specified in {{key-der}}." << endl << endl;

    cout << "HKDF SHA-256 is the HKDF used (as defined by cipher suite 0)." << endl << endl;

    cout << "PRK = HMAC-SHA-256(salt, G_XY)" << endl << endl;

    cout << "Since this is the symmetric case, salt is the PSK:" << endl;

    print_fig_with_bytes("salt" , salt);

    cout << "G_XY is the shared secret, and since the curve25519 is used, the ECDH shared secret is the output of the X25519 function." << endl;

    print_fig_with_bytes("G_XY" , shared_secret);

    cout << "From there, PRK is computed:" << endl;

    print_fig_with_bytes("PRK" , PRK);

    cout << "Key K_2 is the output of HKDF-Expand(PRK, info, L)." << endl << endl;

    cout << "info is defined as follows:" << endl;

    print_fig("info for K_2 =", info_string(to_string(aead_algorithm_id), 128, TH_2));

    cout << "Which as a CBOR encoded data item is:" << endl;

    print_fig_with_bytes("info (K_2) (CBOR-encoded)" , info_K_2);

    cout << "L is the length of K_2, so " + to_string(K_2.size()) + " bytes." << endl << endl;

    cout << "From these parameters, K_2 is computed:" << endl;

    print_fig_with_bytes("K_2", K_2);

    cout << "Nonce IV_2 is the output of HKDF-Expand(PRK, info, L)." << endl;

    cout << "info is defined as follows:" << endl;

    print_fig("info for IV_2 =", info_string("\"IV-GENERATION\"", 104, TH_2));

    cout << "Which as a CBOR encoded data item is:" << endl;

    print_fig_with_bytes("info (IV_2) (CBOR-encoded)" , info_IV_2);

    cout << "L is the length of IV_2, so " + to_string(IV_2.size()) + " bytes." << endl << endl;

    cout << "From these parameters, IV_2 is computed:" << endl;

    print_fig_with_bytes("IV_2", IV_2);


    // Calculate ciphertext
    vector<uint8_t> P_2; // empty byte string
    vector<uint8_t> A_2 = { 0x83 }; // CBOR array of length 3
    vector_append( A_2, cbor_tstr( "Encrypt0" ) );
    vector_append( A_2, cbor_bstr( { } ) ); // empty bstr 
    vector_append( A_2, cbor_bstr( TH_2 ) );
    vector<uint8_t> C_2 = aes_ccm_16_64_128( K_2, IV_2, P_2, A_2 );

    // Print ////////////////////////////////////////////// 

    cout << "#### Ciphertext Computation {#tv-psk-2-ciph}" << endl << endl;

    cout << "COSE_Encrypt0 is computed with the following parameters. Note that AD_2 is omitted." << endl << endl;

    cout << "* empty protected header" << endl << endl;

    cout << "* external_aad = TH_2" << endl << endl;

    cout << "* empty plaintext, since AD_2 is omitted" << endl << endl;

    cout << "* empty plaintext, since AD_2 is omitted" << endl << endl;

    cout << "From the parameters above, the Enc_structure A_2 is computed." << endl;

    print_fig("A_2 =" , enc_string(vector<uint8_t> (),TH_2));

    cout << "Which encodes to the following byte string to be used as Additional Authenticated Data:" << endl;

    print_fig_with_bytes("A_2 (CBOR-encoded)" , A_2);

    cout << "The key and nonce used are defined in {{tv-psk-2-key}}:" << endl << endl;

    cout << "* key = K_2" << endl << endl;

    cout << "* nonce = IV_2" << endl << endl;

    cout << "Using the parameters above, the ciphertext CIPHERTEXT_2 can be computed:" << endl;

    print_fig_with_bytes("CIPHERTEXT_2" , C_2);


    // Calculate message_2
    vector<uint8_t> message_2;
    vector_append( message_2, data_2 );
    vector_append( message_2, cbor_bstr( C_2 ) ); 

    // Print ////////////////////////////////////////////// 

    cout << "#### message_2" << endl << endl;

    cout << "From the parameter computed in {{tv-psk-2}} and {{tv-psk-2-ciph}}, message_2 is computed, as the CBOR Sequence of the following items: (G_Y, C_V, CIPHERTEXT_2)." << endl;

    print_fig("message_2 =" , "(\n  " + vector_to_cddl_bstr(V_kx_pk , 4) + ",\n  " + vector_to_cddl_bstr(C_V , 4)  + ",\n  " + vector_to_cddl_bstr(C_2 , 4) + "\n)");

    cout << "Which encodes to the following byte string:" << endl;

    print_fig_with_bytes("message_2 (CBOR Sequence)" , message_2);


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

    // Print ////////////////////////////////////////////// 

    cout << "### Message 3 {#tv-psk-3}" << endl << endl;

    cout << "Since TYPE mod 4 equals 1, C_V is not omitted from data_3." << endl;

    print_fig_with_bytes("C_V" , C_V);

    cout << "Data_3 is constructed, as the CBOR Sequence of the CBOR data item above." << endl;

    print_fig("data_3 =" , "(\n  " + vector_to_cddl_bstr(C_V , 4) + "\n)");

    print_fig_with_bytes("data_3 (CBOR Sequence)" , data_3);

    cout << "From data_3, CIPHERTEXT_2 ({{tv-psk-2-ciph}}), and TH_2 ({{tv-psk-2}}), compute the input to the transcript hash TH_3 = H(TH_2 , CIPHERTEXT_2, data_3), as a CBOR Sequence of these 3 data items." << endl;

    print_fig_with_bytes("( TH_2, CIPHERTEXT_2, data_3 ) (CBOR Sequence)" , TH_3_input);

    cout << "And from there, compute the transcript hash TH_3 = SHA-256(TH_2 , CIPHERTEXT_2, data_3)" << endl;

    print_fig_with_bytes("TH_3 value" , TH_3);

    cout << "When encoded as a CBOR bstr, that gives:" << endl;

    print_fig_with_bytes("TH_3 (CBOR-encoded)" , cbor_bstr(TH_3));


    // Derive key and IV
    vector<uint8_t> info_K_3 = gen_info( cbor_uint8( aead_algorithm_id ), 128, TH_3 );
    vector<uint8_t> K_3 = hkdf_expand_sha_256( PRK, info_K_3, 16 );
    vector<uint8_t> info_IV_3 = gen_info( cbor_tstr( "IV-GENERATION" ), 104, TH_3 );
    vector<uint8_t> IV_3 = hkdf_expand_sha_256( PRK, info_IV_3, 13 );

    // Print //////////////////////////////////////////////

    cout << "#### Key and Nonce Computation {#tv-psk-3-key}" << endl << endl;

    cout << "The key and nonce for calculating the ciphertext are calculated as follows, as specified in {{key-der}}." << endl << endl;

    cout << "HKDF SHA-256 is the HKDF used (as defined by cipher suite 0)." << endl << endl;

    cout << "PRK = HMAC-SHA-256(salt, G_XY)" << endl << endl;

    cout << "Since this is the symmetric case, salt is the PSK:" << endl;

    print_fig_with_bytes("salt" , salt);

    cout << "G_XY is the shared secret, and since the curve25519 is used, the ECDH shared secret is the output of the X25519 function." << endl;

    print_fig_with_bytes("G_XY" , shared_secret);

    cout << "From there, PRK is computed:" << endl;

    print_fig_with_bytes("PRK" , PRK);

    cout << "Key K_3 is the output of HKDF-Expand(PRK, info, L)." << endl << endl;

    cout << "info is defined as follows:" << endl;

    print_fig("info for K_3 =" , info_string( to_string(aead_algorithm_id) , 128 , TH_3));

    cout << "Which as a CBOR encoded data item is:" << endl;

    print_fig_with_bytes("info (K_3) (CBOR-encoded)" , info_K_3);

    cout << "L is the length of K_3, so " << to_string(K_3.size()) << " bytes." << endl << endl;

    cout << "From these parameters, K_3 is computed:" << endl;

    print_fig_with_bytes("K_3" , K_3);

    cout << "Nonce IV_3 is the output of HKDF-Expand(PRK, info, L)." << endl << endl;

    cout << "info is defined as follows:" << endl;

    print_fig("info for IV_3 =" , info_string("\"IV-GENERATION\"" , 104 , TH_3));

    cout << "Which as a CBOR encoded data item is:" << endl;

    print_fig_with_bytes("info (IV_3) (CBOR-encoded)" , info_IV_3);

    cout << "L is the length of IV_3, so " << to_string(IV_3.size()) << " bytes." << endl << endl;

    cout << "From these parameters, IV_3 is computed:" << endl;

    print_fig_with_bytes("IV_3" , IV_3);

    // Calculate ciphertext
    vector<uint8_t> P_3; // empty byte string
    vector<uint8_t> A_3 = { 0x83 }; // CBOR array of length 3
    vector_append( A_3, cbor_tstr( "Encrypt0" ) );
    vector_append( A_3, cbor_bstr( { } ) ); // empty bstr 
    vector_append( A_3, cbor_bstr( TH_3 ) );
    vector<uint8_t> C_3 = aes_ccm_16_64_128( K_3, IV_3, P_3, A_3 );

    // Print ////////////////////////////////////////////// 

    cout << "#### Ciphertext Computation {#tv-psk-3-ciph}" << endl << endl;

    cout << "COSE_Encrypt0 is computed with the following parameters. Note that AD_3 is omitted." << endl << endl;

    cout << "* empty protected header" << endl << endl;

    cout << "* external_aad = TH_3" << endl << endl;

    cout << "* empty plaintext, since AD_3 is omitted" << endl << endl;

    cout << "From the parameters above, the Enc_structure A_3 is computed." << endl;

    print_fig("A_3 =" , enc_string(vector<uint8_t> (),TH_3));

    cout << "Which encodes to the following byte string to be used as Additional Authenticated Data:" << endl;

    print_fig_with_bytes("A_3 (CBOR-encoded)" , A_3);

    cout << "The key and nonce used are defined in {{tv-psk-3-key}}:" << endl << endl;

    cout << "* key = K_3" << endl << endl;

    cout << "* nonce = IV_3" << endl << endl;

    cout << "Using the parameters above, the ciphertext CIPHERTEXT_3 can be computed:" << endl;

    print_fig_with_bytes("CIPHERTEXT_3" , C_3);


    // Calculate message_3
    vector<uint8_t> message_3;
    vector_append( message_3, data_3 );
    vector_append( message_3, cbor_bstr( C_3 ) );

    // Print ////////////////////////////////////////////// 

    cout << "#### message_3" << endl << endl;

    cout << "From the parameter computed in {{tv-psk-3}} and {{tv-psk-3-ciph}}, message_3 is computed, as the CBOR Sequence of the following items: (C_V, CIPHERTEXT_3)." << endl;

    print_fig("message_3 =" , "(\n  " + vector_to_cddl_bstr(C_V , 4)  + ",\n  " + vector_to_cddl_bstr(C_3 , 4) + "\n)");

    cout << "Which encodes to the following byte string:" << endl;

    print_fig_with_bytes("message_3 (CBOR Sequence)" , message_3);


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

    // Print ////////////////////////////////////////////// 

    cout << "#### OSCORE Security Context Derivation" << endl << endl;

    cout << "From the previous message exchange, the Common Security Context for OSCORE {{RFC8613}} can be derived, as specified in {{exporter}}." << endl << endl;

    cout << "First af all, TH_4 is computed: TH_4 = H( TH_3, CIPHERTEXT_3 ), where the input to the hash function is the CBOR Sequence of TH_3 and CIPHERTEXT_3" << endl;

    print_fig_with_bytes("( TH_3, CIPHERTEXT_3 ) (CBOR Sequence)" , TH_4_input);

    cout << "And from there, compute the transcript hash TH_4 = SHA-256( TH_3, CIPHERTEXT_3 )" << endl;

    print_fig_with_bytes( "TH_4 value" , TH_4);

    cout << "When encoded as a CBOR bstr, that gives:" << endl;

    print_fig_with_bytes( "TH_4 (CBOR-encoded)", cbor_bstr(TH_4));

    cout << "To derive the Master Secret and Master Salt the same HKDF-Expand (PRK, info, L) is used, with different info and L." << endl << endl;

    cout << "For Master Secret:" << endl << endl;

    cout << "L for Master Secret = 16" << endl;

    print_fig("info for Master Secret =", info_string("\"OSCORE Master Secret\"", 128, TH_4));

    cout << "When encoded as a CBOR bstr, that gives:" << endl;

    print_fig_with_bytes("info (OSCORE Master Secret) (CBOR-encoded)" , info_OSCORE_secret);

    cout << "Finally, the Master Secret value computed is:" << endl;

    print_fig_with_bytes("OSCORE Master Secret", OSCORE_secret);

    cout << "For Master Salt:" << endl << endl;

    cout << "L for Master Salt = 8" << endl;

    print_fig("info for Master Salt =", info_string("\"OSCORE Master Salt\"", 64, TH_4));

    cout << "When encoded as a CBOR bstr, that gives:" << endl;

    print_fig_with_bytes("info (OSCORE Master Salt) (CBOR-encoded)" , info_OSCORE_salt);

    cout << "Finally, the Master Salt value computed is:" << endl;

    print_fig_with_bytes("OSCORE Master Salt", OSCORE_salt);

    cout << "The Client's Sender ID takes the value of C_V:" << endl;

    print_fig_with_bytes("Client's OSCORE Sender ID", C_V);

    cout << "The Server's Sender ID takes the value of C_U:" << endl;

    print_fig_with_bytes("Server's OSCORE Sender ID", C_U);

    cout << "The algorithms are those negociated in the cipher suite:" << endl;

    print_fig("AEAD Algorithm", to_string(aead_algorithm_id));

    print_fig("HMAC Algorithm", to_string(hmac_algorithm_id));

}

void rpk_vectors( void )
{

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

    print_fig_with_bytes("Party U's private authentication key", U_sign_sk);

    print_fig_with_bytes("Party U's public authentication key", U_sign_pk);

    print_fig_with_bytes("kid value to identify U's public authentication key" , kid_U);

    cout << "This test vector uses COSE_Key objects to store the raw public keys. Moreover, EC2 keys with curve Ed25519 are used. That is in agreement with the Cipher Suite " << to_string(suite) << "." << endl;

    string cred_u_str = "<< {\n  1:  1,\n -1:  6,\n -2:  " + vector_to_cddl_bstr( U_sign_pk , 8) + "\n} >>";
    string cred_u_str_tab = "<< {\n  1:  1,\n -1:  6,\n -2:  " + vector_to_cddl_bstr( U_sign_pk , 10) + "\n} >>"; // quick fix for when the same string is tabbed

    print_fig("CRED_U =", cred_u_str);

    print_fig_with_bytes("CRED_U (bstr-wrapped COSE_Key) (CBOR-encoded)" , cbor_bstr(CRED_U_CBOR));

    cout << "Because COSE_Keys are used, and because kid = " << vector_to_cddl_bstr( kid_U , 0) <<":";

    string id_cred_u_str = "{ \n  4:  " + vector_to_cddl_bstr( kid_U , 8) + "\n}";
    print_fig("ID_CRED_U =" , id_cred_u_str );

    cout << "Note that since the map for ID_CRED_U contains a single 'kid' parameter, ID_CRED_U is used when transported in the protected header of the COSE Object, but only the kid_value_U is used when added to the plaintext (see {{asym-msg3-proc}}):" << endl;

    print_fig_with_bytes("ID_CRED_U (in protected header) (CBOR-encoded)" , ID_CRED_U_CBOR);
    
    print_fig_with_bytes("kid_value_U (in plaintext) (CBOR-encoded)" , cbor_bstr(kid_U));

    // Input for Party V //////////////////////////////////////////////
    cout << "### Input for Party V {#rpk-tv-input-v}" << endl;

    cout << endl;
    cout << "The following are the parameters that are set in Party V before the first message exchange." << endl;

    print_fig_with_bytes("Party V's private authentication key" , V_sign_sk);

    print_fig_with_bytes("Party V's public authentication key" , V_sign_pk);

    print_fig_with_bytes("kid value to identify V's public authentication key" , kid_V);

    cout << "This test vector uses COSE_Key objects to store the raw public keys. Moreover, EC2 keys with curve Ed25519 are used. That is in agreement with the Cipher Suite " << to_string(suite) << "." << endl;

    string cred_v_str = "<< {\n  1:  1,\n -1:  6,\n -2:  " + vector_to_cddl_bstr( V_sign_pk , 8) + "\n} >>";
    string cred_v_str_tab = "<< {\n  1:  1,\n -1:  6,\n -2:  " + vector_to_cddl_bstr( V_sign_pk , 10) + "\n} >>"; // quick fix for when the same string is tabbed later

    print_fig("CRED_V =" , cred_v_str );

    print_fig_with_bytes("CRED_V (bstr-wrapped COSE_Key) (CBOR-encoded)" , cbor_bstr(CRED_V_CBOR));

    cout << "Because COSE_Keys are used, and because kid = " << vector_to_cddl_bstr( kid_V , 0) <<":";

    string id_cred_v_str = "{ \n  4:  " + vector_to_cddl_bstr( kid_V , 8) + "\n}";
    print_fig("ID_CRED_V =" , id_cred_v_str );

    cout << "Note that since the map for ID_CRED_V contains a single 'kid' parameter, ID_CRED_U is used when transported in the protected header of the COSE Object, but only the kid_value_V is used when added to the plaintext (see {{asym-msg3-proc}}):" << endl;

    print_fig_with_bytes("ID_CRED_V (in protected header) (CBOR-encoded)" , ID_CRED_V_CBOR);
    
    print_fig_with_bytes("kid_value_V (in plaintext) (CBOR-encoded)" , cbor_bstr(kid_V));


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
    print_fig_with_bytes("Party U's ephemeral private key" , U_kx_sk);
    print_fig_with_bytes("G_X (X-coordinate of the ephemeral public key of Party U)" , U_kx_pk);
    print_fig_with_bytes("C_U (Connection identifier chosen by U)" , C_U);

    cout << "No AD_1 is provided, so AD_1 is absent from message_1." << endl << endl;
    cout << "Message_1 is constructed, as the CBOR Sequence of the CBOR data items above." << endl;

    print_fig("message_1 =" , "(\n  " + to_string(TYPE) + ",\n  " + to_string(suite) + ",\n  " + vector_to_cddl_bstr(U_kx_pk , 4) + ",\n  " + vector_to_cddl_bstr(C_U , 4) + "\n)");

    print_fig_with_bytes("message_1 (CBOR Sequence)", message_1);

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

    print_fig_with_bytes("Party V's ephemeral private key" , V_kx_sk);
    print_fig_with_bytes("G_Y (X-coordinate of the ephemeral public key of Party V)" , V_kx_pk);
    print_fig_with_bytes("C_V (Connection identifier chosen by V)" , C_V);

    cout << "Data_2 is constructed, as the CBOR Sequence of the CBOR data items above." << endl << endl;

    print_fig("data_2 =", "(\n  " + vector_to_cddl_bstr(V_kx_pk , 4) + ",\n  " + vector_to_cddl_bstr(C_V , 4) + "\n)");
    print_fig_with_bytes("data_2 (CBOR Sequence)" , data_2);

    cout << "From data_2 and message_1 (from {{tv-rpk-1}}), compute the input to the transcript hash TH_2 = H( message_1, data_2 ), as a CBOR Sequence of these 2 data items." << endl << endl;

    print_fig_with_bytes("( message_1, data_2 ) (CBOR Sequence)" , TH_2_input);

    cout << "And from there, compute the transcript hash TH_2 = SHA-256( message_1, data_2 )" << endl << endl;

    print_fig_with_bytes("TH_2 value" , TH_2);

    cout << "When encoded as a CBOR bstr, that gives:" << endl << endl;

    print_fig_with_bytes("TH_2 (CBOR-encoded)" , cbor_bstr(TH_2));

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

    print_fig("M_V =" , "[\n  \"Signature1\",\n  << " + line(id_cred_v_str) + " >>,\n  " + vector_to_cddl_bstr(TH_2 , 4) + ",\n  "+ tab(cred_v_str_tab) + "\n]");

    cout << "Which encodes to the following byte string ToBeSigned:" << endl;

    print_fig_with_bytes("M_V (message to be signed with Ed25519) (CBOR-encoded)" , message_V);

    cout << "The message is signed using the private authentication key of V, and produces the following signature:" << endl;

    print_fig_with_bytes("V's signature", signature_V);


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

    print_fig_with_bytes("G_XY", shared_secret);

    cout << "From there, PRK is computed:" << endl;

    print_fig_with_bytes("PRK" , PRK);

    cout << "Key K_2 is the output of HKDF-Expand(PRK, info, L)." << endl << endl;
    cout << "info is defined as follows:" << endl;

    print_fig("info for K_2 =", info_string(to_string(aead_algorithm_id), 128, TH_2));

    cout << "Which as a CBOR encoded data item is:" << endl;

    print_fig_with_bytes("info (K_2) (CBOR-encoded)" , info_K_2);

    cout << "L is the length of K_2, so " + to_string(K_2.size()) + " bytes." << endl << endl;

    cout << "From these parameters, K_2 is computed:" << endl;

    print_fig_with_bytes("K_2" , K_2);

    cout << "Nonce IV_2 is the output of HKDF-Expand(PRK, info, L)." << endl << endl;

    cout << "info is defined as follows:" << endl;

    print_fig("info for IV_2 =", info_string("\"IV-GENERATION\"", 104, TH_2));

    cout << "Which as a CBOR encoded data item is:" << endl;

    print_fig_with_bytes("info (IV_2) (CBOR-encoded)" , info_IV_2);
   
    cout << "L is the length of IV_2, so " + to_string(IV_2.size()) + " bytes." << endl << endl;

    cout << "From these parameters, IV_2 is computed:" << endl;

    print_fig_with_bytes("IV_2" , IV_2);


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

    print_fig_with_bytes("P_2 " , P_2);

    cout << "From the parameters above, the Enc_structure A_2 is computed." << endl;

    print_fig("A_2 =" , enc_string(vector<uint8_t> (),TH_2));

    cout << "Which encodes to the following byte string to be used as Additional Authenticated Data:" << endl;

    print_fig_with_bytes("A_2 (CBOR-encoded)" , A_2 );


    cout << "The key and nonce used are defined in {{tv-rpk-2-key}}:" << endl << endl;

    cout << "* key = K_2" << endl << endl;

    cout << "* nonce = IV_2" << endl << endl;

    cout << "Using the parameters above, the ciphertext CIPHERTEXT_2 can be computed:" << endl;

    print_fig_with_bytes("CIPHERTEXT_2" , C_2);


    // Calculate message_2
    vector<uint8_t> message_2;
    vector_append( message_2, data_2 );
    vector_append( message_2, cbor_bstr( C_2 ) ); 

    // Print //////////////////////////////////////////////

    cout << "#### message_2" << endl << endl;

    cout << "From the parameter computed in {{tv-rpk-2}} and {{tv-rpk-2-ciph}}, message_2 is computed, as the CBOR Sequence of the following items: (G_Y, C_V, CIPHERTEXT_2)." << endl << endl;

    print_fig("message_2 =" , "(\n  " + vector_to_cddl_bstr(V_kx_pk , 4) + ",\n  " + vector_to_cddl_bstr(C_V , 4) + ",\n  " + vector_to_cddl_bstr(C_2 , 4) + "\n)");

    cout << "Which encodes to the following byte string:" << endl;

    print_fig_with_bytes("message_2 (CBOR Sequence)" , message_2);


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


    // Print //////////////////////////////////////////////

    cout << "### Message 3 {#tv-rpk-3}" << endl << endl;

    cout << "Since TYPE mod 4 equals " + to_string(TYPE) + ", C_V is not omitted from data_3." << endl << endl;

    print_fig_with_bytes("C_V" , C_V);

    cout << "Data_3 is constructed, as the CBOR Sequence of the CBOR data item above." << endl;

    print_fig("data_3 =" , "(\n  " + vector_to_cddl_bstr(C_V , 4) + "\n)");

    print_fig_with_bytes("data_3 (CBOR Sequence)", data_3);

    cout << "From data_3, CIPHERTEXT_2 ({{tv-rpk-2-ciph}}), and TH_2 ({{tv-rpk-2}}), compute the input to the transcript hash TH_2 = H(TH_2 , CIPHERTEXT_2, data_3), as a CBOR Sequence of these 3 data items." << endl;

    print_fig_with_bytes("( TH_2, CIPHERTEXT_2, data_3 ) (CBOR Sequence)" , TH_3_input);

    cout << "And from there, compute the transcript hash TH_3 = SHA-256(TH_2 , CIPHERTEXT_2, data_3)" << endl;

    print_fig_with_bytes("TH_3 value" , TH_3);

    cout << "When encoded as a CBOR bstr, that gives:" << endl << endl;

    print_fig_with_bytes("TH_3 (CBOR-encoded)" , cbor_bstr(TH_3));   

    // Calculate signature
    vector<uint8_t> message_U { 0x84 }; // CBOR array of length 4
    vector_append( message_U, cbor_tstr( "Signature1" ) );
    vector_append( message_U, cbor_bstr( ID_CRED_U_CBOR ) );
    vector_append( message_U, cbor_bstr( TH_3 ) );
    vector_append( message_U, cbor_bstr( CRED_U_CBOR ) );
    vector<uint8_t> signature_U( crypto_sign_BYTES );
    crypto_sign_detached( signature_U.data(), nullptr, message_U.data(), message_U.size(), U_sign_sk_libsodium.data() );

    // Print //////////////////////////////////////////////

    cout << "#### Signature Computation {#tv-rpk-3-sign}" << endl << endl;

    cout << "COSE_Sign1 is computed with the following parameters. From {{rpk-tv-input-u}}:" << endl << endl;
    cout << "* protected = bstr .cbor ID_CRED_U " << endl << endl;
    cout << "* payload = CRED_U" << endl << endl;
    cout << "And from {{tv-rpk-3}}:" << endl << endl;
    cout << "* external_aad = TH_3" << endl << endl;
    cout << "The Sig_structure M_U to be signed is: \\[ \"Signature1\", << ID_CRED_U >>, TH_3, CRED_U \\] , as defined in {{asym-msg3-proc}}:" << endl << endl;

    print_fig("M_U =" , "[\n  \"Signature1\",\n  << " + line(id_cred_u_str) + " >>,\n  " + vector_to_cddl_bstr(TH_3 , 4) + ",\n  "+ tab(cred_u_str_tab) + "\n]");

    cout << "Which encodes to the following byte string ToBeSigned:" << endl;

    print_fig_with_bytes("M_U (message to be signed with Ed25519) (CBOR-encoded)" , message_U);

    cout << "The message is signed using the private authentication key of U, and produces the following signature:" << endl;

    print_fig_with_bytes("U's signature" , signature_U);



    // Derive key and IV
    vector<uint8_t> info_K_3 = gen_info( cbor_uint8( aead_algorithm_id ), 128, TH_3 );
    vector<uint8_t> K_3 = hkdf_expand_sha_256( PRK, info_K_3, 16 );
    vector<uint8_t> info_IV_3 = gen_info( cbor_tstr( "IV-GENERATION" ), 104, TH_3 );
    vector<uint8_t> IV_3 = hkdf_expand_sha_256( PRK, info_IV_3, 13 );

    // Print //////////////////////////////////////////////

    cout << "#### Key and Nonce Computation {#tv-rpk-3-key}" << endl << endl;

    cout << "The key and nonce for calculating the ciphertext are calculated as follows, as specified in {{key-der}}." << endl << endl;

    cout << "HKDF SHA-256 is the HKDF used (as defined by cipher suite " << suite << " )." << endl << endl;

    cout << "PRK = HMAC-SHA-256(salt, G_XY)" << endl << endl;

    cout << "Since this is the asymmetric case, salt is the empty byte string." << endl << endl;

    cout << "G_XY is the shared secret, and since the curve25519 is used, the ECDH shared secret is the output of the X25519 function." << endl << endl;

    print_fig_with_bytes("G_XY", shared_secret);

    cout << "From there, PRK is computed:" << endl;

    print_fig_with_bytes("PRK", PRK);

    cout << "Key K_3 is the output of HKDF-Expand(PRK, info, L)." << endl << endl;
    cout << "info is defined as follows:" << endl;

    print_fig("info for K_3 =", info_string(to_string(aead_algorithm_id), 128, TH_3));

    cout << "Which as a CBOR encoded data item is:" << endl; 

    print_fig_with_bytes( "info (K_3) (CBOR-encoded)" , info_K_3);

    cout << "L is the length of K_3, so " << K_3.size() << " bytes. "<< endl << endl;

    cout << "From these parameters, K_3 is computed:" << endl;

    print_fig_with_bytes( "K_3" , K_3);

    cout << "Nonce IV_3 is the output of HKDF-Expand(PRK, info, L).";

    cout << "info is defined as follows:" << endl;

    print_fig("info for IV_3 =", info_string("\"IV-GENERATION\"", 104, TH_3));

    cout << "Which as a CBOR encoded data item is:" << endl;

    print_fig_with_bytes("info (IV_3) (CBOR-encoded)", info_IV_3);

    cout << "From these parameters, IV_3 is computed:" << endl;

    print_fig_with_bytes( "IV_3" , IV_3);


    // Calculate ciphertext
    vector<uint8_t> P_3;
    vector_append( P_3, cbor_bstr( kid_U ) ); // ID_CRED_U contains a single 'kid' parameter, so only bstr is used
    vector_append( P_3, cbor_bstr( signature_U ) );
    vector<uint8_t> A_3 = { 0x83 }; // CBOR array of length 3
    vector_append( A_3, cbor_tstr( "Encrypt0" ) );
    vector_append( A_3, cbor_bstr( { } ) ); // empty bstr 
    vector_append( A_3, cbor_bstr( TH_3 ) );
    vector<uint8_t> C_3 = aes_ccm_16_64_128( K_3, IV_3, P_3, A_3 );

    // Print //////////////////////////////////////////////

    cout << "#### Ciphertext Computation {#tv-rpk-3-ciph}" << endl << endl;

    cout << "COSE_Encrypt0 is computed with the following parameters. Note that AD_3 is omitted." << endl << endl;
    cout << "* empty protected header" << endl << endl;
    cout << "* external_aad = TH_3" << endl << endl;
    cout << "* plaintext = CBOR Sequence of the items kid_value_U, signature, in this order." << endl << endl;
    cout << "with kid_value_U taken from {{rpk-tv-input-u}}, and signature as calculated in {{tv-rpk-3-sign}}." << endl << endl;
    cout << "The plaintext is the following:" << endl ;

    print_fig_with_bytes("P_3 " , P_3);

    cout << "From the parameters above, the Enc_structure A_3 is computed." << endl;

    print_fig("A_3 =" , enc_string(vector<uint8_t> (),TH_3));

    cout << "Which encodes to the following byte string to be used as Additional Authenticated Data:" << endl;

    print_fig_with_bytes("A_3 (CBOR-encoded)" , A_3 );


    cout << "The key and nonce used are defined in {{tv-rpk-3-key}}:" << endl << endl;

    cout << "* key = K_3" << endl << endl;

    cout << "* nonce = IV_3" << endl << endl;

    cout << "Using the parameters above, the ciphertext CIPHERTEXT_3 can be computed:" << endl;

    print_fig_with_bytes("CIPHERTEXT_3" , C_3);


    // Calculate message_3
    vector<uint8_t> message_3;
    vector_append( message_3, data_3 );
    vector_append( message_3, cbor_bstr( C_3 ) );

    // Print //////////////////////////////////////////////

    cout << "#### message_3" << endl << endl;

    cout << "From the parameter computed in {{tv-rpk-3}} and {{tv-rpk-3-ciph}}, message_3 is computed, as the CBOR Sequence of the following items: (C_V, CIPHERTEXT_3)." << endl << endl;

    print_fig("message_3 =" , "(\n  " + vector_to_cddl_bstr(C_V , 4) + ",\n  " + vector_to_cddl_bstr(C_3 , 4) + "\n)");

    cout << "Which encodes to the following byte string:" << endl;

    print_fig_with_bytes("message_3 (CBOR Sequence)" , message_3);


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

    // Print //////////////////////////////////////////////

    cout << "#### OSCORE Security Context Derivation" << endl << endl;

    cout << "From the previous message exchange, the Common Security Context for OSCORE {{RFC8613}} can be derived, as specified in {{exporter}}." << endl << endl;

    cout << "First af all, TH_4 is computed: TH_4 = H( TH_3, CIPHERTEXT_3 ), where the input to the hash function is the CBOR Sequence of TH_3 and CIPHERTEXT_3" << endl;

    print_fig_with_bytes("( TH_3, CIPHERTEXT_3 ) (CBOR Sequence)" , TH_4_input);

    cout << "And from there, compute the transcript hash TH_4 = SHA-256( TH_3, CIPHERTEXT_3 )" << endl;

    print_fig_with_bytes( "TH_4 value" , TH_4);

    cout << "When encoded as a CBOR bstr, that gives:" << endl;

    print_fig_with_bytes( "TH_4 (CBOR-encoded)", cbor_bstr(TH_4));

    cout << "To derive the Master Secret and Master Salt the same HKDF-Expand (PRK, info, L) is used, with different info and L." << endl << endl;

    cout << "For Master Secret:" << endl << endl;

    cout << "L for Master Secret = 16" << endl;

    print_fig("info for Master Secret =", info_string("\"OSCORE Master Secret\"", 128, TH_4));

    cout << "When encoded as a CBOR bstr, that gives:" << endl;

    print_fig_with_bytes("info (OSCORE Master Secret) (CBOR-encoded)" , info_OSCORE_secret);

    cout << "Finally, the Master Secret value computed is:" << endl;

    print_fig_with_bytes("OSCORE Master Secret", OSCORE_secret);

    cout << "For Master Salt:" << endl << endl;

    cout << "L for Master Salt = 8" << endl;

    print_fig("info for Master Salt =", info_string("\"OSCORE Master Salt\"", 64, TH_4));

    cout << "When encoded as a CBOR bstr, that gives:" << endl;

    print_fig_with_bytes("info (OSCORE Master Salt) (CBOR-encoded)" , info_OSCORE_salt);

    cout << "Finally, the Master Salt value computed is:" << endl;

    print_fig_with_bytes("OSCORE Master Salt", OSCORE_salt);

    cout << "The Client's Sender ID takes the value of C_V:" << endl;

    print_fig_with_bytes("Client's OSCORE Sender ID", C_V);

    cout << "The Server's Sender ID takes the value of C_U:" << endl;

    print_fig_with_bytes("Server's OSCORE Sender ID", C_U);

    cout << "The algorithms are those negociated in the cipher suite:" << endl;

    print_fig("AEAD Algorithm", to_string(aead_algorithm_id));

    print_fig("HMAC Algorithm", to_string(hmac_algorithm_id));

}

void static_vectors ( void )
{

    cout << endl << "## Test Vectors for EDHOC Authenticated with Static Diffie-Hellman Keys" << endl; 
    cout << endl;
    cout << "EDHOC with static Diffie-Hellman keys and MAC authentication is used:" << endl;

    // Pre-shared stuff ////////////////////////////////////////////////////////////////////////////

    // This uses RFC 8032 notation, libsodium uses the notation from the Ed25519 paper by Bernstein
    // Libsodium seed = RFC 8032 sk
    // Libsodium sk = pruned SHA-512(sk) in RFC 8032

    // The content and ordering of COSE_KEY is not specified in draft-selander-ace-cose-ecdhe-13
    // Suggested Content: Only labels 1 (kty), -1 (EC identifier), -2 (x-coordinate), -3 (y-coordinate only in EC2)
    // Suggested Order: decreasing

    // Generate the Party U's static DH authentication key pair
    vector<uint8_t> I_dh_pk( crypto_kx_PUBLICKEYBYTES ); //G_I
    vector<uint8_t> I_dh_sk( crypto_kx_SECRETKEYBYTES ); //I
    vector<uint8_t> I_dh_seed( crypto_kx_SEEDBYTES, 8 ); ;
    crypto_kx_seed_keypair( I_dh_pk.data(), I_dh_sk.data(), I_dh_seed.data() );

    vector<uint8_t> kid_I { 0xa7 };
    vector<uint8_t> ID_CRED_I_CBOR = { 0xa1, 0x04 }; // CBOR map(1), label = 4
    vector_append( ID_CRED_I_CBOR, cbor_bstr( kid_I ) );
    vector<uint8_t> CRED_I_CBOR { 0xa3, 0x01, 0x01, 0x20, 0x04, 0x21,  }; // CBOR map(3), 1, 1, -1, 4, -2
    vector_append( CRED_I_CBOR, cbor_bstr( I_dh_pk ) );

    // Generate the Party V's static DH authentication key pair 
    vector<uint8_t> R_dh_pk( crypto_kx_PUBLICKEYBYTES ); //G_R
    vector<uint8_t> R_dh_sk( crypto_kx_SECRETKEYBYTES );
    //R
    vector<uint8_t> R_dh_seed( crypto_kx_SEEDBYTES, 9 ); ;
    crypto_kx_seed_keypair( R_dh_pk.data(), R_dh_sk.data(), R_dh_seed.data() );

    vector<uint8_t> kid_R { 0xa8 };
    vector<uint8_t> ID_CRED_R_CBOR = { 0xa1, 0x04 }; // CBOR map(1) label = 4
    vector_append( ID_CRED_R_CBOR, cbor_bstr( kid_R ) );
    vector<uint8_t> CRED_R_CBOR { 0xa3, 0x01, 0x01, 0x20, 0x04, 0x21,  }; // CBOR map(3), 1, 1, -1, 4, -2
    vector_append( CRED_R_CBOR, cbor_bstr( R_dh_pk ) );

    // Other parameters
    uint8_t method = 3; // Static Static
    uint8_t corr = 1; // I is CoAP client
    uint8_t TYPE = 4 * method + corr;
    uint8_t suite = 0; // [ 10, 5, 4, -8, 6 ] AES-CCM-16-64-128, HMAC 256/256, X25519, EdDSA, Ed25519
    int aead_algorithm_id = 10;
    int hmac_algorithm_id = 5;
    vector<uint8_t> C_I { 0xc7 };
    vector<uint8_t> C_R { 0xc8 };


    // Print
    print_fig( "method (MAC Authentication)", to_string(method) );

    cout << "CoaP is used as transport and the Initiator acts as CoAP client:" << endl;
    
    print_fig( "corr (Initiator can correlate message_1 and message_2)", to_string(corr) );
    
    cout << "No unprotected opaque auxiliary data is sent in the message exchanges." << endl;
    cout << endl;
    cout << "The pre-defined Cipher Suite 0 is in place both on Initiator and Responder, see {{cipher-suites}}." << endl;
    cout << endl;

    // Input for Party U //////////////////////////////////////////////
    cout << "### Input for the Initiator {#ss-tv-input-u}" << endl;

    cout << endl;
    cout << "The following are the parameters that are set in the Initiator before the first message exchange." << endl;

    print_fig_with_bytes("Initiator's private static DH authentication key (I)", I_dh_sk);

    print_fig_with_bytes("Initiator's public static DH authentication key (G_I)", I_dh_pk);

    print_fig_with_bytes("kid value to identify the Initiator's public DH authentication key (kid_I)" , kid_I);

    cout << "This test vector uses COSE_Key objects to store the raw public keys. Moreover, EC2 keys with curve X25519 are used. That is in agreement with the Cipher Suite " << to_string(suite) << "." << endl;

    //TODO: if cred_i not serialized, change here
    string cred_I_str = "<< {\n  1:  1,\n -1:  4,\n -2:  " + vector_to_cddl_bstr( I_dh_pk , 8) + "\n} >>";
    string cred_I_str_tab = "<< {\n  1:  1,\n -1:  4,\n -2:  " + vector_to_cddl_bstr( I_dh_pk , 10) + "\n} >>"; // quick fix for when the same string is tabbed

    print_fig("CRED_I =", cred_I_str);

    print_fig_with_bytes("CRED_I (bstr-wrapped COSE_Key) (CBOR-encoded)" , cbor_bstr(CRED_I_CBOR));

    cout << "Because COSE_Keys are used, and because kid = " << vector_to_cddl_bstr( kid_I , 0) <<":";

    string id_cred_I_str = "{ \n  4:  " + vector_to_cddl_bstr( kid_I , 8) + "\n}";
    print_fig("ID_CRED_I =" , id_cred_I_str );

    cout << "Note that since the map for ID_CRED_I contains a single 'kid' parameter, ID_CRED_I is used when transported in the protected header of the COSE Object, but only kid_I is used when added to the plaintext (see {{asym-msg3-proc}}):" << endl;

    print_fig_with_bytes("ID_CRED_I (in protected header) (CBOR-encoded)" , cbor_bstr(ID_CRED_I_CBOR));
    
    print_fig_with_bytes("kid_I (in plaintext) (CBOR-encoded)" , cbor_bstr(kid_I));

    // Input for Party V //////////////////////////////////////////////
    cout << "### Input for the Responder {#ss-tv-input-v}" << endl;

    cout << endl;
    cout << "The following are the parameters that are set in the Responder before the first message exchange." << endl;

    print_fig_with_bytes("Responder's private static DH authentication key (R)" , R_dh_sk);

    print_fig_with_bytes("Responder's private static DH authentication key (G_R)" , R_dh_pk);

    print_fig_with_bytes("kid value to identify the Responder's public authentication key (kid_R)" , kid_R);

    cout << "This test vector uses COSE_Key objects to store the raw public keys. Moreover, EC2 keys with curve X25519 are used. That is in agreement with the Cipher Suite " << to_string(suite) << "." << endl;

    string cred_R_str = "<< {\n  1:  1,\n -1:  4,\n -2:  " + vector_to_cddl_bstr( R_dh_pk , 8) + "\n} >>";
    string cred_R_str_tab = "<< {\n  1:  1,\n -1:  4,\n -2:  " + vector_to_cddl_bstr( R_dh_pk , 10) + "\n} >>"; // quick fix for when the same string is tabbed later

    print_fig("CRED_R =" , cred_R_str );

    print_fig_with_bytes("CRED_R (bstr-wrapped COSE_Key) (CBOR-encoded)" , cbor_bstr(CRED_R_CBOR));

    cout << "Because COSE_Keys are used, and because kid = " << vector_to_cddl_bstr( kid_R , 0) <<":";

    string id_cred_R_str = "{ \n  4:  " + vector_to_cddl_bstr( kid_R , 8) + "\n}";
    print_fig("ID_CRED_R =" , id_cred_R_str );

    cout << "Note that since the map for ID_CRED_R contains a single 'kid' parameter, ID_CRED_R is used when transported in the protected header of the COSE Object, but only the kid_R is used when added to the plaintext (see {{asym-msg3-proc}}):" << endl;

    print_fig_with_bytes("ID_CRED_R (in protected header) (CBOR-encoded)" , cbor_bstr(ID_CRED_R_CBOR));
    
    print_fig_with_bytes("kid_value_R (in plaintext) (CBOR-encoded)" , cbor_bstr(kid_R));

    // message_1 ////////////////////////////////////////////////////////////////////////////

    // Generate the Party U's ephemeral key pair
    vector<uint8_t> I_kx_pk( crypto_kx_PUBLICKEYBYTES ); //G_X
    vector<uint8_t> I_kx_sk( crypto_kx_SECRETKEYBYTES ); 
    vector<uint8_t> I_kx_seed( crypto_kx_SEEDBYTES, 10 ); ;
    crypto_kx_seed_keypair( I_kx_pk.data(), I_kx_sk.data(), I_kx_seed.data() );

    // Calculate message_1
    vector<uint8_t> message_1;
    vector_append( message_1, cbor_uint8( TYPE ) ); 
    vector_append( message_1, cbor_uint8( suite ) ); 
    vector_append( message_1, cbor_bstr( I_kx_pk ) ); 
    vector_append( message_1, cbor_bstr( C_I ) ); 

    // Print //////////////////////////////////////////////
    cout << "### Message 1 {#tv-ss-1}" << endl << endl;
    cout << "From the input parameters (in {{rpk-tv-input-u}}):" << endl;

    print_fig("TYPE (4 * method + corr)" , to_string(TYPE));
    print_fig("suite", to_string(suite));
    print_fig("SUITES_U : suite", to_string(suite));
    print_fig_with_bytes("Initiator's ephemeral private key (I)" , I_kx_sk);
    print_fig_with_bytes("G_X (X-coordinate of the ephemeral public key of the Initiator)" , I_kx_pk);
    print_fig_with_bytes("C_I (Connection identifier chosen by the Initiator)" , C_I);

    cout << "No AD_1 is provided, so AD_1 is absent from message_1." << endl << endl;
    cout << "Message_1 is constructed, as the CBOR Sequence of the CBOR data items above." << endl;

    print_fig("message_1 =" , "(\n  " + to_string(TYPE) + ",\n  " + to_string(suite) + ",\n  " + vector_to_cddl_bstr(I_kx_pk , 4) + ",\n  " + vector_to_cddl_bstr(C_I , 4) + "\n)");

    print_fig_with_bytes("message_1 (CBOR Sequence)", message_1);

    // message_2 ////////////////////////////////////////////////////////////////////////////

    // Generate the Party V's ephemeral key pair 
    vector<uint8_t> R_kx_pk( crypto_kx_PUBLICKEYBYTES ); //G_Y
    vector<uint8_t> R_kx_sk( crypto_kx_SECRETKEYBYTES );
    //Y
    vector<uint8_t> R_kx_seed( crypto_kx_SEEDBYTES, 11 ); ;
    crypto_kx_seed_keypair( R_kx_pk.data(), R_kx_sk.data(), R_kx_seed.data() );

    // Calculate ECDH shared secret G_XY from Y and G_X
    vector<uint8_t> shared_secret( crypto_scalarmult_BYTES );
    if ( crypto_scalarmult( shared_secret.data(), R_kx_sk.data(), I_kx_pk.data() ) == -1 ) {
        cout << "crypto_scalarmult error";
        return;
    }

    // Calculate data_2
    vector<uint8_t> data_2;
    vector_append( data_2, cbor_bstr( R_kx_pk ) ); 
    vector_append( data_2, cbor_bstr( C_R ) ); 

    // Calculate TH_2
    vector<uint8_t> TH_2_input;
    vector_append( TH_2_input, message_1 );
    vector_append( TH_2_input, data_2 );
    vector<uint8_t> TH_2 = hash_sha_256( TH_2_input );



    // Print //////////////////////////////////////////////

    cout << "### Message 2 {#tv-ss-2}" << endl << endl;

    cout << "Since corr equals " + to_string(corr) + ", C_I is omitted from data_2." << endl << endl;

    cout << "The Responder generates an ephemeral ECDH key pair:" << endl;

    print_fig_with_bytes("Responder's ephemeral private key" , R_kx_sk);
    print_fig_with_bytes("G_Y (X-coordinate of the ephemeral public key of the Responder)" , R_kx_pk);

    cout << "The Responder also choses a connection identifier:" << endl;

    print_fig_with_bytes("C_R (Connection identifier chosen by the Responder)" , C_R);

    cout << "Data_2 is constructed, as the CBOR Sequence of the CBOR data items above." << endl << endl;

    print_fig("data_2 =", "(\n  " + vector_to_cddl_bstr(R_kx_pk , 4) + ",\n  " + vector_to_cddl_bstr(C_R , 4) + "\n)");
    print_fig_with_bytes("data_2 (CBOR Sequence)" , data_2);

    cout << "From data_2 and message_1 (from {{tv-ss-1}}), compute the input to the transcript hash TH_2 = H( message_1, data_2 ), as a CBOR Sequence of these 2 data items." << endl << endl;

    print_fig_with_bytes("( message_1, data_2 ) (CBOR Sequence)" , TH_2_input);

    cout << "And from there, compute the transcript hash TH_2 = SHA-256( message_1, data_2 )" << endl << endl;

    print_fig_with_bytes("TH_2 value" , TH_2);

    cout << "When encoded as a CBOR bstr, that gives:" << endl << endl;

    print_fig_with_bytes("TH_2 (CBOR-encoded)" , cbor_bstr(TH_2));

    // Calculate ECDH shared secret G_RX - R and G_X
    vector<uint8_t> shared_secret_es( crypto_scalarmult_BYTES );
    if ( crypto_scalarmult( shared_secret_es.data(), R_dh_sk.data(), I_kx_pk.data() ) == -1 ) {
        cout << "crypto_scalarmult error";
        return;
    }

    // Derive key and IV for MAC
    vector<uint8_t> salt; // empty byte string;
    vector<uint8_t> PRK_2 = hkdf_extract_sha_256( salt, shared_secret );
    vector<uint8_t> PRK_R = hkdf_extract_sha_256( PRK_2, shared_secret_es );
    vector<uint8_t> info_K_R = gen_info( cbor_uint8( aead_algorithm_id ), 128, TH_2 );
    vector<uint8_t> K_R = hkdf_expand_sha_256( PRK_R, info_K_R, 16 );
    vector<uint8_t> info_IV_R = gen_info( cbor_tstr( "IV-GENERATION" ), 104, TH_2 );
    vector<uint8_t> IV_R = hkdf_expand_sha_256( PRK_R, info_IV_R, 13 );

    // Print //////////////////////////////////////////////

    cout << "#### MAC Computation {#tv-ss-2-mac}" << endl << endl;

    cout << "Since method equals 3, a COSE_Encrypt0 is calculated." << endl << endl;

    cout << "##### Key and Nonce Computation {#tv-ss-2-key-mac}" << endl << endl;

    cout << "The key and nonce for calculating the MAC are calculated as follows, as specified in {{key-der}}." << endl << endl;
    cout << "HKDF SHA-256 is the HKDF used (as defined by cipher suite 0)." << endl << endl;
    cout << "PRK_2 = HMAC-SHA-256 (salt, G_XY)" << endl << endl;
    cout << "Since this is the asymmetric case, salt is the empty byte string." << endl << endl;
    cout << "G_XY is the ECDH shared secret, and since the curve25519 is used, the ECDH shared secret is the output of the X25519 function." << endl;

    print_fig_with_bytes("G_XY", shared_secret);

    cout << "From there, PRK_2 is computed:" << endl;

    print_fig_with_bytes("PRK_2" , PRK_2);

    cout << "PRK_R = HKDF-Extract (PRK_2, G_RX)" << endl << endl;
    cout << "G_RX is the ECDH shared secret calculated from G_X received in {{tv-ss-1}} and R in {{ss-tv-input-v}}, and since the curve25519 is used, the ECDH shared secret is the output of the X25519 function." << endl;

    print_fig_with_bytes("G_RX", shared_secret_es);

    cout << "From there, PRK_R is computed:" << endl;

    print_fig_with_bytes("PRK_R" , PRK_R);

    cout << "Key K_R is the output of HKDF-Expand(PRK_R, info, L)." << endl << endl;
    cout << "info is defined as follows:" << endl;

    print_fig("info for K_R =", info_string(to_string(aead_algorithm_id), 128, TH_2));

    cout << "Which as a CBOR encoded data item is:" << endl;

    // TODO: check if info should be a bstr or not
    print_fig_with_bytes("info (K_R) (CBOR-encoded)" , info_K_R);

    cout << "L is the length of K_R, so " + to_string(K_R.size()) + " bytes." << endl << endl;

    cout << "From these parameters, K_R is computed:" << endl;

    print_fig_with_bytes("K_R" , K_R);

    cout << "Nonce IV_R is the output of HKDF-Expand(PRK_R, info, L)." << endl << endl;

    cout << "info is defined as follows:" << endl;

    print_fig("info for IV_R =", info_string("\"IV-GENERATION\"", 104, TH_2));

    cout << "Which as a CBOR encoded data item is:" << endl;

    print_fig_with_bytes("info (IV_R) (CBOR-encoded)" , info_IV_R);
   
    cout << "L is the length of IV_R, so " + to_string(IV_R.size()) + " bytes." << endl << endl;

    cout << "From these parameters, IV_R is computed:" << endl;

    print_fig_with_bytes("IV_R" , IV_R);   

    // Calculate MAC
    vector<uint8_t> P_R;
    vector_append( P_R, cbor_bstr( { } ) ); // empty bstr

    vector<uint8_t> A_R = { 0x83 }; // CBOR array of length 3
    vector_append( A_R, cbor_tstr( "Encrypt0" ) );
    vector_append( A_R, cbor_bstr(ID_CRED_R_CBOR) ); // protected contains the serialized ID_CRED_R
    vector<uint8_t> ext_aad;
    vector_append( ext_aad , TH_2 );
    vector_append( ext_aad , CRED_R_CBOR ); //CRED_R map in this case
    vector_append( A_R, cbor_bstr( ext_aad ) );

    vector<uint8_t> C_M = aes_ccm_16_64_128( K_R, IV_R, P_R, A_R );
    //TODO: Check why this returns 9 bytes of 0s

    cout << "##### MAC Computation {#tv-ss-2-mac-comp}" << endl << endl;

    cout << "COSE_Encrypt0 is computed with the following parameters." << endl << endl;
    cout << "* protected header = CBOR-encoded ID_CRED_R" << endl << endl;
    cout << "* external_aad = CBOR Sequence of TH_2 and CRED_R, in this order" << endl << endl;
    cout << "* empty plaintext" << endl << endl;

    print_fig_with_bytes("Protected header: ID_CRED_R (CBOR-encoded)" , cbor_bstr(ID_CRED_R_CBOR));
  
    cout << "The external_aad is the following:" << endl ;

    print_fig_with_bytes("(TH_2 , CRED_R ) (CBOR Sequence)" , ext_aad);

    cout << "Which encodes to the following byte string:" << endl;

    print_fig_with_bytes("(TH_2 , CRED_R ) (CBOR Sequence) (CBOR-encoded)" , cbor_bstr(ext_aad));

    cout << "From the parameters above, the Enc_structure A_2 is computed." << endl;

    print_fig("A_R =" , enc_string(ID_CRED_R_CBOR , ext_aad));

    cout << "Which encodes to the following byte string to be used as Additional Authenticated Data:" << endl;

    print_fig_with_bytes("A_R (CBOR-encoded)" , A_R );


    cout << "The key and nonce used are defined in {{tv-ss-2-key}}:" << endl << endl;

    cout << "* key = K_R" << endl << endl;

    cout << "* nonce = IV_R" << endl << endl;

    cout << "Using the parameters above, the ciphertext CIPHERTEXT_R can be computed:" << endl;

    print_fig_with_bytes("CIPHERTEXT_R" , C_M);


    // Derive key and IV
    vector<uint8_t> info_K_2 = gen_info( cbor_uint8( aead_algorithm_id ), 128, TH_2 );
    vector<uint8_t> K_2 = hkdf_expand_sha_256( PRK_2, info_K_2, 16 );
    vector<uint8_t> info_IV_2 = gen_info( cbor_tstr( "IV-GENERATION" ), 104, TH_2 );
    vector<uint8_t> IV_2 = hkdf_expand_sha_256( PRK_2, info_IV_2, 13 );

    // Print //////////////////////////////////////////////

    cout << "#### Key and Nonce Computation {#tv-ss-2-key}" << endl << endl;

    cout << "The key and nonce for calculating the ciphertext are calculated as follows, as specified in {{key-der}}." << endl << endl;
    cout << "HKDF SHA-256 is the HKDF used (as defined by cipher suite 0)." << endl << endl;
    cout << "PRK_2  = HMAC-SHA-256(salt, G_XY) as defined in {{tv-ss-2-key-mac}}" << endl << endl;

    print_fig_with_bytes("PRK_2" , PRK_2);

    cout << "Key K_2 is the output of HKDF-Expand(PRK_2, info, L)." << endl << endl;
    cout << "info is defined as follows:" << endl;

    print_fig("info for K_2 =", info_string(to_string(aead_algorithm_id), 128, TH_2));

    cout << "Which as a CBOR encoded data item is:" << endl;

    print_fig_with_bytes("info (K_2) (CBOR-encoded)" , info_K_2);

    cout << "L is the length of K_2, so " + to_string(K_2.size()) + " bytes." << endl << endl;

    cout << "From these parameters, K_2 is computed:" << endl;

    print_fig_with_bytes("K_2" , K_2);

    cout << "Nonce IV_2 is the output of HKDF-Expand(PRK, info, L)." << endl << endl;

    cout << "info is defined as follows:" << endl;

    print_fig("info for IV_2 =", info_string("\"IV-GENERATION\"", 104, TH_2));

    cout << "Which as a CBOR encoded data item is:" << endl;

    print_fig_with_bytes("info (IV_2) (CBOR-encoded)" , info_IV_2);
   
    cout << "L is the length of IV_2, so " + to_string(IV_2.size()) + " bytes." << endl << endl;

    cout << "From these parameters, IV_2 is computed:" << endl;

    print_fig_with_bytes("IV_2" , IV_2);


    // Calculate ciphertext
    vector<uint8_t> P_2;
    vector_append( P_2, cbor_bstr( kid_R ) ); // ID_CRED_V contains a single 'kid' parameter, so only bstr is used
    vector_append( P_2, cbor_bstr( C_M ) );
    vector<uint8_t> A_2 = { 0x83 }; // CBOR array of length 3
    vector_append( A_2, cbor_tstr( "Encrypt0" ) );
    vector_append( A_2, cbor_bstr( { } ) ); // empty bstr 
    vector_append( A_2, cbor_bstr( TH_2 ) );
    vector<uint8_t> C_2 = aes_ccm_16_64_128( K_2, IV_2, P_2, A_2 );

    // Print //////////////////////////////////////////////

    cout << "#### Ciphertext Computation {#tv-ss-2-ciph}" << endl << endl;

    cout << "COSE_Encrypt0 is computed with the following parameters. Note that AD_2 is omitted." << endl << endl;
    cout << "* empty protected header" << endl << endl;
    cout << "* external_aad = TH_2" << endl << endl;
    cout << "* plaintext = CBOR Sequence of the items kid_R, CIPHERTEXT_R, in this order." << endl << endl;
    cout << "with kid_R taken from {{ss-tv-input-v}}, and CIPHERTEXT_R as calculated in {{tv-ss-2-mac-comp}}." << endl << endl;
    cout << "The plaintext is the following:" << endl ;

    print_fig_with_bytes("P_2 " , P_2);

    cout << "From the parameters above, the Enc_structure A_2 is computed." << endl;

    print_fig("A_2 =" , enc_string(vector<uint8_t> (),TH_2));

    cout << "Which encodes to the following byte string to be used as Additional Authenticated Data:" << endl;

    print_fig_with_bytes("A_2 (CBOR-encoded)" , A_2 );


    cout << "The key and nonce used are defined in {{tv-ss-2-key}}:" << endl << endl;

    cout << "* key = K_2" << endl << endl;

    cout << "* nonce = IV_2" << endl << endl;

    cout << "Using the parameters above, the ciphertext CIPHERTEXT_2 can be computed:" << endl;

    print_fig_with_bytes("CIPHERTEXT_2" , C_2);


    // Calculate message_2
    vector<uint8_t> message_2;
    vector_append( message_2, data_2 );
    vector_append( message_2, cbor_bstr( C_2 ) ); 

    // Print //////////////////////////////////////////////

    cout << "#### message_2" << endl << endl;

    cout << "From the parameter computed in {{tv-ss-2}} and {{tv-ss-2-ciph}}, message_2 is computed, as the CBOR Sequence of the following items: (G_Y, C_R, CIPHERTEXT_2)." << endl << endl;

    print_fig("message_2 =" , "(\n  " + vector_to_cddl_bstr(R_kx_pk , 4) + ",\n  " + vector_to_cddl_bstr(C_R , 4) + ",\n  " + vector_to_cddl_bstr(C_2 , 4) + "\n)");

    cout << "Which encodes to the following byte string:" << endl;

    print_fig_with_bytes("message_2 (CBOR Sequence)" , message_2);


/*
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


    // Print //////////////////////////////////////////////

    cout << "### Message 3 {#tv-rpk-3}" << endl << endl;

    cout << "Since TYPE mod 4 equals " + to_string(TYPE) + ", C_V is not omitted from data_3." << endl << endl;

    print_fig_with_bytes("C_V" , C_V);

    cout << "Data_3 is constructed, as the CBOR Sequence of the CBOR data item above." << endl;

    print_fig("data_3 =" , "(\n  " + vector_to_cddl_bstr(C_V , 4) + "\n)");

    print_fig_with_bytes("data_3 (CBOR Sequence)", data_3);

    cout << "From data_3, CIPHERTEXT_2 ({{tv-rpk-2-ciph}}), and TH_2 ({{tv-rpk-2}}), compute the input to the transcript hash TH_2 = H(TH_2 , CIPHERTEXT_2, data_3), as a CBOR Sequence of these 3 data items." << endl;

    print_fig_with_bytes("( TH_2, CIPHERTEXT_2, data_3 ) (CBOR Sequence)" , TH_3_input);

    cout << "And from there, compute the transcript hash TH_3 = SHA-256(TH_2 , CIPHERTEXT_2, data_3)" << endl;

    print_fig_with_bytes("TH_3 value" , TH_3);

    cout << "When encoded as a CBOR bstr, that gives:" << endl << endl;

    print_fig_with_bytes("TH_3 (CBOR-encoded)" , cbor_bstr(TH_3));   

    // Calculate signature
    vector<uint8_t> message_U { 0x84 }; // CBOR array of length 4
    vector_append( message_U, cbor_tstr( "Signature1" ) );
    vector_append( message_U, cbor_bstr( ID_CRED_I_CBOR ) );
    vector_append( message_U, cbor_bstr( TH_3 ) );
    vector_append( message_U, cbor_bstr( CRED_I_CBOR ) );
    vector<uint8_t> signature_U( crypto_sign_BYTES );
    crypto_sign_detached( signature_U.data(), nullptr, message_U.data(), message_U.size(), I_sign_sk_libsodium.data() );

    // Print //////////////////////////////////////////////

    cout << "#### Signature Computation {#tv-rpk-3-sign}" << endl << endl;

    cout << "COSE_Sign1 is computed with the following parameters. From {{rpk-tv-input-u}}:" << endl << endl;
    cout << "* protected = bstr .cbor ID_CRED_U " << endl << endl;
    cout << "* payload = CRED_U" << endl << endl;
    cout << "And from {{tv-rpk-3}}:" << endl << endl;
    cout << "* external_aad = TH_3" << endl << endl;
    cout << "The Sig_structure M_U to be signed is: \\[ \"Signature1\", << ID_CRED_U >>, TH_3, CRED_U \\] , as defined in {{asym-msg3-proc}}:" << endl << endl;

    print_fig("M_U =" , "[\n  \"Signature1\",\n  << " + line(id_cred_I_str) + " >>,\n  " + vector_to_cddl_bstr(TH_3 , 4) + ",\n  "+ tab(cred_I_str_tab) + "\n]");

    cout << "Which encodes to the following byte string ToBeSigned:" << endl;

    print_fig_with_bytes("M_U (message to be signed with Ed25519) (CBOR-encoded)" , message_U);

    cout << "The message is signed using the private authentication key of U, and produces the following signature:" << endl;

    print_fig_with_bytes("U's signature" , signature_U);



    // Derive key and IV
    vector<uint8_t> info_K_3 = gen_info( cbor_uint8( aead_algorithm_id ), 128, TH_3 );
    vector<uint8_t> K_3 = hkdf_expand_sha_256( PRK, info_K_3, 16 );
    vector<uint8_t> info_IV_3 = gen_info( cbor_tstr( "IV-GENERATION" ), 104, TH_3 );
    vector<uint8_t> IV_3 = hkdf_expand_sha_256( PRK, info_IV_3, 13 );

    // Print //////////////////////////////////////////////

    cout << "#### Key and Nonce Computation {#tv-rpk-3-key}" << endl << endl;

    cout << "The key and nonce for calculating the ciphertext are calculated as follows, as specified in {{key-der}}." << endl << endl;

    cout << "HKDF SHA-256 is the HKDF used (as defined by cipher suite " << suite << " )." << endl << endl;

    cout << "PRK = HMAC-SHA-256(salt, G_XY)" << endl << endl;

    cout << "Since this is the asymmetric case, salt is the empty byte string." << endl << endl;

    cout << "G_XY is the shared secret, and since the curve25519 is used, the ECDH shared secret is the output of the X25519 function." << endl << endl;

    print_fig_with_bytes("G_XY", shared_secret);

    cout << "From there, PRK is computed:" << endl;

    print_fig_with_bytes("PRK", PRK);

    cout << "Key K_3 is the output of HKDF-Expand(PRK, info, L)." << endl << endl;
    cout << "info is defined as follows:" << endl;

    print_fig("info for K_3 =", info_string(to_string(aead_algorithm_id), 128, TH_3));

    cout << "Which as a CBOR encoded data item is:" << endl; 

    print_fig_with_bytes( "info (K_3) (CBOR-encoded)" , info_K_3);

    cout << "L is the length of K_3, so " << K_3.size() << " bytes. "<< endl << endl;

    cout << "From these parameters, K_3 is computed:" << endl;

    print_fig_with_bytes( "K_3" , K_3);

    cout << "Nonce IV_3 is the output of HKDF-Expand(PRK, info, L).";

    cout << "info is defined as follows:" << endl;

    print_fig("info for IV_3 =", info_string("\"IV-GENERATION\"", 104, TH_3));

    cout << "Which as a CBOR encoded data item is:" << endl;

    print_fig_with_bytes("info (IV_3) (CBOR-encoded)", info_IV_3);

    cout << "From these parameters, IV_3 is computed:" << endl;

    print_fig_with_bytes( "IV_3" , IV_3);


    // Calculate ciphertext
    vector<uint8_t> P_3;
    vector_append( P_3, cbor_bstr( kid_U ) ); // ID_CRED_U contains a single 'kid' parameter, so only bstr is used
    vector_append( P_3, cbor_bstr( signature_U ) );
    vector<uint8_t> A_3 = { 0x83 }; // CBOR array of length 3
    vector_append( A_3, cbor_tstr( "Encrypt0" ) );
    vector_append( A_3, cbor_bstr( { } ) ); // empty bstr 
    vector_append( A_3, cbor_bstr( TH_3 ) );
    vector<uint8_t> C_3 = aes_ccm_16_64_128( K_3, IV_3, P_3, A_3 );

    // Print //////////////////////////////////////////////

    cout << "#### Ciphertext Computation {#tv-rpk-3-ciph}" << endl << endl;

    cout << "COSE_Encrypt0 is computed with the following parameters. Note that AD_3 is omitted." << endl << endl;
    cout << "* empty protected header" << endl << endl;
    cout << "* external_aad = TH_3" << endl << endl;
    cout << "* plaintext = CBOR Sequence of the items kid_value_U, signature, in this order." << endl << endl;
    cout << "with kid_value_U taken from {{rpk-tv-input-u}}, and signature as calculated in {{tv-rpk-3-sign}}." << endl << endl;
    cout << "The plaintext is the following:" << endl ;

    print_fig_with_bytes("P_3 " , P_3);

    cout << "From the parameters above, the Enc_structure A_3 is computed." << endl;

    print_fig("A_3 =" , enc_string(vector<uint8_t> (),TH_3));

    cout << "Which encodes to the following byte string to be used as Additional Authenticated Data:" << endl;

    print_fig_with_bytes("A_3 (CBOR-encoded)" , A_3 );


    cout << "The key and nonce used are defined in {{tv-rpk-3-key}}:" << endl << endl;

    cout << "* key = K_3" << endl << endl;

    cout << "* nonce = IV_3" << endl << endl;

    cout << "Using the parameters above, the ciphertext CIPHERTEXT_3 can be computed:" << endl;

    print_fig_with_bytes("CIPHERTEXT_3" , C_3);


    // Calculate message_3
    vector<uint8_t> message_3;
    vector_append( message_3, data_3 );
    vector_append( message_3, cbor_bstr( C_3 ) );

    // Print //////////////////////////////////////////////

    cout << "#### message_3" << endl << endl;

    cout << "From the parameter computed in {{tv-rpk-3}} and {{tv-rpk-3-ciph}}, message_3 is computed, as the CBOR Sequence of the following items: (C_V, CIPHERTEXT_3)." << endl << endl;

    print_fig("message_3 =" , "(\n  " + vector_to_cddl_bstr(C_V , 4) + ",\n  " + vector_to_cddl_bstr(C_3 , 4) + "\n)");

    cout << "Which encodes to the following byte string:" << endl;

    print_fig_with_bytes("message_3 (CBOR Sequence)" , message_3);


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

    // Print //////////////////////////////////////////////

    cout << "#### OSCORE Security Context Derivation" << endl << endl;

    cout << "From the previous message exchange, the Common Security Context for OSCORE {{RFC8613}} can be derived, as specified in {{exporter}}." << endl << endl;

    cout << "First af all, TH_4 is computed: TH_4 = H( TH_3, CIPHERTEXT_3 ), where the input to the hash function is the CBOR Sequence of TH_3 and CIPHERTEXT_3" << endl;

    print_fig_with_bytes("( TH_3, CIPHERTEXT_3 ) (CBOR Sequence)" , TH_4_input);

    cout << "And from there, compute the transcript hash TH_4 = SHA-256( TH_3, CIPHERTEXT_3 )" << endl;

    print_fig_with_bytes( "TH_4 value" , TH_4);

    cout << "When encoded as a CBOR bstr, that gives:" << endl;

    print_fig_with_bytes( "TH_4 (CBOR-encoded)", cbor_bstr(TH_4));

    cout << "To derive the Master Secret and Master Salt the same HKDF-Expand (PRK, info, L) is used, with different info and L." << endl << endl;

    cout << "For Master Secret:" << endl << endl;

    cout << "L for Master Secret = 16" << endl;

    print_fig("info for Master Secret =", info_string("\"OSCORE Master Secret\"", 128, TH_4));

    cout << "When encoded as a CBOR bstr, that gives:" << endl;

    print_fig_with_bytes("info (OSCORE Master Secret) (CBOR-encoded)" , info_OSCORE_secret);

    cout << "Finally, the Master Secret value computed is:" << endl;

    print_fig_with_bytes("OSCORE Master Secret", OSCORE_secret);

    cout << "For Master Salt:" << endl << endl;

    cout << "L for Master Salt = 8" << endl;

    print_fig("info for Master Salt =", info_string("\"OSCORE Master Salt\"", 64, TH_4));

    cout << "When encoded as a CBOR bstr, that gives:" << endl;

    print_fig_with_bytes("info (OSCORE Master Salt) (CBOR-encoded)" , info_OSCORE_salt);

    cout << "Finally, the Master Salt value computed is:" << endl;

    print_fig_with_bytes("OSCORE Master Salt", OSCORE_salt);

    cout << "The Client's Sender ID takes the value of C_V:" << endl;

    print_fig_with_bytes("Client's OSCORE Sender ID", C_V);

    cout << "The Server's Sender ID takes the value of C_U:" << endl;

    print_fig_with_bytes("Server's OSCORE Sender ID", C_U);

    cout << "The algorithms are those negociated in the cipher suite:" << endl;

    print_fig("AEAD Algorithm", to_string(aead_algorithm_id));

    print_fig("HMAC Algorithm", to_string(hmac_algorithm_id));
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

    //rpk_vectors();
    //psk_vectors();
    static_vectors();
}
