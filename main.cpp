#include <iostream>
#include <algorithm>


#include <rapidjson/document.h>    // rapidjson's DOM-style API
#include <rapidjson/prettywriter.h> // for stringify JSON
#include <rapidjson/filewritestream.h>

#include <secp256k1.h>
#include <secp256k1_recovery.h>
#include "random.h"

#include <openssl/sha.h>

#include "hash-library/keccak.h"

using namespace rapidjson;
using namespace std;

static const std::string base64_chars =
             "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
             "abcdefghijklmnopqrstuvwxyz"
             "0123456789+/";


string base64_encode(unsigned char const* input, unsigned int len) {
    string ret;
    int i = 0;
    int j = 0;
    unsigned char char_array_3[3];
    unsigned char char_array_4[4];

    while (len--) {
        char_array_3[i++] = *(input++);
        if (i == 3) {
            char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
            char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
            char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
            char_array_4[3] = char_array_3[2] & 0x3f;

            for (i = 0; (i <4) ; i++)
                ret += base64_chars[char_array_4[i]];
            i = 0;
        }
    }

    if (i)
    {
        for (j = i; j < 3; j++)
            char_array_3[j] = '\0';

        char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
        char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
        char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
        char_array_4[3] = char_array_3[2] & 0x3f;

        for (j = 0; (j < i + 1); j++)
            ret += base64_chars[char_array_4[j]];

        while ((i++ < 3))
            ret += '=';

    }

    return ret;

}

struct NameComparator {
    bool operator()(const Value::Member &lhs, const Value::Member &rhs) const {
        return (strcmp(lhs.name.GetString(), rhs.name.GetString()) < 0);
    }
};
template<typename T>
string stringify(const T& o)
{
	StringBuffer sb;
	Writer<StringBuffer> writer(sb);
	o.Accept(writer);
	return sb.GetString();
}

int main() {
    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);

    // sample private key
    const char* pkey = "cf05de7af6ae172b367408067d03f9e5cbdfee7eac9f8e01ddf5bf1ecf77a04b";
    secp256k1_pubkey pubkey;

    // hex decode big endian
    unsigned char pkey_bytes[32];
    for (int i = 0; i < 32; i++) {
        sscanf(pkey + i * 2, "%2hhx", &pkey_bytes[i]);
    }

    auto return_val = secp256k1_ec_pubkey_create(ctx, &pubkey, pkey_bytes);
    assert(return_val);

    // uncompressed_pubkey
    unsigned char uncompressed_pubkey[65];
    size_t outputlen = sizeof(uncompressed_pubkey);
    return_val = secp256k1_ec_pubkey_serialize(ctx, uncompressed_pubkey, &outputlen, &pubkey, SECP256K1_EC_UNCOMPRESSED);
    assert(return_val);
    printf("Public Key: ");
    print_hex(uncompressed_pubkey, sizeof(uncompressed_pubkey));

    // compressed_pubkey
    unsigned char compressed_pubkey[33];
    outputlen = sizeof(compressed_pubkey);
    return_val = secp256k1_ec_pubkey_serialize(ctx, compressed_pubkey, &outputlen, &pubkey, SECP256K1_EC_COMPRESSED);
    assert(return_val);

    printf("Public Key: ");
    print_hex(compressed_pubkey, sizeof(compressed_pubkey));
    print_hex(pubkey.data, sizeof(pubkey.data));

    // base64 encode uncompressed_pubkey
    std::string base64_pubkey = base64_encode(compressed_pubkey, sizeof(compressed_pubkey));
    std::cout << base64_pubkey << std::endl;

    // sample sig
    std::string sig = "04157df208a8e81b4f67ee869404cab239630859a93e9b948cfbd7595fe72d173c8d61f5fa62360cb9a4347dc71939a1e14415c5752b2f61f56cfc10358b987500";
    // create signature
    secp256k1_ecdsa_signature signature;
START:
    auto start = std::chrono::high_resolution_clock::now();

    std::string order = " { \"symbol\":\"SPOT_NEAR_USDC\", \"side\":\"BUY\", \"order_type\":\"LIMIT\", \"order_price\":5.4, \"order_quantity\":1 }";
    Document document;
    document.Parse(order.c_str());

    std::sort(document.MemberBegin(), document.MemberEnd(), NameComparator());

    std::string format_str;
    // serialize into string
    for (Value::ConstMemberIterator itr = document.MemberBegin(); itr != document.MemberEnd(); ++itr) {
        auto value_str = stringify(itr->value);
        value_str.erase(remove(value_str.begin(), value_str.end(), '\"'),value_str.end());
        format_str += std::string(itr->name.GetString()) + "=" + value_str;
        if (itr + 1 != document.MemberEnd()) {
            format_str += "&";
        }
    }
#if 0
    std::cout << format_str << std::endl;
#endif
    
    // StringBuffer sb;
    // PrettyWriter<StringBuffer> writer(sb);
    // document.Accept(writer);
    // std::string order_json = sb.GetString();
    // std::cout << order_json << std::endl;

    // sign format_str
    unsigned char hash[32];
    //SHA256_CTX sha256;
    //SHA256_Init(&sha256);
    //SHA256_Update(&sha256, format_str.c_str(), format_str.size());
    //SHA256_Final(hash, &sha256);

    // keccak256 hash
    Keccak keccak;
    auto hash_bytes = keccak(format_str);
#if 0
    printf("Hash: %s\n", hash_bytes.c_str());
    printf("Hash size: %d\n", hash_bytes.size());
#endif
    // hex decode
    for (int i = 0; i < 32; i++) {
        sscanf(hash_bytes.c_str() + i * 2, "%2hhx", &hash[i]);
    }
    auto stop = std::chrono::high_resolution_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(stop - start).count();
    printf("Hash time: %ld us", elapsed);

    return_val = secp256k1_ecdsa_sign(ctx, &signature, hash, pkey_bytes, NULL, NULL); 
    // print signature
    unsigned char sig_bytes[64];
    secp256k1_ecdsa_signature_serialize_compact(ctx, sig_bytes, &signature);
    printf("Signature: ");
    print_hex(sig_bytes, sizeof(sig_bytes));

#if 1
    // get recoverable signature
    secp256k1_ecdsa_recoverable_signature recoverable_signature;
    return_val = secp256k1_ecdsa_sign_recoverable(ctx, &recoverable_signature, hash, pkey_bytes, NULL, NULL);
    printf("Recoverable Signature: ");
    unsigned char recoverable_sig_bytes[64];
    int recid;
    secp256k1_ecdsa_recoverable_signature_serialize_compact(ctx, recoverable_sig_bytes, &recid, &recoverable_signature);
    print_hex(recoverable_sig_bytes, sizeof(recoverable_sig_bytes));
    printf("Recid: %d\n", recid);
#endif
   
   start = std::chrono::high_resolution_clock::now();
   // ecdsa recover
   secp256k1_pubkey rc_pubkey;
   secp256k1_ecdsa_recover(ctx, &rc_pubkey, &recoverable_signature, hash);
   // rc_pubkey.data to hex
   unsigned char rc_pubkey_bytes[65];
   outputlen = sizeof(rc_pubkey_bytes);
   return_val = secp256k1_ec_pubkey_serialize(ctx, rc_pubkey_bytes, &outputlen, &rc_pubkey, SECP256K1_EC_UNCOMPRESSED);

   stop = std::chrono::high_resolution_clock::now();
   elapsed = std::chrono::duration_cast<std::chrono::microseconds>(stop - start).count();
   printf("Recover time: %ld us", elapsed);

   printf("Recover Public Key: ");
   print_hex(rc_pubkey_bytes, sizeof(rc_pubkey_bytes));

   goto START;
  

}