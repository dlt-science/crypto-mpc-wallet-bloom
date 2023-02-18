#include "crypto-bn/bn.h"
#include "exception/safeheron_exceptions.h"
#include "crypto-tss-rsa/tss_rsa.h"
#include "crypto-encode/hex.h"
#include <bitset>
#include <iostream>
#include <string>
#include <vector>
#include <openssl/sha.h>
#include "../src/crypto-tss-rsa/BloomFilter.h"

using safeheron::bignum::BN;
using safeheron::exception::BadAllocException;
using safeheron::exception::LocatedException;
using safeheron::exception::OpensslException;
using safeheron::exception::RandomSourceException;
using safeheron::tss_rsa::KeyGenParam;
using safeheron::tss_rsa::RSAKeyMeta;
using safeheron::tss_rsa::RSAPrivateKeyShare;
using safeheron::tss_rsa::RSAPublicKey;
using safeheron::tss_rsa::RSASigShare;

int main(int argc, char **argv)
{
    std::string json_str;
    std::string doc("12345678123456781234567812345678");
    Transaction transaction;

    // Key Generation
    int key_bits_length = 1024;
    int k = 2;
    int l = 2;
    std::vector<RSAPrivateKeyShare> priv_arr;
    RSAPublicKey pub;
    RSAKeyMeta key_meta;
    bool status = safeheron::tss_rsa::GenerateKey(key_bits_length, l, k, priv_arr, pub, key_meta);
    key_meta.ToJsonString(json_str);
    std::cout << "key meta data: " << json_str << std::endl;

    pub.ToJsonString(json_str);
    std::cout << "public key: " << json_str << std::endl;

    priv_arr[0].ToJsonString(json_str);
    std::cout << "private key share 1: " << json_str << std::endl;

    safeheron::tss_rsa::update_bloom_filter(transaction, json_str);
    std::cout << "bloom filter after share1: " << transaction.bloom_filter << std::endl;

    priv_arr[1].ToJsonString(json_str);
    std::cout << "private key share 2: " << json_str << std::endl;

    safeheron::tss_rsa::update_bloom_filter(transaction, json_str);
    std::cout << "bloom filter after share 2: " << transaction.bloom_filter << std::endl;

    transaction.data = "transaction_data";
    transaction.data += transaction.bloom_filter.to_string();

    std::cout << "transaction data: " << transaction.data << std::endl;

    // Prepare
    std::string doc_pss = safeheron::tss_rsa::EncodeEMSA_PSS(transaction.data, key_bits_length, safeheron::tss_rsa::SaltLength::AutoLength);
    std::cout << "EM: " << safeheron::encode::hex::EncodeToHex(doc) << std::endl;
    // Party 1 sign.
    RSASigShare sig_share0 = priv_arr[0].Sign(doc_pss, key_meta, pub);
    sig_share0.ToJsonString(json_str);
    std::cout << "signature share 1: " << json_str << std::endl;
    // Party 2 sign.
    RSASigShare sig_share2 = priv_arr[1].Sign(doc_pss, key_meta, pub);
    sig_share2.ToJsonString(json_str);
    std::cout << "signature share 2: " << json_str << std::endl;

    // Combine signatures
    // Distributed signature
    std::vector<RSASigShare> sig_share_arr;
    for (int i = 0; i < l; i++)
    {
        sig_share_arr.emplace_back(priv_arr[i].Sign(doc_pss, key_meta, pub));
    }
    BN sig;
    bool ok = safeheron::tss_rsa::CombineSignatures(doc_pss, sig_share_arr, pub, key_meta, sig);
    std::cout << "succeed to sign: " << ok << std::endl;
    std::cout << "signature: " << sig.Inspect() << std::endl;

    // Verify the final signature.
    std::cout << "Verify Pss: " << safeheron::tss_rsa::VerifyEMSA_PSS(doc, key_bits_length, safeheron::tss_rsa::SaltLength::AutoLength, doc_pss) << std::endl;
    std::cout << "Verify Sig: " << pub.VerifySignature(doc_pss, sig) << std::endl;

    // Extract the bloom filter from the signed transaction
    std::cout << "extracted bloom_str: " << safeheron::tss_rsa::extract_bloom_filter(transaction) << std::endl;
    return 0;
}
