#include "crypto-bn/bn.h"
#include "exception/safeheron_exceptions.h"
#include "crypto-tss-rsa/tss_rsa.h"
#include "crypto-encode/hex.h"
#include <bitset>
#include <iostream>
#include <string>
#include <vector>
#include <openssl/sha.h>

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

// Size of the bloom filter
const int M = 48;
// Number of hash functions
const int K = 17;

// Transaction structure
struct Transaction
{
    std::bitset<M> bloom_filter;
    std::string data;
};

// Hash function
std::string hash(const std::bitset<M> &bloom_filter)
{
    // Convert the bloom filter to a string
    std::string bloom_str = bloom_filter.to_string();

    // Compute the SHA256 hash of the string
    unsigned char digest[SHA256_DIGEST_LENGTH];
    SHA256((const unsigned char *)bloom_str.c_str(), bloom_str.size(), digest);

    // Convert the hash to a string
    std::string hash_str((char *)digest, SHA256_DIGEST_LENGTH);
    return hash_str;
}

// Extract bloom filter from transaction
std::bitset<M> extract_bloom_filter_from_transaction(const std::string &transaction_data)
{
    // Extract the hash of the bloom filter from the transaction data
    std::string bloom_hash = transaction_data.substr(transaction_data.size() - SHA256_DIGEST_LENGTH);
    // std::cout << "transaction_data: " << transaction_data << std::endl;
    // std::cout << "bloom_hash: " << bloom_hash << std::endl;

    // Compute the SHA256 hash of the extracted hash
    unsigned char digest[SHA256_DIGEST_LENGTH];
    SHA256((const unsigned char *)bloom_hash.c_str(), bloom_hash.size(), digest);
    std::string computed_hash_str((char *)digest, SHA256_DIGEST_LENGTH);

    // std::cout << "computed_hash_str: " << computed_hash_str << std::endl;

    // Compute the SHA256 hash of the bloom filter
    std::string bloom_str = transaction_data.substr(transaction_data.size() - SHA256_DIGEST_LENGTH - M / 8, M / 8);

    // std::cout << "bloom_str: " << transaction_data << std::endl;

    std::bitset<M> bloom_filter(bloom_str);
    std::string bloom_hash_str = hash(bloom_filter);

    // Compare the computed hash with the hash of the bloom filter
    if (computed_hash_str == bloom_hash_str)
    {
        return bloom_filter;
    }
    else
    {
        throw std::runtime_error("Invalid bloom filter hash in transaction data");
    }
}

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

    std::vector<int> hash_indices(K);
    for (int i = 0; i < K; i++)
    {
        hash_indices[i] = std::hash<std::string>()(std::to_string(i) + json_str) % M;
    }

    // Set the bits in the bloom filter
    for (int index : hash_indices)
    {
        transaction.bloom_filter.set(index);
    }

    priv_arr[1].ToJsonString(json_str);
    std::cout << "private key share 2: " << json_str << std::endl;

    for (int i = 0; i < K; i++)
    {
        hash_indices[i] = std::hash<std::string>()(std::to_string(i) + json_str) % M;
        std::cout << "hash index: " << hash_indices[i] << std::endl;
    }

    // Set the bits in the bloom filter
    for (int index : hash_indices)
    {
        transaction.bloom_filter.set(index);
    }

    std::cout << "bloom filter: " << transaction.bloom_filter << std::endl;

    std::string bloom_hash = hash(transaction.bloom_filter);
    transaction.data = "random_data";
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
    std::string bloom_str = transaction.data.substr(transaction.data.size() - transaction.bloom_filter.size(), transaction.data.size());
    std::cout << "extracted bloom_str: " << bloom_str << std::endl;
    std::cout << "extracted bloom_str: " << bloom_str.size() << std::endl;
    return 0;
}
