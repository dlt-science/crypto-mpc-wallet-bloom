#ifndef TSS_RSA_BLOOMFILTER_H
#define TSS_RSA_BLOOMFILTER_H

#include <bitset>
#include <iostream>
#include <string>
#include <vector>
// #include <openssl/sha.h>

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

std::vector<int> hash_indices(K);

namespace safeheron
{
    namespace tss_rsa
    {
        void update_bloom_filter(Transaction &transaction, std::string json_str);
        std::string extract_bloom_filter(Transaction &transaction);
    } // namespace tss_rsa
} // namespace safeheron

#endif // TSS_RSA_BLOOMFILTER_H