#include <benchmark/benchmark.h>
#include "gtest/gtest.h"
#include "crypto-bn/bn.h"
#include "../src/crypto-tss-rsa/tss_rsa.h"
#include "exception/safeheron_exceptions.h"
#include "../src/crypto-tss-rsa/BloomFilter.h"
using safeheron::bignum::BN;
using safeheron::tss_rsa::KeyGenParam;
using safeheron::tss_rsa::RSAKeyMeta;
using safeheron::tss_rsa::RSAPrivateKeyShare;
using safeheron::tss_rsa::RSAPublicKey;
using safeheron::tss_rsa::RSASigShare;

void BM_generateRandom(benchmark::State &state, int key_bits_length, int l, int k);
void BM_generateEx(benchmark::State &state, int key_bits_length, int l, int k);

void BM_generateSig(benchmark::State &state);
void BM_combineSig(benchmark::State &state);
void BM_verifySig(benchmark::State &state);

std::vector<std::vector<RSAPrivateKeyShare>> priv_arr;
std::vector<RSAPublicKey> pub;
std::vector<RSAKeyMeta> key_meta;
std::vector<std::vector<RSASigShare>> sig_arr;
std::vector<BN> sig;

std::vector<KeyGenParam> param;
std::string doc[] = {"hello world, 1",
                     "hello world, 2",
                     "hello world, 3",
                     "hello world, 4",
                     "hello world, 5",
                     "hello world, 6",
                     "hello world, 7",
                     "hello world, 8",
                     "hello world, 9",
                     "hello world, 10"};

void BM_generateRandom(benchmark::State &state, int key_bits_length, int l, int k)
{
    priv_arr.resize(state.max_iterations);
    pub.resize(state.max_iterations);
    key_meta.resize(state.max_iterations);
    sig_arr.resize(state.max_iterations);
    sig.resize(state.max_iterations);
    int count = 0;
    for (auto _ : state)
    {
        priv_arr[count].clear();
        safeheron::tss_rsa::GenerateKey(key_bits_length, l, k, priv_arr[count], pub[count], key_meta[count]);
        count++;
    }
}

void BM_generateEx(benchmark::State &state, int key_bits_length, int l, int k)
{
    priv_arr.resize(state.max_iterations);
    pub.resize(state.max_iterations);
    key_meta.resize(state.max_iterations);
    sig_arr.resize(state.max_iterations);
    sig.resize(state.max_iterations);
    int count = 0;
    for (auto _ : state)
    {
        priv_arr[count].clear();
        safeheron::tss_rsa::GenerateKeyEx(key_bits_length, l, k, param[count], priv_arr[count], pub[count], key_meta[count]);
        count++;
    }
}

void BM_generateSig(benchmark::State &state)
{
    for (auto _ : state)
    {
        for (size_t i = 0; i < priv_arr.size(); i++)
        {
            sig_arr[i].clear();
            for (size_t j = 0; j < priv_arr[i].size(); j++)
            {
                sig_arr[i].emplace_back(priv_arr[i][j].Sign(doc[i], key_meta[i], pub[i]));
            }
        }
    }
}

void BM_combineSig(benchmark::State &state)
{
    for (auto _ : state)
    {
        for (size_t i = 0; i < sig_arr.size(); i++)
        {
            CombineSignaturesWithoutValidation(doc[i], sig_arr[i], pub[i], key_meta[i], sig[i]);
        }
    }
}

void BM_verifySig(benchmark::State &state)
{
    for (auto _ : state)
    {
        for (size_t i = 0; i < sig.size(); i++)
        {
            pub[i].VerifySignature(doc[i], sig[i]);
        }
    }
    for (size_t i = 0; i < sig.size(); i++)
    {
        EXPECT_TRUE(pub[i].VerifySignature(doc[i], sig[i]));
    }
}

void BM_update_bloom_filter(benchmark::State &state, Transaction &transaction, std::string &json_str)
{
    for (auto _ : state)
    {
        safeheron::tss_rsa::update_bloom_filter(transaction, json_str);
    }
}

void BM_extract_bloom_filter(benchmark::State &state, Transaction &transaction, std::string &json_str)
{
    safeheron::tss_rsa::update_bloom_filter(transaction, json_str);
    transaction.data += transaction.bloom_filter.to_string();
    for (auto _ : state)
    {
        safeheron::tss_rsa::extract_bloom_filter(transaction);
    }
}

int main(int argc, char **argv)
{
    benchmark::Initialize(&argc, argv);
    int n_key_pairs = 10;
    Transaction transaction;
    transaction.data = "transaction data";
    std::string json_str = "{\"i\" : 1, \"si\" : \"02F0FE9FADE8C17979CCD68D86163A48B0972A24F4C1726F4C5F19180364194E84395A318213BD31A8805466EE01CE30ED4B6D993BE69970F4F726904FBC6A41CAA2FC2A9A938430D8EBE9EC52200BEA868126C15C97A1782C73ADB6BF951D76B559A0C7C6C66C277858B7D0CC7D4222DB77B50FC2F1220B66134B9481A10678\"}";

    // Generate "n_key_pairs" key pairs: n_key_pairs = 10
    ::benchmark::RegisterBenchmark("BM_generateRandom", &BM_generateRandom, 4096, 5, 3)->Iterations(n_key_pairs)->Unit(benchmark::kSecond);
    // Generate 10 * "n_key_pairs" signature shares
    ::benchmark::RegisterBenchmark("BM_generateSig", &BM_generateSig)->Iterations(10)->Unit(benchmark::kSecond);
    // Combine 10 * "n_key_pairs" signatures
    ::benchmark::RegisterBenchmark("BM_combineSig", &BM_combineSig)->Iterations(10)->Unit(benchmark::kSecond);
    // Verify 10 * "n_key_pairs" signatures
    ::benchmark::RegisterBenchmark("BM_verifySig", &BM_verifySig)->Iterations(10)->Unit(benchmark::kSecond);
    // Update bloom filter
    ::benchmark::RegisterBenchmark("BM_updateBloomFilter", &BM_update_bloom_filter, transaction, json_str)->Iterations(10)->Unit(benchmark::kSecond);
    ::benchmark::RegisterBenchmark("BM_updateBloomFilter", [&transaction, &json_str](benchmark::State &state)
                                   { BM_update_bloom_filter(state, transaction, json_str); })
        ->Iterations(10)
        ->Unit(benchmark::kMillisecond);
    ::benchmark::RegisterBenchmark("BM_extractBloomFilter", [&transaction, &json_str](benchmark::State &state)
                                   { BM_extract_bloom_filter(state, transaction, json_str); })
        ->Iterations(10)
        ->Unit(benchmark::kMillisecond);

    benchmark::RunSpecifiedBenchmarks();
    benchmark::Shutdown();
    return 0;
}
