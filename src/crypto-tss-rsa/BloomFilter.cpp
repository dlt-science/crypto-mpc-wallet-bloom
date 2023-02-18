#include "BloomFilter.h"

namespace safeheron
{
    namespace tss_rsa
    {
        void update_bloom_filter(Transaction &transaction, std::string json_str)
        {
            // std::cout << "json_str: " << json_str << std::endl;
            for (int i = 0; i < K; i++)
            {
                hash_indices[i] = std::hash<std::string>()(std::to_string(i) + json_str) % M;
            }

            for (int index : hash_indices)
            {
                transaction.bloom_filter.set(index);
            }
        }

        std::string extract_bloom_filter(Transaction &transaction)
        {
            return transaction.data.substr(transaction.data.size() - transaction.bloom_filter.size(), transaction.data.size());
        }
    } // namespace tss_rsa
} // namespace safeheron