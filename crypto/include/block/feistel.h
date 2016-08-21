#ifndef __CRYPTO_FEISTEL_H
#define __CRYPTO_FEISTEL_H

#include <cstdint>
#include <vector>

std::vector<uint8_t> encrypt_feistel(
                std::vector<uint8_t> block,
                std::vector<uint8_t> key,
                std::vector<std::vector<uint8_t>> (*key_sched)(std::vector<uint8_t>), //key
                std::vector<uint8_t> (*init_func)(std::vector<std::vector<uint8_t>>, std::vector<uint8_t>), //keys, clear
                std::vector<uint8_t> (*end_func)(std::vector<std::vector<uint8_t>>, std::vector<uint8_t>), //keys, preout
                std::vector<uint8_t> (*round_func)(int, std::vector<std::vector<uint8_t>>, std::vector<uint8_t>), //round, keys, data
                int num_rounds,
                int block_size);


#endif
