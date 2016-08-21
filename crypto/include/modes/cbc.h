#ifndef __CRYPTO_MODES_CBC
#define __CRYPTO_MODES_CBC

#include <cstdint>
#include <vector>

std::vector<std::vector<uint8_t>> cbc_encode(std::vector<uint8_t> iv, std::vector<std::vector<uint8_t>> blocks,
			std::vector<uint8_t> (*cypher)(std::vector<uint8_t>, std::vector<uint8_t>), std::vector<uint8_t> key,
			int num_blocks, int block_size);
std::vector<std::vector<uint8_t>> cbc_decode(std::vector<std::vector<uint8_t>> blocks,
			std::vector<uint8_t> (*cypher)(std::vector<uint8_t>, std::vector<uint8_t>), std::vector<uint8_t> key,
			int num_blocks, int block_size);

#endif
