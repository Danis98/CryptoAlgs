#ifndef __CRYPTO_BITPERM_H
#define __CRYPTO_BITPERM_H

#include <cstdint>
#include <vector>

std::vector<uint8_t> permutate_bits(std::vector<uint8_t> source, int l1, int l2, uint8_t *perm_arr);

#endif
