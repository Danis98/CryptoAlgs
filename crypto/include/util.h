#ifndef __CRYPTO_UTIL
#define __CRYPTO_UTIL

#include <cstdint>
#include <vector>

std::vector<uint8_t> byte_arr_to_vec(uint8_t *arr, int size);
uint8_t *array_0_based_to_1_based(uint8_t *arr, int len);

#endif
