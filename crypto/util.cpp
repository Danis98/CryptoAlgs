#include <util.h>

std::vector<uint8_t> byte_arr_to_vec(uint8_t *arr, int size){
	std::vector<uint8_t> vec;
	for(int i=0;i<size;i++)
		vec.push_back(arr[i]);
	return vec;
}

uint8_t *array_0_based_to_1_based(uint8_t *arr, int len){
	uint8_t *res=new uint8_t[len];
	for(int i=0;i<len;i++)
		res[i]=arr[i]+1;
	return res;
}
