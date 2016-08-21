#include <bitperm.h>
#include <util.h>
#include <iostream>

//l1: length of original array, in bytes
//l2: length of final array, in bytes
std::vector<uint8_t> permutate_bits(std::vector<uint8_t> source, int l1, int l2, uint8_t *perm_arr){
	std::vector<uint8_t> p(l2);
	std::vector<uint8_t> perm=byte_arr_to_vec(perm_arr, l2*8);
	for(int i=0;i<l2;i++){
		uint8_t temp=0;
		for(int j=0;j<8;j++){
			uint8_t bit=perm[8*i+j];
			if(bit>l1*8){
				std::cout<<"[ERROR] Bit permutation failed at bit "
					<<(8*i+j)<<": "<<(int)bit<<" is out of bounds\n";
				return p;
			}
			temp<<=1;
			temp|=(source[(bit-1)/8]>>(7-(bit-1)%8))&1;
		}
		p[i]=temp;
	}
	return p;
}
