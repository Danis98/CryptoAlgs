#include <block/feistel.h>
#include <modes/cbc.h>
#include <bitperm.h>
#include <util.h>

#include <iostream>
#include <iomanip>
#include <fstream>
#include <vector>

#define S_TABLE(num) s##num
#define APPLY_S(data, num) (S_TABLE(num)[(data)&0x20 | ((data)&0x01)<<4 | ((data)&0x1e)>>1])

std::ifstream fin("clear.txt");
std::ofstream fout("crypt.crp");

//Initial permutation
uint8_t ip[64]={
	58, 50, 42, 34, 26, 18, 10, 2,
	60, 52, 44, 36, 28, 20, 12, 4,
	62, 54, 46, 38, 30, 22, 14, 6,
	64, 56, 48, 40, 32, 24, 16, 8,
	57, 49, 41, 33, 25, 17,  9, 1,
	59, 51, 43, 35, 27, 19, 11, 3,
	61, 53, 45, 37, 29, 21, 13, 5,
	63, 55, 47, 39, 31, 23, 15, 7
};

//Final permutation, inverse of the initial permutation
uint8_t fp[64]={
        40, 8, 48, 16, 56, 24, 64, 32,
	39, 7, 47, 15, 55, 23, 63, 31,
	38, 6, 46, 14, 54, 22, 62, 30,
	37, 5, 45, 13, 53, 21, 61, 29,
	36, 4, 44, 12, 52, 20, 60, 28,
	35, 3, 43, 11, 51, 19, 59, 27,
	34, 2, 42, 10, 50, 18, 58, 26,
	33, 1, 41,  9, 49, 17, 57, 25
};

//Bit expansion matrix
uint8_t expand[48]={
	32,  1,  2,  3,  4,  5,
	 4,  5,  6,  7,  8,  9,
	 8,  9, 10, 11, 12, 13,
	12, 13, 14, 15, 16, 17,
	16, 17, 18, 19, 20, 21,
	20, 21, 22, 23, 24, 25,
	24, 25, 26, 27, 28, 29,
	28, 29, 30, 31, 32,  1
};

//S-tables
uint8_t s1[64]={
	14, 4,  13, 1,  2,  15, 11, 8,  3,  10, 6,  12, 5,  9,  0,  7,
	0,  15, 7,  4,  14, 2,  13, 1,  10, 6,  12, 11, 9,  5,  3,  8,
	4,  1,  14, 8,  13, 6,  2,  11, 15, 12, 9,  7,  3,  10, 5,  0,
	15, 12, 8,  2,  4,  9,  1,  7,  5,  11, 3,  14, 10, 0,  6,  13
};

uint8_t s2[64]={
	15, 1,  8,  14, 6,  11, 3,  4,  9,  7,  2,  13, 12, 0,  5,  10,
	3,  13, 4,  7,  15, 2,  8,  14, 12, 0,  1,  10, 6,  9,  11, 5,
	0,  14, 7,  11, 10, 4,  13, 1,  5,  8,  12, 6,  9,  3,  2,  15,
	13, 8,  10, 1,  3,  15, 4,  2,  11, 6,  7,  12, 0,  5,  14, 9
};

uint8_t s3[64]={
	10, 0,  9,  14, 6,  3,  15, 5,  1,  13, 12, 7,  11, 4,  2,  8,
	13, 7 , 0,  9,  3,  4,  6,  10, 2,  8,  5,  14, 12, 11, 15, 1,
	13, 6,  4,  9,  8,  15, 3,  0,  11, 1,  2,  12, 5,  10, 14, 7,
	1,  10, 13, 0,  6,  9,  8,  7,  4,  15, 14, 3,  11, 5,  2,  12
};

uint8_t s4[64]={
	7,  13, 14, 3,  0,  6,  9,  10, 1,  2,  8,  5,  11, 12, 4,  15,
	13, 8,  11, 5,  6,  15, 0,  3,  4,  7,  2,  12, 1,  10, 14, 9,
	10, 6,  9,  0,  12, 11, 7,  13, 15, 1,  3,  14, 5,  2,  8,  4,
	3,  15, 0,  6,  10, 1,  13, 8,  9,  4,  5,  11, 12, 7,  2,  14
};

uint8_t s5[64]={
	2,  12, 4,  1,  7,  10, 11, 6,  8,  5,  3,  15, 13, 0,  14, 9,
	14, 11, 2,  12, 4,  7,  13, 1,  5,  0,  15, 10, 3,  9,  8,  6,
	4,  2,  1,  11, 10, 13, 7,  8,  15, 9,  12, 5,  6,  3,  0,  14,
	11, 8,  12, 7,  1,  14, 2,  13, 6,  15, 0,  9,  10, 4,  5,  3
};

uint8_t s6[64]={
	12, 1,  10, 15, 9,  2,  6,  8,  0,  13, 3,  4,  14, 7,  5,  11,
	10, 15, 4,  2,  7,  12, 9,  5,  6,  1,  13, 14, 0,  11, 3,  8,
	9,  14, 15, 5,  2,  8,  12, 3,  7,  0,  4,  10, 1,  13, 11, 6,
	4,  3,  2,  12, 9,  5,  15, 10, 11, 14, 1,  7,  6,  0,  8,  13
};

uint8_t s7[64]={
	4,  11, 2,  14, 15, 0,  8,  13, 3,  12, 9,  7,  5,  10, 6,  1,
	13, 0,  11, 7,  4,  9,  1,  10, 14, 3,  5,  12, 2,  15, 8,  6,
	1,  4,  11, 13, 12, 3,  7,  14, 10, 15, 6,  8,  0,  5,  9,  2,
	6,  11, 13, 8,  1,  4,  10, 7,  9,  5,  0,  15, 14, 2,  3,  12
};

uint8_t s8[64]={
	13, 2,  8,  4,  6,  15, 11, 1,  10, 9,  3,  14, 5,  0,  12, 7,
	1,  15, 13, 8,  10, 3,  7,  4,  12, 5,  6,  11, 0,  14, 9,  2,
	7,  11, 4,  1,  9,  12, 14, 2,  0,  6,  10, 13, 15, 3,  5,  8,
	2,  1,  14, 7,  4,  10, 8,  13, 15, 12, 9,  0,  3,  5,  6,  11
};

//P table
uint8_t p[32]={
	16, 7,  20, 21,
	29, 12, 28, 17,
	1,  15, 23, 26,
	5,  18, 31, 10,
	2,  8,  24, 14,
	32, 27, 3,  9,
	19, 13, 30, 6,
	22, 11, 4, 25
};

//Keysched shifts
uint8_t shift[16]={
	1, 1, 2, 2,
	2, 2, 2, 2,
	1, 2, 2, 2,
	2, 2, 2, 1
};

//Keysched permuted choice 1
uint8_t pc1[56]={
	57, 49, 41, 33, 25, 17, 9,
	1,  58, 50, 42, 34, 26, 18,
	10, 2,  59, 51, 43, 35, 27,
	19, 11, 3,  60, 52, 44, 36,

	63, 55, 47, 39, 31, 23, 15,
	7,  62, 54, 46, 38, 30, 22,
	14, 6,  61, 53, 45, 37, 29,
	21, 13, 5,  28, 20, 12, 4
};

//Keysched permuted choice 2
uint8_t pc2[48]={
	14, 17, 11, 24, 1,  5,
	3,  28, 15, 6,  21, 10,
	23, 19, 12, 4,  26, 8,
	16, 7,  27, 20, 13, 2,
	41, 52, 31, 37, 47, 55,
	30, 40, 51, 45, 33, 48,
	44, 49, 39, 56, 34, 53,
	46, 42, 50, 36, 29, 32
};

std::vector<uint8_t> init(std::vector<std::vector<uint8_t>> round_keys, std::vector<uint8_t> data){
	return permutate_bits(data, 8, 8, ip);
}

std::vector<uint8_t> end(std::vector<std::vector<uint8_t>> round_keys, std::vector<uint8_t> data){
        return permutate_bits(data, 8, 8, fp);
}

std::vector<uint8_t> apply_s_tables(std::vector<uint8_t> data){
	std::vector<uint8_t> res(4);
	res[0]=APPLY_S(data[0]>>2, 1)<<4
		|APPLY_S((data[0]&0x03)<<4 | data[1]>>4, 2);
	res[1]=APPLY_S((data[1]&0x0f)<<2 | data[2]>>6, 3)<<4
		|APPLY_S(data[2]&0x3f, 4);
	res[2]=APPLY_S(data[3]>>2, 5)<<4
		|APPLY_S((data[3]&0x03)<<4 | data[4]>>4, 6);
	res[3]=APPLY_S((data[4]&0x0f)<<2 | data[5]>>6, 7)<<4
		|APPLY_S(data[5]&0x3f, 8);
	return res;
}

std::vector<uint8_t> des_round(int round, std::vector<std::vector<uint8_t>> round_keys, std::vector<uint8_t> data){
	std::vector<uint8_t> enc=permutate_bits(data, 4, 6, expand);
	for(int i=0;i<6;i++)
		enc[i]^=round_keys[round][i];
	std::vector<uint8_t> res=apply_s_tables(enc);
	res=permutate_bits(res, 4, 4, p);
	return res;
}

std::vector<std::vector<uint8_t>> key_sched(std::vector<uint8_t> key){
	std::vector<std::vector<uint8_t>> round_keys(16);
	//Divide in C and D half-keys, kept in a single array
	std::vector<uint8_t> temp=permutate_bits(key, 8, 7, pc1);
	//Generate subkey
	for(int i=0;i<16;i++){
		round_keys[i].resize(6);
		//Rotate
		for(int j=0;j<shift[i];j++){
			//rotate c
			bool high_bit=(temp[3]&128)>0;
			temp[3]=(temp[3]&0xf0)<<1 | temp[3]&0x0f;
			for(int k=2;k>=0;k--){
				bool tmp_bit=(temp[k]&128)>0;
				temp[k]=(temp[k]<<1)&0xff | (high_bit?1:0);
				high_bit=tmp_bit;
			}
			temp[3]|=(high_bit?1:0)<<4;
			//rotate d
			high_bit=(temp[3]&8)>0;
			temp[3]=temp[3]&0xf0 | (temp[3]<<1)&0x0f;
			for(int k=6;k>=4;k--){
				bool tmp_bit=(temp[k]&128)>0;
				temp[k]=(temp[k]<<1)&0xff | (high_bit?1:0);
				high_bit=tmp_bit;
			}
			temp[3]|=high_bit?1:0;
		}
		round_keys[i]=permutate_bits(temp, 7, 6, pc2);
	}
	return round_keys;
}

std::vector<std::vector<uint8_t>> key_sched_inv(std::vector<uint8_t> key){
	std::vector<std::vector<uint8_t>> round_keys=key_sched(key);
	std::vector<std::vector<uint8_t>> round_keys_inv(16);
	for(int i=0;i<16;i++){
		round_keys_inv[i].resize(6);
		for(int j=0;j<6;j++)
			round_keys_inv[i][j]=round_keys[15-i][j];
	}
	return round_keys_inv;
}

std::vector<uint8_t> des_encrypt(std::vector<uint8_t> data, std::vector<uint8_t> key){
	return encrypt_feistel(data, key, key_sched,
				init, end, des_round, 16, 8);
}

std::vector<uint8_t> des_decrypt(std::vector<uint8_t> data, std::vector<uint8_t> key){
	return encrypt_feistel(data, key, key_sched_inv,
				init, end, des_round, 16, 8);
}

int main(){
	//input data
	std::string mode_tag;
	fin>>mode_tag;
	if(mode_tag!="CBC"){
		std::cout<<mode_tag<<" block cypher mode not supported!\n";
		return 0;
	}
	int num_blocks;
	fin>>num_blocks;
	std::vector<std::vector<uint8_t>> blocks(num_blocks);
	std::vector<uint8_t> key(8);
	std::vector<uint8_t> iv(8);
	for(int i=0;i<8;i++){
		int temp;
		fin>>std::hex>>temp;
		iv[i]=temp&0xff;
	}
	for(int i=0;i<8;i++){
		int temp;
		fin>>std::hex>>temp;
		key[i]=temp&0xff;
	}
	std::vector<uint8_t> data_raw;
	for(int i=0;i<num_blocks*8;i++){
		int temp;
		fin>>std::hex>>temp;
		data_raw.push_back(temp&0xff);
	}
	if(data_raw.size()%8!=0){
		std::cout<<"Message data length isn't a multiple of the block length, aborting...\n";
		return 0;
	}
	for(int i=0;i<num_blocks;i++){
		blocks[i].resize(8);
		for(int j=0;j<8;j++)
			blocks[i][j]=data_raw[8*i+j];
	}
	std::cout<<"Initiating DES encryption...\n";
	for(int k=0;k<num_blocks;k++){
		for(int i=0;i<8;i++)
	                std::cout<<std::hex<<std::setw(2)<<std::setfill('0')<<(int)blocks[k][i];
		std::cout<<"\n";
	}
	//encrypt all the things!
	std::cout<<"ENCRYPT\n";
	std::vector<std::vector<uint8_t>> enc=cbc_encode(iv, blocks, des_encrypt, key, num_blocks, 8);
	for(int k=0;k<num_blocks+1;k++){
		for(int i=0;i<8;i++)
	                std::cout<<std::hex<<std::setw(2)<<std::setfill('0')<<(int)enc[k][i];
		std::cout<<"\n";
	}
	//Decrypt all the things!
	std::cout<<"DECRYPT\n";
	std::vector<std::vector<uint8_t>> dec=cbc_decode(enc, des_decrypt, key, num_blocks+1, 8);
	for(int k=0;k<num_blocks;k++){
		for(int i=0;i<8;i++)
	                std::cout<<std::hex<<std::setw(2)<<std::setfill('0')<<(int)dec[k][i];
		std::cout<<"\n";
	}
	return 0;
}
