#include <block/feistel.h>
#include <modes/cbc.h>
#include <bitperm.h>
#include <util.h>

#include <iostream>
#include <fstream>
#include <algorithm>
#include <iomanip>

std::ifstream fin("clear.txt");

//S-boxes
uint8_t s0[16]={
	0x0c, 0x0f, 0x07, 0x0a,
	0x0e, 0x0d, 0x0b, 0x00,
	0x02, 0x06, 0x03, 0x01,
	0x09, 0x04, 0x05, 0x08
};

uint8_t s1[16]={
	0x07, 0x02, 0x0e, 0x09,
	0x03, 0x0b, 0x00, 0x04,
	0x0c, 0x0d, 0x01, 0x0a,
	0x06, 0x0f, 0x08, 0x05
};

//Permutation matrix
uint8_t perm[64]={
	10, 21, 52, 56, 27,  1, 47, 38,
	26, 37,  4,  8, 43, 17, 63, 54,
	42, 53, 20, 24, 59, 33, 15,  6,
	58,  5, 36, 40, 11, 49, 31, 22,
	18, 29, 60,  0, 35,  9, 55, 46,
	34, 45, 12, 16, 51, 25,  7, 62,
	50, 61, 28, 32,  3, 41, 23, 14,
	 2, 13, 44, 48, 19, 57, 39, 30
};

std::vector<std::vector<uint8_t>> key_sched(std::vector<uint8_t> key){
	std::vector<std::vector<uint8_t>>  round_keys(16);
	std::vector<uint8_t> temp=key;
	for(int i=0;i<16;i++){
		//Generate subkey
		round_keys[i].push_back(temp[0]);
		round_keys[i].push_back(temp[0]);
		for(int j=1;j<8;j++)
			round_keys[i].push_back(temp[j]);
		//Rotate key
		uint8_t last_byte=temp[temp.size()-1];
		temp.pop_back();
		temp.insert(temp.begin(), last_byte);
	}
	return round_keys;
}

std::vector<std::vector<uint8_t>> key_sched_inv(std::vector<uint8_t> key){
	std::vector<std::vector<uint8_t>> rounds=key_sched(key);
	std::reverse(rounds.begin(), rounds.end());
	return rounds;
}

std::vector<uint8_t> f_func(int round, std::vector<std::vector<uint8_t>> round_keys, std::vector<uint8_t> data){
	std::vector<uint8_t> res;
	//XOR with the key
	for(int i=0;i<8;i++)
		res.push_back(data[i]^round_keys[round][i+1]);
	//Swap nibbles
	for(int i=0;i<8;i++)
		if((round_keys[round][0]>>(7-i))&1)
			res[i]=(res[i]>>4)|((res[i]&0x0f)<<4);
	//S-boxes
	for(int i=0;i<8;i++)
		res[i]=(s0[res[i]>>4]<<4)|s1[res[i]&0x0f];
	return permutate_bits(res, 8, 8, array_0_based_to_1_based(perm, 64));
}

std::vector<uint8_t> lucifer_encrypt(std::vector<uint8_t> data, std::vector<uint8_t> key){
	return encrypt_feistel(data, key, key_sched,
				NULL, NULL, f_func, 16, 16);
}

std::vector<uint8_t> lucifer_decrypt(std::vector<uint8_t> data, std::vector<uint8_t> key){
	return encrypt_feistel(data, key, key_sched_inv,
				NULL, NULL, f_func, 16, 16);
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
        std::vector<uint8_t> key(16);
        std::vector<uint8_t> iv(16);
        for(int i=0;i<16;i++){
                int temp;
                fin>>std::hex>>temp;
                iv[i]=temp&0xff;
        }
	for(int i=0;i<16;i++){
                int temp;
                fin>>std::hex>>temp;
                key[i]=temp&0xff;
        }
        std::vector<uint8_t> data_raw;
        for(int i=0;i<num_blocks*16;i++){
                int temp;
                fin>>std::hex>>temp;
                data_raw.push_back(temp&0xff);
        }
        if(data_raw.size()%16!=0){
                std::cout<<"Message data length isn't a multiple of the block length\n";
                return 0;
        }
        for(int i=0;i<num_blocks;i++){
                blocks[i].resize(16);
                for(int j=0;j<16;j++)
                        blocks[i][j]=data_raw[16*i+j];
        }
	std::cout<<"Initiating Lucifer encryption...\n";
	for(int k=0;k<num_blocks;k++){
		for(int i=0;i<16;i++)
			std::cout<<std::hex<<std::setw(2)<<std::setfill('0')<<(int)blocks[k][i];
		std::cout<<"\n";
	}
	//encrypt!
	std::cout<<"ENCRYPT\n";
	std::vector<std::vector<uint8_t>> enc=cbc_encode(iv, blocks, lucifer_encrypt,
					key, num_blocks, 16);
	for(int k=0;k<num_blocks+1;k++){
                for(int i=0;i<16;i++)
                        std::cout<<std::hex<<std::setw(2)<<std::setfill('0')<<(int)enc[k][i];
                std::cout<<"\n";
        }
	//decrypt
	std::cout<<"DECRYPT\n";
	std::vector<std::vector<uint8_t>> dec=cbc_decode(enc, lucifer_decrypt,
					key, num_blocks+1, 16);
	for(int k=0;k<num_blocks;k++){
		for(int i=0;i<16;i++)
			std::cout<<std::hex<<std::setw(2)<<std::setfill('0')<<(int)dec[k][i];
		std::cout<<"\n";
	}
	return 0;
}


