#include <modes/cbc.h>

std::vector<std::vector<uint8_t>> cbc_encode(std::vector<uint8_t> iv, std::vector<std::vector<uint8_t>> blocks,
                        std::vector<uint8_t> (*cypher)(std::vector<uint8_t>, std::vector<uint8_t>), std::vector<uint8_t> key,
			int num_blocks, int block_size){
	std::vector<std::vector<uint8_t>> enc(num_blocks+1);
	for(int i=0;i<num_blocks+1;i++){
		enc[i].resize(block_size);
		if(i==0)
			for(int j=0;j<block_size;j++)
				enc[0][j]=iv[j];
		else{
			for(int j=0;j<block_size;j++)
				enc[i][j]=blocks[i-1][j]^enc[i-1][j];
			enc[i]=cypher(enc[i], key);
		}
	}

	return enc;
}

//First cyphertext block is IV
std::vector<std::vector<uint8_t>> cbc_decode(std::vector<std::vector<uint8_t>> blocks,
                        std::vector<uint8_t> (*cypher)(std::vector<uint8_t>, std::vector<uint8_t>), std::vector<uint8_t> key,
			int num_blocks, int block_size){
	std::vector<std::vector<uint8_t>> dec(num_blocks-1);
	for(int i=1;i<num_blocks;i++){
		dec[i-1].resize(block_size);
		dec[i-1]=cypher(blocks[i], key);
		for(int j=0;j<block_size;j++)
			dec[i-1][j]^=blocks[i-1][j];
	}
	return dec;
}

