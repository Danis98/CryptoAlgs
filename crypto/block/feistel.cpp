#include <block/feistel.h>
#include <iostream>

std::vector<uint8_t> encrypt_feistel(
                std::vector<uint8_t> block,
                std::vector<uint8_t> key,
                std::vector<std::vector<uint8_t>> (*key_sched)(std::vector<uint8_t>), //key
                std::vector<uint8_t> (*init_func)(std::vector<std::vector<uint8_t>>, std::vector<uint8_t>), //keys, clear
                std::vector<uint8_t> (*end_func)(std::vector<std::vector<uint8_t>>, std::vector<uint8_t>), //keys, preout
                std::vector<uint8_t> (*round_func)(int, std::vector<std::vector<uint8_t>>, std::vector<uint8_t>), //round, keys$
                int num_rounds,
                int block_size){
	 //Generate round keys
        std::vector<std::vector<uint8_t>> round_keys=key_sched(key);

        std::vector<uint8_t> enc_block(block_size);
        //Perform precomputations, if defined
	for(int i=0;i<block_size;i++)
		enc_block[i]=block[i];
	if(init_func!=NULL)
               enc_block=init_func(round_keys, block);
        std::vector<uint8_t> l(block_size/2);
        std::vector<uint8_t> r(block_size/2);
        for(int i=0;i<block_size;i++){
                if(i<block_size/2)
                        l[i]=enc_block[i];
                else
                        r[i-block_size/2]=enc_block[i];
        }
        //Perform rounds
	std::vector<uint8_t> temp(block_size/2);
        for(int i=0;i<num_rounds;i++){
                temp=round_func(i, round_keys, r);
		for(int j=0;j<block_size/2;j++){
			temp[j]^=l[j];
			l[j]=r[j];
			r[j]=temp[j];
		}
	}
	//Concatenate halfs, undo last swap
	for(int i=0;i<block_size;i++){
		if(i<block_size/2)
			enc_block[i]=r[i];
		else
			enc_block[i]=l[i-block_size/2];
	}
        //Perform final operations, if defined
        if(end_func!=NULL)
                enc_block=end_func(round_keys, enc_block);
        return enc_block;
}

