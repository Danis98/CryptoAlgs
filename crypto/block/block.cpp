#include <block/block.h>

std::vector<uint8_t> encrypt_block(
                std::vector<uint8_t> block,
                std::vector<uint8_t> key,
                std::vector<std::vector<uint8_t>> (*key_sched)(std::vector<uint8_t>), //key
                std::vector<uint8_t> (*init_func)(std::vector<std::vector<uint8_t>>, std::vector<uint8_t>), //keys, clear
                std::vector<uint8_t> (*end_func)(std::vector<std::vector<uint8_t>>, std::vector<uint8_t>), //keys, preout
                std::vector<uint8_t> (*round_func)(int, std::vector<std::vector<uint8_t>>, std::vector<uint8_t>), //round, keys, data
                int num_rounds,
                int block_size){
	//Generate round keys
	std::vector<std::vector<uint8_t>> round_keys=key_sched(key);

	std::vector<uint8_t> temp_round(block_size);
	//Perform precomputations, if defined
	if(init_func!=NULL)
		temp_round=init_func(round_keys, block);
	//Perform rounds
	for(int i=0;i<num_rounds;i++)
		temp_round=round_func(i, round_keys, temp_round);
	//Perform final operations, if defined
	if(end_func!=NULL)
		temp_round=end_func(round_keys, temp_round);
	return temp_round;
}
