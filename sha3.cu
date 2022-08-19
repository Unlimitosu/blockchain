#include "kernel.cuh"

#ifdef __cplusplus
extern "C"{
#endif

#define TXSIZE 1024*1024
#define BLOCKSIZE TXSIZE + 40
#define DIGESTSIZE 256 / 8

extern int end_offset;

typedef struct {
	uint8_t blocknum[20];
	uint8_t prevhashval[20];
	uint8_t transaction[TXSIZE];
}Block;

//! Big number addition
void addone_bignum(uint8_t* arr, size_t size) {
	for (size_t i = 0; i < size; i++) {
		if (arr[i] == 0xff) 
			arr[i] = 0;
		else {
			arr[i] += 1;
			break;
		}
	}
}

//! Print entire chain
void print_chain(Block* chain, size_t n) {
	for (int i = 0; i < n; i++) {
		printf("BlockID: ");
		for (int j = 0; j < 20; j++) {
			printf("%02x ", chain[i].blocknum[j]);
		}printf("\n");

		printf("PrevHashval: ");
		for (int j = 0; j < 20; j++) {
			printf("%02x ", chain[i].prevhashval[j]);
		}printf("\n");

		printf("Transaction:\n");
		for (int j = 0; j < 8; j++) {
			for (int k = 0; k < 128; k++) {
				//printf("%02x ", chain[i].transaction[128 * j + k]);
				//if (k==63) printf("\n");
			}
			//printf("\n");
		}printf("\n");
	}printf("\n");
}

//! print a keccack state
void print_keccackstate(uint8_t* state) {
	for (int i = 0; i < 200; i++) {
		printf("%02x ", state[i]);
		if ((i + 1)% 31 == 0) printf("\n");
	}printf("\n\n");
}

//! Create n block chains
Block* create_chain(size_t n) {
	Block* chain = (Block*)calloc(n, sizeof(Block));
	assert(chain != NULL);

	for (size_t i = 1; i < n; i++) {
		for (int j = 0; j < 20; j++) 
			chain[i].blocknum[j] = chain[i - 1].blocknum[j];
		addone_bignum(chain[i].blocknum, 20);
	}
	for (int i = 0; i < n; i++) 
		for (int j = 0; j < TXSIZE; j++) 
			chain[i].transaction[j] = rand() & 0xff;

	return chain;
}

//! Copy transaction data to txarr
void tx_info(Block* chain, size_t n, uint8_t* txarr) {
	for (int i = 0; i < n; i++) 
		for (int j = 0; j < TXSIZE; j++) 
			txarr[i * TXSIZE + j] = chain[i].transaction[j];
}

//! Copy blockID data to blockid
void blocknum_info(Block* chain, size_t n, uint8_t* blockid) {
	for (int i = 0; i < n; i++) 
		for (int j = 0; j < 20; j++) 
			blockid[i * 20 + j] = chain[i].blocknum[j];
}

//! Copy previous hash value to prehash
void prehash_info(Block* chain, size_t n, uint8_t* prehash) {
	for (int i = 0; i < n; i++) 
		for (int j = 0; j < 20; j++) 
			prehash[i * 20 + j] = chain[i].prevhashval[j];
}

//! Calculate hash value using GPU
void sha3_hash_cuda(Block* chain, size_t n, uint8_t* keccack_state) {
	uint8_t* txarr  = (uint8_t*)calloc(n * TXSIZE, sizeof(uint8_t));
	uint8_t* remain = (uint8_t*)calloc(40, sizeof(uint8_t));
	uint8_t tmp[32] = { 0, };

	assert(txarr != NULL);
	assert(remain != NULL);

	tx_info(chain, n, txarr);

	//! hash transaction data
	sha3_cpu_to_gpu(txarr, keccack_state, n);
	
	//! hash remaining data(blockID, prehash)
	for (int i = 0; i < n; i++) {
		//! copy the remaining data to remain
		memcpy(remain, chain[i].blocknum, 20);
		memcpy(remain + 20, chain[i].prevhashval, 20);

		//! use sha3 with end_offset = 16
		//! because there are already XOR-ed the 16-bytes of lsb of the transaction
		sha3_endoffset16(remain, 40, tmp, keccack_state + (200 * i));

		//! squeeze the final hash value
		memset(tmp, 0x00, 32);
		sha3_final(tmp, keccack_state + 200 * i);
		
		//! copy the last 160-bits of the hash value into the prevhashval
		memcpy(chain[i + 1].prevhashval, tmp + 12, 20);
	}
	free(txarr);
	free(remain);
}

//! hash test function
void hashtest() {
	int n = 10;

	uint8_t* blockinfo = (uint8_t*)calloc(BLOCKSIZE, sizeof(uint8_t));
	uint8_t hashval[DIGESTSIZE] = { 0, };

	uint8_t* keccack_state  = (uint8_t*)calloc(200 * n, sizeof(uint8_t));
	uint8_t* keccack_state2 = (uint8_t*)calloc(200, sizeof(uint8_t));
	assert(keccack_state != NULL);
	assert(keccack_state2 != NULL);

	Block* chain = create_chain(n);
	Block* chain2 = (Block*)calloc(n, sizeof(Block));
	assert(chain2 != NULL);

	memcpy(chain2, chain, sizeof(Block) * n);

	sha3_hash_cuda(chain, n, keccack_state);

	for (int blockid = 0; blockid < n - 1; blockid++) {
		memset(keccack_state2, 0x00, 200);

		for (int i = 0; i < TXSIZE; i++)
			blockinfo[i] = chain[blockid].transaction[i];
		for (int i = 0; i < 20; i++)
			blockinfo[i + TXSIZE] = chain[blockid].blocknum[i];
		for (int i = 0; i < 20; i++)
			blockinfo[i + TXSIZE + 20] = chain[blockid].prevhashval[i];

		sha3(blockinfo, TXSIZE, hashval, keccack_state2);
		sha3_update(blockinfo + TXSIZE, 40, keccack_state2);
		sha3_final(hashval, keccack_state2);

		memcpy(chain2[blockid + 1].prevhashval, hashval + 12, 20);
	}

	free(blockinfo);
	free(keccack_state);
	free(keccack_state2);
	free(chain);
	free(chain2);
}

//! verify the trasaction values linearly
//! use CUDA C for the performance
void verify_transaction(Block* chain, size_t n) {
	uint8_t* txarr   = (uint8_t*)calloc(n * TXSIZE, sizeof(uint8_t));
	uint8_t* bid	 = (uint8_t*)calloc(20 * n, sizeof(uint8_t));
	uint8_t* prehash = (uint8_t*)calloc(20 * n, sizeof(uint8_t));
	uint8_t* out	 = (uint8_t*)calloc(32 * n, sizeof(uint8_t));

	//! copy the data in the chain
	tx_info(chain, n, txarr);
	prehash_info(chain, n, prehash);
	blocknum_info(chain, n, bid);

	//! run CUDA C code to get hash values
	sha3_verify_cpu_to_gpu(txarr, bid, prehash, out, n);

	//! verify the hash values
	//! print ERROR if the hash value is not the same
	for (int i = 1; i < n; i++) {
		if (memcmp(chain[i].prevhashval, out + (32 * (i - 1) + 12), 20) != 0) {
			printf("%d-th chain TX ERROR\n", i - 1);
			for (int j = 0; j < 20; j++)
				printf("%02X ", chain[i].prevhashval[j]);
			printf("\n");

			for (int j = 0; j < 20; j++)
				printf("%02X ", *(out + (32 * (i - 1) + 12 + j)));
			printf("\n");

			goto END;
		}
	}
	printf("ALL BLOCK SUCCESS\n");

END:
	free(txarr);
	free(bid);
	free(prehash);
	free(out);
}

//! test function
void test() {
	int n = 10;

	uint8_t* keccack_state = (uint8_t*)calloc(200 * n, sizeof(uint8_t));
	assert(keccack_state != NULL);

	Block* chain = create_chain(n);

	sha3_hash_cuda(chain, n, keccack_state);

	verify_transaction(chain, n);

	//! modify the random index of block and transaction then verify
	int blockidx, txidx;
	blockidx = rand() % n;
	txidx = rand() % TXSIZE;

	printf("modifed block index: %d\n", blockidx);
	printf("modifed transaction index: %d\n\n", txidx);

	chain[blockidx].transaction[txidx]++;

	verify_transaction(chain, n);

	free(keccack_state);
	free(chain);
}

int main() {
	srand(time(NULL));
	test();
	return 0;
}

#ifdef __cplusplus
}
#endif