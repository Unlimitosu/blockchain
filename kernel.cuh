#include "cuda_runtime.h"
#include "device_launch_parameters.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdint.h>
#include <malloc.h>
#include <assert.h>

#define MESSAGE_NUM			8*192
#define GPB						8
#define BPT						192

#define KECCAK_SPONGE_BIT		1600
#define KECCAK_ROUND			24
#define KECCAK_STATE_SIZE		200

#define KECCAK_SHA3_224			224
#define KECCAK_SHA3_256			256
#define KECCAK_SHA3_384			384
#define KECCAK_SHA3_512			512
#define KECCAK_SHAKE128			128
#define KECCAK_SHAKE256			256

#define KECCAK_SHA3_SUFFIX		0x06
#define KECCAK_SHAKE_SUFFIX		0x1F

typedef enum
{
	SHA3_OK = 0,
	SHA3_PARAMETER_ERROR = 1,
} SHA3_RETRUN;

typedef enum
{
	SHA3_SHAKE_NONE = 0,
	SHA3_SHAKE_USE = 1,
} SHA3_USE_SHAKE;


void sha3_cpu_to_gpu(uint8_t* data,uint8_t* keccak_state,int message_num);
void sha3_update(uint8_t* input, int inLen, uint8_t* keccak_state);
void sha3(uint8_t* data, int datalen, uint8_t* out, uint8_t* keccak_state); 
void sha3_endoffset16(uint8_t* data, int datalen, uint8_t* out, uint8_t* keccak_state);
void sha3_final(uint8_t* output, uint8_t* keccak_state);

void sha3_verify_cpu_to_gpu(uint8_t* TX, uint8_t* bid, uint8_t* prehash, uint8_t* out, int message_num);