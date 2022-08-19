#include "kernel.cuh"

__device__ static unsigned int cuda_keccakRate = 0;
__device__ static unsigned int cuda_keccakCapacity = 0;
__device__ static unsigned int cuda_keccakSuffix = 0;
__device__ static int cuda_end_offset = 0;

static unsigned int keccakRate = 0;
static unsigned int keccakCapacity = 0;
static unsigned int keccakSuffix = 0;
static int end_offset = 0;

__constant__ static const uint32_t cuda_keccakf_rndc[KECCAK_ROUND][2] =
{
	{0x00000001, 0x00000000}, {0x00008082, 0x00000000},
	{0x0000808a, 0x80000000}, {0x80008000, 0x80000000},
	{0x0000808b, 0x00000000}, {0x80000001, 0x00000000},
	{0x80008081, 0x80000000}, {0x00008009, 0x80000000},
	{0x0000008a, 0x00000000}, {0x00000088, 0x00000000},
	{0x80008009, 0x00000000}, {0x8000000a, 0x00000000},

	{0x8000808b, 0x00000000}, {0x0000008b, 0x80000000},
	{0x00008089, 0x80000000}, {0x00008003, 0x80000000},
	{0x00008002, 0x80000000}, {0x00000080, 0x80000000},
	{0x0000800a, 0x00000000}, {0x8000000a, 0x80000000},
	{0x80008081, 0x80000000}, {0x00008080, 0x80000000},
	{0x80000001, 0x00000000}, {0x80008008, 0x80000000}
};
__constant__ unsigned int cuda_keccakf_rotc[KECCAK_ROUND] =
{
	 1,  3,  6, 10, 15, 21, 28, 36, 45, 55,  2, 14,
	27, 41, 56,  8, 25, 43, 62, 18, 39, 61, 20, 44
};
__constant__ unsigned int cuda_keccakf_piln[KECCAK_ROUND] =
{
	10,  7, 11, 17, 18,  3,  5, 16,  8, 21, 24,  4,
	15, 23, 19, 13, 12,  2, 20, 14, 22,  9,  6,  1
};

static const uint32_t keccakf_rndc[KECCAK_ROUND][2] =
{
	{0x00000001, 0x00000000}, {0x00008082, 0x00000000},
	{0x0000808a, 0x80000000}, {0x80008000, 0x80000000},
	{0x0000808b, 0x00000000}, {0x80000001, 0x00000000},
	{0x80008081, 0x80000000}, {0x00008009, 0x80000000},
	{0x0000008a, 0x00000000}, {0x00000088, 0x00000000},
	{0x80008009, 0x00000000}, {0x8000000a, 0x00000000},

	{0x8000808b, 0x00000000}, {0x0000008b, 0x80000000},
	{0x00008089, 0x80000000}, {0x00008003, 0x80000000},
	{0x00008002, 0x80000000}, {0x00000080, 0x80000000},
	{0x0000800a, 0x00000000}, {0x8000000a, 0x80000000},
	{0x80008081, 0x80000000}, {0x00008080, 0x80000000},
	{0x80000001, 0x00000000}, {0x80008008, 0x80000000}
};
unsigned int keccakf_rotc[KECCAK_ROUND] =
{
	 1,  3,  6, 10, 15, 21, 28, 36, 45, 55,  2, 14,
	27, 41, 56,  8, 25, 43, 62, 18, 39, 61, 20, 44
};
unsigned int keccakf_piln[KECCAK_ROUND] =
{
	10,  7, 11, 17, 18,  3,  5, 16,  8, 21, 24,  4,
	15, 23, 19, 13, 12,  2, 20, 14, 22,  9,  6,  1
};


__device__ void cuda_ROL64(uint32_t* in, uint32_t* out, unsigned int offset)
{
	int shift = 0;

	if (offset == 0)
	{
		out[1] = in[1];
		out[0] = in[0];
	}
	else if (offset < 32)
	{
		shift = offset;

		out[1] = (uint32_t)((in[1] << shift) ^ (in[0] >> (32 - shift)));
		out[0] = (uint32_t)((in[0] << shift) ^ (in[1] >> (32 - shift)));
	}
	else if (offset < 64)
	{
		shift = offset - 32;

		out[1] = (uint32_t)((in[0] << shift) ^ (in[1] >> (32 - shift)));
		out[0] = (uint32_t)((in[1] << shift) ^ (in[0] >> (32 - shift)));
	}
	else
	{
		out[1] = in[1];
		out[0] = in[0];
	}
}
void ROL64(uint32_t* in, uint32_t* out, unsigned int offset)
{
	int shift = 0;

	if (offset == 0)
	{
		out[1] = in[1];
		out[0] = in[0];
	}
	else if (offset < 32)
	{
		shift = offset;

		out[1] = (uint32_t)((in[1] << shift) ^ (in[0] >> (32 - shift)));
		out[0] = (uint32_t)((in[0] << shift) ^ (in[1] >> (32 - shift)));
	}
	else if (offset < 64)
	{
		shift = offset - 32;

		out[1] = (uint32_t)((in[0] << shift) ^ (in[1] >> (32 - shift)));
		out[0] = (uint32_t)((in[1] << shift) ^ (in[0] >> (32 - shift)));
	}
	else
	{
		out[1] = in[1];
		out[0] = in[0];
	}
}

__device__ void cuda_keccakf(uint8_t* state)
{
	uint32_t t[2], bc[5][2], s[25][2] = { 0x00, };
	int i, j, round;

	for (i = 0; i < 25; i++)
	{
		s[i][0] = (uint32_t)(state[i * 8 + 0]) |
			(uint32_t)(state[i * 8 + 1] << 8) |
			(uint32_t)(state[i * 8 + 2] << 16) |
			(uint32_t)(state[i * 8 + 3] << 24);
		s[i][1] = (uint32_t)(state[i * 8 + 4]) |
			(uint32_t)(state[i * 8 + 5] << 8) |
			(uint32_t)(state[i * 8 + 6] << 16) |
			(uint32_t)(state[i * 8 + 7] << 24);
	}

	for (round = 0; round < KECCAK_ROUND; round++)
	{
		/* Theta */
		for (i = 0; i < 5; i++)
		{
			bc[i][0] = s[i][0] ^ s[i + 5][0] ^ s[i + 10][0] ^ s[i + 15][0] ^ s[i + 20][0];
			bc[i][1] = s[i][1] ^ s[i + 5][1] ^ s[i + 10][1] ^ s[i + 15][1] ^ s[i + 20][1];
		}

		for (i = 0; i < 5; i++)
		{
			cuda_ROL64(bc[(i + 1) % 5], t, 1);

			t[0] ^= bc[(i + 4) % 5][0];
			t[1] ^= bc[(i + 4) % 5][1];

			for (j = 0; j < 25; j += 5)
			{
				s[j + i][0] ^= t[0];
				s[j + i][1] ^= t[1];
			}
		}

		/* Rho & Pi */
		t[0] = s[1][0];
		t[1] = s[1][1];

		for (i = 0; i < KECCAK_ROUND; i++)
		{
			j = cuda_keccakf_piln[i];

			bc[0][0] = s[j][0];
			bc[0][1] = s[j][1];

			cuda_ROL64(t, s[j], cuda_keccakf_rotc[i]);

			t[0] = bc[0][0];
			t[1] = bc[0][1];
		}

		/* Chi */
		for (j = 0; j < 25; j += 5)
		{
			for (i = 0; i < 5; i++)
			{
				bc[i][0] = s[j + i][0];
				bc[i][1] = s[j + i][1];
			}

			for (i = 0; i < 5; i++)
			{
				s[j + i][0] ^= (~bc[(i + 1) % 5][0]) & bc[(i + 2) % 5][0];
				s[j + i][1] ^= (~bc[(i + 1) % 5][1]) & bc[(i + 2) % 5][1];
			}
		}

		/* Iota */
		s[0][0] ^= cuda_keccakf_rndc[round][0];
		s[0][1] ^= cuda_keccakf_rndc[round][1];
	}

	for (i = 0; i < 25; i++)
	{
		state[i * 8 + 0] = (uint8_t)(s[i][0]);
		state[i * 8 + 1] = (uint8_t)(s[i][0] >> 8);
		state[i * 8 + 2] = (uint8_t)(s[i][0] >> 16);
		state[i * 8 + 3] = (uint8_t)(s[i][0] >> 24);
		state[i * 8 + 4] = (uint8_t)(s[i][1]);
		state[i * 8 + 5] = (uint8_t)(s[i][1] >> 8);
		state[i * 8 + 6] = (uint8_t)(s[i][1] >> 16);
		state[i * 8 + 7] = (uint8_t)(s[i][1] >> 24);
	}
}
void keccakf(uint8_t* state)
{
	uint32_t t[2], bc[5][2], s[25][2] = { 0x00, };
	int i, j, round;
	for (i = 0; i < 25; i++)
	{
		s[i][0] = (uint32_t)(state[i * 8 + 0]) |
			(uint32_t)(state[i * 8 + 1] << 8) |
			(uint32_t)(state[i * 8 + 2] << 16) |
			(uint32_t)(state[i * 8 + 3] << 24);
		s[i][1] = (uint32_t)(state[i * 8 + 4]) |
			(uint32_t)(state[i * 8 + 5] << 8) |
			(uint32_t)(state[i * 8 + 6] << 16) |
			(uint32_t)(state[i * 8 + 7] << 24);
	}

	for (round = 0; round < KECCAK_ROUND; round++)
	{
		/* Theta */
		for (i = 0; i < 5; i++)
		{
			bc[i][0] = s[i][0] ^ s[i + 5][0] ^ s[i + 10][0] ^ s[i + 15][0] ^ s[i + 20][0];
			bc[i][1] = s[i][1] ^ s[i + 5][1] ^ s[i + 10][1] ^ s[i + 15][1] ^ s[i + 20][1];
		}

		for (i = 0; i < 5; i++)
		{
			ROL64(bc[(i + 1) % 5], t, 1);

			t[0] ^= bc[(i + 4) % 5][0];
			t[1] ^= bc[(i + 4) % 5][1];

			for (j = 0; j < 25; j += 5)
			{
				s[j + i][0] ^= t[0];
				s[j + i][1] ^= t[1];
			}
		}

		/* Rho & Pi */
		t[0] = s[1][0];
		t[1] = s[1][1];

		for (i = 0; i < KECCAK_ROUND; i++)
		{
			j = keccakf_piln[i];

			bc[0][0] = s[j][0];
			bc[0][1] = s[j][1];

			ROL64(t, s[j], keccakf_rotc[i]);

			t[0] = bc[0][0];
			t[1] = bc[0][1];
		}

		/* Chi */
		for (j = 0; j < 25; j += 5)
		{
			for (i = 0; i < 5; i++)
			{
				bc[i][0] = s[j + i][0];
				bc[i][1] = s[j + i][1];
			}

			for (i = 0; i < 5; i++)
			{
				s[j + i][0] ^= (~bc[(i + 1) % 5][0]) & bc[(i + 2) % 5][0];
				s[j + i][1] ^= (~bc[(i + 1) % 5][1]) & bc[(i + 2) % 5][1];
			}
		}

		/* Iota */
		s[0][0] ^= keccakf_rndc[round][0];
		s[0][1] ^= keccakf_rndc[round][1];
	}

	for (i = 0; i < 25; i++)
	{
		state[i * 8 + 0] = (uint8_t)(s[i][0]);
		state[i * 8 + 1] = (uint8_t)(s[i][0] >> 8);
		state[i * 8 + 2] = (uint8_t)(s[i][0] >> 16);
		state[i * 8 + 3] = (uint8_t)(s[i][0] >> 24);
		state[i * 8 + 4] = (uint8_t)(s[i][1]);
		state[i * 8 + 5] = (uint8_t)(s[i][1] >> 8);
		state[i * 8 + 6] = (uint8_t)(s[i][1] >> 16);
		state[i * 8 + 7] = (uint8_t)(s[i][1] >> 24);
	}
}

__device__ int cuda_keccak_absorb(uint8_t* input, int inLen, int rate, int capacity, uint8_t* keccak_state)
{
	uint8_t* buf = input;
	int iLen = inLen;
	int rateInBytes = rate / 8;
	int blockSize = 0;
	int i = 0;

	if ((rate + capacity) != KECCAK_SPONGE_BIT)
		return SHA3_PARAMETER_ERROR;

	if (((rate % 8) != 0) || (rate < 1))
		return SHA3_PARAMETER_ERROR;

	while (iLen > 0)
	{
		if ((cuda_end_offset != 0) && (cuda_end_offset < rateInBytes))
		{
			blockSize = (((iLen + cuda_end_offset) < rateInBytes) ? (iLen + cuda_end_offset) : rateInBytes);

			for (i = cuda_end_offset; i < blockSize; i++)
				keccak_state[i] ^= buf[i - cuda_end_offset];

			buf += blockSize - cuda_end_offset;
			iLen -= blockSize - cuda_end_offset;
		}
		else
		{
			blockSize = ((iLen < rateInBytes) ? iLen : rateInBytes);

			for (i = 0; i < blockSize; i++)
				keccak_state[i] ^= buf[i];

			buf += blockSize;
			iLen -= blockSize;
		}

		if (blockSize == rateInBytes)
		{
			cuda_keccakf(keccak_state);
			blockSize = 0;
		}

		cuda_end_offset = blockSize;
	}

	return SHA3_OK;
}
int keccak_absorb(uint8_t* input, int inLen, int rate, int capacity, uint8_t* keccak_state)
{
	uint8_t* buf = input;
	int iLen = inLen;
	int rateInBytes = rate / 8;
	int blockSize = 0;
	int i = 0;

	if ((rate + capacity) != KECCAK_SPONGE_BIT)
		return SHA3_PARAMETER_ERROR;

	if (((rate % 8) != 0) || (rate < 1))
		return SHA3_PARAMETER_ERROR;

	while (iLen > 0)
	{
		if ((end_offset != 0) && (end_offset < rateInBytes))
		{
			blockSize = (((iLen + end_offset) < rateInBytes) ? (iLen + end_offset) : rateInBytes);

			for (i = end_offset; i < blockSize; i++)
				keccak_state[i] ^= buf[i - end_offset];

			buf += blockSize - end_offset;
			iLen -= blockSize - end_offset;
		}
		else
		{
			blockSize = ((iLen < rateInBytes) ? iLen : rateInBytes);

			for (i = 0; i < blockSize; i++)
				keccak_state[i] ^= buf[i];

			buf += blockSize;
			iLen -= blockSize;
		}

		if (blockSize == rateInBytes)
		{
			keccakf(keccak_state);
			blockSize = 0;
		}

		end_offset = blockSize;
	}

	return SHA3_OK;
}

__device__ void __cuda_sha3_init(int bitSize, int useSHAKE, uint8_t* keccak_state)
{
	cuda_keccakCapacity = bitSize * 2;
	cuda_keccakRate = KECCAK_SPONGE_BIT - cuda_keccakCapacity;
	if (useSHAKE)
		cuda_keccakSuffix = KECCAK_SHAKE_SUFFIX;
	else
		cuda_keccakSuffix = KECCAK_SHA3_SUFFIX;
	memset(keccak_state, 0x00, KECCAK_STATE_SIZE);
	cuda_end_offset = 0;
}
void __sha3_init_endoffset16(int bitSize, int useSHAKE, uint8_t* keccak_state)
{
	keccakCapacity = bitSize * 2;
	keccakRate = KECCAK_SPONGE_BIT - keccakCapacity;
	if (useSHAKE)
		keccakSuffix = KECCAK_SHAKE_SUFFIX;
	else
		keccakSuffix = KECCAK_SHA3_SUFFIX;
	//memset(keccak_state, 0x00, KECCAK_STATE_SIZE);
	end_offset = 16;
}
void __sha3_init(int bitSize, int useSHAKE, uint8_t* keccak_state)
{
	keccakCapacity = bitSize * 2;
	keccakRate = KECCAK_SPONGE_BIT - keccakCapacity;
	if (useSHAKE)
		keccakSuffix = KECCAK_SHAKE_SUFFIX;
	else
		keccakSuffix = KECCAK_SHA3_SUFFIX;
	//memset(keccak_state, 0x00, KECCAK_STATE_SIZE);
	end_offset = 0;
}

__device__ void cuda_sha3_update(uint8_t* input, int inLen, uint8_t* keccak_state)
{
	cuda_keccak_absorb(input, inLen, cuda_keccakRate, cuda_keccakCapacity, keccak_state);
}
void sha3_update(uint8_t* input, int inLen, uint8_t* keccak_state)
{
	keccak_absorb(input, inLen, keccakRate, keccakCapacity, keccak_state);
}

__device__ void cuda_sha3_hash(uint8_t* input, int inLen, int bitSize, uint8_t* keccak_state)
{
	cuda_sha3_update(input, inLen, keccak_state);
}
void sha3_hash(uint8_t* input, int inLen, int bitSize, uint8_t* keccak_state)
{
	sha3_update(input, inLen, keccak_state);
}

__device__ void cuda_sha3_init(int bitSize, uint8_t* keccak_state)
{
	__cuda_sha3_init(bitSize, SHA3_SHAKE_NONE, keccak_state);
}
void sha3_init_endoffset16(int bitSize, uint8_t* keccak_state)
{
	__sha3_init_endoffset16(bitSize, SHA3_SHAKE_NONE, keccak_state);
}
void sha3_init(int bitSize, uint8_t* keccak_state)
{
	__sha3_init(bitSize, SHA3_SHAKE_NONE, keccak_state);
}
//ㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡ
// 
//CUDA verify section
__device__ void cuda_verify_sha3_init(int bitSize, uint8_t* keccak_state) {
	cuda_keccakCapacity = bitSize * 2;
	cuda_keccakRate = KECCAK_SPONGE_BIT - cuda_keccakCapacity;
	if (SHA3_SHAKE_NONE)
		cuda_keccakSuffix = KECCAK_SHAKE_SUFFIX;
	else
		cuda_keccakSuffix = KECCAK_SHA3_SUFFIX;
	cuda_end_offset = 0;
}
__device__ int cuda_verify_sha3_update(uint8_t* input, int inLen, uint8_t* keccak_state) {
	uint8_t* buf = input;
	int iLen = inLen;
	int rateInBytes = cuda_keccakRate / 8;
	int blockSize = 0;
	int i = 0;

	if ((cuda_keccakRate + cuda_keccakCapacity) != KECCAK_SPONGE_BIT)
		return SHA3_PARAMETER_ERROR;

	if (((cuda_keccakRate % 8) != 0) || (cuda_keccakRate < 1))
		return SHA3_PARAMETER_ERROR;

	while (iLen > 0)
	{
		if ((cuda_end_offset != 0) && (cuda_end_offset < rateInBytes))
		{
			blockSize = (((iLen + cuda_end_offset) < rateInBytes) ? (iLen + cuda_end_offset) : rateInBytes);

			for (i = cuda_end_offset; i < blockSize; i++)
				keccak_state[i] ^= buf[i - cuda_end_offset];

			buf += blockSize - cuda_end_offset;
			iLen -= blockSize - cuda_end_offset;
		}
		else
		{
			blockSize = ((iLen < rateInBytes) ? iLen : rateInBytes);

			for (i = 0; i < blockSize; i++)
				keccak_state[i] ^= buf[i];

			buf += blockSize;
			iLen -= blockSize;
		}

		if (blockSize == rateInBytes)
		{
			cuda_keccakf(keccak_state);
			blockSize = 0;
		}

		cuda_end_offset = blockSize;
	}

	return SHA3_OK;
}

__device__ int cuda_verify_sha3_final(uint8_t* output, int outLen, int rate, int suffix, uint8_t* keccak_state)
{
	uint8_t* buf = output;
	int oLen = outLen;
	int rateInBytes = rate / 8;
	int blockSize = cuda_end_offset;
	int i = 0;

	keccak_state[blockSize] ^= suffix;

	if (((suffix & 0x80) != 0) && (blockSize == (rateInBytes - 1)))
		cuda_keccakf(keccak_state);

	keccak_state[rateInBytes - 1] ^= 0x80;

	cuda_keccakf(keccak_state);

	while (oLen > 0)
	{
		blockSize = ((oLen < rateInBytes) ? oLen : rateInBytes);
		for (i = 0; i < blockSize; i++)
			buf[i] = keccak_state[i];
		buf += blockSize;
		oLen -= blockSize;

		if (oLen > 0)
			cuda_keccakf(keccak_state);
	}

	return SHA3_OK;
}

//ㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡㅡ
__global__ void cuda_sha3(uint8_t* data, uint8_t* dev_keccak_state)
{
	uint8_t in[1024 * 8] = { 0, }; //124
	int in_length = 1024 * 8;	//byte size
	int hash_bit = 256;		//bit(224,256,384,512)
	int index = 0;	// 각 thread index
	uint8_t keccak_state[KECCAK_STATE_SIZE] = { 0x00, };

	cuda_sha3_init(hash_bit, keccak_state);

	for (int i = 0; i < 1024 / 8; i++) {
		index = (1024 * 1024 * blockIdx.x * blockDim.x + 1024 * 1024 * threadIdx.x) + (i * 1024 * 8);
		for (int j = 0; j < 1024 * 8; j++) 
			in[j] = data[index++];	
		cuda_sha3_hash(in, in_length, hash_bit, keccak_state);
	}
	index = KECCAK_STATE_SIZE * blockIdx.x * blockDim.x + (KECCAK_STATE_SIZE * threadIdx.x);

	for (int i = 0; i < KECCAK_STATE_SIZE; i++) 
		dev_keccak_state[index++] = keccak_state[i];
	/*if (threadIdx.x == 0) {
		printf("threadIdx = 0\n");
		for (int i = 0; i < KECCAK_STATE_SIZE; i++) {
			printf("%02X ", keccak_state[i]);
			if ((i + 1) % 32 == 0)
				printf("\n");
		}
		printf("\n");
	}
	__syncthreads();
	if (threadIdx.x == 1) {
		printf("threadIdx.x = 1\n");
		for (int i = 0; i < KECCAK_STATE_SIZE; i++) {
			printf("%02X ", keccak_state[i]);
			if ((i + 1) % 32 == 0)
				printf("\n");
		}
		printf("\n");
	}
	__syncthreads();
	if (threadIdx.x == 2) {
		printf("threadIdx.x = 2\n");
		for (int i = 0; i < KECCAK_STATE_SIZE; i++) {
			printf("%02X ", keccak_state[i]);
			if ((i + 1) % 32 == 0)
				printf("\n");
		}
		printf("\n");
	}
	__syncthreads();
	if (threadIdx.x == 3) {
		printf("threadIdx.x = 3\n");
		for (int i = 0; i < KECCAK_STATE_SIZE; i++) {
			printf("%02X ", keccak_state[i]);
			if ((i + 1) % 32 == 0)
				printf("\n");
		}
		printf("\n");
	}
	__syncthreads();
	if (threadIdx.x == 4) {
		printf("threadIdx.x = 4\n");
		for (int i = 0; i < KECCAK_STATE_SIZE; i++) {
			printf("%02X ", keccak_state[i]);
			if ((i + 1) % 32 == 0)
				printf("\n");
		}
		printf("\n");
	}
	__syncthreads();*/

}

int keccak_squeeze(uint8_t* output, int outLen, int rate, int suffix, uint8_t* keccak_state)
{
	uint8_t* buf = output;
	int oLen = outLen;
	int rateInBytes = rate / 8;
	int blockSize = end_offset;
	int i = 0;

	keccak_state[blockSize] ^= suffix;

	if (((suffix & 0x80) != 0) && (blockSize == (rateInBytes - 1)))
		keccakf(keccak_state);

	keccak_state[rateInBytes - 1] ^= 0x80;

	keccakf(keccak_state);

	while (oLen > 0)
	{
		blockSize = ((oLen < rateInBytes) ? oLen : rateInBytes);
		for (i = 0; i < blockSize; i++)
			buf[i] = keccak_state[i];
		buf += blockSize;
		oLen -= blockSize;

		if (oLen > 0)
			keccakf(keccak_state);
	}

	return SHA3_OK;
}

void sha3_final(uint8_t* output, uint8_t* keccak_state)
{

	keccak_squeeze(output, 32, keccakRate, keccakSuffix, keccak_state);
	keccakRate = 0;
	keccakCapacity = 0;
	keccakSuffix = 0;
}


void sha3_endoffset16(uint8_t* data, int datalen, uint8_t* out, uint8_t* keccak_state) {
	uint8_t in[1024] = { 0, };
	int in_length = 1024 * 8;	//byte size
	int hash_bit = 256;		//bit(224,256,384,512)
	int index = 0;	// 각 thread index

	sha3_init_endoffset16(hash_bit, keccak_state);
	sha3_update(data, datalen, keccak_state);
}
void sha3(uint8_t* data, int datalen, uint8_t* out, uint8_t* keccak_state) {
	uint8_t in[1024] = { 0, };
	int in_length = 1024 * 8;	//byte size
	int hash_bit = 256;		//bit(224,256,384,512)
	int index = 0;	// 각 thread index

	sha3_init(hash_bit, keccak_state);
	sha3_update(data, datalen, keccak_state);
	//sha3_final(out, keccak_state);
}
void sha3_cpu_to_gpu(uint8_t * data, uint8_t * keccak_state, int message_num){
	uint8_t* dev_data = NULL;
	uint8_t* dev_keccak_state = NULL;
	cudaError_t cudaStatus;

	cudaStatus = cudaMalloc((void**)&dev_data, 1024 * 1024 * message_num * sizeof(uint8_t));
	cudaStatus = cudaMalloc((void**)&dev_keccak_state, KECCAK_STATE_SIZE * message_num * sizeof(uint8_t));

	cudaStatus = cudaMemcpy(dev_data, data, 1024 * 1024 * message_num * sizeof(uint8_t), cudaMemcpyHostToDevice);
	if (cudaStatus != cudaSuccess) {
		printf("dev_data Error\n");
		return;
	}
	cudaStatus = cudaMemcpy(dev_keccak_state, keccak_state, KECCAK_STATE_SIZE * message_num * sizeof(uint8_t), cudaMemcpyHostToDevice);
	if (cudaStatus != cudaSuccess) {
		printf("dev_keccak_state Error\n");
		return;
	}
	if (message_num == MESSAGE_NUM) {
		cuda_sha3 << < GPB, BPT >> > (dev_data, dev_keccak_state);
	}
	else {
		int gpb = message_num / 192;
		int bpt = message_num % 192;
		if (gpb) {
			cuda_sha3 << < gpb, BPT >> > (dev_data, dev_keccak_state);
		}
		if (bpt) {
			cuda_sha3 << < 1, bpt >> > (dev_data + gpb * BPT * 1024 * 1024, dev_keccak_state + gpb * BPT * KECCAK_STATE_SIZE);
		}
	}
	cudaStatus = cudaGetLastError();
	cudaStatus = cudaDeviceSynchronize();
	cudaStatus = cudaMemcpy(keccak_state, dev_keccak_state, KECCAK_STATE_SIZE * message_num * sizeof(uint8_t), cudaMemcpyDeviceToHost);

	cudaFree(dev_data);
	cudaFree(dev_keccak_state);
}

//! 
__global__ void verify_gen_hash(uint8_t* TX, uint8_t* bid, uint8_t* prehash, uint8_t* dev_hash)
{
	uint8_t in[(1024 * 8)] = { 0, }; //124
	int in_length = 1024 * 8;	//byte size
	int hash_bit = 256;		//bit(224,256,384,512)
	int index = 0;	// 각 thread index
	uint8_t keccak_state[KECCAK_STATE_SIZE] = { 0x00, };
	
	cuda_verify_sha3_init(hash_bit, keccak_state);
	for (int i = 0; i < 1024 / 8; i++) {
		index = (1024 * 1024 * blockIdx.x * blockDim.x + 1024 * 1024 * threadIdx.x) + (i * 1024 * 8);
		for (int j = 0; j < 1024 * 8; j++)
			in[j] = TX[index++];
		cuda_verify_sha3_update(in, in_length, keccak_state);
	}
	//! 마지막 40-byte 처리
	index = (20 * blockIdx.x * blockDim.x + 20 * threadIdx.x);
	for (int j = 0; j < 20; j++) {
		in[j] = bid[index + j];
		in[j + 20] = prehash[index + j];
	}
	cuda_verify_sha3_update(in, 40, keccak_state);
	index = (32 * blockIdx.x * blockDim.x + 32 * threadIdx.x);
	cuda_verify_sha3_final(dev_hash + index, 32, cuda_keccakRate, cuda_keccakSuffix, keccak_state);
}

void sha3_verify_cpu_to_gpu(uint8_t* TX, uint8_t* bid, uint8_t* prehash, uint8_t* out, int message_num) {
	uint8_t* dev_TX = NULL;
	uint8_t* dev_bid = NULL;
	uint8_t* dev_prehash = NULL;
	uint8_t* dev_out = NULL;
	cudaError_t cudaStatus;

	cudaStatus = cudaMalloc((void**)&dev_TX, 1024 * 1024 * message_num * sizeof(uint8_t));
	cudaStatus = cudaMalloc((void**)&dev_bid, 20 * message_num * sizeof(uint8_t));
	cudaStatus = cudaMalloc((void**)&dev_prehash, 20 * message_num * sizeof(uint8_t));
	cudaStatus = cudaMalloc((void**)&dev_out, 32 * message_num * sizeof(uint8_t));


	cudaStatus = cudaMemcpy(dev_TX, TX, 1024 * 1024 * message_num * sizeof(uint8_t), cudaMemcpyHostToDevice);
	if (cudaStatus != cudaSuccess) {
		printf("dev_data Error\n");
		return;
	}
	cudaStatus = cudaMemcpy(dev_bid, bid, 20 * message_num * sizeof(uint8_t), cudaMemcpyHostToDevice);
	if (cudaStatus != cudaSuccess) {
		printf("dev_bid Error\n");
		return;
	}
	cudaStatus = cudaMemcpy(dev_prehash, prehash, 20 * message_num * sizeof(uint8_t), cudaMemcpyHostToDevice);
	if (cudaStatus != cudaSuccess) {
		printf("dev_prehash Error\n");
		return;
	}

	if (message_num == MESSAGE_NUM) {
		verify_gen_hash << <GPB, BPT >> > (dev_TX, dev_bid, dev_prehash, dev_out);
		//cuda_sha3 << < GPB, BPT >> > (dev_data, dev_keccak_state);
	}
	else {
		int gpb = message_num / 192;
		int bpt = message_num % 192;
		if (gpb) {
			verify_gen_hash << < gpb, BPT >> > (dev_TX, dev_bid, dev_prehash, dev_out);
		}
		if (bpt) {
			//verify_gen_hash << < 1, bpt >> > (dev_data + gpb * BPT * 1024 * 1024, dev_keccak_state + gpb * BPT * KECCAK_STATE_SIZE);
			verify_gen_hash << < 1, bpt >> > (dev_TX + gpb * BPT * 1024 * 1024, dev_bid + gpb * BPT * 20, dev_prehash + gpb * BPT * 20, dev_out + gpb * BPT * 32);
		}
	}
	cudaStatus = cudaGetLastError();
	cudaStatus = cudaDeviceSynchronize();
	cudaStatus = cudaMemcpy(out, dev_out, 32 * message_num * sizeof(uint8_t), cudaMemcpyDeviceToHost);

	cudaFree(dev_TX);
	cudaFree(dev_bid);
	cudaFree(dev_prehash);
	cudaFree(dev_out);
}