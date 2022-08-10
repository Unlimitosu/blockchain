#ifndef _SHA3_H_
#define _SHA3_H_
#endif 

#ifndef SHALIB_H
#define SHALIB_H

#include <windows.h>

#ifdef DLL_EXPORTS
#define DLL_API __declspec(dllexport)
#else
#define DLL_API __declspec(dllimport)
#endif

#undef __WRAP_CXX_INI
#undef __WRAP_CXX_FIN
#ifdef __cplusplus
#define __WRAP_CXX_INI extern "C" {
#define __WRAP_CXX_FIN }
#else
#define __WRAP_CXX_INI /* empty */
#define __WRAP_CXX_FIN /* empty */
#endif

__WRAP_CXX_INI

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#endif



	__declspec(dllexport) int sha3_hash(uint8_t* output, int outLen, uint8_t* input, int inLen, int bitSize, int useSHAKE);
	__declspec(dllexport) void sha3_init(int bitSize, int useSHAKE);
	__declspec(dllexport) int sha3_update(uint8_t* input, int inLen);
	__declspec(dllexport) int sha3_final(uint8_t* output, int outLen);


__WRAP_CXX_FIN
