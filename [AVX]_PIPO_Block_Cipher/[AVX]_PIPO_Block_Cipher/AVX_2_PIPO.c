#include <immintrin.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "type.h"
#include <Windows.h>

//Table Look Up Method
uint8_t Sbox[256] = {
	0x5E, 0xF9, 0xFC, 0x00, 0x3F, 0x85, 0xBA, 0x5B, 0x18, 0x37, 0xB2, 0xC6, 0x71, 0xC3, 0x74, 0x9D,
	0xA7, 0x94, 0x0D, 0xE1, 0xCA, 0x68, 0x53, 0x2E, 0x49, 0x62, 0xEB, 0x97, 0xA4, 0x0E, 0x2D, 0xD0,
	0x16, 0x25, 0xAC, 0x48, 0x63, 0xD1, 0xEA, 0x8F, 0xF7, 0x40, 0x45, 0xB1, 0x9E, 0x34, 0x1B, 0xF2,
	0xB9, 0x86, 0x03, 0x7F, 0xD8, 0x7A, 0xDD, 0x3C, 0xE0, 0xCB, 0x52, 0x26, 0x15, 0xAF, 0x8C, 0x69,
	0xC2, 0x75, 0x70, 0x1C, 0x33, 0x99, 0xB6, 0xC7, 0x04, 0x3B, 0xBE, 0x5A, 0xFD, 0x5F, 0xF8, 0x81,
	0x93, 0xA0, 0x29, 0x4D, 0x66, 0xD4, 0xEF, 0x0A, 0xE5, 0xCE, 0x57, 0xA3, 0x90, 0x2A, 0x09, 0x6C,
	0x22, 0x11, 0x88, 0xE4, 0xCF, 0x6D, 0x56, 0xAB, 0x7B, 0xDC, 0xD9, 0xBD, 0x82, 0x38, 0x07, 0x7E,
	0xB5, 0x9A, 0x1F, 0xF3, 0x44, 0xF6, 0x41, 0x30, 0x4C, 0x67, 0xEE, 0x12, 0x21, 0x8B, 0xA8, 0xD5,
	0x55, 0x6E, 0xE7, 0x0B, 0x28, 0x92, 0xA1, 0xCC, 0x2B, 0x08, 0x91, 0xED, 0xD6, 0x64, 0x4F, 0xA2,
	0xBC, 0x83, 0x06, 0xFA, 0x5D, 0xFF, 0x58, 0x39, 0x72, 0xC5, 0xC0, 0xB4, 0x9B, 0x31, 0x1E, 0x77,
	0x01, 0x3E, 0xBB, 0xDF, 0x78, 0xDA, 0x7D, 0x84, 0x50, 0x6B, 0xE2, 0x8E, 0xAD, 0x17, 0x24, 0xC9,
	0xAE, 0x8D, 0x14, 0xE8, 0xD3, 0x61, 0x4A, 0x27, 0x47, 0xF0, 0xF5, 0x19, 0x36, 0x9C, 0xB3, 0x42,
	0x1D, 0x32, 0xB7, 0x43, 0xF4, 0x46, 0xF1, 0x98, 0xEC, 0xD7, 0x4E, 0xAA, 0x89, 0x23, 0x10, 0x65,
	0x8A, 0xA9, 0x20, 0x54, 0x6F, 0xCD, 0xE6, 0x13, 0xDB, 0x7C, 0x79, 0x05, 0x3A, 0x80, 0xBF, 0xDE,
	0xE9, 0xD2, 0x4B, 0x2F, 0x0C, 0xA6, 0x95, 0x60, 0x0F, 0x2C, 0xA5, 0x51, 0x6A, 0xC8, 0xE3, 0x96,
	0xB0, 0x9F, 0x1A, 0x76, 0xC1, 0x73, 0xC4, 0x35, 0xFE, 0x59, 0x5C, 0xB8, 0x87, 0x3D, 0x02, 0xFB
};

void convert(uint8_t* X)
{
	int i, j;
	int k = 0;
	uint8_t T[256] = { 0, };
	for (int k = 0; k < 32; k++) {
		for (i = 0; i < 8; i++)
			for (j = 0; j < 8; j++)
				T[32 * i + k] |= (((X[32 * j + k] & (1 << i)) >> i) << j);
	}
	for (i = 0; i < 256; i++)
		X[i] = T[i];
}

void TLU(uint8_t* buffer, int size) {
	convert(buffer);
	for (int i = 0; i < size; i++) {
		buffer[i] = Sbox[buffer[i]];
	}
	convert(buffer);
}

void roundkeyGen(uint32_t* roundkey, uint32_t* masterkey)
{
	int i = 0;
	int j = 0;
	uint32_t RCON = 0;
	for (i = 0; i < ROUND + 1; i++) {
		for (j = 0; j < INT_NUM; j++)
			roundkey[INT_NUM * i + j] = masterkey[(INT_NUM * i + j) % (MASTER_KEY_SIZE * INT_NUM)];
		roundkey[INT_NUM * i] ^= RCON;
		RCON++;
	}
}

void Start_TransForm(uint8_t* plaintext) {
	uint8_t buffer[AVX2_Block];
	memcpy(buffer, plaintext, AVX2_Block);
	for (int i = 0; i < 32; i++) {
		for (int j = 0; j < 8; j++) {
			plaintext[32 * j + i] = buffer[8 * i + j];
		}
	}

}

void End_TransForm(uint8_t* plaintext) {
	uint8_t buffer[AVX2_Block];
	memcpy(buffer, plaintext, AVX2_Block);
	for (int i = 0; i < 32; i++) {
		for (int j = 0; j < 8; j++) {
			plaintext[8 * i + j] = buffer[32 * j + i];
		}
	}
}

__int64 cpucycles() {
	return __rdtsc();
}

//32Block Parallel Encryption using Look-Up Table
void AVX2_PIPO_Test(uint8_t* Plaintext, uint8_t* output, uint32_t* roundkey) {

	uint8_t buffer[AVX2_Block];
	uint8_t* rk = (uint8_t*)roundkey;
	__m256i PT[8];
	__m256i RK[8];
	__m256i T1;
	__m256i T2;
	__m256i T[14];
	__m256i temp1;
	__m256i temp2;
	__m256i temp3;
	__m256i temp4;
	__m256i temp5;

	memcpy(buffer, Plaintext, AVX2_Block);
	Start_TransForm(buffer);

	//PlainText AVX2 Register Setting
	PT[0] = _mm256_loadu_si256(buffer);
	PT[1] = _mm256_loadu_si256(buffer + 32);
	PT[2] = _mm256_loadu_si256(buffer + 64);
	PT[3] = _mm256_loadu_si256(buffer + 96);
	PT[4] = _mm256_loadu_si256(buffer + 128);
	PT[5] = _mm256_loadu_si256(buffer + 160);
	PT[6] = _mm256_loadu_si256(buffer + 192);
	PT[7] = _mm256_loadu_si256(buffer + 224);

	//Round Key AVX2 Register Setting
	RK[0] = _mm256_set1_epi8(rk[0]);
	RK[1] = _mm256_set1_epi8(rk[1]);
	RK[2] = _mm256_set1_epi8(rk[2]);
	RK[3] = _mm256_set1_epi8(rk[3]);
	RK[4] = _mm256_set1_epi8(rk[4]);
	RK[5] = _mm256_set1_epi8(rk[5]);
	RK[6] = _mm256_set1_epi8(rk[6]);
	RK[7] = _mm256_set1_epi8(rk[7]);

	//Initial Round Key Addition Process
	PT[0] = _mm256_xor_si256(PT[0], RK[0]);
	PT[1] = _mm256_xor_si256(PT[1], RK[1]);
	PT[2] = _mm256_xor_si256(PT[2], RK[2]);
	PT[3] = _mm256_xor_si256(PT[3], RK[3]);
	PT[4] = _mm256_xor_si256(PT[4], RK[4]);
	PT[5] = _mm256_xor_si256(PT[5], RK[5]);
	PT[6] = _mm256_xor_si256(PT[6], RK[6]);
	PT[7] = _mm256_xor_si256(PT[7], RK[7]);

	//1bit shifting Masking
	T[0] = _mm256_set1_epi16(0x7F7F);
	T[1] = _mm256_set1_epi16(0x8080);

	//2bit shifting Masking
	T[2] = _mm256_set1_epi16(0x3F3F);
	T[3] = _mm256_set1_epi16(0xC0C0);

	//3bit shifting Masking
	T[4] = _mm256_set1_epi16(0x1F1F);
	T[5] = _mm256_set1_epi16(0xE0E0);

	//4bit shifting Masking
	T[6] = _mm256_set1_epi16(0x0F0F);
	T[7] = _mm256_set1_epi16(0xF0F0);

	//5bit shifting Masking
	T[8] = _mm256_set1_epi16(0x0707);
	T[9] = _mm256_set1_epi16(0xF8F8);

	//6bit shifting Masking
	T[10] = _mm256_set1_epi16(0x0303);
	T[11] = _mm256_set1_epi16(0xFCFC);

	//7bit shifting Masking
	T[12] = _mm256_set1_epi16(0x0101);
	T[13] = _mm256_set1_epi16(0xFEFE);

	//For S-Layer Process, Data Copy(AVX2 Register to 8-bit Data Format)
	_mm256_storeu_si256((__m256i*)(buffer), PT[0]);
	_mm256_storeu_si256((__m256i*)(buffer + 32), PT[1]);
	_mm256_storeu_si256((__m256i*)(buffer + 64), PT[2]);
	_mm256_storeu_si256((__m256i*)(buffer + 96), PT[3]);
	_mm256_storeu_si256((__m256i*)(buffer + 128), PT[4]);
	_mm256_storeu_si256((__m256i*)(buffer + 160), PT[5]);
	_mm256_storeu_si256((__m256i*)(buffer + 192), PT[6]);
	_mm256_storeu_si256((__m256i*)(buffer + 224), PT[7]);

	//1Round
	for (int i = 1; i < ROUND + 1; i++) {

		//S-Layer
		TLU(buffer, AVX2_Block);

		//Data Copy(8-bit Data Format to AVX2 Register)
		PT[0] = _mm256_loadu_si256(buffer);
		PT[1] = _mm256_loadu_si256(buffer + 32);
		PT[2] = _mm256_loadu_si256(buffer + 64);
		PT[3] = _mm256_loadu_si256(buffer + 96);
		PT[4] = _mm256_loadu_si256(buffer + 128);
		PT[5] = _mm256_loadu_si256(buffer + 160);
		PT[6] = _mm256_loadu_si256(buffer + 192);
		PT[7] = _mm256_loadu_si256(buffer + 224);

		//R-Layer
		//PT1
		temp1 = _mm256_and_si256(T[12], PT[1]);
		temp2 = _mm256_and_si256(T[13], PT[1]);
		temp3 = _mm256_slli_epi16(temp1, 7);
		temp4 = _mm256_srli_epi16(temp2, 1);
		PT[1] = _mm256_or_si256(temp3, temp4);

		//PT2
		temp1 = _mm256_and_si256(T[6], PT[2]);
		temp2 = _mm256_and_si256(T[7], PT[2]);
		temp3 = _mm256_slli_epi16(temp1, 4);
		temp4 = _mm256_srli_epi16(temp2, 4);
		PT[2] = _mm256_or_si256(temp3, temp4);

		//PT3
		temp1 = _mm256_and_si256(T[4], PT[3]);
		temp2 = _mm256_and_si256(T[5], PT[3]);
		temp3 = _mm256_slli_epi16(temp1, 3);
		temp4 = _mm256_srli_epi16(temp2, 5);
		PT[3] = _mm256_or_si256(temp3, temp4);

		//PT4
		temp1 = _mm256_and_si256(T[10], PT[4]);
		temp2 = _mm256_and_si256(T[11], PT[4]);
		temp3 = _mm256_slli_epi16(temp1, 6);
		temp4 = _mm256_srli_epi16(temp2, 2);
		PT[4] = _mm256_or_si256(temp3, temp4);

		//PT5
		temp1 = _mm256_and_si256(T[8], PT[5]);
		temp2 = _mm256_and_si256(T[9], PT[5]);
		temp3 = _mm256_slli_epi16(temp1, 5);
		temp4 = _mm256_srli_epi16(temp2, 3);
		PT[5] = _mm256_or_si256(temp3, temp4);

		//PT6
		temp1 = _mm256_and_si256(T[0], PT[6]);
		temp2 = _mm256_and_si256(T[1], PT[6]);
		temp3 = _mm256_slli_epi16(temp1, 1);
		temp4 = _mm256_srli_epi16(temp2, 7);
		PT[6] = _mm256_or_si256(temp3, temp4);

		//PT7
		temp1 = _mm256_and_si256(T[2], PT[7]);
		temp2 = _mm256_and_si256(T[3], PT[7]);
		temp3 = _mm256_slli_epi16(temp1, 2);
		temp4 = _mm256_srli_epi16(temp2, 6);
		PT[7] = _mm256_or_si256(temp3, temp4);

		//RoundKey Setting
		RK[0] = _mm256_set1_epi8(rk[8 * i + 0]);
		RK[1] = _mm256_set1_epi8(rk[8 * i + 1]);
		RK[2] = _mm256_set1_epi8(rk[8 * i + 2]);
		RK[3] = _mm256_set1_epi8(rk[8 * i + 3]);
		RK[4] = _mm256_set1_epi8(rk[8 * i + 4]);
		RK[5] = _mm256_set1_epi8(rk[8 * i + 5]);
		RK[6] = _mm256_set1_epi8(rk[8 * i + 6]);
		RK[7] = _mm256_set1_epi8(rk[8 * i + 7]);

		//RoundKey Addition
		PT[0] = _mm256_xor_si256(PT[0], RK[0]);
		PT[1] = _mm256_xor_si256(PT[1], RK[1]);
		PT[2] = _mm256_xor_si256(PT[2], RK[2]);
		PT[3] = _mm256_xor_si256(PT[3], RK[3]);
		PT[4] = _mm256_xor_si256(PT[4], RK[4]);
		PT[5] = _mm256_xor_si256(PT[5], RK[5]);
		PT[6] = _mm256_xor_si256(PT[6], RK[6]);
		PT[7] = _mm256_xor_si256(PT[7], RK[7]);

		//Data Copy(AVX2 Register to 8-bit Data Format)
		_mm256_storeu_si256((__m256i*)(buffer), PT[0]);
		_mm256_storeu_si256((__m256i*)(buffer + 32), PT[1]);
		_mm256_storeu_si256((__m256i*)(buffer + 64), PT[2]);
		_mm256_storeu_si256((__m256i*)(buffer + 96), PT[3]);
		_mm256_storeu_si256((__m256i*)(buffer + 128), PT[4]);
		_mm256_storeu_si256((__m256i*)(buffer + 160), PT[5]);
		_mm256_storeu_si256((__m256i*)(buffer + 192), PT[6]);
		_mm256_storeu_si256((__m256i*)(buffer + 224), PT[7]);
	}
}

void AVX2_BLC_PIPO_Test(uint8_t* Plaintext, uint8_t* output, uint32_t* roundkey) {

	uint8_t buffer[AVX2_Block];
	uint8_t* rk = (uint8_t*)roundkey;
	__m256i PT[8];
	__m256i RK[8];
	__m256i SboxTemp[8];
	__m256i SboxT[3];
	__m256i T[14];
	__m256i temp1;
	__m256i temp2;
	__m256i temp3;
	__m256i temp4;
	__m256i temp5;
	__m256i X;
	memcpy(buffer, Plaintext, AVX2_Block);


	//1bit shifting Masking
	T[0] = _mm256_set1_epi16(0x7F7F);
	T[1] = _mm256_set1_epi16(0x8080);

	//2bit shifting Masking
	T[2] = _mm256_set1_epi16(0x3F3F);
	T[3] = _mm256_set1_epi16(0xC0C0);

	//3bit shifting Masking
	T[4] = _mm256_set1_epi16(0x1F1F);
	T[5] = _mm256_set1_epi16(0xE0E0);

	//4bit shifting Masking
	T[6] = _mm256_set1_epi16(0x0F0F);
	T[7] = _mm256_set1_epi16(0xF0F0);

	//5bit shifting Masking
	T[8] = _mm256_set1_epi16(0x0707);
	T[9] = _mm256_set1_epi16(0xF8F8);

	//6bit shifting Masking
	T[10] = _mm256_set1_epi16(0x0303);
	T[11] = _mm256_set1_epi16(0xFCFC);

	//7bit shifting Masking
	T[12] = _mm256_set1_epi16(0x0101);
	T[13] = _mm256_set1_epi16(0xFEFE);

	Start_TransForm(buffer);
	PT[0] = _mm256_loadu_si256(buffer);
	PT[1] = _mm256_loadu_si256(buffer + 32);
	PT[2] = _mm256_loadu_si256(buffer + 64);
	PT[3] = _mm256_loadu_si256(buffer + 96);
	PT[4] = _mm256_loadu_si256(buffer + 128);
	PT[5] = _mm256_loadu_si256(buffer + 160);
	PT[6] = _mm256_loadu_si256(buffer + 192);
	PT[7] = _mm256_loadu_si256(buffer + 224);

	RK[0] = _mm256_set1_epi8(rk[0]);
	RK[1] = _mm256_set1_epi8(rk[1]);
	RK[2] = _mm256_set1_epi8(rk[2]);
	RK[3] = _mm256_set1_epi8(rk[3]);
	RK[4] = _mm256_set1_epi8(rk[4]);
	RK[5] = _mm256_set1_epi8(rk[5]);
	RK[6] = _mm256_set1_epi8(rk[6]);
	RK[7] = _mm256_set1_epi8(rk[7]);

	PT[0] = _mm256_xor_si256(PT[0], RK[0]);
	PT[1] = _mm256_xor_si256(PT[1], RK[1]);
	PT[2] = _mm256_xor_si256(PT[2], RK[2]);
	PT[3] = _mm256_xor_si256(PT[3], RK[3]);
	PT[4] = _mm256_xor_si256(PT[4], RK[4]);
	PT[5] = _mm256_xor_si256(PT[5], RK[5]);
	PT[6] = _mm256_xor_si256(PT[6], RK[6]);
	PT[7] = _mm256_xor_si256(PT[7], RK[7]);

	//1Round
	for (int i = 1; i < ROUND + 1; i++) {
		//SBOX

		//S5_1
		SboxTemp[5] = _mm256_xor_si256(PT[5], _mm256_and_si256(PT[7], PT[6]));
		SboxTemp[4] = _mm256_xor_si256(PT[4], _mm256_and_si256(PT[3], SboxTemp[5]));
		SboxTemp[7] = _mm256_xor_si256(PT[7], SboxTemp[4]);
		SboxTemp[6] = _mm256_xor_si256(PT[6], PT[3]);
		SboxTemp[3] = _mm256_xor_si256(PT[3], _mm256_or_si256(SboxTemp[4], SboxTemp[5]));
		SboxTemp[5] = _mm256_xor_si256(SboxTemp[7], SboxTemp[5]);
		SboxTemp[4] = _mm256_xor_si256(SboxTemp[4], _mm256_and_si256(SboxTemp[5], SboxTemp[6]));

		//S5_3
		SboxTemp[2] = _mm256_xor_si256(PT[2], _mm256_and_si256(PT[1], PT[0]));
		SboxTemp[0] = _mm256_xor_si256(PT[0], _mm256_or_si256(SboxTemp[2], PT[1]));
		SboxTemp[1] = _mm256_xor_si256(PT[1], _mm256_or_si256(SboxTemp[2], SboxTemp[0]));
		X = _mm256_set1_epi8(0xff);
		SboxTemp[2] = _mm256_andnot_si256(SboxTemp[2], X);

		//Extend XOR
		SboxTemp[7] = _mm256_xor_si256(SboxTemp[7], SboxTemp[1]);
		SboxTemp[3] = _mm256_xor_si256(SboxTemp[3], SboxTemp[2]);
		SboxTemp[4] = _mm256_xor_si256(SboxTemp[4], SboxTemp[0]);

		//S5_2
		SboxT[0] = SboxTemp[7];
		SboxT[1] = SboxTemp[3];
		SboxT[2] = SboxTemp[4];
		SboxTemp[6] = _mm256_xor_si256(SboxTemp[6], _mm256_and_si256(SboxT[0], SboxTemp[5]));
		SboxT[0] = _mm256_xor_si256(SboxT[0], SboxTemp[6]);
		SboxTemp[6] = _mm256_xor_si256(SboxTemp[6], _mm256_or_si256(SboxT[2], SboxT[1]));
		SboxT[1] = _mm256_xor_si256(SboxT[1], SboxTemp[5]);
		SboxTemp[5] = _mm256_xor_si256(SboxTemp[5], _mm256_or_si256(SboxTemp[6], SboxT[2]));
		SboxT[2] = _mm256_xor_si256(SboxT[2], _mm256_and_si256(SboxT[1], SboxT[0]));

		//Truncate XOR and bit change
		PT[2] = _mm256_xor_si256(SboxTemp[2], SboxT[0]);
		SboxT[0] = _mm256_xor_si256(SboxTemp[1], SboxT[2]);
		PT[1] = _mm256_xor_si256(SboxTemp[0], SboxT[1]);
		PT[0] = SboxTemp[7];
		PT[7] = SboxT[0];

		SboxT[1] = SboxTemp[3];
		PT[3] = SboxTemp[6];
		PT[6] = SboxT[1];
		SboxT[2] = SboxTemp[4];
		PT[4] = SboxTemp[5];
		PT[5] = SboxT[2];

		//PT1
		temp1 = _mm256_and_si256(T[12], PT[1]);
		temp2 = _mm256_and_si256(T[13], PT[1]);
		temp3 = _mm256_slli_epi16(temp1, 7);
		temp4 = _mm256_srli_epi16(temp2, 1);
		PT[1] = _mm256_or_si256(temp3, temp4);

		//PT2
		temp1 = _mm256_and_si256(T[6], PT[2]);
		temp2 = _mm256_and_si256(T[7], PT[2]);
		temp3 = _mm256_slli_epi16(temp1, 4);
		temp4 = _mm256_srli_epi16(temp2, 4);
		PT[2] = _mm256_or_si256(temp3, temp4);

		//PT3
		temp1 = _mm256_and_si256(T[4], PT[3]);
		temp2 = _mm256_and_si256(T[5], PT[3]);
		temp3 = _mm256_slli_epi16(temp1, 3);
		temp4 = _mm256_srli_epi16(temp2, 5);
		PT[3] = _mm256_or_si256(temp3, temp4);

		//PT4
		temp1 = _mm256_and_si256(T[10], PT[4]);
		temp2 = _mm256_and_si256(T[11], PT[4]);
		temp3 = _mm256_slli_epi16(temp1, 6);
		temp4 = _mm256_srli_epi16(temp2, 2);
		PT[4] = _mm256_or_si256(temp3, temp4);

		//PT5
		temp1 = _mm256_and_si256(T[8], PT[5]);
		temp2 = _mm256_and_si256(T[9], PT[5]);
		temp3 = _mm256_slli_epi16(temp1, 5);
		temp4 = _mm256_srli_epi16(temp2, 3);
		PT[5] = _mm256_or_si256(temp3, temp4);

		//PT6
		temp1 = _mm256_and_si256(T[0], PT[6]);
		temp2 = _mm256_and_si256(T[1], PT[6]);
		temp3 = _mm256_slli_epi16(temp1, 1);
		temp4 = _mm256_srli_epi16(temp2, 7);
		PT[6] = _mm256_or_si256(temp3, temp4);

		//PT7
		temp1 = _mm256_and_si256(T[2], PT[7]);
		temp2 = _mm256_and_si256(T[3], PT[7]);
		temp3 = _mm256_slli_epi16(temp1, 2);
		temp4 = _mm256_srli_epi16(temp2, 6);
		PT[7] = _mm256_or_si256(temp3, temp4);

		//RoundKey
		RK[0] = _mm256_set1_epi8(rk[8 * i + 0]);
		RK[1] = _mm256_set1_epi8(rk[8 * i + 1]);
		RK[2] = _mm256_set1_epi8(rk[8 * i + 2]);
		RK[3] = _mm256_set1_epi8(rk[8 * i + 3]);
		RK[4] = _mm256_set1_epi8(rk[8 * i + 4]);
		RK[5] = _mm256_set1_epi8(rk[8 * i + 5]);
		RK[6] = _mm256_set1_epi8(rk[8 * i + 6]);
		RK[7] = _mm256_set1_epi8(rk[8 * i + 7]);

		PT[0] = _mm256_xor_si256(PT[0], RK[0]);
		PT[1] = _mm256_xor_si256(PT[1], RK[1]);
		PT[2] = _mm256_xor_si256(PT[2], RK[2]);
		PT[3] = _mm256_xor_si256(PT[3], RK[3]);
		PT[4] = _mm256_xor_si256(PT[4], RK[4]);
		PT[5] = _mm256_xor_si256(PT[5], RK[5]);
		PT[6] = _mm256_xor_si256(PT[6], RK[6]);
		PT[7] = _mm256_xor_si256(PT[7], RK[7]);

	}

	_mm256_storeu_si256((__m256i*)(output), PT[0]);
	_mm256_storeu_si256((__m256i*)(output + 32), PT[1]);
	_mm256_storeu_si256((__m256i*)(output + 64), PT[2]);
	_mm256_storeu_si256((__m256i*)(output + 96), PT[3]);
	_mm256_storeu_si256((__m256i*)(output + 128), PT[4]);
	_mm256_storeu_si256((__m256i*)(output + 160), PT[5]);
	_mm256_storeu_si256((__m256i*)(output + 192), PT[6]);
	_mm256_storeu_si256((__m256i*)(output + 224), PT[7]);

	End_TransForm(output);
}

int main()
{
	uint32_t PT[64] = { 0x098552F6, 0x1E270026 };
	uint8_t out[256] = { 0, };
	uint32_t MASTER_KEY[MASTER_KEY_SIZE * INT_NUM] = { 0, };
	uint32_t ROUND_KEY[(ROUND + 1) * INT_NUM] = { 0, };
	MASTER_KEY[0] = 0x2E152297;
	MASTER_KEY[1] = 0x7E1D20AD;
	MASTER_KEY[2] = 0x779428D2;
	MASTER_KEY[3] = 0x6DC416DD;
	roundkeyGen(ROUND_KEY, MASTER_KEY);
	for (int i = 0; i < 2; i++) {
		if (i % 2 == 0)
			PT[i] = 0x1E270026;
		else
			PT[i] = 0x098552F6;
	}

	unsigned long long cycle = 0;
	unsigned long long cycle1 = 0;
	unsigned long long cycle2 = 0;

	uint8_t pt[256];
	for (int i = 0; i < 32; i++) {
		pt[8 * i + 0] = 0x26;
		pt[8 * i + 1] = 0x00;
		pt[8 * i + 2] = 0x27;
		pt[8 * i + 3] = 0x1E;
		pt[8 * i + 4] = 0xF6;
		pt[8 * i + 5] = 0x52;
		pt[8 * i + 6] = 0x85;
		pt[8 * i + 7] = 0x09;
	}

	cycle = 0;
	for (int j = 0; j < 10000; j++) {
		cycle1 = cpucycles();
		AVX2_BLC_PIPO_Test(pt, out, ROUND_KEY);
		cycle2 = cpucycles();
		cycle += cycle2 - cycle1;
	}
	printf("BltSliced = %10lld\n", cycle / (10000));

	cycle = 0;
	for (int j = 0; j < 10000; j++) {
		cycle1 = cpucycles();
		AVX2_PIPO_Test(pt, out, ROUND_KEY);
		cycle2 = cpucycles();
		cycle += cycle2 - cycle1;
	}
	printf("LUT = %10lld\n", cycle / (10000));

	for (int i = 0; i < 256; i++) {
		printf("%02X ", out[i]);
		if ((i + 1) % 8 == 0)
			printf("\n");
	}
}

