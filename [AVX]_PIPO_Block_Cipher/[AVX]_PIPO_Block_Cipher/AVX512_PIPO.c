#include "AVX512_type.h"

void sTransForm(uint8_t* in) {
	uint8_t buffer[AVX512_BLOCK];
	memcpy(buffer, in, AVX512_BLOCK);
	for (int i = 0; i < 64; i++) {
		for (int j = 0; j < 8; j++) {
			in[64 * j + i] = buffer[8 * i + j];
		}
	}
}

void eTransForm(uint8_t* in) {
	uint8_t buffer[AVX512_BLOCK];
	memcpy(buffer, in, AVX512_BLOCK);
	for (int i = 0; i < 64; i++) {
		for (int j = 0; j < 8; j++) {
			in[8 * i + j] = buffer[64 * j + i];
		}
	}
}

__int64 cpucycles() {
	return __rdtsc();
}

void AVX512_PIPO(uint8_t* pt, uint8_t* out, uint32_t* roundkey)
{
	uint8_t buffer[AVX512_BLOCK];
	uint8_t* rk = (uint8_t*)roundkey;
	__m512i PT[8];
	__m512i RK[8];
	__m512i SboxTemp[8];
	__m512i SboxT[3];
	__m512i T[14];
	__m512i temp1;
	__m512i temp2;
	__m512i temp3;
	__m512i temp4;
	__m512i temp5;

	memcpy(buffer, pt, AVX512_BLOCK);

	//1bit shifting Masking
	T[0] = _mm512_set1_epi16(0x7F7F);
	T[1] = _mm512_set1_epi16(0x8080);

	//2bit shifting Masking
	T[2] = _mm512_set1_epi16(0x3F3F);
	T[3] = _mm512_set1_epi16(0xC0C0);

	//3bit shifting Masking
	T[4] = _mm512_set1_epi16(0x1F1F);
	T[5] = _mm512_set1_epi16(0xE0E0);

	//4bit shifting Masking
	T[6] = _mm512_set1_epi16(0x0F0F);
	T[7] = _mm512_set1_epi16(0xF0F0);

	//5bit shifting Masking
	T[8] = _mm512_set1_epi16(0x0707);
	T[9] = _mm512_set1_epi16(0xF8F8);

	//6bit shifting Masking
	T[10] = _mm512_set1_epi16(0x0303);
	T[11] = _mm512_set1_epi16(0xFCFC);

	//7bit shifting Masking
	T[12] = _mm512_set1_epi16(0x0101);
	T[13] = _mm512_set1_epi16(0xFEFE);

	sTransForm(buffer);
	PT[0] = _mm512_loadu_si512(buffer);
	PT[1] = _mm512_loadu_si512(buffer + 64);
	PT[2] = _mm512_loadu_si512(buffer + 128);
	PT[3] = _mm512_loadu_si512(buffer + 192);
	PT[4] = _mm512_loadu_si512(buffer + 256);
	PT[5] = _mm512_loadu_si512(buffer + 320);
	PT[6] = _mm512_loadu_si512(buffer + 384);
	PT[7] = _mm512_loadu_si512(buffer + 448);

	RK[0] = _mm512_set1_epi8(rk[0]);
	RK[1] = _mm512_set1_epi8(rk[1]);
	RK[2] = _mm512_set1_epi8(rk[2]);
	RK[3] = _mm512_set1_epi8(rk[3]);
	RK[4] = _mm512_set1_epi8(rk[4]);
	RK[5] = _mm512_set1_epi8(rk[5]);
	RK[6] = _mm512_set1_epi8(rk[6]);
	RK[7] = _mm512_set1_epi8(rk[7]);

	PT[0] = _mm512_xor_si512(PT[0], RK[0]);
	PT[1] = _mm512_xor_si512(PT[1], RK[1]);
	PT[2] = _mm512_xor_si512(PT[2], RK[2]);
	PT[3] = _mm512_xor_si512(PT[3], RK[3]);
	PT[4] = _mm512_xor_si512(PT[4], RK[4]);
	PT[5] = _mm512_xor_si512(PT[5], RK[5]);
	PT[6] = _mm512_xor_si512(PT[6], RK[6]);
	PT[7] = _mm512_xor_si512(PT[7], RK[7]);

	for (int i = 1; i < ROUND + 1; i++) {
		//S-Layer(Bit-slicing)
		//S5_1
		SboxTemp[5] = _mm512_xor_si512(PT[5], _mm512_and_si512(PT[7], PT[6]));
		SboxTemp[4] = _mm512_xor_si512(PT[4], _mm512_and_si512(PT[3], SboxTemp[5]));
		SboxTemp[7] = _mm512_xor_si512(PT[7], SboxTemp[4]);
		SboxTemp[6] = _mm512_xor_si512(PT[6], PT[3]);
		SboxTemp[3] = _mm512_xor_si512(PT[3], _mm512_or_si512(SboxTemp[4], SboxTemp[5]));
		SboxTemp[5] = _mm512_xor_si512(SboxTemp[7], SboxTemp[5]);
		SboxTemp[4] = _mm512_xor_si512(SboxTemp[4], _mm512_and_si512(SboxTemp[5], SboxTemp[6]));

		//S5_3
		SboxTemp[2] = _mm512_xor_si512(PT[2], _mm512_and_si512(PT[1], PT[0]));
		SboxTemp[0] = _mm512_xor_si512(PT[0], _mm512_or_si512(SboxTemp[2], PT[1]));
		SboxTemp[1] = _mm512_xor_si512(PT[1], _mm512_or_si512(SboxTemp[2], SboxTemp[0]));
		temp5 = _mm512_set1_epi8(0xff);
		SboxTemp[2] = _mm512_andnot_si512(SboxTemp[2], temp5);

		//Extend XOR
		SboxTemp[7] = _mm512_xor_si512(SboxTemp[7], SboxTemp[1]);
		SboxTemp[3] = _mm512_xor_si512(SboxTemp[3], SboxTemp[2]);
		SboxTemp[4] = _mm512_xor_si512(SboxTemp[4], SboxTemp[0]);

		//S5_2
		SboxT[0] = SboxTemp[7];
		SboxT[1] = SboxTemp[3];
		SboxT[2] = SboxTemp[4];

		SboxTemp[6] = _mm512_xor_si512(SboxTemp[6], _mm512_and_si512(SboxT[0], SboxTemp[5]));
		SboxT[0] = _mm512_xor_si512(SboxT[0], SboxTemp[6]);

		SboxTemp[6] = _mm512_xor_si512(SboxTemp[6], _mm512_or_si512(SboxT[2], SboxT[1]));
		SboxT[1] = _mm512_xor_si512(SboxT[1], SboxTemp[5]);

		SboxTemp[5] = _mm512_xor_si512(SboxTemp[5], _mm512_or_si512(SboxT[2], SboxTemp[6]));
		SboxT[2] = _mm512_xor_si512(SboxT[2], _mm512_and_si512(SboxT[1], SboxT[0]));

		//Truncate XOR and bit Change
		PT[2] = _mm512_xor_si512(SboxTemp[2], SboxT[0]);
		SboxT[0] = _mm512_xor_si512(SboxTemp[1], SboxT[2]);
		PT[1] = _mm512_xor_si512(SboxTemp[0], SboxT[1]);
		PT[0] = SboxTemp[7];
		PT[7] = SboxT[0];

		SboxT[1] = SboxTemp[3];
		PT[3] = SboxTemp[6];
		PT[6] = SboxT[1];
		SboxT[2] = SboxTemp[4];
		PT[4] = SboxTemp[5];
		PT[5] = SboxT[2];

		//R-Layer
		//PT[1]
		temp1 = _mm512_and_si512(T[12], PT[1]);
		temp2 = _mm512_and_si512(T[13], PT[1]);
		temp3 = _mm512_slli_epi16(temp1, 7);
		temp4 = _mm512_srli_epi16(temp2, 1);
		PT[1] = _mm512_or_si512(temp3, temp4);

		//PT[2]
		temp1 = _mm512_and_si512(T[6], PT[2]);
		temp2 = _mm512_and_si512(T[7], PT[2]);
		temp3 = _mm512_slli_epi16(temp1, 4);
		temp4 = _mm512_srli_epi16(temp2, 4);
		PT[2] = _mm512_or_si512(temp3, temp4);

		//PT[3]
		temp1 = _mm512_and_si512(T[4], PT[3]);
		temp2 = _mm512_and_si512(T[5], PT[3]);
		temp3 = _mm512_slli_epi16(temp1, 3);
		temp4 = _mm512_srli_epi16(temp2, 5);
		PT[3] = _mm512_or_si512(temp3, temp4);

		//PT[4]
		temp1 = _mm512_and_si512(T[10], PT[4]);
		temp2 = _mm512_and_si512(T[11], PT[4]);
		temp3 = _mm512_slli_epi16(temp1, 6);
		temp4 = _mm512_srli_epi16(temp2, 2);
		PT[4] = _mm512_or_si512(temp3, temp4);

		//PT[5]
		temp1 = _mm512_and_si512(T[8], PT[5]);
		temp2 = _mm512_and_si512(T[9], PT[5]);
		temp3 = _mm512_slli_epi16(temp1, 5);
		temp4 = _mm512_srli_epi16(temp2, 3);
		PT[5] = _mm512_or_si512(temp3, temp4);

		//PT[6]
		temp1 = _mm512_and_si512(T[0], PT[6]);
		temp2 = _mm512_and_si512(T[1], PT[6]);
		temp3 = _mm512_slli_epi16(temp1, 1);
		temp4 = _mm512_srli_epi16(temp2, 7);
		PT[6] = _mm512_or_si512(temp3, temp4);

		//PT[7]
		temp1 = _mm512_and_si512(T[2], PT[7]);
		temp2 = _mm512_and_si512(T[3], PT[7]);
		temp3 = _mm512_slli_epi16(temp1, 2);
		temp4 = _mm512_srli_epi16(temp2, 6);
		PT[7] = _mm512_or_si512(temp3, temp4);

		//AddRoundKey
		RK[0] = _mm512_set1_epi8(rk[8 * i + 0]);
		RK[1] = _mm512_set1_epi8(rk[8 * i + 1]);
		RK[2] = _mm512_set1_epi8(rk[8 * i + 2]);
		RK[3] = _mm512_set1_epi8(rk[8 * i + 3]);
		RK[4] = _mm512_set1_epi8(rk[8 * i + 4]);
		RK[5] = _mm512_set1_epi8(rk[8 * i + 5]);
		RK[6] = _mm512_set1_epi8(rk[8 * i + 6]);
		RK[7] = _mm512_set1_epi8(rk[8 * i + 7]);

		PT[0] = _mm512_xor_si512(PT[0], RK[0]);
		PT[1] = _mm512_xor_si512(PT[1], RK[1]);
		PT[2] = _mm512_xor_si512(PT[2], RK[2]);
		PT[3] = _mm512_xor_si512(PT[3], RK[3]);
		PT[4] = _mm512_xor_si512(PT[4], RK[4]);
		PT[5] = _mm512_xor_si512(PT[5], RK[5]);
		PT[6] = _mm512_xor_si512(PT[6], RK[6]);
		PT[7] = _mm512_xor_si512(PT[7], RK[7]);

	}
	_mm512_storeu_si512((__m512i*)(out), PT[0]);
	_mm512_storeu_si512((__m512i*)(out + 64), PT[1]);
	_mm512_storeu_si512((__m512i*)(out + 128), PT[2]);
	_mm512_storeu_si512((__m512i*)(out + 192), PT[3]);
	_mm512_storeu_si512((__m512i*)(out + 256), PT[4]);
	_mm512_storeu_si512((__m512i*)(out + 320), PT[5]);
	_mm512_storeu_si512((__m512i*)(out + 384), PT[6]);
	_mm512_storeu_si512((__m512i*)(out + 448), PT[7]);
	eTransForm(out);
	return;
}

void roundkeyGen(uint32_t* roundkey, uint32_t* masterkey)
{
	int i = 0;
	int j = 0;
	uint32_t RCON = 0;
	for (i = 0; i < ROUND + 1; i++) {
		for (j = 0; j < 2; j++)
			roundkey[2 * i + j] = masterkey[(2 * i + j) % (2 * 2)];
		roundkey[2 * i] ^= RCON;
		RCON++;
	}
}

void PIPO_performance_Test()
{
	uint32_t MASTER_KEY[4] = { 0x2E152297 , 0x7E1D20AD, 0x779428D2, 0x6DC416DD };
	uint32_t ROUND_KEY[14 * 2] = { 0, };
	roundkeyGen(ROUND_KEY, MASTER_KEY);
	uint8_t pt[512] = { 0, };
	uint8_t out[512] = { 0, };
	for (int i = 0; i < 64; i++) {
		pt[8 * i + 0] = 0x26;
		pt[8 * i + 1] = 0x00;
		pt[8 * i + 2] = 0x27;
		pt[8 * i + 3] = 0x1E;
		pt[8 * i + 4] = 0xF6;
		pt[8 * i + 5] = 0x52;
		pt[8 * i + 6] = 0x85;
		pt[8 * i + 7] = 0x09;
	}

	unsigned long long cycle = 0;
	unsigned long long cycle1 = 0;
	unsigned long long cycle2 = 0;
	cycle = 0;
	for (int j = 0; j < 10000; j++) {
		cycle1 = cpucycles();
		AVX512_PIPO(pt, out, ROUND_KEY);
		cycle2 = cpucycles();
		cycle += cycle2 - cycle1;
	}
	printf("Cycle per Byte = %10lld\n", ((cycle / 10000)));
	getchar();
	for (int i = 0; i < 512; i++) {
		printf("%02X ", out[i]);
		if ((i + 1) % 8 == 0)
			printf("\n");
	}
}

int main()
{
	PIPO_performance_Test();
	return 0;
}