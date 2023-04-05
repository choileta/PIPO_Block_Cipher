#pragma once
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>


//Block size Def
#define AVX2_Block		256			
//1Block = 8byte, 32Block = 256byte
#define ROUND 13
//#define SIZE 2
#define INT_NUM 2
#define MASTER_KEY_SIZE 2