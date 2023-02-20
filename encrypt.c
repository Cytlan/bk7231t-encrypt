// Tuya Encryption
// ===============
//
// This program re-implements the encryption algorithm used for firmware packages for BK7231T Tuya devices.
//
// It's still not entierly finished; Only the scramble3 method has been verified against a known result.
// The scramble1 and scramble2 functions still needs to be verified.
// Also, the output filename is hardcoded in this program, instead of adding "_enc" to the filename before the extension.
// The ".cpr" and ".out" file are also not generated (are those even used by anything?).
//
// Hopefully I or someone else can make a decryption routine based on this here code.
//
// Compiling
// ---------
//
// gcc --std=c99 encrypt.c -o encrypt
//
// How the passcodes work
// ----------------------
//
// passcode0 is used if scramble3 is enabled.
// passcode1 is used if scramble1 and/or scramble2 is enabled.
// passcode2 is XOR'd with the result if scramble4 is enabled.
// passcode3 determines which scramble methods are enabled.
// 
// passcode3 format:
//     31      24 23      16 15      8  7       0
//     |       |  |       |  |       |  |       |
//     0000 0000  0000 0000  0000 0000  0000 0000
//     '-------|  |||| ||||  |||| ||||  |||| |||'- scramble1EnableFlag (0: enable, 1: disable)
//             |  |||| ||||  |||| ||||  |||| ||'-- scramble2EnableFlag (0: enable, 1: disable)
//             |  |||| ||||  |||| ||||  |||| |'--- scramble3EnableFlag (0: enable, 1: disable)
//             |  |||| ||||  |||| ||||  |||| '---- scramble4EnableFlag (0: enable, 1: disable)
//             |  |||| ||||  |||| ||||  |||'------ scramble2Add256 (0: disable, 1: enable)
//             |  |||| ||||  |||| ||||  |''------- scramble1Variant
//             |  |||| ||||  |||| ||||  '--------- unused
//             |  |||| ||||  |||| ||''------------ scramble2Variant
//             |  |||| ||||  |||'-+'-------------- unused
//             |  |||| ||||  |''------------------ scramble3Variant
//             |  '+++-++++--'-------------------- unused
//             '---------------------------------- disableScramble (if 0x00 or 0xFF; all other values ignored)
//
// Author:  Cytlan
// Date:    2023-02-20
//
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

uint32_t passcode0;
uint32_t passcode1;
uint32_t passcode2;
uint32_t passcode3;

uint32_t scramble1(uint32_t data)
{
	uint32_t result = ((data << 17) | (data >> 15)) ^ (((data >> 2) & 0xF) * 0x11111111) & 0xe519a4f1;
	return result;
}

uint16_t scramble2(uint32_t data)
{
	uint32_t tmp = (data >> 0xd & 1) +
	               (data >> 1 & 1) * 8 + (data >> 5 & 1) * 4 + (data >> 9 & 1) * 2;
	return (data >> 10 & 0x7f) + (data & 0x3ff) * 0x80 ^
	       (data >> 4 & 1) * 0x10000 + tmp * 0x1000 + tmp * 0x111 & 0x13659;
}

uint16_t scramble3(uint32_t data)
{
	return (data >> 7) + data * 0x200 ^
	       (data >> 5 & 0xf) +
	       (data >> 5) * 0x1000 + (int16_t)((data >> 5 & 0xf) << 8) +
	       (int16_t)(((uint32_t)(data >> 5) & 0xf) << 4) & 0x6371;
}

uint32_t enc_data_my(size_t offset, uint32_t data)
{
	bool disableAllScramble = false;

	uint16_t scramble1Res = 0;
	uint16_t scramble2Res = 0;
	uint32_t scramble3Res = 0;
	uint32_t scramble4 = 0;

	// If the top-most bte of passcode3 is 0x00 or 0xff, then the rest of the options are ignored
	if(((passcode3 & 0xff000000) == 0xff000000) || ((passcode3 & 0xff000000) == 0))
	{
		disableAllScramble = true;
	}

	bool scramble1EnableFlag = !disableAllScramble && (passcode3 & 1) == 0;
	bool scramble2EnableFlag = !disableAllScramble && (passcode3 & 2) == 0;
	bool scramble3EnableFlag = !disableAllScramble && (passcode3 & 4) == 0;
	bool scramble4EnableFlag = !disableAllScramble && (passcode3 & 8) == 0;

	// ---------------------------------------------
	// Scamble method 1
	if(scramble1EnableFlag)
	{
		uint8_t scramble1Variant = (passcode3 >> 5) & 3;
		uint8_t offsetByte1 = offset >> 8;
		uint8_t offsetByte2 = offset >> 0x10;
		uint8_t offsetByte3 = offset >> 0x18;
		uint16_t offsetSwapXor;

		switch(scramble1Variant)
		{
			case 0:
				offsetSwapXor = (offsetByte2 & 0xff) + (int16_t)((offset >> 0x18) << 8) ^ (uint16_t)offset;
				break;
			case 1:
				offsetSwapXor = (offsetByte2 & 0xff) + (int16_t)((offset >> 0x18) << 8) ^ (offsetByte1 & 0xff) + (int16_t)(offset << 8);
				break;
			case 2:
				offsetSwapXor = (offsetByte3 + (int16_t)((offset >> 0x10) << 8)) ^ (uint16_t)offset;
				break;
			case 3:
				offsetSwapXor = (offsetByte3 + (int16_t)((offset >> 0x10) << 8)) ^ (offsetByte1 + (int16_t)(offset << 8));
				break;
		}

		scramble1Res = scramble1((passcode1 >> 0x10) ^ offsetSwapXor);
	}

	// ---------------------------------------------
	// Scamble method 2
	if(scramble2EnableFlag)
	{
		uint8_t addFlag = (passcode3 >> 4) & 1;
		uint8_t passcode1Byte1 = (passcode1 >> 8) & 0xff;
		uint8_t passcode1Byte0 = passcode1 & 0xff;
		uint8_t scramble2Variant = (passcode3 >> 8) & 3;
		uint32_t offsetShifted;

		switch(scramble2Variant)
		{
			case 0:
				offsetShifted = offset & 0x1ffff;
				break;
			case 1:
				offsetShifted = (offset >> 1) & 0x1ffff;
				break;
			case 2:
				offsetShifted = (offset >> 2) & 0x1ffff;
				break;
			case 3:
				offsetShifted = (offset >> 3) & 0x1ffff;
				break;
		}

		scramble2Res = scramble2((passcode1Byte0 + passcode1Byte1 * 0x200 + (addFlag * 0x100)) ^ offsetShifted);
	}

	// ---------------------------------------------
	// Scamble method 3
	if(scramble3EnableFlag)
	{
		uint8_t scramble3Variant = (passcode3 >> 0xb) & 3;
		uint32_t offsetRotated = offset;
		if(scramble3Variant == 1)
			offsetRotated = (offset >> 8) | (offset << 0x18);
		else if(scramble3Variant == 2)
			offsetRotated = (offset >> 0x10) | (offset << 0x10);
		else if(scramble3Variant == 3)
			offsetRotated = (offset << 8) | (offset >> 0x18);
		offsetRotated ^= passcode0;
		scramble3Res = scramble3(offsetRotated);
	}

	// ---------------------------------------------
	// Scamble method 4
	if(scramble4EnableFlag)
	{
		scramble4 = passcode2;
	}

	return ((((scramble1Res << 0x10) + scramble2Res) ^ scramble3Res) ^ scramble4) ^ data;
}

void encrypt(uint32_t* inputData, uint32_t* outputData, size_t blockCount)
{
	uint32_t* inputPtr = inputData;
	uint32_t* outputPtr = outputData;
	for(uint32_t index = 0; index < blockCount * 8; index++)
	{
		uint32_t encryptedWord = enc_data_my(index * 4, *inputPtr);
		*outputPtr = encryptedWord;
		outputPtr++;
		inputPtr++;
	}
}

size_t get_file_size(FILE* file)
{
	off_t offset = ftell(file);
	fseek(file, 0, SEEK_END);
	size_t size = ftell(file);
	fseek(file, offset, SEEK_SET);
	return size;
}

uint32_t str2int(const char* str)
{
	uint32_t out = 0;
	char* strPtr = (char*)str;
	bool negative = false;

	if(*strPtr == '-')
	{
		negative = true;
		strPtr++;
	}

	while(*strPtr)
	{
		char c = *strPtr;
		if(c == ' ')
			break;

		out <<= 4;

		if(c >= '0' && c <= '9')
			out |= c - '0';
		else if(c >= 'A' && c <= 'F')
			out |= 0xA + (c - 'A');
		else if(c >= 'a' && c <= 'f')
			out |= 0xA + (c - 'a');
		else
		{
			out = 0;
			printf("Error: Parameter failed!\n");
			break;
		}

		strPtr++;
	}
	if(negative)
		return -out;
	return out;
}

int main(int argc, char* argv[])
{
	if(argc != 7)
	{
		printf("Usage: encrypt image.bin passcode0 passcode1 passcode2 passcode3 start_address\n");
		printf("       digit is hex number without prefix:0x\n");
		printf("example: encrypt image.bin 12345678 2faa55aa 3aee63dd 4feeaa00 10000\n");
		printf("the intention is: passcode0 0x12345678\n");
		printf("                  passcode1 0x2faa55aa\n");
		printf("                  passcode2 0x3aee63dd\n");
		printf("                  passcode3 0x4feeaa00\n");
		printf("                  start_address 0x10000\n");
		return 1;
	}

	char* inputFileName = argv[1];
	passcode0 = str2int(argv[2]);
	passcode1 = str2int(argv[3]);
	passcode2 = str2int(argv[4]);
	passcode3 = str2int(argv[5]); // This basically defined what scramble operations are used
	uint32_t startAddress = str2int(argv[6]);

	// Read input file
	FILE* inputFile = fopen(inputFileName, "rb");
	if(inputFile == NULL)
	{
		printf("Can't open file %s", inputFileName);
		return 2;
	}
	size_t inputSize = get_file_size(inputFile);
	size_t alignedSize = inputSize;
	if(alignedSize & 0x1F)
		alignedSize += 0x20 - (alignedSize & 0x1F);
	uint32_t* inputData = (uint32_t*)malloc(alignedSize);
	if(!inputData)
	{
		printf("Failed to allocate input data memory\n");
		fclose(inputFile);
		return 3;
	}
	memset(inputData, 0xFF, alignedSize);
	fread(inputData, 1, inputSize, inputFile);
	fclose(inputFile);
	inputFile = NULL;

	// Allocate output data
	size_t outputSize = alignedSize + 0x10;
	uint32_t* outputData = (uint32_t*)malloc(outputSize);
	if(!outputData)
	{
		printf("Failed to allocate input data memory\n");
		free(inputData);
		return 4;
	}
	memset(outputData, 0xFF, outputSize);

	// Encrypt
	size_t blockCount = alignedSize >> 5;
	encrypt(inputData, outputData, blockCount);

	FILE* outFile = fopen("encrypt_out.bin", "wb");
	fwrite(outputData, 1, outputSize, outFile);
	fclose(outFile);

	return 0;
}
