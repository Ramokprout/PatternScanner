#pragma once

#ifndef __PATTERNSCANNER_PATTERN__
#define __PATTERNSCANNER_PATTERN__

#define WINDOWS_LEAN_AND_MEAN
#include <Windows.h>
#include <Psapi.h>
#include <vector>

struct sectionInfo {
	UINT64 dwBaseAddress;
	DWORD dwSectionSize;

	bool operator==(int base) {
		return dwBaseAddress == base && dwSectionSize == base;
	}
};

struct Pattern {
	const char *lpSignature;
	bool bRelative;
	int skipBytes;
	int instructionSize;
};

static Pattern createPattern(const char *signature, bool bRelative = false, int skipBytes = 0x0, int instruction_size = 0) {

	Pattern pattern = { 0 };
	pattern.lpSignature = signature;
	pattern.instructionSize = instruction_size;
	pattern.skipBytes = skipBytes;
	pattern.bRelative = bRelative;

#ifdef PATTERNSCAN_VERBOSE
	printf("createPattern: created pattern\n");
#endif

	return pattern;
}

class PatternScanner {
private:
	sectionInfo PESectionInfo;

	uintptr_t findModule(const wchar_t* lpModuleName) {
		HMODULE base = GetModuleHandleW(lpModuleName);
		if (!base) return 0;

#ifdef PATTERNSCAN_VERBOSE
		printf("findModule: found module base : %llu\n", (uintptr_t)base);
#endif

		return (uintptr_t)base;
	}

	sectionInfo findSectionInfo(uintptr_t mmodule_base, const char* lpSectionName) {
		if (mmodule_base == 0) {
			throw "Invalid module base";
		}

		sectionInfo result = { 0 };
		if (strcmp(lpSectionName, "none") != 0) {
			IMAGE_DOS_HEADER* pDOSHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(mmodule_base);
			IMAGE_NT_HEADERS* pNTHeader = reinterpret_cast<IMAGE_NT_HEADERS*>(mmodule_base + pDOSHeader->e_lfanew);
			UINT nSectionCount = pNTHeader->FileHeader.NumberOfSections;
			PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(pNTHeader);
			for (unsigned int i = 0; i < nSectionCount; ++sectionHeader, ++i) {
				if (strcmp(reinterpret_cast<const char*>(sectionHeader->Name), lpSectionName) == 0) {
#ifdef PATTERNSCAN_VERBOSE
					printf("findSectionInfo: Virtual Address of section '%s' : %lX\n", sectionHeader->Name, sectionHeader->VirtualAddress);
#endif
					result.dwBaseAddress = mmodule_base + sectionHeader->VirtualAddress;
					result.dwSectionSize = sectionHeader->SizeOfRawData;
					break;
				}
			}
		}
		else {
#ifdef PATTERNSCAN_VERBOSE
			printf("findSectionInfo: using all sections.\n");
#endif
		}

		if (result == 0) {
			MODULEINFO info = { 0 };
			if (GetModuleInformation(GetCurrentProcess(), (HMODULE)mmodule_base, &info, sizeof(info))) {
				result.dwBaseAddress = (UINT64)info.lpBaseOfDll;
				result.dwSectionSize = info.SizeOfImage;
			}
			else {
				throw "Unable to get module information";
			}
		}

#ifdef PATTERNSCAN_VERBOSE
		printf("findSectionInfo: found base : %llu, found size : %lu\n", result.dwBaseAddress, result.dwSectionSize);
#endif

		return result;
	}
	DWORD findOffset(int instruction_size) {
		return instruction_size - 4;
	}
	uintptr_t getAbsoluteAddress(uintptr_t pInstruction, int iOffset, int iSize) {
		return pInstruction + *reinterpret_cast<uint32_t*>(pInstruction + iOffset) + iSize;
	}

public:
	PatternScanner(const wchar_t* lpModuleName, const char *sectionName) {
		uintptr_t moduleBase = this->findModule(lpModuleName);
		if (moduleBase == 0) {
			throw "Module not found";
		}

		this->PESectionInfo = this->findSectionInfo(moduleBase, sectionName);


#ifdef PATTERNSCAN_VERBOSE
		printf("PatternScanner: initialized PatternScanner instance with section base : %llu\n", PESectionInfo.dwBaseAddress);
#endif
	}

	uintptr_t scanPattern(const char* signature, int skipBytes = 0x0, bool bRelative = false, int instruction_size = 0) {
		Pattern pat = createPattern(signature, bRelative, skipBytes, instruction_size);
		return this->scan(pat);
	}

	DWORD PatternScan(uintptr_t baseAddress, unsigned long size, std::vector<int> signature) {
		auto scanBytes = reinterpret_cast<UINT8*>(baseAddress);
		auto toScanLength = size - std::size(signature);
		for (auto i = 0ul; i < toScanLength; i++) {
			bool found = true;
			for (int j = 0; j < std::size(signature) && found; j++) {
				if (signature[j] != 0XFF)
					found = scanBytes[i + j] == (BYTE)(signature[j]);
			}

			if (found) {
#ifdef PATTERNSCAN_VERBOSE
				printf("PatternScan: found sig at offset : 0x%lX\n", i);
#endif
				return i;
			}
		}

		return 0;
	}

	std::vector<int> patternToBytes(const char* pattern) 
	{
		auto bytes = std::vector<int>{};
		auto start = const_cast<char*>(pattern);
		auto end = const_cast<char*>(pattern) + strlen(pattern);

		for (auto current = start; current < end; ++current) {
			if (*current == '?') {
				++current;
				if (*current == '?')
					++current;
				bytes.push_back(0xFF);
			}
			else {
				bytes.push_back(strtoul(current, &current, 16));
			}
		}
		return bytes;
	}

	uintptr_t scan(Pattern pattern) {
		std::vector<int> bytes = patternToBytes(pattern.lpSignature);

		DWORD offset = PatternScan(PESectionInfo.dwBaseAddress, PESectionInfo.dwSectionSize, bytes);
		if (offset == 0) return 0;

		auto result = PESectionInfo.dwBaseAddress + offset + pattern.skipBytes;

		if (!pattern.bRelative) return result;

		
#ifdef PATTERNSCAN_VERBOSE
		printf("scan : secInfo.dwBaseAddress: %llu\n", PESectionInfo.dwBaseAddress);
#endif
		int instruction_offset = this->findOffset(pattern.instructionSize);
#ifdef PATTERNSCAN_VERBOSE
		printf("scan : instruction_offset %d\n", instruction_offset);
		printf("scan : pattern.instructionSize %d\n", pattern.instructionSize);
#endif
		return this->getAbsoluteAddress(result, instruction_offset, pattern.instructionSize);
	}
};

#endif
