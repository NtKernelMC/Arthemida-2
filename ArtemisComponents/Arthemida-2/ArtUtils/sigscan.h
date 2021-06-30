#pragma once
#include <Windows.h>
#include <Psapi.h>
#pragma comment (lib, "Psapi.lib")
#include <io.h>
#include <fstream>
class SigScan
{
public:
	static MODULEINFO GetModuleInfo(const char* szModule)
	{
		MODULEINFO modinfo = { 0 };
		HMODULE hModule = GetModuleHandleA(szModule);
		if (hModule == 0) return modinfo;
		K32GetModuleInformation(GetCurrentProcess(), hModule, &modinfo, sizeof(MODULEINFO));
		return modinfo;
	}

	static inline DWORD FindPatternExplicit(DWORD base, DWORD size, const char* szPattern, const char* szMask)
	{
		printf("FindPatternExplicit: B-%08x, S-%d, P-%s, M-%s\n", base, size, szPattern, szMask);
		DWORD patternLength = (DWORD)strlen(szMask);
		
		for (DWORD i = 0; i < size - patternLength; i++)
		{
			bool found = true;
			for (DWORD j = 0; j < patternLength; j++)
			{
				found &= szMask[j] == '?' || szPattern[j] == *(char*)(base + i + j);
			}
			if (found)
			{
				return base + i;
			}
		}

		return NULL;
	}

	static DWORD FindPattern(const char* target_module, const char* pattern, const char* mask)
	{
		MODULEINFO mInfo = GetModuleInfo(target_module);
		DWORD base = (DWORD)mInfo.lpBaseOfDll;
		DWORD size = (DWORD)mInfo.SizeOfImage;
		return FindPatternExplicit(base, size, pattern, mask);
	}

	static DWORD FindPattern(HMODULE hModule, const char* pattern, const char* mask)
	{
		MODULEINFO mInfo = { 0 };
		K32GetModuleInformation(GetCurrentProcess(), hModule, &mInfo, sizeof(MODULEINFO));
		DWORD base = (DWORD)mInfo.lpBaseOfDll;
		DWORD size = (DWORD)mInfo.SizeOfImage;
		return FindPatternExplicit(base, size, pattern, mask);
	}

private:
	static FILE* OpenFileCHandleFromNative(HANDLE hNativeHandle, const char* szMode)
	{
		return _fdopen(_open_osfhandle((intptr_t)hNativeHandle, 0), szMode);
	}

public:

	enum FileScanResult
	{
		FSCAN_STATUS_FAIL,
		FSCAN_STATUS_NOT_FOUND,
		FSCAN_STATUS_FOUND
	};

	static FileScanResult FindPatternFileWin(HANDLE hFile, const char* szPattern, const char* szMask)
	{
		LARGE_INTEGER liSize;
		GetFileSizeEx(hFile, &liSize);
		__int64 llSize = liSize.QuadPart;
		if (llSize < 1)
		{
			return FSCAN_STATUS_FAIL;
		}
		
		DWORD patternLength = (DWORD)strlen(szMask);
		if (patternLength > llSize)
		{
			return FSCAN_STATUS_FAIL;
		}

		constexpr size_t chunkSize = 1024 * 1024; // 1 MB
		unsigned char* pChunk;
		try
		{
			pChunk = new unsigned char[chunkSize];
		} catch (std::bad_alloc) {
			return FSCAN_STATUS_FAIL;
		}

		DWORD patternIndex = 0;
		DWORD matchedBytes = 0;
		bool  chunkTransitionBegin = false;
		bool  chunkTransitionBeingHandled = false;
		DWORD bytesRead = 0;

		int dbgreadcalls = 0;
		while (ReadFile(hFile, pChunk, chunkSize, &bytesRead, 0))
		{
			dbgreadcalls++;
			if (bytesRead < 1)
			{
				delete[] pChunk;
				return FSCAN_STATUS_NOT_FOUND;
			}

			for (long i = 0; i < bytesRead; i++)
			{
				for (; patternIndex < patternLength; patternIndex++)
				{
					if ((i + patternIndex) >= bytesRead && matchedBytes)
					{
						chunkTransitionBegin = true;
						break;
					}
					else if ((i + patternIndex) >= bytesRead) continue;
					if (chunkTransitionBegin || chunkTransitionBeingHandled)
					{
						chunkTransitionBegin = false; chunkTransitionBeingHandled = true;
						static DWORD j = 0;
						if (szMask[patternIndex] != '?' && szPattern[patternIndex] == *(char*)(pChunk + i + j)) matchedBytes++;
						else if (szMask[patternIndex] != '?' && szPattern[patternIndex] != *(char*)(pChunk + i + j)) matchedBytes = 0;
						j++;
					}
					else
					{
						if (szMask[patternIndex] != '?' && szPattern[patternIndex] == *(char*)(pChunk + i + patternIndex)) matchedBytes++;
						else if (szMask[patternIndex] != '?' && szPattern[patternIndex] != *(char*)(pChunk + i + patternIndex)) matchedBytes = 0;
					}
				}

				if (chunkTransitionBegin) break;
				else if (matchedBytes == patternLength && patternIndex == patternLength)
				{
					delete[] pChunk;
					return FSCAN_STATUS_FOUND;
				}
				if (chunkTransitionBeingHandled)
				{
					i = -1;
					chunkTransitionBeingHandled = false;
				}
				patternIndex = 0;
			}
		}

		if (dbgreadcalls == 0)
		{
			delete[] pChunk;
			return FSCAN_STATUS_FAIL;
		}

		delete[] pChunk;
		return FSCAN_STATUS_NOT_FOUND;
	}
};