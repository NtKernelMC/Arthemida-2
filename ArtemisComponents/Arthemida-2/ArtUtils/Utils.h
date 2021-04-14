/*
	Artemis-2 for MTA Province
	Target Platform: x32-x86
	Project by NtKernelMC & holmes0
*/
#pragma once
#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#pragma warning(disable : 4244)
#pragma warning(disable : 4018)
#define ARTEMIS_DEBUG
#ifdef ARTEMIS_DEBUG
#define ARTEMIS_LOG "!0_ArtemisDebug.log"
#endif
#ifdef _WIN64
#define START_ADDRESS (PVOID)0x00000000010000
#define END_ADDRESS (0x00007FF8F2580000 - 0x00000000010000)
#else
#define START_ADDRESS (PVOID)0x10000
#define END_ADDRESS (0x7FFF0000 - 0x10000)
#endif
#include <Windows.h>
#include <stdio.h>
#include <thread>
#include <vector>
#include <string>
#include <map>
#include <tuple>
#include <winternl.h>
#include <TlHelp32.h>
#include <Psapi.h>
#include <conio.h>
#include <algorithm>
#include <intrin.h>
#pragma comment(lib, "Version.lib")
#pragma intrinsic(_ReturnAddress)
#include "../../Arthemida-2/ArtUtils/CRC32.h"
#include "../../Arthemida-2/ArtUtils/sigscan.h"
class Utils
{
public:
	static void LogInFile(const char* log_name, const char* log, ...)
	{
		static bool per_once = false;
		if (!per_once)
		{
			DeleteFileA(ARTEMIS_LOG);
			per_once = true;
		}
		FILE* hFile = fopen(log_name, "a+");
		if (hFile)
		{
			va_list arglist; va_start(arglist, log);
			vfprintf(hFile, log, arglist);
#ifdef _CONSOLE
			vprintf(log, arglist);
#endif
			fclose(hFile); va_end(arglist);
		}
	}
	static std::map<LPVOID, DWORD> __stdcall BuildModuledMemoryMap()
	{
		std::map<LPVOID, DWORD> memoryMap; HMODULE hMods[1024]; DWORD cbNeeded;
		typedef BOOL(__stdcall* PtrEnumProcessModules)(HANDLE hProcess, HMODULE* lphModule, DWORD cb, LPDWORD lpcbNeeded);
		PtrEnumProcessModules EnumProcModules = (PtrEnumProcessModules)
		GetProcAddress(LoadLibraryA("psapi.dll"), "EnumProcessModules");
		EnumProcModules(GetCurrentProcess(), hMods, sizeof(hMods), &cbNeeded);
		typedef BOOL(__stdcall* GetMdlInfoP)(HANDLE hProcess, HMODULE hModule, LPMODULEINFO lpmodinfo, DWORD cb);
		GetMdlInfoP GetMdlInfo = (GetMdlInfoP)GetProcAddress(LoadLibraryA("psapi.dll"), "GetModuleInformation");
		for (unsigned int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++)
		{
			MODULEINFO modinfo; GetMdlInfo(GetCurrentProcess(), hMods[i], &modinfo, sizeof(modinfo));
			memoryMap.insert(memoryMap.begin(), std::pair<LPVOID, DWORD>(modinfo.lpBaseOfDll, modinfo.SizeOfImage));
		}
		return memoryMap;
	}
	// 
	static bool __stdcall IsMemoryInModuledRange(LPVOID base)
	{
		std::map<LPVOID, DWORD> memory = BuildModuledMemoryMap();
		for (const auto& it : memory)
		{
			if (base >= it.first && base <= (LPVOID)((DWORD_PTR)it.first + it.second)) return true;
		}
		return false;
	}
	static long getFileSize(FILE* file)
	{
		long lCurPos, lEndPos;
		lCurPos = ftell(file);
		fseek(file, 0, 2);
		lEndPos = ftell(file);
		fseek(file, lCurPos, 0);
		return lEndPos;
	}
	static DWORD GenerateCRC32(const std::string filePath)
	{
		if (filePath.empty()) return 0x0;
		FILE* hFile = fopen(filePath.c_str(), "rb");
		if (hFile == nullptr) return 0x0;
		BYTE* fileBuf; long fileSize;
		fileSize = getFileSize(hFile);
		fileBuf = new BYTE[fileSize];
		fread(fileBuf, fileSize, 1, hFile);
		fclose(hFile); DWORD crc = CRC::Calculate(fileBuf, fileSize, CRC::CRC_32());
		delete[] fileBuf; return crc;
	}
	template<typename First, typename Second>
	static bool SearchForSingleMapMatch(const std::map<First, Second>& map, const First key)
	{
		for (auto it : map)
		{
			if (it.first == key) return true;
		}
		return false;
	}
	template <typename T>
	static const bool Contains(std::vector<T>& Vec, const T& Element)
	{
		if (std::find(Vec.begin(), Vec.end(), Element) != Vec.end()) return true;
		return false;
	}
	static std::string SearchForSingleMapMatchAndRet(const std::map<PVOID, const char*>& map, const PVOID key)
	{
		for (auto it : map)
		{
			if (it.first == key) return it.second;
		}
		return "EMPTY";
	}
	static bool findStringIC(const std::string& strHaystack, const std::string& strNeedle)
	{
		auto it = std::search(strHaystack.begin(), strHaystack.end(),
		strNeedle.begin(), strNeedle.end(),
		[](char ch1, char ch2) { return std::toupper(ch1) == std::toupper(ch2); });
		return (it != strHaystack.end());
	}
	// 
	static bool SearchForSingleMultiMapMatch2(const std::multimap<DWORD, std::string>& map, DWORD first, std::string second, bool firstOrSecond)
	{
		for (auto it : map)
		{
			if (findStringIC(it.second, second) && firstOrSecond) return true;
			if (it.first == first && !firstOrSecond) return true;
		}
		return false;
	}
	//
	static char* strdel(char* s, size_t offset, size_t count)
	{
		size_t len = strlen(s);
		if (offset > len) return s;
		if ((offset + count) > len) count = len - offset;
		strcpy(s + offset, s + offset + count);
		return s;
	}
	static __forceinline std::string GetDllName(const std::string& szDllNameTmp)
	{
		return szDllNameTmp.substr(szDllNameTmp.find_last_of("/\\") + 1);
	}
	static bool IsVecContain(const std::vector<PVOID>& source, PVOID element)
	{
		if (element == nullptr || source.empty()) return false;
		for (const auto it : source)
		{
			if (it == element) return true;
		}
		return false;
	}
	static bool IsVecContain2(const std::vector<std::string>& source, std::string element)
	{
		if (source.empty() || element.length() < 1) return false;
		for (const auto it : source)
		{
			if (it == element) return true;
		}
		return false;
	}
	static std::string GetMdlNameFromHmodule(HMODULE MDL)
	{
		if (MDL == nullptr) return std::string("UNKNOWN");
		CHAR szFileName[MAX_PATH + 1]; GetModuleFileNameA(MDL, szFileName, MAX_PATH + 1);
		std::string tmpStr(szFileName); return tmpStr.substr(tmpStr.find_last_of("/\\") + 1);
	};
	static std::vector<std::string> GenerateModuleNamesList()
	{
		HMODULE hMods[1024]; DWORD cbNeeded; std::vector<std::string> MdlList;
		typedef BOOL(__stdcall* PtrEnumProcessModules)(HANDLE hProcess, HMODULE* lphModule, DWORD cb, LPDWORD lpcbNeeded);
		PtrEnumProcessModules EnumProcModules =
		(PtrEnumProcessModules)GetProcAddress(LoadLibraryA("psapi.dll"), "EnumProcessModules");
		if (EnumProcModules(GetCurrentProcess(), hMods, sizeof(hMods), &cbNeeded))
		{
			for (unsigned int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++)
			{
				std::string mdl_nm = GetMdlNameFromHmodule(hMods[i]);
				if (mdl_nm.find("UNKNOWN") == std::string::npos) MdlList.push_back(mdl_nm);
			}
		}
		return MdlList;
	}
	static bool IsInModuledAddressSpace(PVOID addr, std::vector<std::string> &mdls)
	{
		if (addr == nullptr || mdls.empty()) return false;
		typedef BOOL(__stdcall* GetMdlInfoP)(HANDLE hProcess, HMODULE hModule, LPMODULEINFO lpmodinfo, DWORD cb);
		GetMdlInfoP GetMdlInfo = (GetMdlInfoP)GetProcAddress(LoadLibraryA("psapi.dll"), "GetModuleInformation");
		if (GetMdlInfo == nullptr) return false;
		for (const auto& it : mdls)
		{
			MODULEINFO modinfo = { 0 }; // make sure that no crashing with fcking magic way
			if (GetMdlInfo(GetCurrentProcess(), GetModuleHandleA(it.c_str()), &modinfo, sizeof(modinfo)))
			{
				if ((DWORD_PTR)addr >= (DWORD_PTR)modinfo.lpBaseOfDll
				&& (DWORD_PTR)addr <= ((DWORD_PTR)modinfo.lpBaseOfDll + modinfo.SizeOfImage))
				{
					return true;
				}
			}
		}
		return false;
	}
	static bool IsModuleDuplicated(HMODULE mdl, std::multimap<DWORD, std::string>& ModuleSnapshot)
	{
		if (mdl == nullptr) return false;
		CHAR szFileName[MAX_PATH + 1]; if (!GetModuleFileNameA(mdl, szFileName, MAX_PATH + 1)) return false;
		DWORD CRC32 = GenerateCRC32(szFileName); std::string DllName = GetDllName(szFileName);
		if (SearchForSingleMultiMapMatch2(ModuleSnapshot, 0x0, DllName, true) &&
		SearchForSingleMultiMapMatch2(ModuleSnapshot, CRC32, "", false))
		{
			std::multimap<std::string, DWORD> tmpModuleSnapshot;
			for (const auto& it : ModuleSnapshot)
			{
				tmpModuleSnapshot.insert(tmpModuleSnapshot.begin(), std::pair<std::string, DWORD>(it.second, it.first));
			}
			if (tmpModuleSnapshot.count(DllName) > 0x0) return true;
		}
		else
		{
			ModuleSnapshot.insert(ModuleSnapshot.begin(), std::pair<DWORD, std::string>(CRC32, DllName));
			return false;
		}
		return false;
	}
	static void DumpExportTable(HMODULE hModule, std::multimap<PVOID, std::string>& ExportsList)
	{
#if defined( _WIN32 )  
		unsigned char* lpBase = reinterpret_cast<unsigned char*>(hModule);
		IMAGE_DOS_HEADER* idhDosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(lpBase);
		if (idhDosHeader->e_magic == 0x5A4D)
		{
#if defined( _M_IX86 )  
			IMAGE_NT_HEADERS32* inhNtHeader = reinterpret_cast<IMAGE_NT_HEADERS32*>(lpBase + idhDosHeader->e_lfanew);
#elif defined( _M_AMD64 )  
			IMAGE_NT_HEADERS64* inhNtHeader = reinterpret_cast<IMAGE_NT_HEADERS64*>(lpBase + idhDosHeader->e_lfanew);
#endif  
			if (inhNtHeader->Signature == 0x4550)
			{
				IMAGE_EXPORT_DIRECTORY* iedExportDirectory = reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>
				(lpBase + inhNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
				for (unsigned int uiIter = 0; uiIter < iedExportDirectory->NumberOfFunctions; ++uiIter)
				{
					unsigned short usOrdinal = reinterpret_cast<unsigned short*>
					(lpBase + iedExportDirectory->AddressOfNameOrdinals)[uiIter];
					char ordNum[25]; memset(ordNum, 0, sizeof(ordNum)); 
					sprintf(ordNum, "Ordinal: %d | 0x%X", usOrdinal, usOrdinal);
					ExportsList.insert(ExportsList.begin(), std::pair<PVOID, std::string>((PVOID)usOrdinal, ordNum));
				}
			}
		}
#endif  
	}
};