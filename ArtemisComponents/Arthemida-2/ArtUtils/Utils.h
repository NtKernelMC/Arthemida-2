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
#pragma intrinsic(_ReturnAddress)
#include "../../Arthemida-2/ArtUtils/CRC32.h"
#include "../../Arthemida-2/ArtUtils/sigscan.h"
class Utils
{
public:
	static void LogInFile(const char* log_name, const char* log, ...)
	{
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
	// Выстраивает и возвращает список базовых адресов загруженных в процесс модулей и их размера
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
	// Генерация CRC32 хеша файла
	static DWORD GenerateCRC32(const std::string filePath)
	{
		if (filePath.empty()) return 0x0;
		auto getFileSize = [](FILE* file) -> long
		{
			long lCurPos, lEndPos;
			lCurPos = ftell(file);
			fseek(file, 0, 2);
			lEndPos = ftell(file);
			fseek(file, lCurPos, 0);
			return lEndPos;
		};
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
	// Поиск субстринга без case-sensevity
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
	static std::string GetDllName(char* szDllNameTmp)
	{
		char szDllName[300]; memset(szDllName, 0, sizeof(szDllName));
		strcpy(szDllName, szDllNameTmp);
		char fname[256]; char* ipt = strrchr(szDllName, '\\');
		memset(fname, 0, sizeof(fname));
		strdel(szDllName, 0, (ipt - szDllName + 1));
		strncpy(fname, szDllName, strlen(szDllName));
		std::string ProcName(fname);
		return ProcName;
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
		CHAR szFileName[MAX_PATH + 1];
		GetModuleFileNameA(MDL, szFileName, MAX_PATH + 1);
		char fname[256]; char* ipt = strrchr(szFileName, '\\');
		memset(fname, 0, sizeof(fname));
		strdel(szFileName, 0, (ipt - szFileName + 1));
		strncpy(fname, szFileName, strlen(szFileName));
		for (DWORD x = 0; x < strlen(fname); x++) fname[x] = tolower(fname[x]);
		return std::string(fname);
	};
	static std::vector<std::string> GenerateModuleNamesList()
	{
		HMODULE hMods[1024]; DWORD cbNeeded; std::vector<std::string> MdlList;
		typedef BOOL(__stdcall* PtrEnumProcessModules)(HANDLE hProcess, HMODULE* lphModule, DWORD cb, LPDWORD lpcbNeeded);
		PtrEnumProcessModules EnumProcModules =
		(PtrEnumProcessModules)GetProcAddress(LoadLibraryA("psapi.dll"), "EnumProcessModules");
		EnumProcModules(GetCurrentProcess(), hMods, sizeof(hMods), &cbNeeded);
		for (unsigned int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++)
		{
			MdlList.push_back(GetMdlNameFromHmodule(hMods[i]));
		}
		return MdlList;
	}
	static std::string GetNameOfModuledAddressSpace(PVOID addr, std::vector<std::string> mdls)
	{
		if (addr == nullptr || mdls.empty()) return std::string("EMPTY");
		typedef BOOL(__stdcall* GetMdlInfoP)(HANDLE hProcess, HMODULE hModule, LPMODULEINFO lpmodinfo, DWORD cb);
		GetMdlInfoP GetMdlInfo = (GetMdlInfoP)GetProcAddress(LoadLibraryA("psapi.dll"), "GetModuleInformation");
		for (const auto& it : mdls)
		{
			MODULEINFO modinfo; GetMdlInfo(GetCurrentProcess(), GetModuleHandleA(it.c_str()), &modinfo, sizeof(modinfo));
			if ((DWORD_PTR)addr >= (DWORD_PTR)modinfo.lpBaseOfDll
			&& (DWORD_PTR)addr <= ((DWORD_PTR)modinfo.lpBaseOfDll + modinfo.SizeOfImage))
			{
				return GetMdlNameFromHmodule((HMODULE)modinfo.lpBaseOfDll);
			}
		}
		return std::string("UNKNOWN");
	}
	static bool CheckCRC32(HMODULE mdl, std::multimap<DWORD, std::string>& ModuleSnapshot)
	{
		if (mdl == nullptr) return false;
		CHAR szFileName[MAX_PATH + 1]; GetModuleFileNameA(mdl, szFileName, MAX_PATH + 1);
		DWORD CRC32 = GenerateCRC32(szFileName); std::string DllName = GetDllName(szFileName);
		if (SearchForSingleMultiMapMatch2(ModuleSnapshot, 0x0, DllName, true) &&
		SearchForSingleMultiMapMatch2(ModuleSnapshot, CRC32, "", false))
		{
			std::multimap<std::string, DWORD> tmpModuleSnapshot;
			for (const auto& it : ModuleSnapshot)
			{
				tmpModuleSnapshot.insert(tmpModuleSnapshot.begin(), std::pair<std::string, DWORD>(it.second, it.first));
			}
			if (tmpModuleSnapshot.count(DllName) == 0x1) return true;
		}
		else
		{
			ModuleSnapshot.insert(ModuleSnapshot.begin(), std::pair<DWORD, std::string>(CRC32, DllName));
			return true;
		}
		return false;
	}
	// Функция для дампа экспортов указанного модуля (hModule) в ExportsList
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
				IMAGE_EXPORT_DIRECTORY* iedExportDirectory = reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(lpBase + inhNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
				for (unsigned int uiIter = 0; uiIter < iedExportDirectory->NumberOfFunctions; ++uiIter)
				{
					unsigned short usOrdinal = reinterpret_cast<unsigned short*>(lpBase + iedExportDirectory->AddressOfNameOrdinals)[uiIter];
					char ordNum[25]; memset(ordNum, 0, sizeof(ordNum)); sprintf(ordNum, "Ordinal: %d | 0x%X", usOrdinal, usOrdinal);
					ExportsList.insert(ExportsList.begin(), std::pair<PVOID, std::string>((PVOID)usOrdinal, ordNum));
				}
			}
		}
#endif  
	}
};