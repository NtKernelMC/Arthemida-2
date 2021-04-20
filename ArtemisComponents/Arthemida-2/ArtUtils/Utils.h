/*
	Artemis-2 for MTA Province
	Target Platform: x32-x86 (VC19 IDE)
	Minimal required standart C++20
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
#include <semaphore>
#include <vector>
#include <string>
#include <map>
#include <tuple>
#include <algorithm>
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
// Multi-threaded control for module parser
static bool dllsListFilled = false;
static std::multimap<PVOID, DWORD> orderedMapping; // global module runtime list (PE Image Info)
static std::multimap<DWORD, std::string> orderedIdentify; // global module runtime list (Identify Info)
static std::binary_semaphore fireSignal(0); // C++20 CODE! (Semaphores like Mutexes but fully independent of thread binding.)
// Hooks Data
static BYTE ldrLoad[5], ldrUnload[5];
static DWORD fTr1 = 0x0, fTr2 = 0x0;
// Windows Legacy Mode Support for Win7
typedef BOOL(__stdcall* PtrEnumProcessModules)(HANDLE hProcess, HMODULE* lphModule, DWORD cb, LPDWORD lpcbNeeded);
typedef BOOL(__stdcall* GetMdlInfoP)(HANDLE hProcess, HMODULE hModule, LPMODULEINFO lpmodinfo, DWORD cb);
typedef DWORD(__stdcall* LPFN_GetMappedFileNameA)(HANDLE hProcess, LPVOID lpv, LPCSTR lpFilename, DWORD nSize);
typedef NTSTATUS(__stdcall* tNtQueryInformationThread)(HANDLE ThreadHandle, THREADINFOCLASS ThreadInformationClass, 
PVOID ThreadInformation, ULONG ThreadInformationLength, PULONG ReturnLength);
static PtrEnumProcessModules EnumProcModules = nullptr;
static GetMdlInfoP GetMdlInfo = nullptr;
static LPFN_GetMappedFileNameA lpGetMappedFileNameA = nullptr;
static tNtQueryInformationThread pNtQueryInformationThread = nullptr;
/////////////////////////////////////////////
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
	static decltype(auto) RuntimeIatResolver(const std::string& libra, const std::string& func_name)
	{
		decltype(auto) UnresolvedError = [&libra, &func_name](bool empty_args = false) -> PVOID
		{
#ifdef ARTEMIS_DEBUG
			if (empty_args) Utils::LogInFile(ARTEMIS_LOG, "[RESOLVER] IAT filler failure! EMPTY ARGS.\n");
			else Utils::LogInFile(ARTEMIS_LOG, "[RESOLVER] IAT filler failure %s || %s\n", libra.c_str(), func_name.c_str());
#endif
			return nullptr;
		}; 
		if (libra.empty() || func_name.empty()) UnresolvedError(true);
		PVOID handla = (PVOID)LoadLibraryA(libra.c_str());
		if (handla == nullptr) return UnresolvedError();
		PVOID apiSha = (PVOID)GetProcAddress((HMODULE)handla, func_name.c_str());
		if (apiSha == nullptr) return UnresolvedError();
		return apiSha;
	}
	static LPMODULEINFO GetModuleMemoryInfo(HMODULE Addr)
	{
		if (Addr == nullptr) return NULL;
		static MODULEINFO modinfo = { 0 }; DWORD cbs = NULL;
		if (GetMdlInfo(GetCurrentProcess(), Addr, &modinfo, cbs)) return &modinfo;
		return NULL;
	}
	static bool IsInModuledAddressSpace(PVOID addr, std::vector<std::string>& mdls)
	{
		if (addr == nullptr || mdls.empty()) return false;
		for (const auto& it : mdls)
		{
			LPMODULEINFO modinfo = GetModuleMemoryInfo((HMODULE)addr);
			if (modinfo != nullptr)
			{
				if ((DWORD_PTR)addr >= (DWORD_PTR)modinfo->lpBaseOfDll
				&& (DWORD_PTR)addr <= ((DWORD_PTR)modinfo->lpBaseOfDll + modinfo->SizeOfImage))
				{
					return true;
				}
			}
		}
		return false;
	}
	static bool IsModuleDuplicated(HMODULE mdl, std::multimap<DWORD, std::string>& ModuleSnapshot)
	{
		if (mdl == nullptr || ModuleSnapshot.empty()) return false;
		CHAR szFileName[MAX_PATH + 1]; if (!GetModuleFileNameA(mdl, szFileName, MAX_PATH + 1)) return false;
		DWORD CRC32 = GenerateCRC32(szFileName); std::string DllName = GetDllName(szFileName);
		for (const auto& it_snap : ModuleSnapshot) // parsing the list (Primary key: CRC32, Value: Library name)
		{
			if (it_snap.first != CRC32 && !findStringIC(it_snap.second, DllName)) continue;
			else // if anyone of those data will match - then we got a suspected :)
			{
				std::multimap<std::string, DWORD> tmpModuleSnapshot; // reverse roles of key & value
				for (const auto& it : ModuleSnapshot)
				{
					tmpModuleSnapshot.insert(std::pair<std::string, DWORD>(it.second, it.first));
				}
				if (tmpModuleSnapshot.count(DllName) > 0x0) return true;
			}
		}
		ModuleSnapshot.insert(ModuleSnapshot.begin(), std::pair<DWORD, std::string>(CRC32, DllName)); 
		// legit module or yet not analyzed so good )
		return false;
	}
	static void __stdcall BuildModuledMemoryMap(void)
	{
		if (!dllsListFilled) 
		{ // let`s parse it only one times, cuz we need to know wich exactly modules was loaded before us
			fireSignal.acquire(); HMODULE hMods[1024]; DWORD cbNeeded = NULL;
			if (EnumProcModules(GetCurrentProcess(), hMods, sizeof(hMods), &cbNeeded))
			{
				for (unsigned int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++)
				{
					if (hMods[i] == nullptr) continue;
					LPMODULEINFO modinfo = GetModuleMemoryInfo(hMods[i]);
					if (modinfo != nullptr) orderedMapping.insert(std::pair<PVOID, DWORD>
					(modinfo->lpBaseOfDll, modinfo->SizeOfImage));
				}
			} // now - we can obtain a fresh lists at the run-time, big advantage for speed perfomance
			dllsListFilled = true; fireSignal.release();
		}
	}
	static bool __stdcall IsMemoryInModuledRange(PVOID base)
	{
		if (base == nullptr) return false; 
		fireSignal.acquire(); for (const auto& it : orderedMapping)
		{
			if (base >= it.first && base <= (PVOID)((DWORD)it.first + it.second)) return true;
		}  
		fireSignal.release();
		return false;
	}
	static decltype(auto) GetLibNameFromHandle(HMODULE MDL)
	{
		if (MDL == nullptr) return std::string("");
		CHAR szFileName[MAX_PATH + 1]; GetModuleFileNameA(MDL, szFileName, MAX_PATH + 1);
		std::string tmpStr(szFileName); return tmpStr.substr(tmpStr.find_last_of("/\\") + 1);
	};
	static long getFileSize(FILE* file)
	{
		if (file == nullptr) return 0x0;
		long lCurPos, lEndPos;
		lCurPos = ftell(file);
		fseek(file, 0, 2);
		lEndPos = ftell(file);
		fseek(file, lCurPos, 0);
		return lEndPos;
	}
	static DWORD GenerateCRC32(const std::string& filePath)
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
	static bool SearchForSingleMapMatch(const std::map<First, Second>& map, const First& key)
	{
		if (map.empty()) return false;
		for (const auto &it : map)
		{
			if (it.first == key) return true;
		}
		return false;
	}
	template <typename T>
	static const bool Contains(std::vector<T>& Vec, const T& Element)
	{
		if (Vec.empty()) return false;
		if (std::find(Vec.begin(), Vec.end(), Element) != Vec.end()) return true;
		return false;
	}
	static std::string SearchForSingleMapMatchAndRet(const std::map<PVOID, const char*>& map, const PVOID key)
	{
		if (map.empty() || key == nullptr) return std::string("");
		for (const auto &it : map)
		{
			if (it.first == key) return it.second;
		}
		return std::string("");
	}
	// overloading, unfortunally templates doesn`t works with std::basic_string container
	static bool findStringIC(const std::string& strHaystack, const std::string& strNeedle)
	{
		auto it = std::search(strHaystack.begin(), strHaystack.end(),
		strNeedle.begin(), strNeedle.end(),
		[](char ch1, char ch2) { return std::toupper(ch1) == std::toupper(ch2); });
		return (it != strHaystack.end());
	}
	static bool w_findStringIC(const std::wstring& strHaystack, const std::wstring& strNeedle)
	{
		auto it = std::search(strHaystack.begin(), strHaystack.end(),
		strNeedle.begin(), strNeedle.end(),
		[](wchar_t ch1, wchar_t ch2) { return std::toupper(ch1) == std::toupper(ch2); });
		return (it != strHaystack.end());
	}
	static std::string GetDllName(const std::string& szDllNameTmp)
	{
		if (szDllNameTmp.empty()) return szDllNameTmp;
		return szDllNameTmp.substr(szDllNameTmp.find_last_of("/\\") + 1);
	}
	static bool IsVecContain(const std::vector<PVOID>& source, PVOID element)
	{
		if (element == nullptr || source.empty()) return false;
		for (const auto &it : source)
		{
			if (it == element) return true;
		}
		return false;
	}
	static void TraverseEAT(HMODULE hModule, std::multimap<PVOID, std::string>& ExportsList)
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