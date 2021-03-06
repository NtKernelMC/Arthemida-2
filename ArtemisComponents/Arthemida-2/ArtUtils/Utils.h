/*
	Artemis-2 for MTA Province
	Target Platform: x32-x86 (VC19 IDE)
	Minimal required standart C++17
	Project by NtKernelMC & holmes0
*/
#pragma once
#ifndef _SILENCE_CXX17_CODECVT_HEADER_DEPRECATION_WARNING
#define _SILENCE_CXX17_CODECVT_HEADER_DEPRECATION_WARNING
#endif
#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#pragma warning(disable : 4244)
#pragma warning(disable : 4018)
#ifndef ARTEMIS_USER_INTERACTIONS
#define ARTEMIS_USER_INTERACTIONS
#endif
//#define ARTEMIS_DEBUG
//#ifdef ARTEMIS_DEBUG
#define ARTEMIS_LOG "!0_ArtemisDebug.log"
//#endif
#include <Windows.h>
#include <stdio.h>
#include <thread>
#include <vector>
#include <chrono>
#include <string>
#include <map>
#include <set>
#include <tuple>
#include <algorithm>
#include <winternl.h>
#include <TlHelp32.h>
#include <Psapi.h>
#include <codecvt>
#include <conio.h>
#include <intrin.h>
#include <cwctype>
#include <dbghelp.h>
#pragma comment(lib, "dbghelp.lib")
#pragma intrinsic(_ReturnAddress)
#include "CRC32.h"
#include "sigscan.h"
#include "MiniJumper.h"
#include "WinReg.hpp"
// Hooks Data
static DWORD memTramplin = NULL; static BYTE Prolog[5];
// Multi-threaded control for module parser
static std::map<DWORD, DWORD> orderedMapping; // global module runtime list (PE Image Info)
static std::map<DWORD, std::wstring> orderedIdentify; // global module runtime list (Identify Info)
// Windows Legacy Mode Support for Win7
typedef void(__stdcall* PtrLdrInitializeThunk)(PCONTEXT Context);
typedef BOOL(__stdcall* PtrIfFileProtected)(HANDLE sfRPC, LPCWSTR fPath);
typedef BOOL(__stdcall* PtrEnumProcessModules)(HANDLE hProcess, HMODULE* lphModule, DWORD cb, LPDWORD lpcbNeeded);
typedef BOOL(__stdcall* GetMdlInfoP)(HANDLE hProcess, HMODULE hModule, LPMODULEINFO lpmodinfo, DWORD cb);
typedef DWORD(__stdcall* LPFN_GetMappedFileNameA)(HANDLE hProcess, LPVOID lpv, LPCSTR lpFilename, DWORD nSize);
typedef NTSTATUS(__stdcall* tNtQueryInformationThread)(HANDLE ThreadHandle, THREADINFOCLASS ThreadInformationClass,
PVOID ThreadInformation, ULONG ThreadInformationLength, PULONG ReturnLength);
static PtrIfFileProtected CheckIfFileProtected = nullptr;
static PtrEnumProcessModules EnumProcModules = nullptr;
static GetMdlInfoP GetMdlInfo = nullptr;
static LPFN_GetMappedFileNameA lpGetMappedFileNameA = nullptr;
static tNtQueryInformationThread pNtQueryInformationThread = nullptr;
static PtrLdrInitializeThunk callLdrInitializeThunk = nullptr;
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Macro utils

// Check bitmask in any integer type larger than unsigned char
#define BITMASK_CHECK(value, mask) (bool)((value & mask) == mask)

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
class Utils
{
public:
	typedef enum _THREAD_INFORMATION_CLASS
	{


		ThreadBasicInformation,
		ThreadTimes,
		ThreadPriority,
		ThreadBasePriority,
		ThreadAffinityMask,
		ThreadImpersonationToken,
		ThreadDescriptorTableEntry,
		ThreadEnableAlignmentFaultFixup,
		ThreadEventPair,
		ThreadQuerySetWin32StartAddress,
		ThreadZeroTlsCell,
		ThreadPerformanceCount,
		ThreadAmILastThread,
		ThreadIdealProcessor,
		ThreadPriorityBoost,
		ThreadSetTlsArrayAddress,
		ThreadIsIoPending,
		ThreadHideFromDebugger,
		ThreadBreakOnTermination
	} THREAD_INFORMATION_CLASS, *PTHREAD_INFORMATION_CLASS;
	static BOOL SetPrivilege(HANDLE hToken, LPCTSTR lpszPrivilege, BOOL bEnablePrivilege)
	{
		TOKEN_PRIVILEGES tp = { 0 }; LUID luid { 0 };
		if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) return false;
		if (!LookupPrivilegeValueA(0, lpszPrivilege, &luid)) return false;
		tp.PrivilegeCount = 1; tp.Privileges[0].Luid = luid;
		if (bEnablePrivilege) tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
		else tp.Privileges[0].Attributes = 0;
		if (!AdjustTokenPrivileges(hToken, 0, &tp, sizeof(tp), 0, 0)) return false;
		return true;
	}
	static std::string CvWideToAnsi(const std::wstring& wstr)
	{
		using convert_typeX = std::codecvt_utf8<wchar_t>;
		std::wstring_convert<convert_typeX, wchar_t> converterX;

		return converterX.to_bytes(wstr);
	}

	static std::wstring CvAnsiToWide(const std::string& str)
	{
		using convert_typeX = std::codecvt_utf8<wchar_t>;
		std::wstring_convert<convert_typeX, wchar_t> converterX;

		return converterX.from_bytes(str);
	}
	static void LogInFile(const char* log_name, const char* log, ...)
	{
		static bool per_once = false;
		if (!per_once)
		{
			DeleteFileA(log_name);
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
	static LPMODULEINFO GetModuleMemoryInfo(const HMODULE Addr)
	{
		if (Addr == nullptr) return nullptr;
		static MODULEINFO modinfo = { 0 }; ZeroMemory(&modinfo, sizeof(MODULEINFO));
		__try
		{
			if (GetMdlInfo(GetCurrentProcess(), Addr, &modinfo, sizeof(MODULEINFO))) return &modinfo;
		}
		__except (EXCEPTION_EXECUTE_HANDLER) 
		{
#ifdef ARTEMIS_DEBUG
			Utils::LogInFile(ARTEMIS_LOG, "[SEH] 0x%X from GetModuleMemoryInfo!\n", GetExceptionCode());
#endif
		}
		return nullptr;
	}
	static bool IsInModuledAddressSpace(const PVOID addr, std::vector<std::string> &mdls) 
	{
		if (addr == nullptr || mdls.empty()) return false;
		for (const auto& it : mdls)
		{
			HMODULE mhdl = GetModuleHandleA(it.c_str());
			if (mhdl == nullptr) continue;
			LPMODULEINFO modinfo = GetModuleMemoryInfo(mhdl);
			if (modinfo != nullptr)
			{
				if ((DWORD)addr >= (DWORD)modinfo->lpBaseOfDll
				&& (DWORD)addr <= ((DWORD)modinfo->lpBaseOfDll + modinfo->SizeOfImage))
				{
					return true;
				}
			}
		}
		return false;
	}
	static BOOL OsProtectedFile(LPCWSTR fPath)
	{
		if (fPath == nullptr) return FALSE;
		return CheckIfFileProtected(NULL, fPath);
	}
	static bool IsModuleDuplicated(/*in*/const HMODULE mdl, /*out*/std::wstring& full_path,
	/*in*/std::map<DWORD, std::wstring>& ModuleSnapshot, /*out*/std::wstring& nameOfDll)
	{
		if (mdl == nullptr || ModuleSnapshot.empty()) return false;
		WCHAR wszFileName[MAX_PATH + 1]; 
		if (!GetModuleFileNameW(mdl, wszFileName, MAX_PATH + 1)) return false;
		std::wstring DllName = GetDllName(wszFileName); 
		nameOfDll = DllName; 
		full_path = wszFileName; 
		for (const auto& it_snap : ModuleSnapshot) // parsing the list (Primary key: CRC32, Value: Library name)
		{
			if (!w_findStringIC(it_snap.second, DllName)) continue; // We don`t need to check CRC32, it`s the unique key for map!
			else // if any of value's will match - then we got a suspected :)
			{
				// reversed list with values to -> keys order, multimap doesn`t have the limit of duplicated keys.
				std::multimap<std::wstring, DWORD> tmpModuleSnapshot; // here might be only two pairs of duplicated keys.
				for (const auto& it : ModuleSnapshot) // let`s gonna copy all in new order, cuz multimap/map can check only key!
				{
					// as map can accept duplicated values but our hashes always unique, so just swap the args!
					tmpModuleSnapshot.insert(std::pair<std::wstring, DWORD>(it.second, it.first));
				}
				size_t count = 0;
				for (const auto& it : tmpModuleSnapshot)
				{
					if (w_findStringIC(it.first, DllName)) count++;
				}
				// if we found at least one duplicated pair and more..
				if (count >= 0x2) return true;
				// searching of duplicate's, can be only by keys (there no way to do it with values)
			}
		}
		return false;
	}
	static decltype(auto) GetLibNameFromHandle(const HMODULE MDL, std::string dll_path = "")
	{
		if (MDL == nullptr) return std::string("");
		if (dll_path.empty())
		{
			CHAR szFileName[MAX_PATH + 1]; GetModuleFileNameA(MDL, szFileName, MAX_PATH + 1);
			std::string tmpStr(szFileName); return tmpStr.substr(tmpStr.find_last_of("/\\") + 1);
		}
		return dll_path.substr(dll_path.find_last_of("/\\") + 1);
	};
	static bool __stdcall IsMemoryInModuledRange(const DWORD base, const std::string& mapped_name, bool *cloacking = nullptr)
	{
		if (base == NULL) return false;
		for (const auto& it : orderedMapping)
		{
			if (base >= it.first && base <= (it.first + it.second)) return true;
		}
		if (!mapped_name.empty() && mapped_name.length() > 4) 
		{ 
			if ((DWORD)GetModuleHandleA(mapped_name.c_str()) == base) return true; 
			else { if (cloacking != nullptr) *cloacking = true; }
		}
		return false;
	}
	static void __stdcall BuildModuledMemoryMap(HANDLE hProc = GetCurrentProcess())
	{
		HMODULE hMods[1024] { nullptr }; DWORD cbNeeded = NULL;
		if (EnumProcModules(hProc, hMods, sizeof(hMods), &cbNeeded))
		{
			DWORD MdlCount = (cbNeeded / sizeof(HMODULE));
			for (unsigned int i = 0; i < MdlCount; i++)
			{
				if (hMods[i] == nullptr) continue;
				LPMODULEINFO modinfo = GetModuleMemoryInfo(hMods[i]);
				if (modinfo != nullptr)
				{
					if (orderedMapping.count((DWORD)modinfo->lpBaseOfDll) != 0x1)
					{
						orderedMapping.insert(std::pair<DWORD, DWORD>((DWORD)modinfo->lpBaseOfDll, modinfo->SizeOfImage));
						WCHAR wszFileName[MAX_PATH + 1]; if (!GetModuleFileNameW((HMODULE)
						modinfo->lpBaseOfDll, wszFileName, MAX_PATH + 1)) return;
						DWORD CRC32 = GenerateCRC32(wszFileName, nullptr); 
						std::wstring DllName = GetDllName(wszFileName);
						if (orderedIdentify.count(CRC32) != 0x1) orderedIdentify.insert(orderedIdentify.begin(),
						std::pair<DWORD, std::wstring>(CRC32, DllName));
					}
				}
			}
		}
	}
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
	static DWORD GenerateCRC32(const std::string& filePath, DWORD *FileSize)
	{
		if (filePath.empty()) return 0x0;
		FILE* hFile = fopen(filePath.c_str(), "rb");
		if (hFile == nullptr) return 0x0;
		BYTE* fileBuf = nullptr;
		DWORD fileSize = getFileSize(hFile);
		if (FileSize != nullptr) *FileSize = fileSize;
		fileBuf = new BYTE[fileSize];
		fread(fileBuf, fileSize, 1, hFile);
		fclose(hFile); DWORD crc = CRC::Calculate(fileBuf, fileSize, CRC::CRC_32());
		delete[] fileBuf; return crc;
	}
	static DWORD GenerateCRC32(const std::wstring& wfilePath, DWORD* FileSize)
	{
		if (wfilePath.empty()) return 0x0;
		FILE* hFile = _wfopen(wfilePath.c_str(), L"rb");
		if (hFile == nullptr) return 0x0;
		BYTE* fileBuf = nullptr;
		DWORD fileSize = getFileSize(hFile);
		if (FileSize != nullptr) *FileSize = fileSize;
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
	template <typename T, typename T2>
	static const bool Contains(std::vector<T>& Vec, T2& Element)
	{
		if (Vec.empty()) return false;
		for (const auto& it : Vec)
		{
			if (it == Element) return true;
		}
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
		[](wchar_t ch1, wchar_t ch2) { return std::towupper(ch1) == std::towupper(ch2); });
		return (it != strHaystack.end());
	}
	static std::string GetDllName(std::string szDllNameTmp)
	{
		if (szDllNameTmp.empty()) return szDllNameTmp;
		return szDllNameTmp.substr(szDllNameTmp.find_last_of("/\\") + 1);
	}
	static std::wstring GetDllName(std::wstring wszDllNameTmp)
	{
		if (wszDllNameTmp.empty()) return wszDllNameTmp;
		return wszDllNameTmp.substr(wszDllNameTmp.find_last_of(L"/\\") + 1);
	}
	template<typename S, typename E>
	static bool IsVecContain(const std::vector<S>& source, const E element)
	{
		if (source.empty() || element == NULL) return false;
		for (decltype(auto) it : source)
		{
			if (it == element) return true;
		}
		return false;
	}
	static void TraverseEAT(const HMODULE hModule, std::map<PVOID, std::string>& ExportsList)
	{
		if (hModule == nullptr) return;
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

	/**
	*  Example: splits 1500 into vector of 500, 500, 500 for 3 threads
	*  Example 2: splits 1631 into vector of 407, 408, 408, 408 for 4 threads
	*  In case if objects won't evenly split, more are given to last threads and less to first
	*/
	static std::vector<int> SplitObjectsForThreading(unsigned int uiObjectCount, unsigned int uiThreadCount)
	{
		std::vector<int> parts;

		for (int i = 0; i < uiThreadCount; i++)
		{
			parts.push_back(uiObjectCount / uiThreadCount);
		}

		for (int i = 0; i < (uiObjectCount % uiThreadCount); i++)
		{
			*(parts.rbegin() + i) += 1;
		}

		return parts;
	}

private:
	static void DispatchUserMessageEndPoint(const char* szMessage)
	{
		MessageBoxA(GetActiveWindow(), szMessage, "MTA Province", MB_OK | MB_ICONINFORMATION);
	}

	static void DispatchUserMessageEndPoint(const wchar_t* wszMessage)
	{
		MessageBoxW(GetActiveWindow(), wszMessage, L"MTA Province", MB_OK | MB_ICONINFORMATION);
	}

public:
	static void DispatchUserMessage(const char* szFormat, ...)
	{
		va_list vl;
		va_start(vl, szFormat);

		va_list vlc;
		va_copy(vlc, vl);
		int iRequiredCapacity = _vscprintf(szFormat, vlc);
		if (iRequiredCapacity < 1) return;
		char* szDest = new char[iRequiredCapacity + 2];
		va_copy(vlc, vl);
		int iSize = vsnprintf(szDest, iRequiredCapacity + 1, szFormat, vlc);
		if (iSize < 1) return;
		else szDest[iSize] = '\0';

		DispatchUserMessageEndPoint(szDest);

		delete[] szDest;
		va_end(vl);
	}

	static void DispatchUserMessage(const wchar_t* wszFormat, ...)
	{
		va_list vl;
		va_start(vl, wszFormat);

		va_list vlc;
		va_copy(vlc, vl);
		int iRequiredCapacity = _vscwprintf(wszFormat, vlc);
		if (iRequiredCapacity < 1) return;
		wchar_t* wszDest = new wchar_t[iRequiredCapacity + 2];
		va_copy(vlc, vl);
		int iSize = _vsnwprintf(wszDest, iRequiredCapacity + 1, wszFormat, vlc);
		if (iSize < 1) return;
		else wszDest[iSize] = L'\0';

		DispatchUserMessageEndPoint(wszDest);

		delete[] wszDest;
		va_end(vl);
	}
};
