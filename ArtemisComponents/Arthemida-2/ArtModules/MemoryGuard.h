#include "ArtemisInterface.h"

GameHooks::ptrLdrLoadDll GameHooks::callLdrLoadDll = nullptr;
std::map<PVOID, PVOID> GameHooks::HooksList;
NTSTATUS __stdcall GameHooks::LdrLoadDll(PWCHAR PathToFile, ULONG FlagsL, PUNICODE_STRING ModuleFileName, HMODULE* ModuleHandle)
{
    NTSTATUS rslt = callLdrLoadDll(PathToFile, FlagsL, ModuleFileName, ModuleHandle);
    std::wstring ModulePath(ModuleFileName->Buffer, ModuleFileName->Length);
    if (ModulePath.find(L"client.dll") != std::wstring::npos) // ���� client.dll ����������� - ������ ������� ����
    {
#ifdef ARTEMIS_DEBUG
        Utils::LogInFile(ARTEMIS_LOG, "[LdrLoadDll] client.dll module was been successfully loaded!\nInstalling game hooks...\n");
#endif
        InstallGameHooks(g_cfg); // ��������� ������� �����
    }
    return rslt;
}

// ��������� ���� �� LdrLoadDll ��� ����� �������� client.dll (������ ������ ���)
bool __stdcall GameHooks::InstallModuleHook(void)
{
    auto ErrorHook = [](const char* log) -> bool
    {
#ifdef ARTEMIS_DEBUG
        Utils::LogInFile(ARTEMIS_LOG, log);
#endif
        return false;
    };
    MH_STATUS mhs = MH_Initialize(); // ������������� ������� ��� ����������� ��������� �����
    if (mhs == MH_OK || mhs == MH_ERROR_ALREADY_INITIALIZED)
    {
        DWORD ldrAddr = (DWORD)GetProcAddress(GetModuleHandleA("ntdll.dll"), "LdrLoadDll");
        if (ldrAddr != NULL)
        {
            MH_STATUS mhs = MH_CreateHook((PVOID)ldrAddr, &LdrLoadDll, reinterpret_cast<PVOID*>(&callLdrLoadDll));
            if (mhs == MH_OK || mhs == MH_ERROR_ALREADY_CREATED)
            {
#ifdef ARTEMIS_DEBUG
                Utils::LogInFile(ARTEMIS_LOG, ARTEMIS_LDR_SUCCESS);
#endif
            }
            else return ErrorHook(ARTEMIS_LDR_ERROR);
        }
        else return ErrorHook(ARTEMIS_LDR_ERROR);
    }
    else return ErrorHook(ARTEMIS_LDR_ERROR3);
    MH_EnableHook(MH_ALL_HOOKS);
    return true;
};

bool __stdcall GameHooks::InstallGameHooks(ART_LIB::ArtemisLibrary::ArtemisConfig* cfg)
{
	if (cfg == nullptr) return false;
	if (!HooksList.empty()) HooksList.clear();
	if (cfg->DetectReturnAddresses) // ���� ������� ����� �������� ��������� ������ ��������� �� ������ ����-����
	{
		bool HookIntegrity = true;
		auto AddEventHandlerHook = [&HookIntegrity]() -> void
		{
			const char pattern[] = { "\x55\x8B\xEC\x56\x8B\x75\x0C\x85\xF6\x75\x06\x89\x35\x00\x00\x00\x00\x8B\x00\x00\x00\x00\x00\x56\xE8\x00\x00\x00\x00\x85\xC0\x74\x29" };
			const char mask[] = { "xxxxxxxxxxxxxxxxxx?????xx????xxxx" };
			DWORD Addr = SigScan::FindPattern("client.dll", pattern, mask);
			if (Addr != NULL)
			{
				HooksList.insert(std::pair<PVOID, PVOID>(AddEventHandler, (PVOID)Addr));
				MH_CreateHook((PVOID)Addr, &GameHooks::AddEventHandler, reinterpret_cast<PVOID*>(&GameHooks::callAddEventHandler));
#ifdef ARTEMIS_DEBUG
				Utils::LogInFile(ARTEMIS_LOG, "CStaticFunctionDefinitions::AddEventHandler Hook installed!\n");
#endif
			}
			else {
				HookIntegrity = false;
#ifdef ARTEMIS_DEBUG
				Utils::LogInFile(ARTEMIS_LOG, "CStaticFunctionDefinitions::AddEventHandler - Can`t find sig.\n");
#endif
			}
		};
		AddEventHandlerHook(); // ������������ �������� ��� ���������� ���������� �������
		
		
		auto ElementDataHook = [&HookIntegrity]() -> void
		{
			const char pattern[] = { "\x55\x8B\xEC\x6A\xFF\x68\x00\x00\x00\x00\x64\xA1\x00\x00\x00\x00\x50\x81\xEC\xB4\x00\x00\x00\xA1\x00\x00\x00\x00\x33\xC5\x89\x45\xF0\x56" };
			const char mask[] = { "xxxxxx????xxxxxxxxxxxxxx????xxxxxx" };
			DWORD Addr = SigScan::FindPattern("client.dll", pattern, mask);
			if (Addr != NULL)
			{
				HooksList.insert(std::pair<PVOID, PVOID>(SetCustomData, (PVOID)Addr));
				MH_CreateHook((PVOID)Addr, &GameHooks::SetCustomData, reinterpret_cast<PVOID*>(&GameHooks::ptrSetCustomData));
#ifdef ARTEMIS_DEBUG
				Utils::LogInFile(ARTEMIS_LOG, "CClientEntity::SetCustomData Hook installed!\n");
#endif
			}
			else {
				HookIntegrity = false;
#ifdef ARTEMIS_DEBUG
				Utils::LogInFile(ARTEMIS_LOG, "CClientEntity::SetCustomData - Can`t find sig.\n");
#endif
			}

			const char pattern2[] = { "\x55\x8B\xEC\x53\x8A\x5D\x0C" };
			const char mask2[] = { "xxxxxxx" };
			Addr = SigScan::FindPattern("client.dll", pattern2, mask2);
			if (Addr != NULL)
			{
				HooksList.insert(std::pair<PVOID, PVOID>(GetCustomData, (PVOID)Addr));
				MH_CreateHook((PVOID)Addr, &GameHooks::GetCustomData, reinterpret_cast<PVOID*>(&GameHooks::ptrGetCustomData));
#ifdef ARTEMIS_DEBUG
				Utils::LogInFile(ARTEMIS_LOG, "CClientEntity::GetCustomData Hook installed!\n");
#endif
			}
			else {
				HookIntegrity = false;
#ifdef ARTEMIS_DEBUG
				Utils::LogInFile(ARTEMIS_LOG, "CClientEntity::GetCustomData - Can`t find sig.\n");
#endif
			}
		};
		ElementDataHook(); // ������������ �������� ��� ��������� ������ ������� ��� � ��� �������� (setElementData/getElementData)
		
		
		auto InstallLuaHook = [&HookIntegrity]()
		{
			const char pattern[] = { "\x55\x8B\xEC\x56\x8B\x75\x0C\x57\x8B\x7D\x08\xFF\x36\xFF\x37\xE8\x00\x00\x00\x00\x83\xC4\x08\x84\xC0\x74\x0C\x83\x07\x03\xB0\x01\x83\x06\xFD\x5F\x5E\x5D\xC3" };
			const char mask[] = { "xxxxxxxxxxxxxxxx????xxxxxxxxxxxxxxxxxxx" };
			DWORD luaHook = SigScan::FindPattern("client.dll", pattern, mask);
			if (luaHook != NULL)
			{
				HooksList.insert(std::pair<PVOID, PVOID>(CheckUTF8BOMAndUpdate, (PVOID)luaHook));
				MH_CreateHook((PVOID)luaHook, &GameHooks::CheckUTF8BOMAndUpdate, reinterpret_cast<PVOID*>(&GameHooks::callCheckUTF8BOMAndUpdate));
#ifdef ARTEMIS_DEBUG
				Utils::LogInFile(ARTEMIS_LOG, "CLuaShared::CheckUTF8BOMAndUpdate Hook installed!\n");
#endif
			}
			else {
				HookIntegrity = false;
#ifdef ARTEMIS_DEBUG
				Utils::LogInFile(ARTEMIS_LOG, "CLuaShared::CheckUTF8BOMAndUpdate Can`t find sig.\n");
#endif
			}
		};
		InstallLuaHook(); // ������������ �������� ��� ������� lua �������� � ����� ����� ������ FireFest ����������
		
		
		auto InstallServerEventsHook = [&HookIntegrity]()
		{
			const char pattern[] = { "\x55\x8B\xEC\x51\x53\x56\x57\x8B\x7D\x08\x85" };
			const char mask[] = { "xxxxxxxxxxx" };
			DWORD Hook = SigScan::FindPattern("client.dll", pattern, mask);
			if (Hook != NULL)
			{
				HooksList.insert(std::pair<PVOID, PVOID>(TriggerServerEvent, (PVOID)Hook));
				MH_CreateHook((PVOID)Hook, &GameHooks::TriggerServerEvent, reinterpret_cast<PVOID*>(&GameHooks::callTriggerServerEvent));
#ifdef ARTEMIS_DEBUG
				Utils::LogInFile(ARTEMIS_LOG, "CStaticFunctionDefinitions::TriggerServerEvent Hook installed!\n");
#endif
			}
			else {
				HookIntegrity = false;
#ifdef ARTEMIS_DEBUG
				Utils::LogInFile(ARTEMIS_LOG, "CStaticFunctionDefinitions::TriggerServerEvent Can`t find sig.\n");
#endif
			}
		};
		InstallServerEventsHook(); // ������������ �������� ��� ��������� ������ ��������� �������

		// ���� ���� �� �������� �� ����� ���� ������� (��� ����� ���� �������������� ���, ��� ���-�� ��� ��������� ���� ��� �� ���), ������� ������ � ����� �� �������
		if (HookIntegrity == false) {
			ART_LIB::ArtemisLibrary::ARTEMIS_DATA data;
			data.type = ART_LIB::ArtemisLibrary::DetectionType::ART_SIGNATURES_MODIFIED;
			cfg->callback(&data);
			return false;
		}
	}
	
	// �������� ��� ���� ������� ���� 
	MH_EnableHook(MH_ALL_HOOKS);
	if (cfg->DetectMemoryPatch) // ��������� ��� ������� ��� ������ ����� �� �� ������
	{
		std::thread MemThread(MemoryGuardScanner, cfg);
		MemThread.detach();
	}
	return true; // ���� ����� ��� ��� ���� � ����������� ����������� �������
}

void __stdcall GameHooks::MemoryGuardScanner(ART_LIB::ArtemisLibrary::ArtemisConfig* cfg) // ������� ����������� ������ ��� ����� ������� �����
{
	if (cfg == nullptr) return;
	if (cfg->MemoryGuardDelay <= 1) cfg->MemoryGuardDelay = 1000;
	auto ReverseDelta = [](DWORD_PTR CurrentAddress, DWORD Delta, size_t InstructionLength, bool bigger = false) -> DWORD_PTR
	{
		if (bigger) return ((CurrentAddress + (Delta + InstructionLength)) - 0xFFFFFFFE);
		return CurrentAddress + (Delta + InstructionLength);
	};
	while (true)
	{
		if (!GetModuleHandleA("client.dll")) break;
		if (!cfg->DetectMemoryPatch) break;
		for (const auto& it : HooksList)
		{
			if (!GetModuleHandleA("client.dll")) break;
			DWORD Delta = NULL; 
			memcpy(&Delta, (PVOID)((DWORD)it.second + 0x1), 4);

			DWORD_PTR DestinationAddr = ReverseDelta((DWORD_PTR)it.second, Delta, 5);
			if (*(BYTE*)it.second != 0xE9 || (*(BYTE*)it.second == 0xE9 && DestinationAddr != (DWORD)it.first))
			{
				if (!Utils::IsVecContain(cfg->ExcludedPatches, it.second))
				{
					ArtemisLibrary::ARTEMIS_DATA data; data.baseAddr = it.second;
					data.MemoryRights = PAGE_EXECUTE_READWRITE; data.regionSize = 0x5;
					data.dllName = "client.dll"; data.dllPath = "MTA\\mods\\deadmatch\\client.dll";
					data.type = ArtemisLibrary::DetectionType::ART_MEMORY_CHANGED;
					cfg->callback(&data); cfg->ExcludedPatches.push_back(it.second);
				}
			}
		}
		Sleep(cfg->MemoryGuardDelay);
	}
}

bool __stdcall GameHooks::DeleteGameHooks()
{
	ART_LIB::ArtemisLibrary::DeleteApcDispatcher(); // ��������� �������, �� �������
	MH_DisableHook(MH_ALL_HOOKS); // ������� ��� ���� ����
	MH_Uninitialize(); // ��������������� ������� ��� ����������� ��� ���������� ������������� ����� ����������� ��������
	return true; // ���� ����� ��� ��� ���� ���� ��������� ����� � ����� ���������� � ���������� ��������
}

GameHooks::ptrAddEventHandler GameHooks::callAddEventHandler = nullptr;
GameHooks::callGetCustomData GameHooks::ptrGetCustomData = (GameHooks::callGetCustomData)0x0;
GameHooks::callSetCustomData GameHooks::ptrSetCustomData = (GameHooks::callSetCustomData)0x0;
GameHooks::ptrCheckUTF8BOMAndUpdate GameHooks::callCheckUTF8BOMAndUpdate = (GameHooks::ptrCheckUTF8BOMAndUpdate)0x0;
GameHooks::ptrTriggerServerEvent GameHooks::callTriggerServerEvent = (GameHooks::ptrTriggerServerEvent)0x0;
void GameHooks::CheckIfReturnIsLegit(const char* function_name, PVOID return_address)
{
    if (function_name == nullptr || return_address == nullptr) return;
	vector<string> allowedModules = { "client.dll", "multiplayer_sa.dll", "game_sa.dll", 
	"core.dll", "gta_sa.exe", "proxy_sa.exe", "lua5.1c.dll", "pcre3.dll" };
    string moduleName = Utils::GetNameOfModuledAddressSpace(return_address, Utils::GenerateModuleNamesList());
	if (!Utils::IsVecContain2(allowedModules, moduleName) && !Utils::IsVecContain(g_cfg->ExcludedMethods, return_address))
	{
        typedef DWORD(__stdcall* LPFN_GetMappedFileNameA)(HANDLE hProcess, LPVOID lpv, LPCSTR lpFilename, DWORD nSize);
        LPFN_GetMappedFileNameA g_GetMappedFileNameA = nullptr; HMODULE hPsapi = LoadLibraryA("psapi.dll");
        g_GetMappedFileNameA = (LPFN_GetMappedFileNameA)GetProcAddress(hPsapi, "GetMappedFileNameA");
        char MappedName[256]; memset(MappedName, 0, sizeof(MappedName));
        g_GetMappedFileNameA(GetCurrentProcess(), (PVOID)return_address, MappedName, sizeof(MappedName));
        ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
        MEMORY_BASIC_INFORMATION mme{ 0 }; ArtemisLibrary::ARTEMIS_DATA data; // ���������� �������� ��������� ��������
        VirtualQueryEx(GetCurrentProcess(), return_address, &mme, 5); // ��������� ��������� ���������� �� ������� ������
        data.baseAddr = (LPVOID)return_address; // ������ �������� ������ ������� ������
        data.MemoryRights = mme.AllocationProtect; // ������ ���� ������� � ������� ������
        data.regionSize = mme.RegionSize; // ������ ������� ������� ������
        data.type = ArtemisLibrary::DetectionType::ART_RETURN_ADDRESS; // ����������� ���� �������
        data.dllName = moduleName; data.dllPath = MappedName; // ������������ ������ � ���� � ����
        if (g_cfg != nullptr)
        {
            g_cfg->callback(&data); g_cfg->ExcludedMethods.push_back(return_address); // �������� ������� �������� � ��������� ������������ � ����-����
#ifdef ARTEMIS_DEBUG
            Utils::LogInFile(ARTEMIS_LOG, "Returned from %s function to 0x%X in to module %s\n", function_name, return_address, moduleName.c_str());
#endif
        }
	}
}
void* __fastcall GameHooks::GetCustomData(CClientEntity* ECX, void* EDX, const char* szName, bool bInheritData, bool* pbIsSynced)
{
    GameHooks::CheckIfReturnIsLegit(__FUNCTION__, _ReturnAddress());
    return ptrGetCustomData(ECX, szName, bInheritData, pbIsSynced);
}
void __fastcall GameHooks::SetCustomData(CClientEntity* ECX, void* EDX, const char* szName, void* Variable, bool bSynchronized)
{
    GameHooks::CheckIfReturnIsLegit(__FUNCTION__, _ReturnAddress());
    ptrSetCustomData(ECX, szName, Variable, bSynchronized);
}
bool __cdecl GameHooks::AddEventHandler(CLuaMain* LuaMain, const char* szName, CClientEntity* Entity,
const CLuaFunctionRef* iLuaFunction, bool bPropagated, DWORD eventPriority, float fPriorityMod)
{
    GameHooks::CheckIfReturnIsLegit(__FUNCTION__, _ReturnAddress());
    return callAddEventHandler(LuaMain, szName, Entity, iLuaFunction, bPropagated, eventPriority, fPriorityMod);
}
bool __cdecl GameHooks::CheckUTF8BOMAndUpdate(char** pcpOutBuffer, unsigned int* puiOutSize)
{
    GameHooks::CheckIfReturnIsLegit(__FUNCTION__, _ReturnAddress());
    return callCheckUTF8BOMAndUpdate(pcpOutBuffer, puiOutSize);
}
bool __cdecl GameHooks::TriggerServerEvent(const char* szName, CClientEntity* CallWithEntity, void* Arguments)
{
    GameHooks::CheckIfReturnIsLegit(__FUNCTION__, _ReturnAddress());
    return callTriggerServerEvent(szName, CallWithEntity, Arguments);
}