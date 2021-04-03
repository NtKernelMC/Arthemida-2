/*
	Artemis-2 for MTA Province
	Target Platform: x32-x86
	Project by NtKernelMC & holmes0
*/
#include "ArtemisInterface.h"
void ConfirmLegitReturn(const char* function_name, PVOID return_address)
{
	if (function_name == nullptr || return_address == nullptr) return;
	ArtemisConfig* cfg = IArtemisInterface::GetConfig();
	if (cfg == nullptr) return; std::vector<std::string> allowedModules = { "client.dll", "multiplayer_sa.dll", "game_sa.dll",
	"core.dll", "gta_sa.exe", "proxy_sa.exe", "lua5.1c.dll", "pcre3.dll" };
	std::string moduleName = Utils::GetNameOfModuledAddressSpace(return_address, Utils::GenerateModuleNamesList());
	if (!Utils::IsVecContain2(allowedModules, moduleName) && !Utils::IsVecContain(cfg->ExcludedMethods, return_address))
	{
		char MappedName[256]; memset(MappedName, 0, sizeof(MappedName));
		cfg->lpGetMappedFileNameA(GetCurrentProcess(), (PVOID)return_address, MappedName, sizeof(MappedName));
		///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
		MEMORY_BASIC_INFORMATION mme{ 0 }; ARTEMIS_DATA data; data.EmptyVersionInfo = true;
		VirtualQuery(return_address, &mme, sizeof(MEMORY_BASIC_INFORMATION)); // Получение подробной информации по региону памяти
		data.baseAddr = (LPVOID)return_address; // Запись базового адреса региона памяти
		data.MemoryRights = mme.AllocationProtect; // Запись прав доступа к региону памяти
		data.regionSize = mme.RegionSize; // Запись размера региона памяти
		data.type = DetectionType::ART_RETURN_ADDRESS; // Выставление типа детекта
		data.dllName = moduleName; data.dllPath = MappedName; // Наименование модуля и путь к нему
		if (cfg != nullptr)
		{
			cfg->callback(&data); cfg->ExcludedMethods.push_back(return_address); // вызываем коллбэк артемиды и добавляем срабатывание в анти-флуд
#ifdef ARTEMIS_DEBUG
			Utils::LogInFile(ARTEMIS_LOG, "Returned from %s function to 0x%X in to module %s\n", function_name, return_address, moduleName.c_str());
#endif
		}
	}
}
/*bool __cdecl GameHooks::TriggerServerEvent(const char* szName, CClientEntity* CallWithEntity, void* Arguments)
{
	GameHooks::CheckIfReturnIsLegit(__FUNCTION__, _ReturnAddress());
	return callTriggerServerEvent(szName, CallWithEntity, Arguments);
}*/
void __stdcall MemoryGuardScanner(ArtemisConfig* cfg) // сканнер целостности памяти для наших игровых хуков
{
	if (cfg == nullptr)
	{
#ifdef ARTEMIS_DEBUG
		Utils::LogInFile(ARTEMIS_LOG, "[ERROR] Passed null pointer to MemoryGuardScanner\n");
#endif
		return;
	}
#ifdef ARTEMIS_DEBUG
	Utils::LogInFile(ARTEMIS_LOG, "[INFO] Created async thread for MemoryGuardScanner!\n");
#endif
	auto ReverseDelta = [](DWORD_PTR CurrentAddress, DWORD Delta, size_t InstructionLength, bool bigger = false) -> DWORD_PTR
	{
		if (bigger) return ((CurrentAddress + (Delta + InstructionLength)) - 0xFFFFFFFE);
		return CurrentAddress + (Delta + InstructionLength);
	};
	while (true)
	{
		if (!GetModuleHandleA("client.dll")) break;
		if (!cfg->DetectMemoryPatch) break;
		for (const auto& it : cfg->HooksList)
		{
			if (!GetModuleHandleA("client.dll")) break;
			DWORD Delta = NULL; memcpy(&Delta, (PVOID)((DWORD)it.second + 0x1), 4);
			DWORD_PTR DestinationAddr = ReverseDelta((DWORD_PTR)it.second, Delta, 5);
			if (*(BYTE*)it.second != 0xE9 || (*(BYTE*)it.second == 0xE9 && DestinationAddr != (DWORD)it.first))
			{
				if (!Utils::IsVecContain(cfg->ExcludedPatches, it.second))
				{
					ARTEMIS_DATA data; data.baseAddr = it.second; data.EmptyVersionInfo = true;
					data.MemoryRights = PAGE_EXECUTE_READWRITE; data.regionSize = 0x5;
					data.dllName = "client.dll"; data.dllPath = "MTA\\mods\\deadmatch\\client.dll";
					data.type = DetectionType::ART_MEMORY_CHANGED;
					cfg->callback(&data); cfg->ExcludedPatches.push_back(it.second);
				}
			}
		}
		Sleep(cfg->MemoryGuardScanDelay);
	}
}