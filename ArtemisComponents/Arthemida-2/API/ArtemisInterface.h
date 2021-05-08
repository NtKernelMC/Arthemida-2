/*
	Artemis-2 for MTA Province
	Target Platform: x32-x86
	Project by NtKernelMC
*/
#pragma once
#include "../../Arthemida-2/API/ArtemisTypes.h"
namespace ARTEMIS_INTERFACE
{
	using namespace ArtemisData;
	class IBaseArtemis
	{
	protected:
		virtual ~IBaseArtemis() = default;
	public:
		IBaseArtemis& operator=(const IBaseArtemis&) = delete;
	};
	class IArtemisInterface : public IBaseArtemis
	{
	public:
		static IArtemisInterface* __stdcall InstallArtemisMonitor(ArtemisConfig* cfg);
		static IArtemisInterface* __stdcall GetInstance();
		static ArtemisConfig* __stdcall GetConfig();
		void __thiscall ConfirmLegitReturn(const char* function_name, PVOID return_address);
	protected:
		virtual ~IArtemisInterface() = default;
		static IArtemisInterface* CreateInstance(ArtemisConfig* cfg); 
	private:
		static IArtemisInterface* i_art;
		static ArtemisConfig* g_cfg;
	};
};