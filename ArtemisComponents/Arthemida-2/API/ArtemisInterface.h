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
		virtual void ReleaseInstance() = 0;
		IBaseArtemis& operator=(const IBaseArtemis&) = delete;
	};
	class IArtemisInterface : public IBaseArtemis
	{
	public:
		static IArtemisInterface* __stdcall SwitchArtemisMonitor(ArtemisConfig* cfg, bool selector = true);
		static IArtemisInterface* __stdcall GetInstance();
		static ArtemisConfig* __stdcall GetConfig();
	protected:
		virtual ~IArtemisInterface() = default;
		static IArtemisInterface* CreateInstance(ArtemisConfig* cfg);
	private:
		static bool WasReloaded;
		static IArtemisInterface* i_art;
		static ArtemisConfig* g_cfg;
	};
};