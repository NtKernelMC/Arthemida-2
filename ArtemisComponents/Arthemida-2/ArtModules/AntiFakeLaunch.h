/*
	Artemis-2 for MTA Province
	Target Platform: x32-x86
	Project by NtKernelMC & holmes0
*/
void __stdcall ConfirmLegitLaunch(ArtemisConfig* cfg)
{
	if (cfg == nullptr)
	{
#ifdef ARTEMIS_DEBUG
		Utils::LogInFile(ARTEMIS_LOG, "[ERROR] Passed null pointer to CheckLauncher\n");
#endif
		return;
	}
#ifdef ARTEMIS_DEBUG
	Utils::LogInFile(ARTEMIS_LOG, "[INFO] Created async thread for CheckLauncher! Thread id: %d\n", GetCurrentThreadId());
#endif
	decltype(auto) AttemptAboveIt = [&]() -> void
	{
		ARTEMIS_DATA data;
		data.type = DetectionType::ART_FAKE_LAUNCHER;
		cfg->callback(&data);
	};
	DISPLAY_DEVICE DevInfo; DevInfo.cb = sizeof(DISPLAY_DEVICE);
	if (EnumDisplayDevicesA(NULL, 0, &DevInfo, 0))
	{
		std::string VideoCard = DevInfo.DeviceString;
		if (!OpenMutexA(MUTEX_ALL_ACCESS, FALSE, VideoCard.c_str())) AttemptAboveIt();
	}
}