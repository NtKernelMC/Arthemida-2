project "CEFLauncher"
	language "C++"
	kind "WindowedApp"
	targetname "CEFLauncher"
	targetdir(buildpath("mta/cef"))

	includedirs { "../sdk" }

	links { "CEFLauncher DLL"}
	entrypoint "WinMainCRTStartup"

	vpaths {
		["Headers/*"] = "**.h",
		["Sources/*"] = "**.cpp",
		["*"] = "premake5.lua"
	}


	files {
		"premake5.lua",
		"*.h",
		"*.cpp"
	}

	filter "architecture:x64"
		flags { "ExcludeFromBuild" }
	filter "system:not windows"
		flags { "ExcludeFromBuild" }
