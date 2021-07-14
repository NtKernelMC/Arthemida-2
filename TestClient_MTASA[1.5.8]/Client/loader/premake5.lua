project "Loader"
	language "C++"
	kind "SharedLib"
	targetname "loader"
	targetdir(buildpath("mta"))

	filter "system:windows"
		linkoptions { "/SAFESEH:NO" }

	includedirs {
		"../sdk",
		"../../vendor"
	}

	libdirs {
		"../../vendor/detours/lib"
	}

	links {
		"unrar", "d3d9",
		"../../vendor/nvapi/x86/nvapi.lib"
	}

	pchheader "StdInc.h"
	pchsource "StdInc.cpp"

	vpaths {
		["Headers/*"] = "**.h",
		["Sources"] = "*.c",
		["Resources/*"] = {"*.rc", "**.bmp"},
		["*"] = "premake5.lua"
	}

	files {
		"premake5.lua",
		"*.h",
		"*.cpp"
	}

	filter "system:windows"
		files {
			"loader.rc",
			"resource/splash.bmp"
		}

	filter "architecture:x64"
		flags { "ExcludeFromBuild" }

	filter "system:not windows"
		flags { "ExcludeFromBuild" }
