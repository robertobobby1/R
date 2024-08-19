outputdir = "%{cfg.buildcfg}-%{cfg.system}-%{cfg.architecture}"

workspace "Server"
	configurations
	{
		"Debug",
		"Release",
		"Dist"
	}

	project "TestProject"
		kind "ConsoleApp"
		language "C++"
		cppdialect "C++20"
	
		targetdir ("%{wks.location}/bin/" .. outputdir .. "/")
		objdir ("%{wks.location}/bin/bin-int/" .. outputdir .. "/%{prj.name}")

		files
		{
			"%{wks.location}/NetworkBasics/Source/**.h",
			"%{wks.location}/NetworkBasics/Source/**.cpp",
		}
		includedirs
		{
			"%{wks.location}/NoBiggyServer/Source",
		}