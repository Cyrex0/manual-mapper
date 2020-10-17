#include "imports.h"


int main(int argc, char *argv[])
{

	if (argc != 3)
	{
		printf_s("[!] Usage:\n injector.exe <process name> <dll path>\n");
		return -1;
	}

	auto procName = std::string(argv[1]);
	
	auto dllPath = std::filesystem::path(argv[2]);
	if (!std::filesystem::exists(dllPath) || dllPath.extension().compare(L".dll") != 0)
	{
		printf_s("[!] Invalid dll path supplied");
		return -1;
	}

	Process proc(procName);
	while (!proc.isValid())
	{
		proc = Process(procName);
		printf_s("[<] Process %s not found, retrying in 3 seconds...\n", procName.c_str());
		Sleep(3000);
	}


	Image pe(dllPath);
	if (!pe.isImageValid())
	{
		printf_s("[!] Invalid image\n");
		return -1;
	}

	if (proc.isWow64Process())
	{
#ifndef _X86
		printf_s("[!] Must use x86 version to inject into x86 processes\n");
		return -1;
#endif // !_X86

		
		if (pe.isImage64bits())
		{
			printf_s("[!] Cannot inject 64 bit dll into a WoW64 process\n");
			return -1;
		}
	}
	else
	{
#ifdef _X86
		printf_s("[!] Must use x64 version to inject into x64 processes\n");
		return -1;
#endif // _X86

		if (!pe.isImage64bits())
		{
			printf_s("[!] Cannot inject 32 bit dll into a 64 bit process\n");
			return -1;
		}
	}

	if (!mapper::manualMap(proc, pe))
	{
		printf_s("[!] Failed to manual map %s", pe.getImageName().c_str());
		return -1;
	}
	return 0;
}