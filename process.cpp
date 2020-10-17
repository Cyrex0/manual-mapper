#include "process.h"

Process::Process(const std::string &procName)
	:
	isWow64(FALSE),
	pid(0ul),
	procHandle(nullptr)
{
	if (!getProcessHandle(procName))
	{
		return;
	}

	if (!IsWow64Process(procHandle, &isWow64))
	{
		printf_s("[>] Call to IsWow64Process failed, assuming process is x64\n");
		isWow64 = FALSE;
	}
}

BOOL Process::getProcessHandle(const std::string& procName)
{
	auto procSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

	if (procSnap == INVALID_HANDLE_VALUE)
	{
		printf_s("[-] Failed to get process snapshot\n");
		return FALSE;
	}

	PROCESSENTRY32 procEntry = { 0 };
	procEntry.dwSize = sizeof(PROCESSENTRY32);

	for (auto success = Process32First(procSnap, &procEntry); success != FALSE; success = Process32Next(procSnap, &procEntry))
	{
		if (procName.compare(procEntry.szExeFile) == 0)
		{
			pid = procEntry.th32ProcessID;
			procHandle = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE, FALSE, pid);

			if (procHandle != INVALID_HANDLE_VALUE)
			{
				printf_s("[-] Failed to open handle to process %s [%d]\n", procName.c_str(), pid);
				CloseHandle(procSnap);
				return TRUE;
			}

			printf_s("[+] Opened handle to process %s [%d]\n", procName.c_str(), pid);
			CloseHandle(procSnap);
			return FALSE;
		}
	}

	CloseHandle(procSnap);
	return FALSE;
}

DWORD Process::getProcessId()
{
	return pid;
}

PBYTE Process::getModuleBase(const std::string& modName, HMODULE hModule)
{
	auto base = getModuleInfo(modName).base;
	if (base)
		return base;

	char path[MAX_PATH];
	if (!GetModuleFileNameA(hModule, path, MAX_PATH))
	{
		return nullptr;
	}
	std::filesystem::path dllPath(path);

	base = getModuleInfo(dllPath.filename().string()).base;
	if (base)
		return base;

	// TODO: Store manual mapped dll's info

	base = mapper::manualMap(*this, dllPath);
	if (base)
		return base;

	return nullptr;
}

MOD_INFO Process::getModuleInfo(const std::string &modName)
{
	auto modSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
	MOD_INFO modInfo = { 0 };

	if (modSnap == INVALID_HANDLE_VALUE)
	{
		printf_s("[-] Failed to get module snapshot\n");
		return modInfo;
	}

	MODULEENTRY32 modEntry = { 0 };
	modEntry.dwSize = sizeof(MODULEENTRY32);

	for (auto success = Module32First(modSnap, &modEntry); success != FALSE; success = Module32Next(modSnap, &modEntry))
	{
		if (_stricmp(modName.c_str(), modEntry.szModule) == 0)
		{
			modInfo.base = modEntry.modBaseAddr;
			modInfo.size = modEntry.modBaseSize;
			modInfo.path = std::string(modEntry.szExePath);
			CloseHandle(modSnap);
			return modInfo;
		}
	}

	CloseHandle(modSnap);
	return modInfo;
}

std::string Process::getProcessExePath()
{
	char exePath[MAX_PATH] = { 0 };
	DWORD size = MAX_PATH;

	if (QueryFullProcessImageName(procHandle, NULL, exePath, &size))
	{
		return std::string(exePath);
	}

	return "";
}

PBYTE Process::alloc(PBYTE addr, SIZE_T size)
{
	return reinterpret_cast<PBYTE>(VirtualAllocEx(procHandle, addr, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
}

BOOL Process::free(PBYTE addr, SIZE_T size, DWORD freeType)
{
	return VirtualFreeEx(procHandle, addr, size, freeType);
}

BOOL Process::protect(PBYTE addr, DWORD *protect, SIZE_T size)
{
	return VirtualProtectEx(procHandle, addr, size, *protect, protect);
}

BOOL Process::write(PBYTE dst, PBYTE src, SIZE_T size)
{
	return WriteProcessMemory(procHandle, dst, src, size, NULL);
}

BOOL Process::read(PBYTE dst, PBYTE src, SIZE_T size)
{
	return ReadProcessMemory(procHandle, src, dst, size, NULL);
}

BOOL Process::isValid()
{
	return (procHandle == nullptr) ? FALSE : TRUE;
}

BOOL Process::isWow64Process()
{
	return isWow64;
}