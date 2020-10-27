#pragma once
#include "imports.h"

typedef struct tagMOD_INFO
{
	PBYTE base = NULL;
	PBYTE entryPoint = NULL;
	DWORD size = NULL;
	std::string path = "";
} MOD_INFO, *PMOD_INFO;

typedef std::vector<std::unique_ptr<MOD_INFO>> ModuleList;

class Process
{
public:

	Process(const std::string& procName);

private:

	BOOL isWow64;
	DWORD pid;
	HANDLE procHandle;
	ModuleList modules;

	BOOL getProcessHandle(const std::string& procName);

public:

	DWORD		getProcessId();
	PBYTE		getModuleBase(const std::string& modName, HMODULE hModule);
	MOD_INFO	getModuleInfo(const std::string& modName);
	std::string getProcessExePath();

	PBYTE	alloc(PBYTE addr, SIZE_T size);
	BOOL	free(PBYTE addr, SIZE_T size, DWORD freeType = MEM_RELEASE);
	BOOL	protect(PBYTE addr, PDWORD protect, SIZE_T size);
	BOOL	write(PBYTE dst, PBYTE src, SIZE_T size);
	BOOL	read(PBYTE dst, PBYTE src, SIZE_T size);

	VOID		AddMappedModule(MOD_INFO modInfo);
	MOD_INFO	GetMappedModule(const std::string& name);

	BOOL	isValid();
	BOOL	isWow64Process();
};