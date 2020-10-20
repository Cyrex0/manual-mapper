#pragma once
#include "imports.h"


class Image
{
public:

	Image(std::filesystem::path path);

private:

	std::vector<BYTE> raw;
	std::vector<BYTE> mapped;
	std::string name;

	BOOL isValid = FALSE;
	BOOL is64bits = FALSE;
	PIMAGE_NT_HEADERS nt = nullptr;
	PIMAGE_NT_HEADERS32 nt32 = nullptr;

	PBYTE resolveRVA(ULONGLONG rva);
	PBYTE rebase(ULONGLONG va);
	VOID  mapImage();

public:

	BOOL resolveImports(Process &target);
	VOID resolveRelocations(PBYTE base);
	VOID initSecurityCookie(Process &target);
	VOID protectSections(Process &target, PBYTE base);
	BOOL resolveStaticTLS(Process &target, PBYTE base);

	BOOL			isImageValid();
	BOOL			isImage64bits();
	DWORD			getImageSize();
	PBYTE			getProcAddress(PBYTE imageBase, std::string funcName);
	PBYTE			getPreferredBase();
	PBYTE			getAddressOfEntryPoint(PBYTE base);
	PBYTE			getData();
	std::string		getImageName();

};