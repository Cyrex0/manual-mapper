#include "mmap.h"
#pragma warning(disable:4311)
#pragma warning(disable:4302)

PBYTE mapper::manualMap(Process& target, Image& pe)
{
	printf_s("[<] Manual mapping %s\n", pe.getImageName().c_str());

	// Attempt to allocate at preferred base
	auto base = target.alloc(pe.getPreferredBase(), pe.getImageSize());
	if (!base)
	{
		base = target.alloc(NULL, pe.getImageSize());
		if (!base)
		{
			printf_s("[-] Failed to allocate memory in target process\n");
			return nullptr;
		}
	}
	printf_s("[+] Allocated base at 0x%p\n", base);

	// TLS (no support for new static/threadsafe stuff - must compile with /Zc:threadSafeInit-)
	pe.resolveStaticTLS(target, base);
	printf_s("[+] Resolved Static TLS\n");

	// Imports
	if (!pe.resolveImports(target))
	{
		printf_s("[-] Failed to resolve imports\n");
		return nullptr;
	}
	printf_s("[+] Resolved imports\n");

	// Security Cookie
	pe.initSecurityCookie(target);
	printf_s("[+] Initialized Security Cookie\n");

	// Relocations
	pe.resolveRelocations(base);
	printf_s("[+] Resolved relocations\n");

	// Fix Protection
	pe.protectSections(target, base);
	printf_s("[+] Protected Sections\n");

	// Write mapped image to target
	if (!target.write(base, pe.getData(), pe.getImageSize()))
	{
		printf_s("[-] Failed writing image to target process\n");
		return nullptr;
	}
	printf_s("[+] Wrote image to allocated base\n");
	
	// Hijack thread to call entrypoint
	if (target.isWow64Process())
	{
		if (!callEntryPoint32(target, pe.getAddressOfEntryPoint(base)))
		{
			printf_s("[-] Failed to call entry point\n");
			return nullptr;
		}
	}
	else
	{
		if (!callEntryPoint(target, pe.getAddressOfEntryPoint(base)))
		{
			printf_s("[-] Failed to call entry point\n");
			return nullptr;
		}
	}
	
	printf_s("[+] Successfully manual mapped %s at 0x%p\n", pe.getImageName().c_str(), base);
	return base;
}

PBYTE mapper::manualMap(Process& target, std::filesystem::path& path)
{
	Image pe(path);
	return manualMap(target, pe);
}

BOOL mapper::callEntryPoint(Process& target, PBYTE entryPoint)
{
	/*	
0:  48 b8 ef be ad de ef be ad de   movabs rax,0xdeadbeefdeadbeef
a:  48 ba ef be ad de ef be ad de   movabs rdx,0xdeadbeefdeadbeef 
14: 48 89 10						mov    QWORD PTR [rax],rdx
17: 48 ba ef be ad de ef be ad de   movabs rdx,0xdeadbeefdeadbeef
21: 48 89 50 08						mov    QWORD PTR [rax+0x8],rdx
25: 48 31 c0						xor    rax,rax
28: 48 83 ec 28						sub    rsp,0x28
2c: 48 ba 01 00 00 00 00 00 00 00   movabs rdx,0x1
36: 48 b8 ef be ad de ef be ad de   movabs rax,0xdeadbeefdeadbeef
40: ff d0							call   rax
42: 48 83 c4 28						add    rsp,0x28
46: 48 b8 ef be ad de ef be ad de   movabs rax,0xdeadbeefdeadbeef
50: 48 c7 00 01 00 00 00			mov	   QWORD PTR [rax],0x1
57: c3								ret 
	*/

	// Get address of PeekMessageW in target 

	auto moduleBase = LoadLibraryA("user32.dll");
	if (!moduleBase)
	{
		printf_s("[-] Failed to load user32.dll\n");
		return FALSE;
	}
	auto func = GetProcAddress(moduleBase, "PeekMessageW");

	auto remoteBase = target.getModuleInfo("user32.dll").base;

	auto remoteFunc = remoteBase + (reinterpret_cast<ULONGLONG>(func) - reinterpret_cast<ULONGLONG>(moduleBase));

	if (!remoteFunc)
	{
		printf_s("[-] Failed to get address of PeekMessageW in target process\n");
		return FALSE;
	}

	// Insert correct addresses into shellcode

	BYTE shellcode[] = { 0x00, 0x48, 0xB8, 0xEF, 0xBE, 0xAD, 0xDE, 0xEF, 0xBE, 0xAD, 0xDE, 0x48, 0xBA, 0xEF, 0xBE, 0xAD, 0xDE, 0xEF, 0xBE, 0xAD, 0xDE, 0x48, 0x89, 0x10, 0x48, 0xBA, 0xEF, 0xBE, 0xAD, 0xDE, 0xEF, 0xBE, 0xAD, 0xDE, 0x48, 0x89, 0x50, 0x08, 0x48, 0x31, 0xC0, 0x48, 0x83, 0xEC, 0x28, 0x48, 0xBA, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0xB8, 0xEF, 0xBE, 0xAD, 0xDE, 0xEF, 0xBE, 0xAD, 0xDE, 0xFF, 0xD0, 0x48, 0x83, 0xC4, 0x28, 0x48, 0xB8, 0xEF, 0xBE, 0xAD, 0xDE, 0xEF, 0xBE, 0xAD, 0xDE, 0x48, 0xC7, 0x00, 0x01, 0x00, 0x00, 0x00, 0x48, 0x31, 0xC0, 0xC3 };

	auto mappedShellcode = target.alloc(NULL, sizeof(shellcode));
	if (!mappedShellcode)
	{
		printf_s("[-] Failed to allocate memory for shellcode\n");
		return FALSE;
	}

	*reinterpret_cast<PBYTE*>(&shellcode[0x3]) = remoteFunc;
	target.read(&shellcode[0xD], remoteFunc, sizeof(ULONGLONG));
	target.read(&shellcode[0x1A], remoteFunc + 0x8, sizeof(ULONGLONG));
	*reinterpret_cast<PBYTE*>(&shellcode[0x39]) = entryPoint;
	*reinterpret_cast<PBYTE*>(&shellcode[0x49]) = mappedShellcode;
	
	// write entry point shellcode and jump shellcode

	if (!target.write(mappedShellcode, shellcode, sizeof(shellcode)))
	{
		printf_s("[-] Failed to write shellcode to target process\n");
		target.free(mappedShellcode, NULL, MEM_RELEASE);
		return FALSE;
	}

	BYTE jumpShellcode[] = { 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00, 0xEF, 0xBE, 0xAD, 0xDE, 0xEF, 0xBE, 0xAD, 0xDE };
	*reinterpret_cast<PVOID*>(&jumpShellcode[0x6]) = mappedShellcode + 1;

	DWORD protect = PAGE_EXECUTE_READWRITE;
	target.protect(remoteFunc, &protect, sizeof(ULONGLONG) * 2);

	if (!target.write(remoteFunc, jumpShellcode, sizeof(jumpShellcode)))
	{
		printf_s("[-] Failed to write jump shellcode\n");
		target.protect(remoteFunc, &protect, sizeof(ULONGLONG) * 2);
		target.free(mappedShellcode, NULL, MEM_RELEASE);
		return FALSE;
	}

	// Wait for shellcode to be called

	for (auto bytes = 0ULL; ; Sleep(1))
	{
		if (!target.read(reinterpret_cast<PBYTE>(&bytes), remoteFunc + 0x6, sizeof(bytes)))
		{
			printf_s("[-] Failed reading bytes at remote function\n");
			return FALSE;
		}

		if (bytes != *reinterpret_cast<PULONGLONG>(&jumpShellcode[0x6]))
		{
			break;
		}
	}

	// Wait for entry point to return
	for (BYTE b = NULL; ; Sleep(1))
	{
		if (!target.read(&b, mappedShellcode, sizeof(BYTE)))
		{
			printf_s("[-] Failed to read shellcode status\n");
			return FALSE;
		}

		if (b)
		{
			break;
		}
	}

	target.protect(remoteFunc, &protect, sizeof(ULONGLONG) * 2);
	target.free(mappedShellcode, NULL, MEM_RELEASE);

	return TRUE;
}

BOOL mapper::callEntryPoint32(Process& target, PBYTE entryPoint)
{
	// Same thing as with 64 but just need different shellcode and different way to get func to hook

	/*
	
0:  55                      push   ebp
1:  89 e5                   mov    ebp,esp
3:  b8 ef be ad de          mov    eax,0xdeadbeef
8:  ba ef be ad de          mov    edx,0xdeadbeef
d:  89 10                   mov    DWORD PTR [eax],edx
f:  ba ef be ad de          mov    edx,0xdeadbeef
14: 89 50 04                mov    DWORD PTR [eax+0x4],edx
17: b8 ef be ad de          mov    eax,0xdeadbeef
1c: 6a 00                   push   0x0
1e: 6a 01                   push   0x1
20: 6a 00                   push   0x0
22: ff d0                   call   eax
24: b8 ef be ad de          mov    eax,0xdeadbeef
29: c7 00 01 00 00 00       mov    DWORD PTR [eax],0x1
2f: 89 ec                   mov    esp,ebp
31: 5d                      pop    ebp
32: c3                      ret
	*/

	// Get address of PeekMessageW in target 

	auto moduleInfo = target.getModuleInfo("USER32.dll");
	
	Image module(moduleInfo.path);

	auto remoteFunc = module.getProcAddress(moduleInfo.base, "PeekMessageW");

	if (!remoteFunc)
	{
		printf_s("[-] Failed to get remote address of user32!PeekMessageW\n");
		return FALSE;
	}

	// Insert correct addresses into shellcode

	BYTE shellcode[] = { 0x00, 0x55, 0x89, 0xE5, 0xB8, 0xEF, 0xBE, 0xAD, 0xDE, 0xBA, 0xEF, 0xBE, 0xAD, 0xDE, 0x89, 0x10, 0xBA, 0xEF, 0xBE, 0xAD, 0xDE, 0x89, 0x50, 0x04, 0xB8, 0xEF, 0xBE, 0xAD, 0xDE, 0x6A, 0x00, 0x6A, 0x01, 0x6A, 0x00, 0xFF, 0xD0, 0xB8, 0xEF, 0xBE, 0xAD, 0xDE, 0xC7, 0x00, 0x01, 0x00, 0x00, 0x00, 0x89, 0xEC, 0x5D, 0xC3 };
	
	auto mappedShellcode = target.alloc(NULL, sizeof(shellcode));
	if (!mappedShellcode)
	{
		printf_s("[-] Failed to allocate memory for shellcode\n");
		return FALSE;
	}

	*reinterpret_cast<DWORD*>(&shellcode[0x5]) = reinterpret_cast<DWORD>(remoteFunc);
	target.read(&shellcode[0xA], remoteFunc, sizeof(DWORD));
	target.read(&shellcode[0x11], remoteFunc + sizeof(DWORD), sizeof(DWORD));
	*reinterpret_cast<DWORD*>(&shellcode[0x19]) = reinterpret_cast<DWORD>(entryPoint);
	*reinterpret_cast<DWORD*>(&shellcode[0x26]) = reinterpret_cast<DWORD>(mappedShellcode);

	// write entry point shellcode and jump shellcode

	if (!target.write(mappedShellcode, shellcode, sizeof(shellcode)))
	{
		printf_s("[-] Failed to write shellcode to allocated memory\n");
		return FALSE;
	}

	BYTE jumpShellcode[] = { 0xB8, 0xEF, 0xBE, 0xAD, 0xDE, 0xFF, 0xE0 };
	*reinterpret_cast<DWORD*>(&jumpShellcode[0x1]) = reinterpret_cast<DWORD>(mappedShellcode + 1);

	DWORD protect = PAGE_EXECUTE_READWRITE;
	target.protect(remoteFunc, &protect, sizeof(jumpShellcode));

	if (!target.write(remoteFunc, jumpShellcode, sizeof(jumpShellcode)))
	{
		printf_s("[-] Failed to write jump shellcode to remote function\n");
		return FALSE;
	}

	// Wait for shellcode to be called

	for (auto bytes = 0UL; ; Sleep(1))
	{
		if (!target.read(reinterpret_cast<PBYTE>(&bytes), remoteFunc, sizeof(DWORD)))
		{
			printf_s("[-] Failed to read bytes at remote function\n");
			return FALSE;
		}

		if (bytes != *reinterpret_cast<DWORD*>(&jumpShellcode))
		{
			break;
		}
	}

	// Wait for entry point to return

	for (BYTE b = NULL; ; Sleep(1))
	{
		if (!target.read(&b, mappedShellcode, sizeof(b)))
		{
			printf_s("[-] Failed to read shellcode status\n");
			return FALSE;
		}

		if (b)
		{
			break;
		}
	}

	target.protect(remoteFunc, &protect, sizeof(jumpShellcode));
	target.free(mappedShellcode, NULL, MEM_RELEASE);

	return TRUE;
}
