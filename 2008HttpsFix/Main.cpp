#include "Main.h"

#include <WinInet.h>
#include <string>

const DWORD hookAddress = 0x0057E326;
const size_t hookSize = 0x19;
const DWORD jumpAddress = hookAddress + hookSize;

void* _edi;
void* _ebp;
void* _eax;
void* _edx;

bool isSecure(const char* _url)
{
	return std::string(_url).substr(0, 8) == "https://";
}

void __declspec(naked) hookHttpsFix()
{
	__asm
	{
		mov _edi, edi
		mov _ebp, ebp
		mov _eax, eax
		mov _edx, edx
	}

	HttpOpenRequest(*(HINTERNET*)((DWORD)_ebp + 0x2C), (char*)_eax, (char*)_edx, nullptr, nullptr, nullptr, isSecure(*(char**)_edi) ? 0x20C00010 : 0x20400010, 1);

	__asm
	{
		jmp jumpAddress
	}
}

void _main()
{
	DWORD unused;
	VirtualProtect((void*)hookAddress, hookSize, PAGE_EXECUTE_READWRITE, &unused);

	memset((void*)hookAddress, 0x90, hookSize);

	*(BYTE*)hookAddress = 0xE9;
	*(DWORD*)(hookAddress + 1) = (DWORD)hookHttpsFix - hookAddress - 5;
}
