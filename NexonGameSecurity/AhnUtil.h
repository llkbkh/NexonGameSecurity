#pragma once
#include "AhnInterface.h"
#include <wow64ext/internal.h>
#include <PackWrite.h>
#include <CACEInterface.h>
WORD sysback_fs = 0;
PVOID NtDLL64CallHandle = nullptr;

void __declspec(naked) NtDll64HookAsm() 
{
	//_asm _emit 0x87;
	//_asm _emit 0xC0;

	_asm dec eax;
	_asm mov ecx, dword ptr[esp];
	_asm mov ecx, dword ptr[ecx];
	_asm cmp ecx, 0xEC4D8B48;

	//mov rcx,r10
	_asm _emit 0x49;
	_asm _emit 0x8B;
	_asm _emit 0xCA;
	_asm jne l_syscall;
	_asm X64_End();
	_asm mov dx, ds;
	_asm mov ss, dx;
	//_asm mov dx, word ptr[ebp - 0x4C];
	_asm mov fs, sysback_fs;
	_asm push eax;
	_asm lea eax, dword ptr[ebp + 0x8];
	_asm push eax;
	_asm call NtDLL64CallHandle;
	_asm X64_Start();
	_asm retn;
l_syscall:
	_asm EMIT(0x0F);
	_asm EMIT(0x05);
	_asm retn;
}

void SetNtDLL64CallHandle(PVOID CallBack)
{
	if (sysback_fs == 0)
	{
		_asm mov sysback_fs, fs
	}

	NtDLL64CallHandle = CallBack;
}

ULONG64 GetVirtualProAddres(DWORD64 lib, char* ApiName)
{
	CACEPE64 PE_64 = CACEPE64(lib);
	PE_64.SetPEType(TRUE);
	auto ides = PE_64.GetExportTable();

	for (unsigned i = 0; i < std::get<1>(ides)->NumberOfNames; i++)
	{
		DWORD dwNameAddress = PE_64.RVAToFOA(std::get<1>(ides)->AddressOfNames);
		DWORD64 ApiNameAddress = lib + (dwNameAddress + i * 4);
		DWORD dwOffset = 0;
		X64GetMem64(&dwOffset, ApiNameAddress, 4);
		//name
		ApiNameAddress = PE_64.RVAToFOA(dwOffset) + lib;
		char szApiName[MAX_PATH] = { 0 };
		PE_64.X64ReadStr(ApiNameAddress, szApiName, MAX_PATH);

		DWORD dwNameOrdinals = PE_64.RVAToFOA(std::get<1>(ides)->AddressOfNameOrdinals);
		DWORD64 Hint = lib + (dwNameOrdinals + i * 2);
		int ThunkOfIndex = 0;
		X64GetMem64(&ThunkOfIndex, Hint, 2);

		DWORD dwFunsAddress = PE_64.RVAToFOA(std::get<1>(ides)->AddressOfFunctions);
		DWORD64 ApiAddress = lib + (dwFunsAddress + ThunkOfIndex * 4);
		DWORD dwApiAddressOffset = 0;
		X64GetMem64(&dwApiAddressOffset, ApiAddress, 4);
		DWORD64 HookAddres = lib + PE_64.RVAToFOA(dwApiAddressOffset);

		if (lstrcmpiA(szApiName, ApiName) == 0)
		{

			return HookAddres;
		}
	}
	return 0;
}
typedef struct _HookSection 
{
	ULONG Count;			//次数
	//ULONG Index;			//索引号
	std::map<ULONG, DWORD> Index;
} TAGHookSection, * PTAGHookSection;

std::map<DWORD64, PTAGHookSection> MapHookSection;
BOOL HookExport64NtAPI(DWORD64 lib, DWORD64 OriginFuncAddress, DWORD64 RVA,DWORD64 dwSectionAddress,ULONG Index)
{
	PTAGHookSection  pHookSection = nullptr;

	if (MapHookSection.count(lib) == 0)
	{
		pHookSection        = new TAGHookSection();
		pHookSection->Count = 1;

		MapHookSection.insert(std::map<DWORD64, PTAGHookSection>::value_type(lib, pHookSection));
	}
	pHookSection = MapHookSection.at(lib);

	if (pHookSection->Index.count(Index))
	{
		ACEErrorFileLog("[{}] hook already exist Index:0x{:X}",__FUNCTION__, Index);

		DWORD dwOldProtect = 0;

		DWORD64 FunOffset = pHookSection->Index.at(Index);


		VirtualProtectEx64(GetCurrentProcess(), RVA, 0x1000, PAGE_EXECUTE_READWRITE, &dwOldProtect);
		WriteProcessMemory64(GetCurrentProcess(), RVA, &FunOffset, 4, nullptr);
		VirtualProtectEx64(GetCurrentProcess(), RVA, 0x1000, dwOldProtect, &dwOldProtect);

		return TRUE;
	}
	

	/*
	*			mov r12,rcx
	*			mov rax,index
	*			mov rcx,HookAsm
	*			jmp rcx
	*/
	ULONG CodeLenght = 17;

	/*
	*		算出新的导出函数偏移 
	*		text节 最后一段内存 每次都往前Hook
	*/
	DWORD HookCount = pHookSection->Count;

	DWORD64 ExportFunNewAddress = dwSectionAddress + (CodeLenght * HookCount) ;

	//BYTE bCode[17] = {0};
	//BYTE bSrcCode[17] = { 0 };
	//X64GetMem64(bCode, ExportFunNewAddress, CodeLenght);


	static DWORD64 _Ntdll = GetModuleHandle64(xorstr_(L"ntdll.dll"));

	//if (_Ntdll == lib)
	//{
	//	if (memcmp(bCode, bSrcCode, CodeLenght) != 0)
	//	{
	//		ExportFunNewAddress = dwSectionAddress + (CodeLenght * HookCount);

	//		X64GetMem64(bCode, ExportFunNewAddress, CodeLenght);

	//		if (memcmp(bCode, bSrcCode, CodeLenght) != 0)
	//		{
	//			MessageBoxA(0, "地址更新错误.请联系 管理员", 0, 0);
	//			exit(0);
	//		}

	//	}

	//}

	






	// hookCount + 1
	pHookSection->Count = ++HookCount;


	auto lPackWrite = std::make_shared<PackWriter>(100);

	//保存8字节
	X64GetMem64(lPackWrite->GetBytes(), OriginFuncAddress, 8);
	lPackWrite->SetOffset(8);
	// - push rcx
	lPackWrite->WriteByte(0x48);
	lPackWrite->WriteByte(0xc7);
	lPackWrite->WriteByte(0xc1);
	lPackWrite->WriteInt((ULONG)NtDll64HookAsm);
	lPackWrite->WriteByte(0xff);
	lPackWrite->WriteByte(0xe1);

	// new fun 
	DWORD dwOldProtect = 0;
	VirtualProtectEx64(GetCurrentProcess(), ExportFunNewAddress, 0x1000, PAGE_EXECUTE_READWRITE, &dwOldProtect);
	WriteProcessMemory64(GetCurrentProcess(), ExportFunNewAddress, lPackWrite->GetBytes(), lPackWrite->GetBytesLength(), nullptr);
	VirtualProtectEx64(GetCurrentProcess(), ExportFunNewAddress, 0x1000, dwOldProtect, &dwOldProtect);


	//修改导出函数偏移


	DWORD FunOffset = ExportFunNewAddress - lib;

	if (_Ntdll != lib)
	{
		// 文件偏移转内存虚拟地址
		/*
		*	
		*/
		CACEPE64 PE64 = CACEPE64(lib);

		PE64.SetPEType(TRUE);

		PE64.EnumSectionInfo([&](PIMAGE_SECTION_HEADER Section)
			{

				if (lstrcmpiA((char*)Section->Name, xorstr_(".text")) == 0)
				{
					DWORD dwDis = Section->VirtualAddress - Section->PointerToRawData;

					FunOffset = FunOffset + dwDis;

				}
			});
	}

	


	VirtualProtectEx64(GetCurrentProcess(), RVA, 0x1000, PAGE_EXECUTE_READWRITE, &dwOldProtect);
	WriteProcessMemory64(GetCurrentProcess(), RVA, &FunOffset, 4, nullptr);
	VirtualProtectEx64(GetCurrentProcess(), RVA, 0x1000, dwOldProtect, &dwOldProtect);

	//* Hook完毕
	pHookSection->Index.insert(std::map<ULONG, BOOL>::value_type(Index, FunOffset));



	ACEWarningFileLog("[{}] ExportFunNewAddress:0x{:X} HookCount:0x{:X}  FunOffset:0x{:X}", __FUNCTION__, ExportFunNewAddress, HookCount, FunOffset);

	return TRUE;
}




BOOL HookInline64NtAPI(DWORD64 lib, PVOID64 Address,BOOL IsNTDLL)
{
	VMProtectBegin(__FUNCTION__);

	DWORD64 dwAddress = (DWORD64)Address;

	auto lPackWrite = std::make_shared<PackWriter>(100);

	/*
	*	2022-05-19 05:34:03 韩服更新NGS 5.1.5.2
	*	检测 push 0x 改为 jump reg
	*/

	// - push rcx
	lPackWrite->WriteByte(0x48);
	lPackWrite->WriteByte(0xc7);
	lPackWrite->WriteByte(0xc1);
	lPackWrite->WriteInt((ULONG)NtDll64HookAsm);
	lPackWrite->WriteByte(0xff);
	lPackWrite->WriteByte(0xe1);

	DWORD dwOldProtect = 0;
	VirtualProtectEx64(GetCurrentProcess(), dwAddress, 0x1000, PAGE_EXECUTE_READWRITE, &dwOldProtect);
	WriteProcessMemory64(GetCurrentProcess(), dwAddress + 8, lPackWrite->GetBytes(), lPackWrite->GetBytesLength(), nullptr);
	VirtualProtectEx64(GetCurrentProcess(), dwAddress, 0x1000, dwOldProtect, &dwOldProtect);


	ACEInfoFileLog("[{}] 0x{:X}",__FUNCTION__, dwAddress);

	//g_pHook->HookWithNaked((ULONG)NtDll64HookAsm - 5, 5, SetNtDLL64CallHandle);

	VMProtectEnd();

	return TRUE;
}