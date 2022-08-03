#pragma once
#include "AhnInterface.h"
// 导出表回调
typedef void(_cdecl* EatTableCallBack)(DWORD64 Address, std::string ApiName);

//NTSTATUS(NTAPI* RtlWow64GetCpuAreaInfo)(PWOW64_CPURESERVED CpuReserved,ULONG Reserved, PWOW64_CPU_AREA_INFO CpuAreaInfo) = nullptr;




BOOL MapViewNTDLL64(EatTableCallBack CallBack)
{
	VMProtectBegin(__FUNCTION__);


	PVOID OldValue = nullptr;
	Wow64DisableWow64FsRedirection(&OldValue);

	DWORD64 NTDLL64 = GetModuleHandle64(xorstr_(L"ntdll.dll"));

	auto Ntdll64Path = g_pHook64->GetModulePathFromAddress(NTDLL64);;

	CACEFile TempFile;

	TempFile.GetTempFileNameA(xorstr_("ACE"),TRUE);

	if (TempFile.OpenFile(CREATE_ALWAYS) == INVALID_HANDLE_VALUE)
	{
		ACEErrorFileLog("{} CreateTemp fail FileName:{}",__FUNCTION__, TempFile.GetFilePath());
		Wow64RevertWow64FsRedirection(OldValue);
		return FALSE;
	}
	//无法自动删除.时间长了会留下垃圾文件
	TempFile.CloseFile();
	//将ntdll 拷贝到 临时目录里去
	CopyFileA(Ntdll64Path.c_str(), TempFile.GetFilePath().data(), false);

	//Dos 路径转Nt路径
	UNICODE_STRING NtPath;	
	g_pUtil->DosPathToNtPath(g_pUtil->StringToWstring(TempFile.GetFilePath()),&NtPath);

	//文件映射到内存
	HANDLE Section = INVALID_HANDLE_VALUE;
	PVOID BaseAddress = nullptr;
	NTSTATUS Status = g_pMemory->FileMapping(&NtPath, &Section, &BaseAddress);
	Wow64RevertWow64FsRedirection(OldValue);

	if (!NT_SUCCESS(Status) /*&& Status != STATUS_IMAGE_NOT_AT_BASE*/ && BaseAddress == nullptr)
	{
		//失败了
		ACEErrorFileLog("[{}] SSDT 初始化失败 0x{:X}", __FUNCTION__,Status);
		return FALSE;
	}

	//高位要设置为0
	ULONG64 lib = (ULONG64)BaseAddress & 0xFFFFFFFF;


	CACEPE64 PE_64 = CACEPE64(lib);
	PE_64.SetPEType(FALSE);

	PE_64.EnumExportTable([&](int Index, std::string ApiName, ULONG64 Address, ULONG64 Offset ,DWORD64 RVA)->void
		{
			if (ApiName.find("Zw")== 0 || ApiName.find("Nt") == 0 /*|| ApiName == xorstr_("RtlWow64GetCpuAreaInfo")*/)
			{
				DWORD ssdt_index = g_pMemory->Read<DWORD>(Address + 4) & 0x00000FFF;

				MapViewOfSectionNGSList ApiInfo;
				ApiInfo.NtApName   = ApiName;
				ApiInfo.HookStatus = FALSE;					//如果是调试模式.可以默认为 TRUE
				ApiInfo.dwAddress  = Address;			
				ApiInfo.Ordinal    = Index;

				VecNGS_MapList.insert(std::map<ULONG, MapViewOfSectionNGSList>::value_type(ssdt_index, ApiInfo));


				//ACEDebugFileLog("{} {} 0x{:X} 0x{:X} 0x{:X} ", Index, ApiName, Address, Offset, ssdt_index);


			}

			
		});


	VMProtectEnd();
	return !VecNGS_MapList.empty();
}
//导入系统调用函数
void ImpSystemFunCall()
{
	//映射 ntdll64 
	MapViewNTDLL64(nullptr);
	//初始化 x64回调函数
	FunsInitX64CallBack();

	FunsInitX32VirtualExportCallBack();
}
