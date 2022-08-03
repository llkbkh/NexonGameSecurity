#pragma once
#include "AhnInterface.h"
// ������ص�
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
	//�޷��Զ�ɾ��.ʱ�䳤�˻����������ļ�
	TempFile.CloseFile();
	//��ntdll ������ ��ʱĿ¼��ȥ
	CopyFileA(Ntdll64Path.c_str(), TempFile.GetFilePath().data(), false);

	//Dos ·��תNt·��
	UNICODE_STRING NtPath;	
	g_pUtil->DosPathToNtPath(g_pUtil->StringToWstring(TempFile.GetFilePath()),&NtPath);

	//�ļ�ӳ�䵽�ڴ�
	HANDLE Section = INVALID_HANDLE_VALUE;
	PVOID BaseAddress = nullptr;
	NTSTATUS Status = g_pMemory->FileMapping(&NtPath, &Section, &BaseAddress);
	Wow64RevertWow64FsRedirection(OldValue);

	if (!NT_SUCCESS(Status) /*&& Status != STATUS_IMAGE_NOT_AT_BASE*/ && BaseAddress == nullptr)
	{
		//ʧ����
		ACEErrorFileLog("[{}] SSDT ��ʼ��ʧ�� 0x{:X}", __FUNCTION__,Status);
		return FALSE;
	}

	//��λҪ����Ϊ0
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
				ApiInfo.HookStatus = FALSE;					//����ǵ���ģʽ.����Ĭ��Ϊ TRUE
				ApiInfo.dwAddress  = Address;			
				ApiInfo.Ordinal    = Index;

				VecNGS_MapList.insert(std::map<ULONG, MapViewOfSectionNGSList>::value_type(ssdt_index, ApiInfo));


				//ACEDebugFileLog("{} {} 0x{:X} 0x{:X} 0x{:X} ", Index, ApiName, Address, Offset, ssdt_index);


			}

			
		});


	VMProtectEnd();
	return !VecNGS_MapList.empty();
}
//����ϵͳ���ú���
void ImpSystemFunCall()
{
	//ӳ�� ntdll64 
	MapViewNTDLL64(nullptr);
	//��ʼ�� x64�ص�����
	FunsInitX64CallBack();

	FunsInitX32VirtualExportCallBack();
}
