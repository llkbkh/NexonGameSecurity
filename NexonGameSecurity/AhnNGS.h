#pragma once

#include "AhnInterface.h"
#include "CSagaClient.h"
#include "AhnUtil.h"
#include "AhnDef.h"

#include <sys/timeb.h>
#include <winioctl.h>
#include "AhnWMI.h"




int WINAPI NGS_MapViewOfSectionHandle(HANDLE ProcessHandle, PVOID* BaseAddress, PULONG ViewSize, ULONG AllocationType, BOOL Is64Call);
NTSTATUS WINAPI  NGS_NtOpenProcessHandle(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId);
NTSTATUS WINAPI  NGS_NtReadVirtualMemoryHandle(HANDLE 	ProcessHandle, PVOID64 BaseAddress, PVOID Buffer, ULONG64 BufferLength, PULONGLONG ReturnLength);
NTSTATUS(NTAPI* NtWow64QueryInformationProcess64)(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation64, ULONG Length, PULONG ReturnLength) = NULL;
NTSTATUS WINAPI  NGS_QueryVirtualMemorHandle(HANDLE ProcessHandle, PVOID64 BaseAddress, MEMORY_INFORMATION_CLASS MemoryInformationClass, PVOID MemoryInformation, ULONG64 Length, PULONGLONG ReturnLength, NTSTATUS Status);
void WINAPI AhnVirtualExportNaked(char* DllName, char* CurDllName, HMODULE lib, BOOL IsFOA);
NTSTATUS WINAPI  NGS_NtCreateFileHandle(X64Call_Param* p);
std::map<ULONG, MapViewOfSectionNGSList> VecNGS_MapList;


BOOL FunsInitX64CallBack()
{
	for (auto& it : VecNGS_MapList)
	{
		if (it.second.NtApName == xorstr_("NtCreateSection"))
		{
			it.second.CallBack = [&](X64Call_Param* p, int server_index)->DWORD64
			{
				return X64Call(p->Function, 7,
					p->Args->Param_1,
					p->Args->Param_2,
					p->Args->Param_3,
					p->Args->Param_4,
					p->Args->Param_5,
					p->Args->Param_6,
					p->Args->Param_7);
			};
			
		}
		else if (it.second.NtApName == xorstr_("NtMapViewOfSection"))
		{
			it.second.CallBack = [&](X64Call_Param* p, int server_index)->DWORD64
			{
				DWORD64 status = X64Call(p->Function, 10,
					p->Args->Param_1,
					p->Args->Param_2,
					p->Args->Param_3,
					p->Args->Param_4,
					p->Args->Param_5,
					p->Args->Param_6,
					p->Args->Param_7,
					p->Args->Param_8,
					p->Args->Param_9,
					p->Args->Param_10);
				if (NT_SUCCESS(status))
				{
					auto ProcessHandle = (HANDLE)p->Args->Param_2;
					auto BaseAddress = (PVOID*)p->Args->Param_3;
					auto ViewSize = (PULONG)p->Args->Param_7;
					NGS_MapViewOfSectionHandle(ProcessHandle, BaseAddress, ViewSize, 0, TRUE);
				}
				return status;
			};

			it.second.HookStatus = TRUE;
		}
		else if (it.second.NtApName == xorstr_("NtProtectVirtualMemory"))
		{
			it.second.CallBack = [&](X64Call_Param* p, int server_index)->DWORD64
			{

				DWORD64 dwStatus = X64Call(p->Function, 5,
					p->Args->Param_1,
					p->Args->Param_2,
					p->Args->Param_3,
					p->Args->Param_4,
					p->Args->Param_5);

				HANDLE ProcessHandle = (HANDLE)p->Args->Param_1;
				PVOID64* BaseAddress = (PVOID64*)p->Args->Param_2;
				DWORD64* ProtectSize = (DWORD64*)p->Args->Param_3;
				DWORD64 NewProtect   = (DWORD64)p->Args->Param_4;
				DWORD64 OldProtect   = (DWORD64)p->Args->Param_5;


				ACEWarningFileLog("[{}] �ڴ��޸����� 0x{:X} (0x{:X} 0x{:X}) {:X} {:X} Status:{}", __FUNCTION__, (DWORD)ProcessHandle, (DWORD)*BaseAddress, (DWORD)*ProtectSize, (DWORD)NewProtect, (DWORD)OldProtect, (DWORD)dwStatus);


				return dwStatus;
			};
			//it.second.HookStatus = TRUE;
		}
		else if (it.second.NtApName == xorstr_("NtReadVirtualMemory"))
		{
			it.second.CallBack = [&](X64Call_Param* p, int server_index)->DWORD64
			{
				DWORD64 status = X64Call(p->Function, 5,
					p->Args->Param_1,
					p->Args->Param_2,
					p->Args->Param_3,
					p->Args->Param_4,
					p->Args->Param_5);

				if (NT_SUCCESS(status))
				{
					HANDLE 	ProcessHandle   = (HANDLE)p->Args->Param_1;
					PVOID64 BaseAddress     = (PVOID64)p->Args->Param_2;
					PVOID Buffer            = (PVOID64)p->Args->Param_3;
					ULONG64 BufferLength    = (ULONG64)p->Args->Param_4;
					PULONGLONG ReturnLength = (PULONGLONG)p->Args->Param_5;
					status                  = NGS_NtReadVirtualMemoryHandle(ProcessHandle, BaseAddress, Buffer, BufferLength, ReturnLength);
				}
				return status;
			};
			it.second.HookStatus = TRUE;
		}
		else if (it.second.NtApName == xorstr_("NtOpenProcess"))
		{
			it.second.CallBack = [&](X64Call_Param* p, int server_index)->DWORD64
			{
				DWORD64 status = X64Call(p->Function, 4,
					p->Args->Param_1,
					p->Args->Param_2,
					p->Args->Param_3,
					p->Args->Param_4);
				if (NT_SUCCESS(status))
				{
					PHANDLE ProcessHandle               = (PHANDLE)p->Args->Param_1;
					ACCESS_MASK DesiredAccess           = (ACCESS_MASK)p->Args->Param_2;
					POBJECT_ATTRIBUTES ObjectAttributes = (POBJECT_ATTRIBUTES)p->Args->Param_3;
					PCLIENT_ID ClientId                 = (PCLIENT_ID)p->Args->Param_4;
					status                              = NGS_NtOpenProcessHandle(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
				}

				return status;
			};
			it.second.HookStatus = TRUE;
		}
		else if (it.second.NtApName == xorstr_("NtQueryVirtualMemory"))
		{
			it.second.CallBack = [&](X64Call_Param* p, int server_index)->DWORD64
			{


				DWORD64	status = X64Call(p->Function, 6,
					p->Args->Param_1,
					p->Args->Param_2,
					p->Args->Param_3,
					p->Args->Param_4,
					p->Args->Param_5,
					p->Args->Param_6);

				HANDLE ProcessHandle                            = (HANDLE)p->Args->Param_1;
				PVOID64 BaseAddress                             = (PVOID64)p->Args->Param_2;
				MEMORY_INFORMATION_CLASS MemoryInformationClass = (MEMORY_INFORMATION_CLASS)p->Args->Param_3;
				PVOID MemoryInformation                         = (PVOID)p->Args->Param_4;
				ULONG64 Length                                  = (ULONG64)p->Args->Param_5;
				PULONGLONG ReturnLength                         = (PULONGLONG)p->Args->Param_6;
				status                                          = NGS_QueryVirtualMemorHandle(ProcessHandle, BaseAddress, MemoryInformationClass, MemoryInformation, Length, ReturnLength, status);

				return status;
			};

			it.second.HookStatus = TRUE;
		}
		else if (it.second.NtApName == xorstr_("NtCreateFile"))
		{
			it.second.CallBack = [&](X64Call_Param* p, int server_index)->DWORD64
			{
				return NGS_NtCreateFileHandle(p);
			};

			
			it.second.HookStatus = TRUE;

		}
		else if (it.second.NtApName == xorstr_("NtQueryInformationProcess"))
		{
			it.second.CallBack = [&](X64Call_Param* p, int server_index)->DWORD64
			{

				PROCESSINFOCLASS ProcessInformationClass = (PROCESSINFOCLASS)p->Args->Param_2;

				ACEWarningFileLogW(L"[{}] ProcessInformationClass:{}", L"NtQueryInformationProcess", (DWORD32)ProcessInformationClass);

				DWORD64 status = X64Call(p->Function, 5,
					p->Args->Param_1,
					p->Args->Param_2,
					p->Args->Param_3,
					p->Args->Param_4,
					p->Args->Param_5);
				return status;
			};
			//it.second.HookStatus = TRUE;
		}
	}
	return TRUE;
}



DWORD64 WINAPI X64CallHandle(X64Call_Param* p, int server_index) 
{
	VMProtectBegin(__FUNCTION__);

	auto status = 0ull;

	int Pos = VecNGS_MapList.count(server_index);

	if (Pos)
	{
		PMapViewOfSectionNGSList List =  &(VecNGS_MapList.at(server_index));
		ACEDebugFileLog("{} server_index:{} {}", __FUNCTION__, server_index, List->NtApName);
		if (List->CallBack == 0)
		{

			//MessageBoxA(0, "�ص�Ϊ��", 0, 0);
		}
		status = List->CallBack(p, server_index);
	}
	else
	{
		//ACEErrorFileLog("{} fail server_index:{} ", __FUNCTION__, server_index);
		//MessageBoxA(0, "����δ�ҵ�����", 0, 0);
	}

	VMProtectEnd();
	return (DWORD64)status;
}





DWORD64	ZwReadVirtualMemory64 = NULL;
NTSTATUS NTAPI ZwReadVirtualMemoryWin10(HANDLE ProcessHandle, PVOID64 BaseAddress, PVOID Buffer, ULONG64 BufferLength, PULONGLONG ReturnLength)
{
	VMProtectBegin(__FUNCTION__);
	if (!ZwReadVirtualMemory64)
	{
		ZwReadVirtualMemory64 = GetProcAddress64(GetModuleHandle64(xorstr_(L"ntdll.dll")), xorstr_("NtReadVirtualMemory"));
	}

	NTSTATUS	Status = X64Call(ZwReadVirtualMemory64, 5, (DWORD64)ProcessHandle, (DWORD64)BaseAddress, (DWORD64)Buffer, (DWORD64)BufferLength, (DWORD64)ReturnLength);

	VMProtectEnd();

	return Status;
}




void HookNt64(DWORD64 lib)
{

	VMProtectBegin(__FUNCTION__);

	// hook ӳ���ڴ�
	CACEPE64 PE64 = CACEPE64(lib);

	PE64.SetPEType(TRUE);

	auto Section = PE64.GetSectionInformation(xorstr_(".text"));


	PE64.EnumExportTable([&](int Index, std::string ApiName, ULONG64 Address, ULONG64 Offset, DWORD64 RVA)
	{

#if 1
			if (ApiName.find("Zw") == 0 || ApiName.find("Nt") == 0)
			{
				DWORD ssdt_index = g_pMemory->Read<DWORD>(Address + 4) & 0x00000FFF;

				MapViewOfSectionNGSList &  Info =  VecNGS_MapList.at(ssdt_index);

				if (Info.HookStatus)
				{
					ACEWarningFileLog("[Hook VirtualNTDLL 64] ApiName:{} hModule:0x{:X} OriginAddress:0x{:X} ExportFunsRVA:0x{:X}", ApiName, lib, Info.dwAddress, RVA);
					//HookExport64NtAPI(lib, Info.dwAddress, RVA, std::get<1>(Section) /*+ std::get<2>(Section)*/, ssdt_index);
	
					HookInline64NtAPI(lib, (PVOID64)Address,FALSE);


				}
			}
#endif
	});

	//hook ��ʵ64λNTDLL ,ֻ��һ��
	static BOOL bIsHook = FALSE;
	if (bIsHook)
	{
		return;
	}
	bIsHook = TRUE;

	DWORD64 _Ntdll = GetModuleHandle64(xorstr_(L"ntdll.dll"));

	CACEPE64 PE64Ntdll = CACEPE64(_Ntdll);

	auto Section64 = PE64Ntdll.GetSectionInformation(xorstr_(".text"));

	ACEDebugFileLog("[{}] Size:{}", std::get<1>(Section64) , std::get<2>(Section64));


	PE64Ntdll.EnumExportTable([&](int Index, std::string ApiName, ULONG64 Address, ULONG64 Offset, DWORD64 RVA)
	{

#if 1
			if (ApiName.find("Zw") == 0 || ApiName.find("Nt") == 0)
			{
				DWORD64 ssdt_index = 0;

				X64GetMem64(&ssdt_index, Address + 4, 4);

				ssdt_index = ssdt_index & 0x00000FFF;

				MapViewOfSectionNGSList& Info = VecNGS_MapList.at(ssdt_index);

				if (Info.HookStatus)
				{
					if (ApiName == "NtMapViewOfSection" || ApiName == "ZwMapViewOfSection")
					{
						ACEWarningFileLog("[Hook NTDLL 64] ApiName:{} hModule:0x{:X} OriginAddress:0x{:X} ExportFunsRVA:0x{:X}", ApiName, _Ntdll, Info.dwAddress, RVA);
						//HookExport64NtAPI(_Ntdll, Info.dwAddress, RVA, std::get<1>(Section64) /*+ std::get<2>(Section64)*/, ssdt_index);
						HookInline64NtAPI(lib, (PVOID64)Address, FALSE);
					}
				}
			}
#endif


		});


	VMProtectEnd();
}







PVOID alloc_section(unsigned long size)
{
	HANDLE handle = CreateFileMappingA(INVALID_HANDLE_VALUE, nullptr, PAGE_EXECUTE_READWRITE, 0, size, nullptr);
	if (handle == nullptr)
	{
		return nullptr;
	}
	auto section = MapViewOfFile(handle, FILE_MAP_ALL_ACCESS, 0, 0, 0);
	CloseHandle(handle);
	return section;
}


NTSTATUS NTAPI NGS_NtMapViewOfSection32(HANDLE SectionHandle, HANDLE ProcessHandle, PVOID* BaseAddress, ULONG ZeroBits, ULONG CommitSize, PLARGE_INTEGER SectionOffset, PULONG ViewSize, SECTION_INHERIT InheritDisposition, ULONG AllocationType, ULONG Protect)
{
	auto Status = NtMapViewOfSection(
		SectionHandle,
		ProcessHandle,
		BaseAddress,
		ZeroBits,
		CommitSize,
		SectionOffset,
		ViewSize,
		InheritDisposition,
		AllocationType,
		Protect);

	if (NT_SUCCESS(Status))
	{
		

		NGS_MapViewOfSectionHandle(ProcessHandle, BaseAddress, ViewSize, AllocationType, FALSE);
	}


	return Status;
}
int WINAPI NGS_MapViewOfSectionHandle(HANDLE ProcessHandle, PVOID* BaseAddress, PULONG ViewSize, ULONG AllocationType, BOOL Is64Call)
{
	VMProtectBegin(__FUNCTION__);

	MEMORY_SECTION_NAME MapSectionName;

	ULONG length = 0;
	NTSTATUS  Status = NtQueryVirtualMemory(ProcessHandle, (*BaseAddress), MemoryMappedFilenameInformation, &MapSectionName, sizeof(MapSectionName), &length);

	MEMORY_BASIC_INFORMATION	mbi;
	ULONG						Size = 0;
	if (!NT_SUCCESS(NtQueryVirtualMemory(ProcessHandle, *BaseAddress, MemoryBasicInformation, &mbi, sizeof(MEMORY_BASIC_INFORMATION), &Size)) && Size == sizeof(MEMORY_BASIC_INFORMATION))
		return 0;

	if (NT_SUCCESS(Status))
	{
		auto file_name = wcsrchr(MapSectionName.Buffer, L'\\') + 1;

		if (file_name == nullptr)
			return 0;

		if (!StrStrW(file_name, L".tmp"))
		{
			//ΪʲôҪ�ж��Ƿ���ϵͳ�ļ���?>��ֹ�Ժ���ϵͳ�ļ���CRCУ��
			if (!(lstrcmpiW(file_name, xorstr_(L"kernelBase.dll")) == 0 || lstrcmpiW(file_name, xorstr_(L"ntdll.dll")) == 0 || lstrcmpiW(file_name, xorstr_(L"kernel32.dll")) == 0))
			{
				ACEInfoFileLogW(L"[{}]{}", __FUNCTIONW__, MapSectionName.Buffer);
			
				return 0;
			}
		}
		//�ų�����tmp�ļ�
		if (file_name[0] != L'B' || file_name[1] != L'C')
		{
			ACEErrorFileLogW(L"[{}]{} file_name��{}", __FUNCTIONW__, L"��ϵͳ�ļ�", MapSectionName.Buffer);
			//һ����ϵͳ�ļ�.
			//exit(0); //�����ǳ�����.��ֹ����dump��Ϣ
			//����ϵͳ���� ntdll.dll.tmp
	
			return 0;
		}

		ACEInfoFileLogW(L"[{}]{}",__FUNCTIONW__, MapSectionName.Buffer);

		//ȡPEͷ����Ϣ
		auto VirtualBase = VirtualAlloc(nullptr, *ViewSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		//ֻ����PEǰ0x1000�ֽ�
		memcpy(VirtualBase, *BaseAddress, 0x1000);

		if (PIMAGE_DOS_HEADER(VirtualBase)->e_magic != IMAGE_DOS_SIGNATURE)
		{
			//����PE�ļ� ����		
			VirtualFree(VirtualBase, 0, MEM_RELEASE);
			ACEErrorFileLog("[{}]{}", __FUNCTION__, "��PE�ļ�");
			return 0;
		}
		
		CACEPE PE_32 = CACEPE((ULONG)VirtualBase);

		//�����ڴ������ļ�����
		auto NtHeadres = PE_32.GetNtHeadersInfo();
		
		
		//�Ƿ�Ϊ�ļ�ӳ���ַ
		DWORD64 IsFileFOA = 0;		//0xCC Ҳ��
		// ��ַҪ��ΪBaseAddress ��ΪVirtualBaseֻ������ǰ0x1000���ֽ�.���ͷ����С����0x1000 ��һֱ�쳣
		if (ReadProcessMemory64(INVALID_HANDLE_VALUE, (DWORD64)(*BaseAddress) + NtHeadres->OptionalHeader.SizeOfHeaders, (PVOID)&IsFileFOA, 8, NULL) == FALSE)
		{
			//��ȡ�쳣 100%�� ���ص�DLL ���� ���������ڴ��DLL
			ACEErrorLog("[{}]{}", __FUNCTION__, "Read SizeOfHeaders Exception");
			exit(0);
		}
		else
		{
			// ��ȡ�Ŀ�����0xCC Ҳ�����ļ�ӳ��� Ҳ���Բ�ת��
			if (IsFileFOA != 0)
			{
				IsFileFOA = 1;
			}
			if (IsFileFOA)
			{
				//���ļ������ڴ�.ֱ�ӿ���
				memcpy(VirtualBase, *BaseAddress, *ViewSize);
			}
			else
			{
				//����DLL
				VirtualBase = *BaseAddress;
			}

		}

		PE_32.SetModuleLib((HMODULE)VirtualBase);

		BOOL	bDLL64 =  NtHeadres->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64;
		//����DLL ��
		char ExportDllName[MAX_PATH] = { 0 };

		if (bDLL64) 
		{
			//get export dll name
			CACEPE64 PE_64 = CACEPE64((DWORD64)VirtualBase);
			PE_64.SetPEType(IsFileFOA);
			auto ides =  PE_64.GetExportTable();
			if (std::get<0>(ides) == FALSE || std::get<1>(ides)->NumberOfFunctions <= 0)
			{
				ACEErrorFileLog("[{}]{}", __FUNCTION__, "64PE_ExportTab fail");
				exit(0);
				return FALSE;
			}
				
			int  NameOffset = IsFileFOA ? PE_64.RVAToFOA(std::get<1>(ides)->Name): std::get<1>(ides)->Name;
			PE_64.X64ReadStr(NameOffset + (DWORD64)VirtualBase, ExportDllName, MAX_PATH);
			
		}
		else
		{
			//32 dll
			PE_32.SetPEType(IsFileFOA);
			auto ides = PE_32.GetExportTable();

			if (std::get<0>(ides) == FALSE || std::get<1>(ides)->NumberOfFunctions <= 0)
			{
				ACEErrorFileLog("[{}]{}", __FUNCTION__, "32PE_ExportTab fail");
				exit(0);
				return FALSE;
			}

			int  NameOffset = IsFileFOA ? PE_32.RVAToFOA(std::get<1>(ides)->Name) : std::get<1>(ides)->Name;
		
			strcpy(ExportDllName, (char*)((ULONG)VirtualBase + NameOffset));
		}

		ACEInfoFileLog("[{}] DllName:{} BaseAddress:0x{:X} ViewSize:0x{:X} Is64Call:{}", __FUNCTION__, ExportDllName, (DWORD64)VirtualBase, *ViewSize, Is64Call);

		if (!(lstrcmpiA(ExportDllName, xorstr_("kernelBase.dll")) == 0 || lstrcmpiA(ExportDllName, xorstr_("ntdll.dll")) == 0 || lstrcmpiA(ExportDllName, xorstr_("kernel32.dll")) == 0))
		{
			ACEErrorFileLog("[{}]{}", __FUNCTION__, "����ģ��δ�ҵ�");
			exit(0);
			return FALSE;
		}
		auto new_section = alloc_section(*ViewSize);

		DWORD64 lib = (DWORD64)VirtualBase;

		//��֤
		static BOOL Init = FALSE;

		if (!Init &&  lstrcmpiA(g_pModule->GetModuleInfo()->AppName, xorstr_("BlackCipher.aes"))==0 )
		{
			Init = TRUE;

			if (CSagaClient::GetInstance()->SagaCheckVar() == FALSE)
			{
				ACEErrorFileLog("[{}]{}", __FUNCTION__, "SagaCheckVar Fail");
				exit(0);
				return FALSE;
			}

		}

		//hook 
		if (bDLL64)
		{
			SetNtDLL64CallHandle(X64CallHandle);
			//�������64λPE�ļ�ӳ��
			HookNt64(lib);



			memcpy(new_section, VirtualBase, *ViewSize);
			UnmapViewOfFile(*BaseAddress);
			*BaseAddress = new_section;

		}
		else
		{
#if 0
			AhnVirtualExportNaked(ExportDllName, g_pUtil->WstringToString(file_name).data(), (HMODULE)VirtualBase, IsFileFOA);

			if (IsFileFOA)
			{
				memcpy(new_section, VirtualBase, *ViewSize);
				UnmapViewOfFile(*BaseAddress);
				*BaseAddress = new_section;
			}
#endif
			

		}




	}

	VMProtectEnd();
	return 1;
}
void WINAPI NGS_ThreadCallBack(LPVOID lpParam)
{
	ULONG	ProcessId = (ULONG)lpParam;

	HANDLE	hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, ProcessId);

	WaitForSingleObject(hProcess, INFINITE);

	TerminateProcess(GetCurrentProcess(), 0);

	ExitProcess(0);
}
NTSTATUS WINAPI  NGS_NtOpenProcessHandle(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId)
{
	VMProtectBegin(__FUNCTION__);

	POBJECT_ATTRIBUTES	ObjectAttributesInfo = ObjectAttributes;
	ObjectAttributesInfo->Length /= 2;

	static HANDLE ulClientId = NULL;
	
	if (ulClientId == NULL && (DesiredAccess & PROCESS_DUP_HANDLE))
	{

		if (lstrcmpiA(g_pModule->GetModuleInfo()->AppName, xorstr_("BlackCipher.aes")) == 0)
		{
			HANDLE hSrcPid = ClientId->UniqueProcess;

			ClientId->UniqueProcess = (HANDLE)GetCurrentProcessId();

			HANDLE		Process = NULL;

			NTSTATUS	Status = NtOpenProcess(&Process, PROCESS_ALL_ACCESS, ObjectAttributesInfo, ClientId);

			if (NT_SUCCESS(Status))
			{
				PROCESS_BASIC_INFORMATION    pbi;

				Status = NtQueryInformationProcess(Process, ProcessBasicInformation, (PVOID)&pbi, sizeof(PROCESS_BASIC_INFORMATION), NULL);

				if (NT_SUCCESS(Status))
				{
					ulClientId = (HANDLE)pbi.InheritedFromUniqueProcessId;


					ACEWarningFileLog("[{}] ��Client-> {}", __FUNCTION__, ulClientId);


					DWORD	lpThreadId;
					CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)(NGS_ThreadCallBack), ulClientId, NULL, &lpThreadId);

				}

			}

			ClientId->UniqueProcess = hSrcPid;
		}
		else
		{
			ulClientId = ClientId->UniqueProcess;
		}
	}
	else
	{
		if (ulClientId && (ClientId->UniqueProcess != ulClientId && ClientId->UniqueProcess != (HANDLE)GetCurrentProcessId()))
		{

			if (lstrcmpiA(g_pModule->GetModuleInfo()->AppName, xorstr_("BlackCipher.aes")) == 0)
			{

				if (CSagaClient::GetInstance()->SagaCheckVar() == FALSE)
				{
					ACEErrorFileLog("[{}]{}", __FUNCTION__, "SagaCheckVar Fail");
					//MessageBoxA(0, "SagaCheckVar Fail", 0, 0);
					exit(0);
					return FALSE;
				}
			}

			ACEWarningFileLog("[{}] {}",__FUNCTION__,"��ֹ�߳�");

			Sleep(INFINITE);

			CloseHandle(*ProcessHandle);

			return  STATUS_ACCESS_DENIED;

		}

	}

	ACEWarningFileLog("[{}] ���� {} ", __FUNCTION__,  (ULONG)ClientId->UniqueProcess);

	VMProtectEnd();

	return 0;
}
BOOL	NGS_InitailPebStatus = FALSE;
NTSTATUS WINAPI  NGS_NtReadVirtualMemoryHandle(HANDLE 	ProcessHandle, PVOID64 BaseAddress, PVOID Buffer, ULONG64 BufferLength, PULONGLONG ReturnLength)
{
	NTSTATUS Status = STATUS_SUCCESS;
	VMProtectBegin(__FUNCTION__);

	char	szFileName[MAX_PATH];

	if (GetMappedFileNameA(ProcessHandle, BaseAddress, szFileName, MAX_PATH) > 0)
	{
		char* AppName = strrchr(szFileName, '\\') + 1;

		ACEDebugFileLog("[{}] AppName {} BaseAddress:0x{:X} lenght:0x{:X}", __FUNCTION__, AppName, (DWORD64)BaseAddress, BufferLength);

	}

	//64LDR 0x58  
	if (BufferLength == /*sizeof(_LDR_DATA_TABLE_ENTRY64)*/0x88)
	{
		LDR_DATA_TABLE_ENTRY64*		LdrTableDate = (LDR_DATA_TABLE_ENTRY64*)Buffer;

		ULONG64						Result;
		PROCESS_BASIC_INFORMATION64	ProcessInfo;
		if (NT_SUCCESS(NtWow64QueryInformationProcess64(ProcessHandle, ProcessBasicInformation, &ProcessInfo, sizeof(PROCESS_BASIC_INFORMATION64), (ULONG*)&Result)))
		{
			PEB64	Peb;
			if (NT_SUCCESS(ZwReadVirtualMemoryWin10(ProcessHandle, ProcessInfo.PebBaseAddress, &Peb, sizeof(PEB64), &Result)))
			{
				PEB_LDR_DATA64	LdrDate;
				if (NT_SUCCESS(ZwReadVirtualMemoryWin10(ProcessHandle, (PVOID64)Peb.Ldr, &LdrDate, sizeof(PEB_LDR_DATA64), &Result)))
				{
					LdrTableDate->InLoadOrderLinks.Flink = LdrDate.InLoadOrderModuleList.Flink;

					ACEDebugFileLog("[{}] ���� 64λ PEB ��� 0x{}", __FUNCTION__, LdrDate.InLoadOrderModuleList.Flink);

				}
			}
		}


	}
	else if (BufferLength == 0x48/*sizeof(LDR_DATA_TABLE_ENTRY)*/)
	{
		PLDR_DATA_TABLE_ENTRY		LdrTableDate = (PLDR_DATA_TABLE_ENTRY)Buffer;

		ULONG			Result;
		PROCESS_BASIC_INFORMATION	pbi;

		if (NT_SUCCESS(NtQueryInformationProcess(ProcessHandle, ProcessBasicInformation, &pbi, sizeof(PROCESS_BASIC_INFORMATION), &Result)))
		{

			if ((DWORD)pbi.UniqueProcessId == GetCurrentProcessId() && !NGS_InitailPebStatus && lstrcmpiA(g_pModule->GetModuleInfo()->AppName, xorstr_("BlackCipher.aes")) != 0)
			{
				if (NGS_InitailPebStatus)
				{
					Status = STATUS_ACCESS_DENIED;
					goto LAB_PEB32_EXIT;
				}
				WCHAR* FilterList[] =
				{
					L"NGClient.aes",
				};

				PTEB			Teb = NtCurrentTeb();
				
				PPEB_LDR_DATA	LdrDate = Teb->ProcessEnvironmentBlock->Ldr;
				PLDR_DATA_TABLE_ENTRY	ListHead = (PLDR_DATA_TABLE_ENTRY)&LdrDate->InLoadOrderModuleList;

				//ָ��ǰ�Ѷ�ȡ�Ķ���
				PLDR_DATA_TABLE_ENTRY	FirstLder = (PLDR_DATA_TABLE_ENTRY)LdrTableDate->InLoadOrderLinks.Flink;

				while (TRUE)
				{
					if (ListHead->InLoadOrderLinks.Flink == FirstLder->InLoadOrderLinks.Flink)
					{
						//Status	=	STATUS_ACCESS_DENIED;

						ACEWarningFileLog("{}","[��ǰ����32λPEB����]");

						*LdrTableDate = *FirstLder;

						break;
					}

					for (int i = 0; i < sizeof(FilterList) / sizeof(WCHAR*); i++)
					{
						if (lstrcmpiW(FilterList[i], FirstLder->BaseDllName.Buffer) == 0)
						{
							*LdrTableDate = *FirstLder;

							goto LAB_PEB32_EXIT;
						}
					}

					FirstLder = (PLDR_DATA_TABLE_ENTRY)FirstLder->InLoadOrderLinks.Flink;
				}

				NGS_InitailPebStatus = TRUE;
			LAB_PEB32_EXIT:
				Teb = NULL;

			}
			else
			{
				Status = STATUS_ACCESS_DENIED;

			}


		}
	}


	ACEDebugFileLog("[{}] {} ->{} - {} 0x{:X} 0x{:X} ", __FUNCTION__, ProcessHandle, GetCurrentProcessId(), GetProcessId(ProcessHandle), (DWORD64)BaseAddress, (DWORD64)BufferLength);




	VMProtectEnd();
	return Status;
}
NTSTATUS WINAPI  NGS_QueryVirtualMemorHandle(HANDLE ProcessHandle, PVOID64 BaseAddress, MEMORY_INFORMATION_CLASS MemoryInformationClass, PVOID MemoryInformation, ULONG64 Length, PULONGLONG ReturnLength, NTSTATUS Status)
{
	VMProtectBegin(__FUNCTION__);

	switch (MemoryInformationClass)
	{
	case MemoryBasicInformation:
	{
		PMEMORY_BASIC_INFORMATION64	mbi = (PMEMORY_BASIC_INFORMATION64)MemoryInformation;

		//ULONG64	RegionSize = 0x7FFFFFFFFFFFFFF;
		ULONG64 RegionSize = sizeof(ULONG64);
		if (Length == 0x30/* && BaseAddress == 0x0*/)
		{
			//�޸ĵ�ַ
			mbi->RegionSize = RegionSize - mbi->RegionSize;

			Status = 0xC000000D;

			//��ֹ����ö���ڴ���Ϣ.���뷵�ش���.�����ö��32/64λģ��

			//ACEDebugFileLog("BseAddress:0x{:X} RegionSize:0x{:X}", mbi->BaseAddress, mbi->RegionSize);
		}
	}
	break;
	case MemoryMappedFilenameInformation:
	{
		PMEMORY_SECTION_NAME_NGS SectionName = (PMEMORY_SECTION_NAME_NGS)MemoryInformation;
		if (NT_SUCCESS(Status))
		{
			ACEErrorFileLogW(L"[{}] SectionName:{}", __FUNCTIONW__, SectionName->Buffer);
		}
	}
	break;
	default:
		ACEErrorFileLogW(L"[{}] MemoryInformationClass:{}", __FUNCTIONW__, (ULONG)MemoryInformationClass);
		break;
	}

	ACEWarningFileLog("[{}] ��ѯ�ڴ���Ϣ 0x{:X} 0x{:X} 0x{:X} [0x{:X} 0x{:X}] 0x{:X}", __FUNCTION__, (ULONG)MemoryInformationClass, (DWORD)ProcessHandle, (DWORD64)BaseAddress, (DWORD)MemoryInformation, Length, (DWORD)Status);

	VMProtectEnd();
	return Status;
}

template<typename t>
wchar_t* unicode_str_buffer_t(void* p) {
	t* unicode_str = (t*)p;
	return (unicode_str == nullptr ?
		nullptr : unicode_str->Buffer);
}

template<typename t>
void unicode_str_init_t(void* p, wchar_t* str) {
	t* unicode_str = (t*)p;
	unicode_str->Buffer = str;
	unicode_str->Length = USHORT(wcslen(str) * 2);
	unicode_str->MaximumLength = unicode_str->Length + 2;
}

#define unicode_str_buffer32 unicode_str_buffer_t<UNICODE_STRING>
#define unicode_str_buffer64 unicode_str_buffer_t<UNICODE_STRING64>
#define unicode_str_init32  unicode_str_init_t<UNICODE_STRING>
#define unicode_str_init64  unicode_str_init_t<UNICODE_STRING64>

NTSTATUS WINAPI  NGS_NtCreateFileHandle(X64Call_Param* p)
{
	NTSTATUS Status;

	POBJECT_ATTRIBUTES64 ObjectAttributes = (POBJECT_ATTRIBUTES64)p->Args->Param_3;

	

	if (ObjectAttributes && ObjectAttributes->ObjectName)
	{
		ACEWarningFileLogW(L"[{}] FileName:{}",__FUNCTIONW__, ObjectAttributes->ObjectName->Buffer);

		char* PipeName = xorstr_("\\??\\pipe\\BlackCipher");

		char	szFileName[MAX_PATH];

		g_pUtil->UnicodeToAnsi((WCHAR*)ObjectAttributes->ObjectName->Buffer, szFileName);

		if (strnicmp(PipeName, szFileName, strlen(PipeName) -1) == 0 && NGSPipeNameProcessId)
		{
			char	FileName[MAX_PATH] = { 0 };

			int FileSize = wsprintfA(FileName, "%s_%d", szFileName, NGSPipeNameProcessId);


			wchar_t	wszFileName[MAX_PATH];
			g_pUtil->AnsiToUnicode(FileName, wszFileName);

			//new pip name
			unicode_str_init64(ObjectAttributes->ObjectName, wszFileName);

			Status = X64Call(p->Function, 11,
				p->Args->Param_1,
				p->Args->Param_2,
				p->Args->Param_3,
				p->Args->Param_4,
				p->Args->Param_5,
				p->Args->Param_6,
				p->Args->Param_7,
				p->Args->Param_8,
				p->Args->Param_9,
				p->Args->Param_10,
				p->Args->Param_11);


			ACEDebugFileLog("[{}] BlackCipher New Pipe Name -> {}   0x{:X}", __FUNCTION__, FileName, Status);


			//��ԭ
			g_pUtil->AnsiToUnicode(FileName, wszFileName);
			unicode_str_init64(ObjectAttributes->ObjectName, wszFileName);


			return Status;

		}

	}

	Status = X64Call(p->Function, 11,
		p->Args->Param_1,
		p->Args->Param_2,
		p->Args->Param_3,
		p->Args->Param_4,
		p->Args->Param_5,
		p->Args->Param_6,
		p->Args->Param_7,
		p->Args->Param_8,
		p->Args->Param_9,
		p->Args->Param_10,
		p->Args->Param_11);

	return Status;
}




HANDLE WINAPI NGS_FindFirstFileW(_In_ LPCWSTR lpFileName, _Out_ LPWIN32_FIND_DATAW lpFindFileData)
{

	ACEDebugFileLogW(L"[{}] {}", __FUNCTIONW__, lpFileName);

	return INVALID_HANDLE_VALUE;

	//return FindFirstFileW(lpFileName, lpFindFileData);
}
BOOL WINAPI NGS_Thread32Next(HANDLE hSnapshot, LPTHREADENTRY32 lpte)
{

	ACEDebugFileLogW(L"[{}] ", __FUNCTIONW__);

	return FALSE;
}
BOOL WINAPI NGS_Process32FirstW(HANDLE hSnapshot, LPPROCESSENTRY32W lppe)
{
	ACEDebugFileLogW(L"[{}] ", __FUNCTIONW__);

	return FALSE;
}
BOOL WINAPI NGS_Module32FirstW(HANDLE hSnapshot, LPMODULEENTRY32W lpme)
{
	ACEDebugFileLogW(L"[{}] ", __FUNCTIONW__);

	return FALSE;
}

BOOL WINAPI NGS_Process32NextW(HANDLE hSnapshot, LPPROCESSENTRY32W lppe)
{

	ACEDebugFileLogW(L"[{}] ", __FUNCTIONW__);

	return FALSE;
}
LSTATUS(APIENTRY* _RegOpenKeyExW)(HKEY hKey, LPCWSTR lpSubKey, DWORD ulOptions, REGSAM samDesired, PHKEY phkResult) = nullptr;

LSTATUS APIENTRY extRegOpenKeyExW(HKEY hKey, LPCWSTR lpSubKey, DWORD ulOptions, REGSAM samDesired, PHKEY phkResult)
{
	VMProtectBegin(__FUNCTION__);
	LSTATUS Status = _RegOpenKeyExW(hKey, lpSubKey, ulOptions, samDesired, phkResult);
	
	if (lpSubKey)
	{
		ACEErrorFileLogW(L"[{}] {} ", __FUNCTIONW__, lpSubKey);
		
		//��ֹ��ѯ��ʷ��¼
		if (lstrcmpW(lpSubKey, xorstr_(L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist")) == 0)
		{

			return ERROR_FILE_NOT_FOUND;
		}
	}

	

	VMProtectEnd();
	return Status;
}


LSTATUS APIENTRY NGS_RegEnumKeyExW(
	_In_ HKEY hKey,
	_In_ DWORD dwIndex,
	_Out_writes_to_opt_(*lpcchName, *lpcchName + 1) LPWSTR lpName,
	_Inout_ LPDWORD lpcchName,
	_Reserved_ LPDWORD lpReserved,
	_Out_writes_to_opt_(*lpcchClass, *lpcchClass + 1) LPWSTR lpClass,
	_Inout_opt_ LPDWORD lpcchClass,
	_Out_opt_ PFILETIME lpftLastWriteTime
)
{
	LSTATUS Status = RegEnumKeyExW(hKey, dwIndex, lpName, lpcchName, lpReserved, lpClass, lpcchClass, lpftLastWriteTime);

	ACEErrorFileLogW(L"[{}] {} ", __FUNCTIONW__, lpName);

	return Status;
}
NTSTATUS NTAPI NGS_NtQueryValueKey(
	_In_ HANDLE KeyHandle,
	_In_ PUNICODE_STRING ValueName,
	_In_ KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
	_Out_writes_bytes_to_opt_(Length, *ResultLength) PVOID KeyValueInformation,
	_In_ ULONG Length,
	_Out_ PULONG ResultLength
)
{
	LSTATUS Status = NtQueryValueKey(KeyHandle, ValueName, KeyValueInformationClass, KeyValueInformation, Length, ResultLength);

	if (ValueName->Buffer/* && KeyValueInformationClass != KeyValueBasicInformation*/)
	{

		ACEErrorFileLogW(L"[{}] {} ", __FUNCTIONW__, ValueName->Buffer);
	}
	return Status;
}
NTSTATUS NTAPI NGS_NtOpenKeyEx(
	_Out_ PHANDLE KeyHandle,
	_In_ ACCESS_MASK DesiredAccess,
	_In_ POBJECT_ATTRIBUTES ObjectAttributes,
	_In_ ULONG OpenOptions
)
{
	LSTATUS Status = NtOpenKeyEx(KeyHandle, DesiredAccess, ObjectAttributes, OpenOptions);

	if (1)
	{

		ACEErrorFileLogW(L"[{}] {} ", __FUNCTIONW__, ObjectAttributes->ObjectName->Buffer);
	}
	return Status;
}




NTSTATUS NTAPI NGS_NtQueryVirtualMemoryX32(HANDLE ProcessHandle, PVOID BaseAddress, MEMORY_INFORMATION_CLASS MemoryInformationClass, PVOID MemoryInformation, ULONG MemoryInformationLength, PULONG ReturnLength)
{
	NTSTATUS	Status = NtQueryVirtualMemory(ProcessHandle, BaseAddress, MemoryInformationClass, MemoryInformation, MemoryInformationLength, ReturnLength);

	VMProtectBegin(__FUNCTION__);
	//��ֹ��ѯ������	->	����ö�ٽ���ӳ����
	if (MemoryInformationClass == MemoryBasicInformation)
	{

		PMEMORY_BASIC_INFORMATION	mbi = (PMEMORY_BASIC_INFORMATION)MemoryInformation;

		ULONG	RegionSize = 0x7FFE0000;

		if (BaseAddress == (void*)0x10000)
		{
			//�޸ĵ�ַ
			mbi->RegionSize = RegionSize - mbi->RegionSize;

			Status = 0xC000000D;

			MessageBoxA(0, __FUNCTION__, 0, 0);
		}
	}
	//else if (MemoryInformationClass == MemoryWorkingSetList)
	//{
	//	//����ڴ��б�
	//	PMEMORY_WORKING_SET_LIST	mws = (PMEMORY_WORKING_SET_LIST)MemoryInformation;

	//	mws->NumberOfPages = 1;
	//}
	else if (MemoryInformationClass == MemoryMappedFilenameInformation)
	{
		//char	szFileName[MAX_PATH];

		//GetModuleFileNameA(AntiHookGetSelfModuleByAddress(BaseAddress), szFileName, MAX_PATH);

		//if (AntiHookGetSelfModuleByAddress(BaseAddress) == AntiHookGetSelfModuleHandle())
		//{
		//	Status = STATUS_INVALID_ADDRESS;
		//}
		PMEMORY_SECTION_NAME SectionName = (PMEMORY_SECTION_NAME)MemoryInformation;
		if (NT_SUCCESS(Status))
		{
			ACEErrorFileLogW(L"[{}] SectionName:{}", __FUNCTIONW__, SectionName->Buffer);
		}


	}
	VMProtectEnd();
	ACEWarningFileLog("[{}] ��ѯ�ڴ���Ϣ 0x{:X} 0x{:X} 0x{:X} [0x{:X} 0x{:X}] 0x{:X}", __FUNCTION__, (ULONG)MemoryInformationClass, (DWORD)ProcessHandle, (DWORD)BaseAddress, (DWORD)MemoryInformation, MemoryInformationLength, (DWORD)Status);
	return Status;
}


void WINAPI AhnVirtualLog(PTAG_VIRTUAL_API_INFO Virtual)
{

	if (/*CheckReturnAddressIsNGSModule()*/1)
	{

		ACEDebugLog("[{}] ->{} {},0x{:X} {} 0x{:X}", __FUNCTION__, Virtual->DllName, Virtual->Name, GetCurrentThreadId(), Virtual->CurDllName, Virtual->CallBack);


	}
		

}
DSAPI void WINAPI AhnVirtualDispacther()
{
	__asm
	{
		pop eax	//�ָ�ջ��
#if ANTI_DEBUG
		pushad
		pushfd
		push eax
		call AhnVirtualLog
		popfd
		popad
#endif
		jmp dword ptr ds : [eax]
	}

}
char* FilterName[] =
{
	"WaitForSingleObject",
	"NtDelayExecution",
	"RtlLeaveCriticalSection",
	"RtlEnterCriticalSection",
	"RtlInitializeCriticalSection",
	"EtwEventActivityIdControl",
	"RtlEnterCriticalSection",
	"EventRegister",
	"RtlEnterCriticalSection",
	"NtWaitForSingleObject",
	"GetCurrentThreadId",
	"RtlFreeHeap",
	"RtlEnterCriticalSection",
#if 1

	"GetProcessHeap",
	"Wow64Transition",	// ��HOOK��� 
	"EnterCriticalSection",
	"LeaveCriticalSection",


	"InitializeCriticalSection",
	"NtDelayExecution",

	"HeapAlloc",
	"HeapFree",
	//"VirtualAlloc",
	//"VirtualFree",
	"Sleep",
	"FlsGetValue",
	"SetLastError",
	"GetLastError",
	"LocalFree",
	"LocalAlloc",
	"EnterCriticalSection",
	"LeaveCriticalSection",
	"TlsGetValue",
	"FlsAlloc",
	"FlsSetValue",
	"GetThreadPriority",
	"IsBadReadPtr",
	"DecodePointer",
	"EncodePointer",
	"RtlDecodePointer",
	"RtlEncodePointer",
	"InitializeCriticalSectionAndSpinCount",
	"InterlockedIncrement",
	"InterlockedDecrement",
	"InterlockedExchange",
	"InterlockedCompareExchange",
	//"IsDebuggerPresent",
	//"GetTickCount",
	//"ReadFile",
	//"SetFilePointer",
	//"WriteFile",
	//"FindWindowA",
	"WaitForSingleObject",
	"WaitForSingleObjectEx",
	//"GetNativeSystemInfo",
	//"ResumeThread",
	//"GetSystemTimeAsFileTime",
	//"CompareStringEx",
	//"MultiByteToWideChar",
	//"WideCharToMultiByte",
	"InterlockedCompareExchange64",
	"DeleteCriticalSection",
	//"QueryPerformanceCounter",
	//"HeapSize",
	//"HeapReAlloc",
	//"RegGetValueW",
	//"EqualRect",
	"SetRect",
	"UnionRect",
	"IntersectRect",
	"MulDiv",
	"OffsetRect",
	//
	//"GetCurrentThreadId",
	//"NlsGetCacheUpdateCount",
	"ReleaseMutex",
	"WaitForMultipleObjects",
	"ResetEvent",
	"SetEvent",
	"WaitForMultipleObjectsEx",
	"ReleaseSemaphore",
	//"SystemTimeToFileTime",
	//"CreateEventW",
	//"SetHandleInformation",
	//"CloseHandle",
	"VerifyVersionInfoA",
	//"GetCurrentProcessId",
	//"MapViewOfFile",
	//"UnmapViewOfFile",
	//"GetCurrentProcessId",
	"InitializeSRWLock",
	"InitializeCriticalSectionEx",
	"RtlInitializeSRWLock",
	"RtlAllocateHeap",




#endif
};

NTSTATUS NTAPI NGS_NtOpenProcess(
	_Out_ PHANDLE ProcessHandle,
	_In_ ACCESS_MASK DesiredAccess,
	_In_ POBJECT_ATTRIBUTES ObjectAttributes,
	_In_opt_ PCLIENT_ID ClientId
)
{

	NTSTATUS Status = NtOpenProcess(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);

	ACEDebugFileLog("[{}] ClientID:0x{:X} Status:0x{:X}",__FUNCTION__, GetProcessId(*ProcessHandle),(ULONG)Status);

	return Status;
}

NTSTATUS NTAPI NGS_NtQuerySystemInformation(
	_In_ SYSTEM_INFORMATION_CLASS SystemInformationClass,
	PVOID SystemInformation,
	_In_ ULONG SystemInformationLength,
	_Out_opt_ PULONG ReturnLength
)
{
	NTSTATUS Status = NtQuerySystemInformation(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);

	switch (SystemInformationClass)
	{
	case SystemProcessInformation:

		if (NT_SUCCESS(Status))
		{
			PSYSTEM_PROCESS_INFORMATION pSystemInformation = (PSYSTEM_PROCESS_INFORMATION)SystemInformation;
			// ��ֹö��ϵͳ����
			pSystemInformation->NextEntryOffset = 0;

			ACEWarningFileLog("[ö��ϵͳ����] {} {} Status 0x{:X}", __FUNCTION__, GetCurrentThreadId(), (ULONG)Status);
		}
		break;
	case SystemModuleInformation:
	{
		if (NT_SUCCESS(Status))
		{
			//��ֹö��ϵͳ����
			PSYSTEM_MODULE_INFORMATION	Array = (PSYSTEM_MODULE_INFORMATION)SystemInformation;


			for (int count = 0; count < Array->LoadCount; count++)
			{
				//ACEInfoFileLog("LoadIndex=%d        ImageBase=0x%X        ImageSize=0x%X       ImageName=%s",
				//	Array->smi[count].LoadCount,
				//	Array->smi[count].Base,
				//	Array->smi[count].Size,
				//	Array->smi[count].ImageName);
			}

			ACEWarningFileLog("[ϵͳ�����б�] {} {}{}  Status 0x{:X}", __FUNCTION__, GetCurrentThreadId(), Array->LoadCount, (ULONG)Status);

			RtlZeroMemory(Array, SystemInformationLength);
		}
	}
	break;
		
	default:
		break;
	}


	ACEDebugFileLog("[{}] SystemInformationClass:0x{:X} Status:0x{:X}", __FUNCTION__, ULONG(SystemInformationClass), (ULONG)Status);

	return Status;
}



//ҪHook�����⵼������ FunName ,CallBack
std::map<std::string, ULONG> MapHookVirtualExportFuns;
void FunsInitX32VirtualExportCallBack()
{
	//̫������.�������
	//MapHookVirtualExportFuns.insert(std::map<std::string, ULONG>::value_type("NtOpenProcess", (ULONG)extNtOpenProcess));
}




//���⵼����Map
std::map<std::string, PTAG_VIRTUAL_API_INFO> VirtualExportMap;

void WINAPI AhnVirtualExportNaked(char* DllName, char* CurDllName, HMODULE lib, BOOL IsFOA)
{
	ACEDebugLog("[{}] {} {} 0x{:X} {}",__FUNCTION__, DllName, CurDllName,(DWORD)lib, IsFOA);


	/*
	*	NGS��Ե��������CRCУ��
	*	��ģ����ӳ���ļ����бȶ� 
	*	����ӳ���ļ� ������ ��FOAתΪRVA + lib = VA
	*	����ģ��	 ������ RVA+lib = VA 
	*	���߽��жԱ�.������ַ��ͬ ��ͨ��.��RVA��FOA ��ͬҲ����ͨ��.
	*	
	*	����취:
	*	��֤RVA��FOA ָ���ַ��ͬ�İ취
	*	��һ�֣�PE����һ������.����������ȫ����������...
	*	�ڶ��֣������������������.��һ��հ׵�ַ...XX00
	*	������: ģ���FOA��ӳ���FA ��ַһ��Ҳ����.
	* 
	*/
	PTAG_VIRTUAL_API_INFO	pVirtualList = nullptr;

	for (auto & iter : VirtualExportMap)
	{
		if (iter.first == DllName)
		{
			pVirtualList = iter.second;

			
			break;
		}
	}
	CACEPE PE_32 = CACEPE((DWORD)lib);

	PE_32.SetPEType(IsFOA);

	auto ides = PE_32.GetExportTable();

	PIMAGE_EXPORT_DIRECTORY pExport = std::get<PIMAGE_EXPORT_DIRECTORY>(ides);

	if (pVirtualList == nullptr)
	{
		pVirtualList = (PTAG_VIRTUAL_API_INFO)VirtualAlloc(NULL, sizeof(TAG_VIRTUAL_API_INFO) * std::get<1>(ides)->NumberOfFunctions, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

		if (pVirtualList == nullptr)
		{
			ACEErrorFileLog("[{}] VirtualAlloc Error:0x{:X}",__FUNCTION__,GetLastError());
			return;
		}
		ZeroMemory(pVirtualList, sizeof(TAG_VIRTUAL_API_INFO) * std::get<1>(ides)->NumberOfFunctions);
		VirtualExportMap.insert(std::pair<std::string, PTAG_VIRTUAL_API_INFO>(DllName, pVirtualList));
	}

	DWORD lpProtect = 0;
	if (!IsFOA)
	{
		VirtualProtect(PBYTE(lib) + pExport->AddressOfFunctions, pExport->NumberOfFunctions * sizeof(ULONG), PAGE_EXECUTE_READWRITE, &lpProtect);
	}

	PE_32.EnumExportTable([&](int Index, std::string ApiName, ULONG Address, PDWORD Offset)
	{
			//��ŵ����Ĳ�HOOK
			if (ApiName.find("#")== 0)
			{
				//return;
			}

			if (ApiName ==  "LoadLibraryA" || ApiName == "ZwQueryInformationProcess" || ApiName == "ZwSetEvent" || ApiName == "ZwSetInformationThread")
				return;

			for (auto & j : FilterName)
			{
				if (ApiName == j)
				{
					return;
				}
			}

			//��������
			PTAG_VIRTUAL_API_INFO	Virtual = &pVirtualList[Index - pExport->Base];

			if (!Virtual->CallBack)
			{
				//ֻ����ģ��
				//Virtual->CallBack = (ULONG)g_pHook->GetProcAddress(lib, ApiName);
				Virtual->CallBack =(ULONG)::GetProcAddress(lib, ApiName.data());

				if (!Virtual->CallBack)
				{
					Virtual->CallBack = (ULONG)g_pHook->GetProcAddress(lib, ApiName);
				}


			}
			//���Hook�˵Ļ� �ص��� �Լ���
			for (auto& Hook : MapHookVirtualExportFuns)
			{
				if (Hook.first == ApiName)
				{
					Virtual->CallBack = (ULONG)Hook.second;
					break;
				}
			}

			Virtual->Address = (ULONG)AhnVirtualDispacther;
			if (Virtual->DllName == nullptr)
			{
				Virtual->DllName = (char*)malloc(strlen(DllName) + 1);
				strcpy(Virtual->DllName, DllName);
			}
			if (Virtual->CurDllName == nullptr)
			{
				Virtual->CurDllName = (char*)malloc(strlen(CurDllName) + 1);
				strcpy(Virtual->CurDllName, CurDllName);
			}
			if (Virtual->Name == nullptr)
			{
				Virtual->Name = (char*)malloc(ApiName.length() + 1);
				strcpy(Virtual->Name, ApiName.data());
			}

			//Ϊģ��ʱ ��¼��FOA
			if (!IsFOA)
			{
				Virtual->FunOffser = (ULONG)(&Virtual->Code) - (ULONG)lib;
			}
			//��������һ�µ�ƫ��..��CRCЧ�� ���������FOA�Ļ� ֱ��д�뱣���ƫ��			
			//����ֱ�Ӹ��Ƶ�ǰ������ �滻����  [��¼ģ�鵼����RVA ��ӳ���ļ����غ󸲸�FOA] -
			*Offset = Virtual->FunOffser;

			*(BYTE*)(Virtual->Code)                              = 0x68;
			*(ULONG*)((ULONG)Virtual->Code + 1)                  = (ULONG)(Virtual);
			*(WORD*)((ULONG)Virtual->Code + 0x5)                 = 0x25FF;
			*(ULONG*)((ULONG)Virtual->Code + sizeof(WORD) + 0x5) = (ULONG)(&Virtual->Address);


			//ACEDebugFileLog("[{}]DllName:{} APIName:{} CallBack:0x{:X} Virtual:{:X} FunAddress:0x{:X} VirtualAddress:0x{:X}", "AhnVirtualExportNaked", Virtual->DllName, Virtual->Name, Virtual->CallBack, Virtual->Address, Address, (ULONG)Virtual);

	});





	if (!IsFOA)
	{
		VirtualProtect(PBYTE(lib) + pExport->AddressOfFunctions, pExport->NumberOfFunctions * sizeof(ULONG), lpProtect, &lpProtect);
	}
}

HWND(NTAPI* _FindWindowA)(_In_opt_ LPCSTR lpClassName, _In_opt_ LPCSTR lpWindowName) = NULL;

HWND WINAPI extFindWindowA(_In_opt_ LPCSTR lpClassName,_In_opt_ LPCSTR lpWindowName)
{


	ACEDebugFileLog("[{}] {} {}", __FUNCTION__, lpClassName != nullptr ? lpClassName:"", lpWindowName != nullptr ? lpWindowName : "");


	return _FindWindowA(lpClassName, lpWindowName);
}
NTSTATUS(NTAPI* _LdrLoadDll)(PWCHAR PathToFile OPTIONAL, ULONG Flags OPTIONAL, PUNICODE_STRING ModuleFileName, PHANDLE ModuleHandle) = NULL;
NTSTATUS NTAPI extLdrLoadDll(PWCHAR PathToFile OPTIONAL, ULONG Flags OPTIONAL, PUNICODE_STRING ModuleFileName, PHANDLE ModuleHandle)
{
	VMProtectBegin(__FUNCTION__);

	char	lpLibFileName[MAX_PATH];

	g_pUtil->UnicodeToAnsi(ModuleFileName->Buffer, lpLibFileName);


	char* pszName = (strrchr(lpLibFileName, '\\') != NULL) ? (char*)strrchr(lpLibFileName, '\\') + 1 : (char*)lpLibFileName;

	NTSTATUS	Status = STATUS_SUCCESS;

	HMODULE		lib = NULL;

	Status = _LdrLoadDll(PathToFile, Flags, ModuleFileName, ModuleHandle);

	lib = *(HMODULE*)ModuleHandle;

	//ACEDebugFileLog("[{}] {}", __FUNCTION__, pszName);


	if (lstrcmpiA(pszName, "combase.dll") == 0)
	{
		//CACEHook::AntiHookSetDetectExport(&TAG_ANTI_HOOK_API_INFO(lib, "CoSetProxyBlanket", NGS_CoSetProxyBlanket, &_CoSetProxyBlanket,  ANTI_HOOK_TYPE_EAT));

		return Status;
	}
	else if (lstrcmpiA(pszName, "ole32.dll") == 0)
	{
		// hook wmi
		g_pHook->HookSetDetectExport(&TAG_ACE_HOOK_API_INFO(lib, "CoSetProxyBlanket", NGS_CoSetProxyBlanket, &_CoSetProxyBlanket, ACE_HOOK_TYPE_EAT));
		return Status;
	}
	else if (lstrcmpiA(pszName, "USER32.dll") == 0)
	{
		//AhnVirtualExportNaked("user32.dll", "user32.dll", lib, FALSE);

		return Status;
	}
	else if (lstrcmpiA(pszName, "ntdll.dll") == 0)
	{
		//AhnVirtualExportNaked(pszName, pszName, lib, FALSE);

		return Status;
	}
	else 
	{
		//AhnVirtualExportNaked(pszName, pszName, lib, FALSE);

		return Status;
	}

	VMProtectEnd();
	

	return	Status;
}

int WINAPI NGS_lstrcmpiA(
	_In_ LPCSTR lpString1,
	_In_ LPCSTR lpString2
)
{
	int Ret = lstrcmpiA(lpString1, lpString2);

	ACEDebugFileLog("[{}] {} {}", __FUNCTION__, lpString1, lpString2);

	return Ret;
}

std::string GetRandomStr(char* Seral)
{
	//����
	struct timeb time_seed;
	ftime(&time_seed);
	srand(time_seed.time * 1000 + time_seed.millitm);

	std::string random_str;
	for (int i = 0; i < strlen(Seral); ++i)
	{
		if (Seral[i] == '_' || Seral[i] == '.' || Seral[i] == '{' || Seral[i] == '}' || Seral[i] == '-')
		{
			//����_ ��. {} ����
			random_str += Seral[i];

			continue;
		}

		switch (rand() % 3)
		{
		case 1:
			random_str += ('A' + rand() % 26);
			break;
			//case 2:
			//	random_str += ('a' + rand() % 26);
			//	break;
		default:
			random_str += ('0' + rand() % 10);
			break;
		}
	}
	return random_str;
}

//������޸ĵ����к�(�������� Ӳ��)
std::map<std::string, std::string> MapSeriaNumber;

ULONG(WINAPI* _NGS_GetAdaptersInfo)(PIP_ADAPTER_INFO AdapterInfo, PULONG SizePointer) = nullptr;

ULONG WINAPI NGS_GetAdaptersInfo(PIP_ADAPTER_INFO AdapterInfo, PULONG SizePointer)
{
	VMProtectBegin(__FUNCTION__);

	ULONG Status = _NGS_GetAdaptersInfo(AdapterInfo, SizePointer);

	if (Status == ERROR_SUCCESS)
	{
		IP_ADAPTER_INFO* pNextAd = AdapterInfo;;

		if (pNextAd)
		{


			auto FakeAdapterName        = GetRandomStr(pNextAd->AdapterName);
			Sleep(5);
			auto FakeAdapterDescription = GetRandomStr(pNextAd->Description);

			ACEWarningFileLog("[{}] AdapterName:{} Description:{} FakeAdapterName:{} FakeDescription:{}", __FUNCTION__, pNextAd->AdapterName, pNextAd->Description, FakeAdapterName, FakeAdapterDescription);

			if (MapSeriaNumber.count(pNextAd->Description))
			{
				FakeAdapterDescription = MapSeriaNumber.at(pNextAd->Description);
			}
			else
			{
				MapSeriaNumber.insert(std::map<std::string, std::string>::value_type(pNextAd->Description, FakeAdapterDescription));
			}

			RtlZeroMemory(pNextAd->Description, strlen(pNextAd->Description));
			memcpy(pNextAd->Description, FakeAdapterDescription.data(), FakeAdapterDescription.length());

			if (MapSeriaNumber.count(pNextAd->AdapterName))
			{
				FakeAdapterName = MapSeriaNumber.at(pNextAd->AdapterName);
			}
			else
			{
				MapSeriaNumber.insert(std::map<std::string, std::string>::value_type(pNextAd->AdapterName, FakeAdapterName));
			}

			RtlZeroMemory(pNextAd->AdapterName, strlen(pNextAd->AdapterName));
			memcpy(pNextAd->AdapterName, FakeAdapterName.data(), FakeAdapterName.length());

			
			//ֻ����һ������
			pNextAd->Next = nullptr;
		}
		

	}
	VMProtectEnd();
	return Status;
}
CHAR* ConvertSENDCMDOUTPARAMSBufferToString(const DWORD* dwDiskData, DWORD nFirstIndex, DWORD nLastIndex)
{
	static CHAR szResBuf[IDENTIFY_BUFFER_SIZE];    //512
	DWORD nIndex = 0;
	DWORD nPosition = 0;

	for (nIndex = nFirstIndex; nIndex <= nLastIndex; nIndex++)
	{
		// get high byte
		szResBuf[nPosition] = (CHAR)(dwDiskData[nIndex] >> 8);
		nPosition++;

		// get low byte
		szResBuf[nPosition] = (CHAR)(dwDiskData[nIndex] & 0xff);
		nPosition++;
	}

	// End the string
	szResBuf[nPosition] = '\0';

	return szResBuf;
}


BOOL(WINAPI* _NGS_DeviceIoControl)(HANDLE hDevice, DWORD dwIoControlCode, LPVOID lpInBuffer, DWORD nInBufferSize, LPVOID lpOutBuffer, DWORD nOutBufferSize, LPDWORD lpBytesReturned, LPOVERLAPPED lpOverlapped) = nullptr;

BOOL WINAPI NGS_DeviceIoControl(HANDLE hDevice,DWORD dwIoControlCode,LPVOID lpInBuffer,DWORD nInBufferSize,LPVOID lpOutBuffer,DWORD nOutBufferSize,LPDWORD lpBytesReturned,LPOVERLAPPED lpOverlapped)
{
	VMProtectBegin(__FUNCTION__);

	BOOL Result = _NGS_DeviceIoControl(hDevice, dwIoControlCode, lpInBuffer, nInBufferSize, lpOutBuffer, nOutBufferSize, lpBytesReturned, lpOverlapped);

	if (Result)
	{
		switch (dwIoControlCode)
		{
		case IOCTL_STORAGE_QUERY_PROPERTY:	//0x2D1400
		{
			//��ѯ��С->����
			if (nOutBufferSize == sizeof(STORAGE_PROPERTY_QUERY))
				break;

			STORAGE_DEVICE_DESCRIPTOR* Device = (STORAGE_DEVICE_DESCRIPTOR*)lpOutBuffer;

			if (Device->SerialNumberOffset != 0 && Device->SerialNumberOffset != -1)
			{
				//���к�
				char* Seral = (char*)((ULONG)Device + (ULONG)Device->SerialNumberOffset);
				auto FakeSeriaNumber  = GetRandomStr(Seral);
				ACEWarningFileLog("[Ӳ�����к�]{} ������к�:{}", Seral, FakeSeriaNumber);

				if (MapSeriaNumber.count(Seral))
				{
					FakeSeriaNumber = MapSeriaNumber.at(Seral);
				}
				else
				{
					MapSeriaNumber.insert(std::map<std::string, std::string>::value_type(Seral, FakeSeriaNumber));
				}

				memcpy(Seral, FakeSeriaNumber.data(), FakeSeriaNumber.length());
			}

		}
		break;
		case SMART_RCV_DRIVE_DATA:	//0x07C088  -SATAӲ�̽ӿڲ�ѯ.������û�� �޷�����
		{
			DWORD dwDiskData[IDENTIFY_BUFFER_SIZE / 2];
			WORD* pIDSector; 
			pIDSector = (WORD*)(((SENDCMDOUTPARAMS*)lpOutBuffer)->bBuffer);
			for (int i = 0; i < IDENTIFY_BUFFER_SIZE / 2; i++)
			{
				dwDiskData[i] = pIDSector[i];      //lint !e662 !e661
			}

			char modelNumber[1024] = { 0 };

			strcpy(modelNumber, ConvertSENDCMDOUTPARAMSBufferToString(dwDiskData, 27, 46));

			//����Ͳ�����.�������

			//���
			for (size_t i = 27; i < 46; i++)
			{
				pIDSector[i] = g_pUtil-> GetRandomNumber('A', 'Z');
			}

			ACEInfoFileLog("[SATA���кţ�]{} ������к�:{}", modelNumber, ConvertSENDCMDOUTPARAMSBufferToString(dwDiskData, 27, 46));
		}
		break;
		case SMART_GET_VERSION:	//0x74080 - ��ȡ�������汾
		{
			PGETVERSIONINPARAMS Info = (PGETVERSIONINPARAMS)lpOutBuffer;

			//ûɶ��.��ʱ������
			std::vector<BYTE> Vec(*lpBytesReturned);
			memcpy(Vec.data(), lpOutBuffer, *lpBytesReturned);
			ACEWarningFileLog("[��ȡ�������汾]{:02X}", fmt::join(Vec.begin(), Vec.end(), " "));

		}
		break;
		case 0x390008:
			break;			//��֪��ɶ����.Ӧ�ú�NGS�޹�
		break;
		default:
		{
			//δ֪��.
			//MessageBoxA(0, 0, 0, 0);
		}
			break;
		}


	}
	VMProtectEnd();
	ACEWarningFileLog("[{}] dwIoControlCode 0x{:X} Status0x{:X} ", __FUNCTION__, dwIoControlCode, Result);
	return Result;
}
HANDLE WINAPI extOpenFileMappingA(DWORD dwDesiredAccess, BOOL bInheritHandle, LPCSTR lpName)
{
	VMProtectBegin(__FUNCTION__);
	if (lpName)
	{
		ACEDebugFileLog("[{}] {}", __FUNCTION__, lpName);
		if (lstrcmpiA(lpName, xorstr_("CSO.SharedDict")) == 0)
		{
			SetLastError(ERROR_FILE_NOT_FOUND);
			return 0;
		}

	}
	VMProtectEnd();
	return ::OpenFileMappingA(dwDesiredAccess, bInheritHandle, lpName);
}
HANDLE WINAPI extCreateFileMappingA(HANDLE hFile, LPSECURITY_ATTRIBUTES lpFileMappingAttributes, DWORD flProtect, DWORD dwMaximumSizeHigh, DWORD dwMaximumSizeLow, LPCSTR lpName)
{
	VMProtectBegin(__FUNCTION__);
	if (lpName)
	{

		ACEDebugFileLog("[{}] {}", __FUNCTION__, (lpName) ? lpName : xorstr_("NULL"));

		if (lstrcmpiA(lpName, xorstr_("CSO.SharedDict")) == 0)
		{
			HANDLE Result = CreateFileMappingA(hFile, lpFileMappingAttributes, flProtect, dwMaximumSizeHigh, dwMaximumSizeLow, lpName);

			SetLastError(ERROR_SUCCESS);
			return Result;
		}

	}
	VMProtectEnd();
	return CreateFileMappingA(hFile, lpFileMappingAttributes, flProtect, dwMaximumSizeHigh, dwMaximumSizeLow, lpName);
}
BOOL WINAPI extProcess32Next(HANDLE hSnapshot, LPPROCESSENTRY32 lppe)
{
	return FALSE;
}
BOOL WINAPI extProcess32NextW(HANDLE hSnapshot, LPPROCESSENTRY32W lppe)
{
	return FALSE;
}
HANDLE(WINAPI* _CreateMutexA)(LPSECURITY_ATTRIBUTES lpMutexAttributes, BOOL bInitialOwner, LPCSTR lpName) = NULL;
HANDLE(WINAPI* _CreateMutexW)(LPSECURITY_ATTRIBUTES lpMutexAttributes, BOOL bInitialOwner, LPCWSTR lpName) = NULL;
void  WINAPI AhnCreateMutexCheck(HANDLE& hMutex, LPCSTR szName, LPSECURITY_ATTRIBUTES lpMutexAttributes, BOOL bInitialOwner)
{

	PTAG_ACE_HOOK_MODULE_INFO ulModuleInfo = g_pModule->GetModuleInfo();
	if (szName && ulModuleInfo->MutextName)
	{
		if ((lstrcmpiA(szName, ulModuleInfo->MutextName) == 0 || strstr(szName, ulModuleInfo->MutextName) != NULL))
		{

			ACEDebugFileLog("[{}]  ��ֹ {}", __FUNCTION__, szName);
			char ulMutextName[MAX_PATH];
			wsprintfA(ulMutextName, "%s_%d", szName, GetCurrentProcessId());
			hMutex = _CreateMutexA(lpMutexAttributes, bInitialOwner, ulMutextName);
		}
	}
}

HANDLE	WINAPI extCreateMutexA(LPSECURITY_ATTRIBUTES lpMutexAttributes, BOOL bInitialOwner, LPCSTR lpName)
{
	HANDLE	hMutext = NULL;
	if (lpName)
	{
		AhnCreateMutexCheck(hMutext, lpName, lpMutexAttributes, bInitialOwner);
	}
	return (hMutext) ? hMutext : _CreateMutexA(lpMutexAttributes, bInitialOwner, lpName);
}

HANDLE	WINAPI extCreateMutexW(LPSECURITY_ATTRIBUTES lpMutexAttributes, BOOL bInitialOwner, LPCWSTR lpName)
{
	HANDLE	hMutext = NULL;
	if (lpName)
	{
		char	szFileName[MAX_PATH];
		g_pUtil->UnicodeToAnsi((LPWSTR)lpName, szFileName);
		AhnCreateMutexCheck(hMutext, szFileName, lpMutexAttributes, bInitialOwner);
	}
	return (hMutext) ? hMutext : _CreateMutexW(lpMutexAttributes, bInitialOwner, lpName);
}
NTSTATUS NTAPI NGS_NtQueryObject(HANDLE ObjectHandle, OBJECT_INFORMATION_CLASS ObjectInformationClass, PVOID ObjectInformation, ULONG ObjectInformationLength, PULONG ReturnLength OPTIONAL)
{
	NTSTATUS Status = NtQueryObject(ObjectHandle, ObjectInformationClass, ObjectInformation, ObjectInformationLength, ReturnLength);;

	if (NT_SUCCESS(Status) && ObjectInformationClass == ObjectNameInformation)
	{
		if (ObjectInformation && PUNICODE_STRING(ObjectInformation)->Length > 1 && PUNICODE_STRING(ObjectInformation)->MaximumLength > 1)
		{
			PUNICODE_STRING Str = PUNICODE_STRING(ObjectInformation);

			wchar_t* name = PUNICODE_STRING(ObjectInformation)->Buffer;

			if (name != nullptr)
			{
				if (wcsstr(name, xorstr_(L"\\NamedPipe\\BlackCipher")))
				{
					PUNICODE_STRING	vObjectName = (PUNICODE_STRING)ObjectInformation;

					LPWSTR	Value = StrStrW(vObjectName->Buffer, L"_");
					if (Value)
					{
						Value[0] = 0;
						vObjectName->Length = wcslen(vObjectName->Buffer) * sizeof(WCHAR);
					}

				}

			}

			ACEDebugFileLogW(L"[{}] des {} {}", __FUNCTIONW__, name, Status);

		}


	}
	return Status;
}
NTSTATUS	NTAPI	NGS_NtCreateNamedPipeFile(
	OUT PHANDLE FileHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	IN ULONG ShareAccess,
	IN ULONG CreateDisposition,
	IN ULONG CreateOptions,
	IN BOOLEAN TypeMessage,
	IN BOOLEAN ReadmodeMessage,
	IN BOOLEAN Nonblocking,
	IN ULONG MaxInstances,
	IN ULONG InBufferSize,
	IN ULONG OutBufferSize,
	IN PLARGE_INTEGER DefaultTimeout
)
{
	NTSTATUS	Status = STATUS_SUCCESS;

	VMProtectBegin(__FUNCTION__);

#if 1
	if (ObjectAttributes && ObjectAttributes->ObjectName && ObjectAttributes->ObjectName->Length > 0)
	{
		char	szFileName[MAX_PATH];
		char	*PipeName = xorstr_("pipe\\BlackCipher");

		g_pUtil->UnicodeToAnsi(ObjectAttributes->ObjectName->Buffer, szFileName);


		if (strstr(szFileName, PipeName))
		{
			char FileName[MAX_PATH] = { 0 };

			int FileSize = wsprintfA(FileName, "%s_%d", szFileName, GetCurrentProcessId());


			wchar_t	wszFileName[MAX_PATH];
			g_pUtil ->AnsiToUnicode(FileName, wszFileName);

			UNICODE_STRING newObjectName;

			RtlInitUnicodeString(&newObjectName, wszFileName);

			PUNICODE_STRING	oldObjectName = ObjectAttributes->ObjectName;

			ObjectAttributes->ObjectName = &newObjectName;

			Status = NtCreateNamedPipeFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, ShareAccess, CreateDisposition, CreateOptions, TypeMessage, ReadmodeMessage, Nonblocking, MaxInstances, InBufferSize, OutBufferSize, DefaultTimeout);


			ACEDebugFileLogW(L"[{}] BlackCipher Create Pipe Name -> {} Ret ={}  Old Pipe Name -> {}", __FUNCTIONW__, ObjectAttributes->ObjectName->Buffer, Status, oldObjectName->Buffer);

			ObjectAttributes->ObjectName = oldObjectName;

			return Status;
		}
	}
#endif

	VMProtectEnd();

	Status = NtCreateNamedPipeFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, ShareAccess, CreateDisposition, CreateOptions, TypeMessage, ReadmodeMessage, Nonblocking, MaxInstances, InBufferSize, OutBufferSize, DefaultTimeout);

	return Status;
}
NTSTATUS NTAPI NGS_ZwCreateFile(
	OUT PHANDLE FileHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	IN PLARGE_INTEGER AllocationSize OPTIONAL,
	IN ULONG FileAttributes,
	IN ULONG ShareAccess,
	IN ULONG CreateDisposition,
	IN ULONG CreateOptions,
	IN PVOID EaBuffer OPTIONAL,
	IN ULONG EaLength
)
{
	NTSTATUS Status = 0;


	if (ObjectAttributes && ObjectAttributes->ObjectName && ObjectAttributes->Length > 1)
	{
		char	*PipeName = xorstr_("\\\\.\\pipe\\BlackCipher");

		char	szFileName[MAX_PATH];

		g_pUtil->UnicodeToAnsi(ObjectAttributes->ObjectName->Buffer, szFileName);

		char	FileName[MAX_PATH] = { 0 };

#if 0
		if (_strnicmp(PipeName, szFileName,strlen(PipeName) - 1) == 0)
		{

			int FileSize = wsprintfA(FileName, "%s_%d", szFileName, NGSPipeNameProcessId);


			wchar_t	wszFileName[MAX_PATH];
			g_pUtil->AnsiToUnicode(FileName, wszFileName);


			UNICODE_STRING NewObjectName;

			RtlInitUnicodeString(&NewObjectName, wszFileName);


			PUNICODE_STRING PipeSt = ObjectAttributes->ObjectName;


			ObjectAttributes->ObjectName = &NewObjectName;


			Status = NtCreateFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes, ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength);



			ACEDebugFileLog("[{}] BlackCipher New Pipe Name -> {}   {}", __FUNCTION__, FileName, Status);


			ObjectAttributes->ObjectName = PipeSt;

			return Status;



		}
#endif
		ACEErrorFileLogW(L"{} {} Status:0x{:X}", __FUNCTIONW__, ObjectAttributes->ObjectName->Buffer, Status);
	}

	Status = NtCreateFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes, ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength);


	return Status;
}

HANDLE WINAPI NGS_OpenThread(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwThreadId)
{
	ACEDebugFileLog("[{}] dwThreadId:0x{:X}",__FUNCTION__, dwThreadId);

	Sleep(INFINITE);

	return  INVALID_HANDLE_VALUE;//  OpenThread(dwDesiredAccess, bInheritHandle, dwThreadId);
}
NTSTATUS NTAPI NGS_NtQueryInformationProcess( HANDLE ProcessHandle,PROCESSINFOCLASS ProcessInformationClass,PVOID ProcessInformation,ULONG ProcessInformationLength, PULONG ReturnLength)
{
	NTSTATUS Status = NtQueryInformationProcess(ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength, ReturnLength);


	ACEDebugFileLog("[{}] ProcessHandle:0x{:X} ProcessInformationClass:{} lenght:0x{:X} Status:0x{:X}",__FUNCTION__,(int)ProcessHandle, (ULONG)ProcessInformationClass, ProcessInformationLength, (ULONG)Status);


	return Status;
}

NTSTATUS NTAPI NGS_NtSetInformationProcess(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength)
{
	NTSTATUS Status = NtSetInformationProcess(ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength);

	ACEDebugFileLog("[{}] ProcessHandle:0x{:X} ProcessInformationClass:{} lenght:0x{:X} Status:0x{:X}", __FUNCTION__, (int)ProcessHandle, (ULONG)ProcessInformationClass, ProcessInformationLength, (ULONG)Status);


	return Status;

}

UINT WINAPI NGS_EnumSystemFirmwareTables(DWORD FirmwareTableProviderSignature, PVOID pFirmwareTableEnumBuffer, DWORD BufferSize)
{
	return 0;
}
LPVOID WINAPI NGS_VirtualAlloc(
	_In_opt_ LPVOID lpAddress,
	_In_ SIZE_T dwSize,
	_In_ DWORD flAllocationType,
	_In_ DWORD flProtect
)
{
	LPVOID Address = VirtualAlloc(lpAddress, dwSize, flAllocationType, flProtect);

	if (Address)
	{
		ACEWarningFileLog("[{}] 0x{:X}", __FUNCTION__, (DWORD)Address);
	}
	

	return Address;
}