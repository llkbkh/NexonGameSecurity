#pragma once
#include "AhnInterface.h"

ULONG NGSPipeNameProcessId = 0;

NTSTATUS NTAPI extNtCreateUserProcess(
	_Out_ PHANDLE ProcessHandle,
	_Out_ PHANDLE ThreadHandle,
	_In_ ACCESS_MASK ProcessDesiredAccess,
	_In_ ACCESS_MASK ThreadDesiredAccess,
	_In_opt_ POBJECT_ATTRIBUTES ProcessObjectAttributes,
	_In_opt_ POBJECT_ATTRIBUTES ThreadObjectAttributes,
	_In_ ULONG ProcessFlags,
	_In_ ULONG ThreadFlags,
	_In_ PRTL_USER_PROCESS_PARAMETERS ProcessParameters,
	_Inout_ PPS_CREATE_INFO CreateInfo,
	_In_ PPS_ATTRIBUTE_LIST AttributeList)
{

	NTSTATUS Status = NtCreateUserProcess
	(
		ProcessHandle,
		ThreadHandle,
		ProcessDesiredAccess,
		ThreadDesiredAccess,
		ProcessObjectAttributes,
		ThreadObjectAttributes,
		ProcessFlags,
		ThreadFlags,
		ProcessParameters,
		CreateInfo,
		AttributeList);

	if (NT_SUCCESS(Status))
	{
		VMProtectBegin(__FUNCTION__);

		auto lpCommandLine = ProcessParameters->CommandLine.Buffer;

		char	szFileName[MAX_PATH];

		ULONG	ReturnLength;

		PROCESS_BASIC_INFORMATION	psi = { 0 };

		if (NT_SUCCESS(NtQueryInformationProcess(*ProcessHandle, ProcessBasicInformation, &psi, sizeof(PROCESS_BASIC_INFORMATION), &ReturnLength)))
		{
			if (GetProcessImageFileNameA(*ProcessHandle, szFileName, MAX_PATH) > 0)
			{
				char* szAppName = (strrchr(szFileName, '\\')) ? strrchr(szFileName, '\\') + 1 : szFileName;

				GetModuleFileNameA(g_pHook->GetSelfModuleHandle(), szFileName, MAX_PATH);

				g_pProcess->ProcessCreateRmoterThreadEx(*ProcessHandle, *ThreadHandle, szFileName);

				char szCommndLine[MAX_PATH] = { 0 };

				g_pUtil->UnicodeToAnsi(lpCommandLine, szCommndLine);

				//senddump
				if (szCommndLine && strstr(szCommndLine, xorstr_("CSOLauncher.exe")) != 0)
				{
					//TerminateProcess(*ProcessHandle, 0);
					//exit(0);
				}
				if (szCommndLine && strstr(szCommndLine, xorstr_("BlackCipher.aes")) != 0)
				{
					NGSPipeNameProcessId = (ULONG)psi.UniqueProcessId;

				}

				ACEDebugFileLog("[{}] {} ",__FUNCTION__, szCommndLine);
			}
		}

		VMProtectEnd();
	}

	return Status;
}
