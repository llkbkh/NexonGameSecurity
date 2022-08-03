// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "AhnInterface.h"
#include "AhnConnect.h"
#include "AhnSystemCall.h"
std::shared_ptr<CACEModule> g_pModule   = nullptr;
std::shared_ptr<CACEHook> g_pHook       = nullptr;
std::shared_ptr<CACEProcess> g_pProcess = nullptr;
std::shared_ptr<CACEFile> g_pFile       = nullptr;
std::shared_ptr<CACEHook64> g_pHook64   = nullptr;
std::shared_ptr<CACEUtil> g_pUtil       = nullptr;
std::shared_ptr<CACEMemory> g_pMemory   = nullptr;

LONG NTAPI AhnExceptionHandler(struct _EXCEPTION_POINTERS* ExceptionInfo)
{
	ULONG				nRet = EXCEPTION_CONTINUE_SEARCH;

	VMProtectBegin(__FUNCTION__);
	PEXCEPTION_RECORD	Record = ExceptionInfo->ExceptionRecord;
	PCONTEXT			Context = ExceptionInfo->ContextRecord;


	char szText[2046] = { 0 };

	sprintf(szText, "[%s] 0x%X -> 0x%X\nEAX:0x%X\nECX:0x%X\nEDX:0x%X\nEBX:0x%X\nESP:0x%X\nEBP:0x%X\nESI:0x%X\nEDI:0x%X\nEIP:0x%X",
		__FUNCTION__,
		Record->ExceptionAddress,
		Record->ExceptionCode,
		ExceptionInfo->ContextRecord->Eax,
		ExceptionInfo->ContextRecord->Ecx,
		ExceptionInfo->ContextRecord->Edx,
		ExceptionInfo->ContextRecord->Ebx,
		ExceptionInfo->ContextRecord->Esp,
		ExceptionInfo->ContextRecord->Ebp,
		ExceptionInfo->ContextRecord->Esi,
		ExceptionInfo->ContextRecord->Edi,
		ExceptionInfo->ContextRecord->Eip);


	switch (Record->ExceptionCode)
	{
	case EXCEPTION_BREAKPOINT:
	{
		nRet = EXCEPTION_CONTINUE_SEARCH;


		MessageBox(0, szText, 0, 0);


		return nRet;
	}
	}

	VMProtectEnd();

	

	





	/*ACEDebugFileLog(
		"[{}] 0x{:X} -> 0x{:X}\nEAX:0x{:X}\nECX:0x{:X}\nEDX:0x{:X}\nEBX:0x{:X}\nESP:0x{:X}\nEBP:0x{:X}\nESI:0x{:X}\nEDI:0x{:X}\nEIP:0x{:X}",
		__FUNCTION__,
		Record->ExceptionAddress,
		Record->ExceptionCode,
		ExceptionInfo->ContextRecord->Eax,
		ExceptionInfo->ContextRecord->Ecx,
		ExceptionInfo->ContextRecord->Edx,
		ExceptionInfo->ContextRecord->Ebx,
		ExceptionInfo->ContextRecord->Esp,
		ExceptionInfo->ContextRecord->Ebp,
		ExceptionInfo->ContextRecord->Esi,
		ExceptionInfo->ContextRecord->Edi,
		ExceptionInfo->ContextRecord->Eip
	);*/

	return nRet;
}

BOOL APIENTRY DllMain( HMODULE hModule, DWORD  ul_reason_for_call,LPVOID lpReserved )
{
	VMProtectBegin(__FUNCTION__);

    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    {
		g_pModule  = std::make_shared<CACEModule>();
		g_pHook    = std::make_shared<CACEHook>();
		g_pProcess = std::make_shared<CACEProcess>();
		g_pProcess->ProcessSetToken();
		DisableThreadLibraryCalls(g_pHook->GetSelfModuleByAddress(hModule));

		TAG_ACE_HOOK_MODULE_INFO AppList[] =
		{
			ACE_HOOK_MODULE_INFO("","cstrike-online.exe",	"NexonCSOMutex"),	
			ACE_HOOK_MODULE_INFO("","CSOLauncher.exe","CSOLauncherMutex82"),
			ACE_HOOK_MODULE_INFO("BlackCipher.aes"),
			ACE_HOOK_MODULE_INFO("BlackXchg.aes"),
			ACE_HOOK_MODULE_INFO("NGS_TestApp.exe"),
		};

		if (!CACEModule::GetModuleDetect(AppList, sizeof(AppList) / sizeof(TAG_ACE_HOOK_MODULE_INFO)))  return false;

		g_pFile   = std::make_shared<CACEFile>();
		g_pUtil   = std::make_shared<CACEUtil>();
		g_pMemory = std::make_shared<CACEMemory>();

		auto AppName = g_pModule->GetModuleInfo()->AppName;

#if ANTI_DEBUG
		ACELog.ACELogInstal(AppName, ACE_LOG_FILE_ONCUT);
		ACELog.ACEDebugView(CONSOLE|DEBUG_VIEW);
#endif

		g_pFile->SetFileName(fmt::format(xorstr_("{}\\ACE_DEBUG"), g_pModule->GetModuleInfo()->ModulePath));

		if (g_pFile->OpenFile(OPEN_EXISTING) != INVALID_HANDLE_VALUE)
		{
			g_pFile->CloseFile();
			MessageBoxA(NULL, GetCommandLineA(), xorstr_("拦截启动"), MB_OK);
		}

		g_pHook64 = std::make_shared<CACEHook64>();



		if (!NtWow64QueryInformationProcess64)
		{
			(FARPROC&)NtWow64QueryInformationProcess64 = GetProcAddress(GetModuleHandleA(xorstr_("ntdll.dll")), xorstr_("NtWow64QueryInformationProcess64"));
		}
		//ULONG64 RtlWow64GetCpuAreaInfoAdres = GetProcAddress64(GetModuleHandle64(xorstr_(L"ntdll.dll")), xorstr_("RtlWow64GetCpuAreaInfo"));


		
		//PVOID	VectException = AddVectoredExceptionHandler(EXCEPTION_EXECUTE_HANDLER, AhnExceptionHandler);
		ImpSystemFunCall();

		g_pHook64->HookSSDTDetectInfo(xorstr_("NtCreateUserProcess"), extNtCreateUserProcess, 11);

		//重要的Hook
		g_pHook64->HookSSDTDetectInfo(xorstr_("NtMapViewOfSection"), NGS_NtMapViewOfSection32, 10);
	
	

		//多开
		g_pHook64->HookSSDTDetectInfo(xorstr_("NtQueryObject"), NGS_NtQueryObject, 5);
		g_pHook64->HookSSDTDetectInfo(xorstr_("NtCreateNamedPipeFile"), NGS_NtCreateNamedPipeFile, 14);
		//g_pHook64->HookSSDTDetectInfo(xorstr_("NtCreateFile"), NGS_ZwCreateFile, 11);

		//AhnVirtualExportNaked("ntdll.dll",	 "ntdll.dll", (HMODULE)GetModuleHandleA("ntdll.dll"), FALSE);
		
		//AhnVirtualExportNaked("iphlpapi.dll", "iphlpapi.dll", (HMODULE)LoadLibraryA("iphlpapi.dll"), FALSE);
		//AhnVirtualExportNaked("Advapi32.dll", "Advapi32.dll", (HMODULE)LoadLibraryA("Advapi32.dll"), FALSE);

		//psapi
		//g_pHook->HookSetDetectAll(&TAG_ACE_HOOK_API_INFO(xorstr_("user32.dll"), xorstr_("FindWindowA"), extFindWindowA, nullptr, ACE_HOOK_TYPE_IAT | ACE_HOOK_TYPE_EAT))

	;	// AhnVirtualExportNaked("psapi.dll", "psapi.dll", (HMODULE)LoadLibraryA("psapi.dll"), FALSE);
		//AhnVirtualExportNaked("iphlpapi.dll", "iphlpapi.dll", (HMODULE)LoadLibraryA("iphlpapi.dll"), FALSE);

		TAG_ACE_HOOK_API_INFO DetectApi[] =
		{
			//TAG_ACE_HOOK_API_INFO(xorstr_("ntdll.dll"),xorstr_("LdrLoadDll"),extLdrLoadDll, &_LdrLoadDll,ACE_HOOK_TYPE_IAT | ACE_HOOK_TYPE_EAT),
			//TAG_ACE_HOOK_API_INFO(xorstr_("user32.dll"), xorstr_("FindWindowA"), extFindWindowA, nullptr, ACE_HOOK_TYPE_IAT | ACE_HOOK_TYPE_EAT),
			TAG_ACE_HOOK_API_INFO(xorstr_("kernel32.dll"),xorstr_("CreateMutexA"),extCreateMutexA,&_CreateMutexA,ACE_HOOK_TYPE_IAT | ACE_HOOK_TYPE_EAT),
			TAG_ACE_HOOK_API_INFO(xorstr_("kernel32.dll"),xorstr_("CreateMutexW"),extCreateMutexW,&_CreateMutexW,ACE_HOOK_TYPE_IAT | ACE_HOOK_TYPE_EAT),
			//TAG_ACE_HOOK_API_INFO(xorstr_("kernel32.dll"),xorstr_("VirtualAlloc"),NGS_VirtualAlloc,nullptr,ACE_HOOK_TYPE_IAT | ACE_HOOK_TYPE_EAT),
			

		};
	/*	AhnVirtualExportNaked("kernel32.dll", "kernel32.dll", (HMODULE)GetModuleHandleA("kernel32.dll"), FALSE);
		AhnVirtualExportNaked("kernelbase.dll", "kernelbase.dll", (HMODULE)GetModuleHandleA("kernelbase.dll"), FALSE);
		AhnVirtualExportNaked("ntdll.dll", "ntdll.dll", (HMODULE)GetModuleHandleA("ntdll.dll"), FALSE);*/

		for (auto& it : DetectApi)
		{
			g_pHook->HookSetDetectAll(&it);
		}

		if (lstrcmpi(AppName,xorstr_("BlackCipher.aes")) == 0)
		{
			CSagaClient::GetInstance()->StartThreadRCFInit();

			TAG_ACE_HOOK_API_INFO DetectApi[] =
			{
				TAG_ACE_HOOK_API_INFO(xorstr_("kernel32.dll"),xorstr_("FindFirstFileW"),NGS_FindFirstFileW,nullptr,ACE_HOOK_TYPE_IAT| ACE_HOOK_TYPE_EAT),
				TAG_ACE_HOOK_API_INFO(xorstr_("kernel32.dll"),xorstr_("Thread32Next"),NGS_Thread32Next,nullptr,ACE_HOOK_TYPE_IAT | ACE_HOOK_TYPE_EAT),
				TAG_ACE_HOOK_API_INFO(xorstr_("kernel32.dll"),xorstr_("Process32FirstW"),NGS_Process32FirstW,nullptr,ACE_HOOK_TYPE_IAT | ACE_HOOK_TYPE_EAT),
				TAG_ACE_HOOK_API_INFO(xorstr_("kernel32.dll"),xorstr_("Module32FirstW"),NGS_Module32FirstW,nullptr,ACE_HOOK_TYPE_IAT | ACE_HOOK_TYPE_EAT),
				TAG_ACE_HOOK_API_INFO(xorstr_("kernel32.dll"),xorstr_("Process32NextW"),NGS_Process32NextW,nullptr,ACE_HOOK_TYPE_IAT | ACE_HOOK_TYPE_EAT),
				TAG_ACE_HOOK_API_INFO(xorstr_("Advapi32.dll"),xorstr_("RegOpenKeyExW"),extRegOpenKeyExW,&_RegOpenKeyExW,ACE_HOOK_TYPE_IAT | ACE_HOOK_TYPE_EAT),
				//TAG_ACE_HOOK_API_INFO(xorstr_("kernel32.dll"),xorstr_("OpenThread"),NGS_OpenThread,nullptr,ACE_HOOK_TYPE_IAT | ACE_HOOK_TYPE_EAT),
				//TAG_ACE_HOOK_API_INFO(xorstr_("Advapi32.dll"),xorstr_("RegEnumKeyExW"),NGS_RegEnumKeyExW,nullptr,ACE_HOOK_TYPE_IAT | ACE_HOOK_TYPE_EAT),
				//TAG_ACE_HOOK_API_INFO(xorstr_("ntdll.dll"),xorstr_("NtQueryValueKey"),NGS_NtQueryValueKey,nullptr,ACE_HOOK_TYPE_IAT | ACE_HOOK_TYPE_EAT),
				//TAG_ACE_HOOK_API_INFO(xorstr_("ntdll.dll"),xorstr_("NtOpenKeyEx"),NGS_NtOpenKeyEx,nullptr,ACE_HOOK_TYPE_IAT | ACE_HOOK_TYPE_EAT),
				//TAG_ACE_HOOK_API_INFO(xorstr_("user32.dll"), xorstr_("FindWindowA"), extFindWindowA, &_FindWindowA, ACE_HOOK_TYPE_IAT | ACE_HOOK_TYPE_EAT),
				//TAG_ACE_HOOK_API_INFO(xorstr_("ntdll.dll"), xorstr_("NtOpenProcess"), NGS_NtOpenProcess,nullptr, ACE_HOOK_TYPE_IAT | ACE_HOOK_TYPE_EAT),
				TAG_ACE_HOOK_API_INFO(xorstr_("ntdll.dll"), xorstr_("NtQuerySystemInformation"), NGS_NtQuerySystemInformation,nullptr, ACE_HOOK_TYPE_IAT | ACE_HOOK_TYPE_EAT),
				//TAG_ACE_HOOK_API_INFO(xorstr_("kernel32.dll"),xorstr_("lstrcmpiA"),NGS_lstrcmpiA,nullptr,ACE_HOOK_TYPE_IAT | ACE_HOOK_TYPE_EAT),
				//TAG_ACE_HOOK_API_INFO(xorstr_("ntdll.dll"), xorstr_("NtQueryInformationProcess"), NGS_NtQueryInformationProcess,nullptr, ACE_HOOK_TYPE_IAT | ACE_HOOK_TYPE_EAT),
				//TAG_ACE_HOOK_API_INFO(xorstr_("ntdll.dll"), xorstr_("NtSetInformationProcess"), NGS_NtSetInformationProcess,nullptr, ACE_HOOK_TYPE_IAT | ACE_HOOK_TYPE_EAT),
				TAG_ACE_HOOK_API_INFO(xorstr_("Kernel32.dll"), xorstr_("EnumSystemFirmwareTables"), NGS_EnumSystemFirmwareTables,nullptr, ACE_HOOK_TYPE_IAT | ACE_HOOK_TYPE_EAT),
				
				//网卡与硬盘
				
				TAG_ACE_HOOK_API_INFO(xorstr_("iphlpapi.dll"), xorstr_("GetAdaptersInfo"), NGS_GetAdaptersInfo,&_NGS_GetAdaptersInfo, ACE_HOOK_TYPE_IAT | ACE_HOOK_TYPE_EAT),
				TAG_ACE_HOOK_API_INFO(xorstr_("kernel32.dll"),xorstr_("DeviceIoControl"),NGS_DeviceIoControl,&_NGS_DeviceIoControl,ACE_HOOK_TYPE_IAT | ACE_HOOK_TYPE_EAT),
				
			};
			/*	AhnVirtualExportNaked("kernel32.dll", "kernel32.dll", (HMODULE)GetModuleHandleA("kernel32.dll"), FALSE);
				AhnVirtualExportNaked("kernelbase.dll", "kernelbase.dll", (HMODULE)GetModuleHandleA("kernelbase.dll"), FALSE);
				AhnVirtualExportNaked("ntdll.dll", "ntdll.dll", (HMODULE)GetModuleHandleA("ntdll.dll"), FALSE);*/
			//AhnVirtualExportNaked("iphlpapi.dll", "iphlpapi.dll", (HMODULE)LoadLibraryA("iphlpapi.dll"), FALSE);
			
			for (auto &it: DetectApi)
			{
				g_pHook->HookSetDetectAll(&it);
			}
			//g_pHook64->HookSSDTDetectInfo(xorstr_("NtQueryVirtualMemory"), NGS_NtQueryVirtualMemoryX32, 6);

		}
		else if (lstrcmpi(AppName, xorstr_("NGS_TestApp.exe")) == 0)
		{
			//MessageBoxA(0, GetCommandLineA(), 0, 0);
		}
		else if (lstrcmpi(AppName, xorstr_("CSOLauncher.exe")) == 0)
		{
			TAG_ACE_HOOK_API_INFO DetectApi[] =
			{
				TAG_ACE_HOOK_API_INFO(xorstr_("kernel32.dll"),xorstr_("OpenFileMappingA"),extOpenFileMappingA,nullptr,ACE_HOOK_TYPE_IAT | ACE_HOOK_TYPE_EAT),
				TAG_ACE_HOOK_API_INFO(xorstr_("kernel32.dll"),xorstr_("CreateFileMappingA"),extCreateFileMappingA,nullptr,ACE_HOOK_TYPE_IAT | ACE_HOOK_TYPE_EAT),

			};
			for (auto& it : DetectApi)
			{
				g_pHook->HookSetDetectAll(&it);
			}

		}
		else if (lstrcmpi(AppName, xorstr_("cstrike-online.exe")) == 0)
		{
			TAG_ACE_HOOK_API_INFO DetectApi[] =
			{
				TAG_ACE_HOOK_API_INFO(xorstr_("kernel32.dll"),xorstr_("Process32NextW"),extProcess32NextW,nullptr,ACE_HOOK_TYPE_IAT | ACE_HOOK_TYPE_EAT),
				TAG_ACE_HOOK_API_INFO(xorstr_("kernel32.dll"),xorstr_("Process32Next"),extProcess32Next,nullptr,ACE_HOOK_TYPE_IAT | ACE_HOOK_TYPE_EAT),

			};
			for (auto& it : DetectApi)
			{
				g_pHook->HookSetDetectAll(&it);
			}
		}
		
		break;
    }
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }

	VMProtectEnd();
    return TRUE;
}

