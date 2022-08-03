// NGS_TestApp.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <CACEInterface.h>
#include <wow64ext/internal.h>
#include <wow64ext/wow64ext.h>
#include <PackWrite.h>

extern "C" void   NewKiUserExceptionDispatcher(PEXCEPTION_RECORD ExceptionRecord, PCONTEXT  Context)
{

	if (ExceptionRecord->ExceptionCode == 1010)//确认我们自己的异常 可以用线程ID替代？
	{
		printf("劫持异常代码 ： %d\n此次异常不会执行任务异常处理程序\n", ExceptionRecord->ExceptionCode);
		////利用栈回溯 获取异常函数call下一条指令地址？  
		//StackTrace64(Context);
		////+0x2  是__except处理的的地址
		//Context->Rip += 0x2;
		////通知R0 从__except开始运行 
		//RtlRestoreContext(Context, 0);
		////下边不会运行
		//printf("这句永远不会运行\n");
	}
}

void __stdcall extKiUserExceptionDispatcher(PTAG_PEB_STACK  Stack)
{
	PEXCEPTION_RECORD ExceptionRecord = (PEXCEPTION_RECORD)*(PULONG)((ULONG)Stack->ESP);
	PCONTEXT ContextRecord            = (PCONTEXT) * (PULONG)((ULONG)Stack->ESP + 4);


	char szText[2046] = { 0 };

	sprintf(szText, "[%s] 0x%X -> 0x%X\nEAX:0x%X\nECX:0x%X\nEDX:0x%X\nEBX:0x%X\nESP:0x%X\nEBP:0x%X\nESI:0x%X\nEDI:0x%X\nEIP:0x%X",
		__FUNCTION__,
		ExceptionRecord->ExceptionAddress,
		ExceptionRecord->ExceptionCode,

		ContextRecord->Ecx,
		ContextRecord->Edx,
		ContextRecord->Ebx,
		ContextRecord->Esp,
		ContextRecord->Ebp,
		ContextRecord->Esi,
		ContextRecord->Edi,
		ContextRecord->Eip);

	ACEDebugLog("{} {:X}", szText, offsetof(CONTEXT, Eip));


	ContextRecord->Eip += CACEInterface::GetInstance()->GetHook()->GetDisasmLenght(ContextRecord->Eip);
	
	


	NtContinue(ContextRecord, 0);
	//永远不会执行下一句
	//RtlRaiseStatus(pContext->Eax);
	//NtRaiseException((PEXCEPTION_RECORD)Stack->ESP, pContext,0);
}

ULONG ulRetAddress = 0;

void DSAPI DsKiUserExceptionDispatcher()
{
	__asm 
	{
		pushad
		push esp
		call extKiUserExceptionDispatcher
		popad
		jmp [ulRetAddress]
	}
}

LONG __stdcall VEHandler(struct _EXCEPTION_POINTERS* ExceptionInfo)
{
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

	ACEDebugLog("{}", szText);

	return EXCEPTION_CONTINUE_EXECUTION;//忽略异常=什么都没发生 try块当然也无法捕获到
}

// 异常分发Hook
#if 0
int main()
{

	// HOOK  KiUserExceptionDispatcher

	CACEHook Hook;

	DWORD Funs = (DWORD)Hook.GetProcAddress(Hook.GetNtModuleHandle(), "KiUserExceptionDispatcher");

	auto CodeText = Hook.GetDisamCompleteInstr(Funs, 1);

	int nLenght = 0;

	auto Info = Hook.GetDisasmInfo(Funs, nLenght);

	if (nLenght >= 1 && Info.Instruction.Opcode == 0x83)
	{
		/*
			83 3D A069B377 00     - cmp dword ptr [ntdll.LdrParentRtlInitializeNtUserPfn+10],00
			74 0E                 - je ntdll.KiUserExceptionDispatcher+17
			8B 0D A069B377        - mov ecx,[ntdll.LdrParentRtlInitializeNtUserPfn+10]
			FF 15 E091B377        - call dword ptr [ntdll.LdrParentInterlockedPopEntrySList+280C]
			FF E1                 - jmp ecx

		*/

		// 填充地址
		auto ptr = *(uintptr_t**)(Funs + 2);


		*ptr = (ULONG)DsKiUserExceptionDispatcher;

	}

	//找到返回地址
	Info = Hook.GetDisasmInfo(Funs + nLenght, nLenght);

	if (nLenght >= 1 && Info.Instruction.Opcode == 0x74)
	{

		ulRetAddress = Info.Instruction.AddrValue;

	}



	PVOID	VectException = AddVectoredExceptionHandler(EXCEPTION_EXECUTE_HANDLER, VEHandler);

	DebugBreak();


	ACEDebugLog("{}", CodeText);


	//判断是否可以Hook



	getchar();
}

#endif
WORD sysback_fs = 0;
PVOID NtDLL64CallHandle = nullptr;

void __declspec(naked) NtDll64HookAsm()
{
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

DWORD64 WINAPI X64CallHandle(PVOID* p, int server_index)
{
	MessageBox(0, 0, 0, 0);

	return 1;
}


int main()
{
	// 64位导出表 Hook
	auto _Ntdll =  GetModuleHandle64(L"ntdll.dll");
	CACEPE64 PE64(_Ntdll);

	SetNtDLL64CallHandle(X64CallHandle);

	auto v1 = PE64.GetSectionInformation(".text");

	// .text 最后有空闲的可以Hook  每个函数最少17个字节
	DWORD64 dwHook64Address = std::get<1>(v1) + std::get<2>(v1) - 17;
	auto lPackWrite         = std::make_shared<PackWriter>(100);
	X64GetMem64(lPackWrite->GetBytes(), dwHook64Address, 17);

	auto ExpTable =  PE64.GetExportTable();

	ACEDebugLog("ExportTableAddress: 0x{:X}", std::get<3>(ExpTable));

	PE64.EnumExportTable([&](int Index, std::string ApiName, ULONG64 Address, ULONG64 Offset, DWORD64 RVA)
	{
		ACEDebugLog("{} {} 0x{:X} 0x{:X} 0x{:X}",Index, ApiName, Address, Offset, RVA);

		if (ApiName == "NtOpenProcess")
		{
			DWORD dwOldProtect = 0;

			DWORD FunOffset = dwHook64Address - _Ntdll;

			VirtualProtectEx64(GetCurrentProcess(), RVA , 0x1000, PAGE_EXECUTE_READWRITE, &dwOldProtect);
			WriteProcessMemory64(GetCurrentProcess(),RVA, &FunOffset, 4, nullptr);
			VirtualProtectEx64(GetCurrentProcess(), RVA, 0x1000, dwOldProtect, &dwOldProtect);


			//拷贝
			X64GetMem64(lPackWrite->GetBytes(), Address, 8);
			lPackWrite->SetOffset(8);
			// - push rcx
			lPackWrite->WriteByte(0x48);
			lPackWrite->WriteByte(0xc7);
			lPackWrite->WriteByte(0xc1);
			lPackWrite->WriteInt((ULONG)NtDll64HookAsm);
			lPackWrite->WriteByte(0xff);
			lPackWrite->WriteByte(0xe1);

			VirtualProtectEx64(GetCurrentProcess(), dwHook64Address, 0x1000, PAGE_EXECUTE_READWRITE, &dwOldProtect);
			WriteProcessMemory64(GetCurrentProcess(), dwHook64Address, lPackWrite->GetBytes(), 17, nullptr);
			VirtualProtectEx64(GetCurrentProcess(), dwHook64Address, 0x1000, dwOldProtect, &dwOldProtect);


		}

		



	});


	auto vFuns =  GetProcAddress64(_Ntdll, "NtOpenProcess");


	getchar();
}

