#pragma once
#include "AhnInterface.h"
#include <wow64ext/wow64ext.h>
#include <wow64ext/internal.h>
#pragma pack(push, 1)
typedef struct _X64Call_Args {

	DWORD64 Param_1;
	DWORD64 Param_2;
	DWORD64 Param_3;
	DWORD64 Param_4;
	DWORD64 Param_5;
	DWORD64 Param_6;
	DWORD64 Param_7;
	DWORD64 Param_8;
	DWORD64 Param_9;
	DWORD64 Param_10;
	DWORD64 Param_11;
}X64Call_Args, * PX64Call_Args;

typedef struct _X64Call_Param {

	DWORD64 Function;
	PX64Call_Args	Args;
}X64Call_Param, * PX64Call_Param;
#pragma pack(pop)

typedef struct _PROCESS_BASIC_INFORMATION64
{
	PVOID Reserved1[2];
	PVOID64 PebBaseAddress;
	PVOID Reserved2[4];
	ULONG_PTR UniqueProcessId[2];
	PVOID Reserved3[2];
} PROCESS_BASIC_INFORMATION64, * PPROCESS_BASIC_INFORMATION64;

typedef struct _NT_PROC_THREAD_ATTRIBUTE_ENTRY {
	ULONG Attribute;    // PROC_THREAD_ATTRIBUTE_XXX，参见MSDN中UpdateProcThreadAttribute的说明
	SIZE_T Size;        // Value的大小
	ULONG_PTR Value;    // 保存4字节数据（比如一个Handle）或数据指针
	ULONG Unknown;      // 总是0，可能是用来返回数据给调用者
} PROC_THREAD_ATTRIBUTE_ENTRY, * PPROC_THREAD_ATTRIBUTE_ENTRY;

typedef struct _NT_PROC_THREAD_ATTRIBUTE_LIST {
	ULONG Length;       // 结构总大小
	PROC_THREAD_ATTRIBUTE_ENTRY Entry[1];
} NT_PROC_THREAD_ATTRIBUTE_LIST, * PNT_PROC_THREAD_ATTRIBUTE_LIST;

typedef struct _MEMORY_SECTION_NAME {
	UNICODE_STRING Name;
	WCHAR     Buffer[512];
	_MEMORY_SECTION_NAME()
	{
		RtlZeroMemory(this, sizeof(_MEMORY_SECTION_NAME));
		this->Name.MaximumLength = sizeof(this->Buffer);
		this->Name.Buffer = this->Buffer;
	}
}MEMORY_SECTION_NAME, * PMEMORY_SECTION_NAME;

typedef struct _UNICODE_STRING64 {
	USHORT Length;
	USHORT MaximumLength;
	WCHAR* POINTER_64 Buffer;
}UNICODE_STRING64, * PUNICODE_STRING64;

typedef struct _MEMORY_SECTION_NAME_NGS {
	UNICODE_STRING64 Name;
	WCHAR     Buffer[260];
}MEMORY_SECTION_NAME_NGS, * PMEMORY_SECTION_NAME_NGS;


typedef struct _OBJECT_ATTRIBUTES64 {
	ULONG Length;
	PVOID64 RootDirectory;
	UNICODE_STRING64* POINTER_64 ObjectName;
	ULONG Attributes;
	PVOID64 SecurityDescriptor;
	PVOID64 SecurityQualityOfService;
} OBJECT_ATTRIBUTES64, * POBJECT_ATTRIBUTES64;


//X64回调
typedef std::function<DWORD64(X64Call_Param* p, int server_index)> X64NGSCallback_t;

typedef struct _MapViewOfSectionNGSList 
{
	std::string NtApName;			
	BOOL HookStatus;					//是否可Hook
	DWORD64 dwAddress;					//原始地址
	X64NGSCallback_t CallBack;			//回调
	ULONG	Ordinal;					//序号

	inline _MapViewOfSectionNGSList()
	{
		this->HookStatus = FALSE;
		this->dwAddress  = 0;
		this->CallBack   = 0;
	}
	inline _MapViewOfSectionNGSList(std::string api, BOOL HookStatus)
	{
		this->NtApName   = api;
		this->HookStatus = HookStatus;
		this->dwAddress  = 0;
		this->CallBack   = 0;
	}
}MapViewOfSectionNGSList, * PMapViewOfSectionNGSList;

typedef struct
{
	ULONG	CallBack;
	ULONG	Address;
	char* DllName;
	char* CurDllName;
	char* Name;
	ULONG	FunOffser;		//导出函数偏移
	char	Code[16];
}TAG_VIRTUAL_API_INFO, * PTAG_VIRTUAL_API_INFO;

typedef struct _SYSTEM_MODULE_INFORMATION
{
	ULONG Reserved[2];
	PBYTE Base;
	ULONG Size;
	ULONG Flags;
	USHORT Index;
	USHORT Unknown;
	USHORT LoadCount;
	USHORT ModuleNameOffset;
	CHAR ImageName[256];
} SYSTEM_MODULE_INFORMATION, * PSYSTEM_MODULE_INFORMATION;

typedef struct _WOW64_CPURESERVED {
	USHORT          Flags;
	USHORT          MachineType;

	//
	// CONTEXT has different alignment for
	// each architecture and its location
	// is determined at runtime (see
	// RtlWow64GetCpuAreaInfo below).
	//
	// CONTEXT      Context;
	// CONTEXT_EX   ContextEx;
	//
} WOW64_CPURESERVED, * PWOW64_CPURESERVED;

typedef struct _WOW64_CPU_AREA_INFO {
	//PCONTEXT_UNION  Context;
	//PCONTEXT_EX     ContextEx;
	PVOID  Context;
	PVOID     ContextEx;

	PVOID           ContextFlagsLocation;
	PWOW64_CPURESERVED CpuReserved;
	ULONG           ContextFlag;
	USHORT          MachineType;
} WOW64_CPU_AREA_INFO, * PWOW64_CPU_AREA_INFO;