#pragma once
#include "AhnConnect.h"
#define _WIN32_DCOM
#include <comdef.h>   
#include <Wbemidl.h>   
#include <tlhelp32.h>
# pragma comment(lib, "wbemuuid.lib")   

IEnumWbemClassObject* m_pEnumClsObj;
IWbemClassObject* m_pWbemClsObj;
IWbemServices* m_pWbemSvc;
IWbemLocator* m_pWbemLoc;

HRESULT(STDMETHODCALLTYPE* _WMIGet)(
	IWbemClassObject* This,
	/* [string][in] */ LPCWSTR wszName,
	/* [in] */ long lFlags,
	/* [unique][in][out] */ VARIANT* pVal,
	/* [unique][in][out] */ CIMTYPE* pType,
	/* [unique][in][out] */ long* plFlavor);


HRESULT  STDMETHODCALLTYPE NGS_WMIGet(
	IWbemClassObject* This,
	/* [string][in] */ LPCWSTR wszName,
	/* [in] */ long lFlags,
	/* [unique][in][out] */ VARIANT* pVal,
	/* [unique][in][out] */ CIMTYPE* pType,
	/* [unique][in][out] */ long* plFlavor)
{
	HRESULT hres  = _WMIGet(This, wszName, lFlags, pVal, pType, plFlavor);
	
	switch (pVal->vt)
	{
	case VT_BSTR:
		ACEDebugFileLogW(L"[{}]{}", wszName, pVal->bstrVal);
		break;
	case VT_I4:
		ACEDebugFileLogW(L"[{}]{}", wszName, pVal->ulVal);
		break;

	default:
		ACEDebugFileLogW(L"[{}] unk {}", wszName, pVal->vt);
		break;
	}
	return hres;
}



HRESULT(STDMETHODCALLTYPE* _EnumClsNext)(
	IEnumWbemClassObject* This,
	/* [in] */ long lTimeout,
	/* [in] */ ULONG uCount,
	/* [length_is][size_is][out] */ __RPC__out_ecount_part(uCount, *puReturned) IWbemClassObject** apObjects,
	/* [out] */ __RPC__out ULONG* puReturned) = nullptr;

HRESULT STDMETHODCALLTYPE NGS_EnumClsNext(
	IEnumWbemClassObject* This,
	/* [in] */ long lTimeout,
	/* [in] */ ULONG uCount,
	/* [length_is][size_is][out] */ __RPC__out_ecount_part(uCount, *puReturned) IWbemClassObject** apObjects,
	/* [out] */ __RPC__out ULONG* puReturned)
{

	HRESULT hr = _EnumClsNext(This, lTimeout, uCount, apObjects, puReturned);


	if (SUCCEEDED(hr))
	{
		if (apObjects && *apObjects)
		{
			m_pWbemClsObj = *apObjects;

			DWORD VirtualFunctionsEnumClsGet = (DWORD)((*(PDWORD)m_pWbemClsObj) + 0x10);
			//hook -可以直接替换虚表-也可以直接Hook函数 
			//->替换

		
			if (g_pHook->GetSelfModuleByAddress((PVOID) * (PDWORD)(VirtualFunctionsEnumClsGet)) != g_pHook->GetSelfModuleHandle())
			{
				DWORD	lpflOldProtect;
				VirtualProtect((PVOID)VirtualFunctionsEnumClsGet, 5, PAGE_EXECUTE_READWRITE, &lpflOldProtect);

				(DWORD&)_WMIGet = (DWORD) * (PDWORD)(VirtualFunctionsEnumClsGet);
				*(PDWORD)(VirtualFunctionsEnumClsGet) = (DWORD)NGS_WMIGet;

				VirtualProtect((PVOID)VirtualFunctionsEnumClsGet, 5, lpflOldProtect, &lpflOldProtect);

			}
		}


	}
	return hr;
}



HRESULT(STDMETHODCALLTYPE* _ExecQuery)(
	IWbemClassObject* This,
	/* [in] */ __RPC__in const BSTR strQueryLanguage,
	/* [in] */ __RPC__in const BSTR strQuery,
	/* [in] */ long lFlags,
	/* [in] */ __RPC__in_opt IWbemContext* pCtx,
	/* [out] */ __RPC__deref_out_opt IEnumWbemClassObject** ppEnum) = nullptr;


HRESULT STDMETHODCALLTYPE NGS_ExecQuery(
	IWbemClassObject* This,
	/* [in] */ __RPC__in const BSTR strQueryLanguage,
	/* [in] */ __RPC__in const BSTR strQuery,
	/* [in] */ long lFlags,
	/* [in] */ __RPC__in_opt IWbemContext* pCtx,
	/* [out] */ __RPC__deref_out_opt IEnumWbemClassObject** ppEnum)
{
	HRESULT hr = _ExecQuery(This,strQueryLanguage, strQuery, lFlags, pCtx, ppEnum);


	if (SUCCEEDED(hr))
	{
		ACEWarningFileLogW(L"[{}] {} {}", __FUNCTIONW__, strQueryLanguage, strQuery);

		if (ppEnum && *ppEnum)
		{
			m_pEnumClsObj = (IEnumWbemClassObject*)*ppEnum;

			DWORD VirtualFunctionsEnumClsNext = (DWORD)((*(PDWORD)m_pEnumClsObj) + 0x10);
			//hook -可以直接替换虚表-也可以直接Hook函数 
			//->替换
			if (g_pHook->GetSelfModuleByAddress((PVOID) * (PDWORD)(VirtualFunctionsEnumClsNext)) != g_pHook->GetSelfModuleHandle())
			{
				DWORD	lpflOldProtect;
				VirtualProtect((PVOID)VirtualFunctionsEnumClsNext, 5, PAGE_EXECUTE_READWRITE, &lpflOldProtect);

				(DWORD&)_EnumClsNext = (DWORD) * (PDWORD)(VirtualFunctionsEnumClsNext);
				*(PDWORD)(VirtualFunctionsEnumClsNext) = (DWORD)NGS_EnumClsNext;

				VirtualProtect((PVOID)VirtualFunctionsEnumClsNext, 5, lpflOldProtect, &lpflOldProtect);

			}

			//ACEDebugFileLog("[{}]{}",__FUNCTION__ ,"禁止查询 WMI");
			//禁止查询 WMI
			//return WBEM_E_FAILED;
		}
		

	}

	return hr;
}




HRESULT (WINAPI* _CoSetProxyBlanket)(_In_ IUnknown* pProxy,
	_In_ DWORD dwAuthnSvc,
	_In_ DWORD dwAuthzSvc,
	_In_opt_ OLECHAR* pServerPrincName,
	_In_ DWORD dwAuthnLevel,
	_In_ DWORD dwImpLevel,
	_In_opt_ RPC_AUTH_IDENTITY_HANDLE pAuthInfo,
	_In_ DWORD dwCapabilities) = nullptr;


HRESULT WINAPI NGS_CoSetProxyBlanket(
	_In_ IUnknown* pProxy,
	_In_ DWORD dwAuthnSvc,
	_In_ DWORD dwAuthzSvc,
	_In_opt_ OLECHAR* pServerPrincName,
	_In_ DWORD dwAuthnLevel,
	_In_ DWORD dwImpLevel,
	_In_opt_ RPC_AUTH_IDENTITY_HANDLE pAuthInfo,
	_In_ DWORD dwCapabilities
)
{
	HRESULT hr = CoSetProxyBlanket(pProxy, dwAuthnSvc, dwAuthzSvc, pServerPrincName, dwAuthnLevel, dwImpLevel, pAuthInfo, dwCapabilities);


	if (SUCCEEDED(hr))
	{

		if (pProxy && dwAuthnSvc == RPC_C_AUTHN_WINNT)
		{
			m_pWbemSvc = (IWbemServices*)pProxy;

			DWORD VirtualFunctionsExecQuery = (DWORD)((*(PDWORD)m_pWbemSvc) + 0x50);
			//hook -可以直接替换虚表-也可以直接Hook函数 
			//->替换
			if (g_pHook->GetSelfModuleByAddress((PVOID) * (PDWORD)(VirtualFunctionsExecQuery)) != g_pHook->GetSelfModuleHandle())
			{
				DWORD	lpflOldProtect;
				VirtualProtect((PVOID)VirtualFunctionsExecQuery, 5, PAGE_EXECUTE_READWRITE, &lpflOldProtect);

				(DWORD&)_ExecQuery = (DWORD) * (PDWORD)(VirtualFunctionsExecQuery);
				*(PDWORD)(VirtualFunctionsExecQuery) = (DWORD)NGS_ExecQuery;
				
				VirtualProtect((PVOID)VirtualFunctionsExecQuery, 5, lpflOldProtect, &lpflOldProtect);

			}
		}

	}
	return hr;
}



