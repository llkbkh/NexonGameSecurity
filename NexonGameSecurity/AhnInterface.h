#pragma once
#include <ACEConnect.h>
#include <ACEHook64.h>
#include <ACEPE64.h>
#include <wow64ext/wow64ext.h>
#include "AhnDef.h"

extern std::shared_ptr<CACEModule> g_pModule;
extern std::shared_ptr<CACEHook> g_pHook;
extern std::shared_ptr<CACEProcess> g_pProcess;
extern std::shared_ptr<CACEFile> g_pFile;
extern std::shared_ptr<CACEHook64> g_pHook64;
extern std::shared_ptr<CACEUtil> g_pUtil;
extern std::shared_ptr<CACEMemory> g_pMemory;


extern std::map<ULONG, MapViewOfSectionNGSList> VecNGS_MapList;

