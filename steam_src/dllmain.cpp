    #include <iostream>
#include <windows.h>

#include <vector>

#include <fstream>
#include <sstream>
#include <algorithm>

#include "minhook/MinHook.h"

using namespace std;

using CreateProcessW_t = BOOL(__stdcall*) (LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);
CreateProcessW_t o_CreateProcessW;

auto open_binary(std::string m_sSource, std::vector< std::uint8_t >& m_aData) -> void
{
    std::ifstream m_strFile(m_sSource, std::ios::binary);
    m_strFile.unsetf(std::ios::skipws);
    m_strFile.seekg(0, std::ios::end);

    const auto m_iSize = m_strFile.tellg();

    m_strFile.seekg(0, std::ios::beg);
    m_aData.reserve(static_cast<uint32_t>(m_iSize));
    m_aData.insert(m_aData.begin(), std::istream_iterator< std::uint8_t >(m_strFile), std::istream_iterator< std::uint8_t >());
    m_strFile.close();
}

auto wstring2string(const std::wstring& sSource, std::string& sDest) -> void
{
    std::string tmp;
    tmp.resize(sSource.size());
    std::transform(sSource.begin(), sSource.end(), tmp.begin(), wctob);
    tmp.swap(sDest);
}

BOOL __stdcall hkCreateProcessW(LPCWSTR lpApplicationName, LPWSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcAttr,
    LPSECURITY_ATTRIBUTES lpThreadAttr, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment,
    LPCWSTR lpCurrentDir, LPSTARTUPINFOW pStartupInfo, LPPROCESS_INFORMATION pProcessInfo)
{
    std::wstring wsApplicationName = std::wstring(lpCommandLine);

    std::string sApplicationName;
    wstring2string(wsApplicationName, sApplicationName);

    if (!strstr(sApplicationName.c_str(), "csgo.exe"))
    {

        return o_CreateProcessW(lpApplicationName, lpCommandLine, lpProcAttr, lpThreadAttr, bInheritHandles,
            dwCreationFlags, lpEnvironment, lpCurrentDir, pStartupInfo, pProcessInfo);
    }

    BOOL bResult = o_CreateProcessW(lpApplicationName, lpCommandLine, lpProcAttr, lpThreadAttr, bInheritHandles,
        dwCreationFlags, lpEnvironment, lpCurrentDir, pStartupInfo, pProcessInfo);

  //  if (!bResult)
  //      return bResult;

    HANDLE hProcess = pProcessInfo->hProcess;

   // if (!hProcess)
   // {
    //    return bResult;
    //}

    VirtualAllocEx(hProcess, reinterpret_cast<void*>(0x40000000), 0x1219000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    //MessageBoxA(NULL, "bag pl in mt", "cioroi prost", MB_ICONWARNING | MB_OK |  MB_YESNO);
    return bResult;
}

auto init_hooks() -> void
{
    if (MH_Initialize() != MH_OK)
    {
        MessageBoxA(NULL, "Failed to initialize hook", "prim", MB_ICONERROR | MB_OK);
        return;
    }

    if (MH_CreateHookApi(L"kernelbase.dll", "CreateProcessW",
        hkCreateProcessW, reinterpret_cast<void**>(&o_CreateProcessW)) != MH_OK)
    {
        MessageBoxA(NULL, "Failed to create hook", "prim", MB_ICONERROR | MB_OK);
        return;
    }

    if (MH_EnableHook(MH_ALL_HOOKS) != MH_OK)
    {
        MessageBoxA(NULL, "Failed to enable hook", "prim", MB_ICONERROR | MB_OK);
        return;
    }
}

auto init() -> void
{
  
    init_hooks();
}

BOOL __stdcall DllMain(HMODULE hModule, DWORD ulReason, LPVOID lpReserved)
{
    if (ulReason != DLL_PROCESS_ATTACH)
        return 0;


    CreateThread(0, 0, (LPTHREAD_START_ROUTINE)init, 0, 0, 0);
    return 1;
}
