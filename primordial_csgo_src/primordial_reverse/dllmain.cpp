//pasted full of shit code

#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS

#include <winsock2.h>
#include <Windows.h>
#include <iostream>
#include <cstdint>
#include <intrin.h>
#include <wininet.h>
#include <filesystem>
#include <fstream>
#include <array>
#include <map>
#include <unordered_map>
#include <tlhelp32.h>
#include <mutex>

#include "minhook/MinHook.h"
#include "imports.h"
#include "resource.h"
#include "offsets.h"
#include "Json.hpp"
//#include "relocs.hpp"

std::uintptr_t wolfssl_read = 0xE82E0;
std::uintptr_t memory_size = 0x1219000;
std::uintptr_t new_alloc = 0;
std::uintptr_t base_address = 0x40000000;

struct g_result_data
{
    int result;
};

std::map<int, std::vector<uint8_t>> g_ssl_stages = {
{0, {0x55,0x00,0x00,0x00,0x28,0x22,0x3b,0x61,0x46,0xe5,0x40,0x6b,0xee,0x2e,0x18,0x07,0xb0,0x30,0x92,0x6d,0x4d,0x38,0x5c,0x3a,0x17,0x6e,0xb6,0x64,0x89,0x2a,0x2f,0x60,0x13,0xc2,0x8e,0x80,0x6a,0x9a,0xd9,0x8a,0x02,0x2f,0xaf,0x98,0xfe,0x7d,0x00,0xa9,0x0a,0x03,0x84,0xa8,0xe0,0x68,0x1b,0x4a,0xd8,0xf1,0x42,0x09,0x77,0xf5,0xe8,0x7a,0x9b,0xba,0xb3,0x02,0x8b,0x59,0x9b,0xde,0xa4,0xad,0x98,0x8f,0xe7,0x02,0xf4,0x8f,0xbf,0x50,0xfd,0x8a,0x3c,}},
{1, {0x25,0x02,0x00,0x00,0x92,0xf4,0x54,0xfe,0xea,0x1b,0x4c,0x33,0x9c,0x42,0x6a,0x91,0x26,0xc8,0x0d,0x76,0xc6,0xb3,0xf0,0xbe,0xba,0x37,0x10,0x08,0x41,0x64,0x2d,0xc6,0x04,0xb9,0xe9,0x60,0x08,0xb8,0xda,0x89,0x58,0xa9,0x86,0xba,0xd8,0xab,0x39,0x24,0xbe,0xe4,0x87,0xd1,0xf6,0xdf,0x06,0xf4,0x7d,0xa7,0x3d,0x8e,0x0a,0xcc,0x84,0xac,0x28,0xc9,0xca,0x0e,0x31,0x98,0x32,0x50,0x09,0xf8,0x31,0x9c,0x6f,0x15,0x11,0xf1,0xa2,0x0e,0xb1,0x4c,0x7f,0x23,0x46,0x6c,0x97,0x2d,0x1b,0xbb,0x97,0x10,0x99,0x12,0x20,0xc5,0x31,0x53,0xc5,0x47,0xd1,0x8a,0x28,0x28,0xcb,0x71,0xcf,0x55,0xb3,0xe8,0x3c,0x2c,0xcb,0x54,0xb7,0xad,0x8e,0x03,0xc9,0xbb,0xbe,0x42,0xe7,0x1e,0xa6,0xd4,0x74,0x46,0xd0,0xf6,0x95,0xfd,0x47,0x64,0xe6,0xe3,0xc2,0x7d,0x24,0xf6,0xad,0x63,0x55,0x8a,0x6e,0x86,0xfb,0xc4,0xf3,0xbd,0xed,0x3f,0x30,0xb0,0xd7,0x29,0xa3,0x79,0x6d,0x72,0x34,0x08,0x7f,0x87,0x40,0x74,0x21,0x5c,0xdc,0xac,0xda,0x6f,0xa4,0xb4,0xce,0x6e,0x32,0xc6,0x34,0x3f,0x37,0xa8,0x5e,0x2f,0x8c,0x02,0xc8,0x8e,0x24,0x08,0x41,0x4a,0xc0,0x59,0x05,0x17,0xf1,0x35,0x90,0x5b,0x38,0x24,0xeb,0xbb,0x29,0x1a,0x37,0x13,0x74,0x7b,0xd2,0x8e,0x3b,0x3a,0x47,0x55,0xf2,0x9c,0x4d,0xe8,0xea,0x35,0xee,0x40,0x82,0xfd,0xe4,0x08,0xb2,0x03,0x15,0xa5,0xb5,0x97,0x81,0xf5,0xf0,0x6a,0x80,0x69,0x27,0x8c,0x3d,0xc6,0x42,0x31,0x7c,0x5a,0x4d,0xed,0x45,0x77,0x25,0x27,0x20,0x94,0xb8,0x09,0xe8,0xd7,0xbc,0x76,0xa1,0xdc,0x15,0x36,0xe2,0xe1,0x20,0x86,0x77,0x01,0xaa,0x52,0xd2,0x3a,0xf6,0x78,0xb7,0x00,0x60,0x45,0xe0,0x06,0x97,0xcf,0xbe,0x36,0xd6,0x2f,0x98,0x0a,0x90,0x00,0xc0,0xc9,0x3d,0x05,0x6d,0x24,0x85,0x0a,0xe4,0x62,0x86,0x71,0x5c,0x30,0x3c,0xab,0xf4,0x93,0xcb,0xaf,0xe9,0x56,0x26,0x4f,0xfa,0x6a,0x2a,0x37,0x94,0x0c,0x65,0xa5,0x5a,0x12,0x35,0x59,0x4b,0xb8,0xa8,0xce,0x57,0x5b,0x7f,0x07,0xa0,0xac,0x86,0xe4,0x51,0x69,0x4b,0x5a,0x7f,0xfb,0x73,0x81,0xbc,0x1f,0x39,0x39,0x3f,0xb0,0x54,0xb3,0x56,0xce,0x95,0xab,0x27,0x39,0xa9,0x23,0x7c,0x55,0xa0,0xa5,0x91,0x9d,0x2d,0xd7,0xed,0xc4,0x5b,0xd2,0xef,0x77,0x28,0xe8,0x87,0x16,0x16,0x4d,0x96,0xc3,0x5a,0xb5,0xbe,0x01,0xc3,0x05,0x82,0xee,0xb9,0xda,0xa6,0x36,0xca,0xba,0x63,0x6f,0x54,0xe2,0xdf,0xfb,0x81,0xef,0x6f,0xea,0xcf,0xa3,0xa3,0xe0,0x96,0x6d,0x4d,0xa5,0x83,0xed,0x91,0xe5,0xdc,0xda,0x8b,0x43,0x1d,0xbc,0x50,0xfd,0x50,0xca,0x25,0xd5,0xd5,0x83,0xaf,0x7d,0x6f,0xc6,0xe0,0x69,0xa0,0x54,0xe6,0xaa,0xb0,0xff,0x3e,0x99,0x5d,0xa2,0x20,0x98,0xb8,0xd8,0x54,0x44,0xb1,0xa0,0x49,0xc5,0xee,0x39,0x86,0x20,0xc1,0x76,0x18,0x06,0xd4,0x3f,0x25,0xd2,0x86,0xab,0xfc,0x53,0x58,0x4f,0xd3,0x70,0xe5,0xed,0x2e,0x96,0x75,0x82,0xba,0x57,0x38,0x62,0xbd,0x3e,0x85,0xc9,0xca,0xdf,0x4f,0x43,0x34,0xbc,0x17,0x6c,0x0e,0xc6,0x3b,0x21,0x7e,0x39,0x6f,0x9e,0x38,0x71,0xc4,0xb1,0x32,0x74,0xc6,0x13,0x4c,0xfa,0xdd,0xe3,0x05,0x0e,0x96,0x19,0x66,0x55,0x0a,0x79,0x2b,0x68,0x0b,0xa3,0x1e,0x28,0x26,0x3c,0x65,0xf0,0xdd,0x06,0xce,}},
};

static inline const std::map< int, int > g_wolfssl_results = {
    { 0, 0x55 }, { 1, 0x225 },
};


int stage = 0;

typedef int (*wolfssl_read_t)(int sockfd, void* buf, size_t count);
wolfssl_read_t orig_wolfssl_read;

int hooked_wolfssl_read(int sockfd, void* buf, size_t count)
{
    //printf("call now\n");
    memcpy(buf, g_ssl_stages.at(stage).data(), g_ssl_stages.at(stage).size());

    int result = g_wolfssl_results.at(stage);
    //printf("result - 0x%x\n", result);

    stage++;

    return result;

}

int wolfsend(uintptr_t a1, uintptr_t a2, uintptr_t a3)
{
    return a3;
}

typedef int (*wolfssl_connect)(int sockfd);
wolfssl_connect orig_wolfconnect;

int hooked_wolfssl_connect(int sockfd)
{
    sockfd = 1;
    return 1;
}

std::unordered_map<std::string, HMODULE> moduleCache;
std::unordered_map<std::string, FARPROC> functionCache;

HMODULE GetCachedModule(const std::string& moduleName) {
    if (moduleCache.find(moduleName) == moduleCache.end()) {
        moduleCache[moduleName] = LoadLibraryA(moduleName.c_str());
    }
    return moduleCache[moduleName];
}

FARPROC GetCachedFunction(HMODULE hModule, const std::string& functionName) {
    std::string key = std::to_string(reinterpret_cast<uintptr_t>(hModule)) + functionName;
    if (functionCache.find(key) == functionCache.end()) {
        functionCache[key] = GetProcAddress(hModule, functionName.c_str());
    }
    return functionCache[key];
}

int hooks_shit()
{
    if (MH_Initialize() != MH_OK)
    {
    }

    for (const auto hook : g_hooks) {
        if (hook.original != 0x0)
        {
            MH_CreateHook(reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(GetModuleHandleA(hook.mod)) + hook.offset), (void*)(base_address + hook.rva), (void**)(base_address + hook.original));
        }
        else
        {
            MH_CreateHook(reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(GetModuleHandleA(hook.mod)) + hook.offset), (void*)(base_address + hook.rva), NULL);
        }
    }
    if (MH_EnableHook(MH_ALL_HOOKS) != MH_OK)
    {
    }
    return 0;
}

bool memcheck(uintptr_t Ret)
{
    if (Ret >= base_address && Ret <= base_address + memory_size)
        return true;

    return false;
}

decltype(&connect) oConnect;

BOOL
PASCAL
hooked_connect(
    _In_ SOCKET s,
    _In_reads_bytes_(namelen) const struct sockaddr FAR* name,
    _In_ int namelen)
{
    if (memcheck((uintptr_t)_ReturnAddress()))
    {
        return 0;
    }
    return oConnect(s, name, namelen);
}

decltype(&socket) oSocket;

BOOL
PASCAL
hooked_socket(
    _In_ int af,
    _In_ int type,
    _In_ int protocol)
{
    if (memcheck((uintptr_t)_ReturnAddress()))
    {
        return 0x1488;
    }
    return oSocket(af, type, protocol);
}

decltype(&setsockopt) oSetsockopt;

int
PASCAL
hooked_setsockopt(
    _In_ SOCKET     s,
    _In_ int        level,
    _In_ int        optname,
    _In_ const char* optval,
    _In_ int        optlen)
{
    if (memcheck((uintptr_t)_ReturnAddress()))
    {
        return 0;
    }
    return oSetsockopt(s, level, optname, optval, optlen);
}

void* orig_json_dump = nullptr;
void* orig_json_sstream = nullptr;

using json_stream_t = void ( __thiscall* ) ( void* string, const bool strict, nlohmann::json* pResult );

void __fastcall hooked_parse( void* string, int, const bool strict, nlohmann::json* pResult )
{

	( ( json_stream_t ) orig_json_sstream )( string, strict, pResult );
}

int main(HMODULE mod)
{
    std::uintptr_t new_alloc = 0x40000000;

    std::uintptr_t entrypoint = new_alloc + 0x52F64E;

    HRSRC res = FindResourceA(mod, (LPCSTR)0x65, "GANGBANG");
    if (!res) {
        return 1;
    }

    HGLOBAL load = LoadResource(mod, res);
    if (!load) {
        return 1;
    }

    size_t size = SizeofResource(mod, res);
    if (!size) {
        return 1;
    }

    std::uintptr_t resource = reinterpret_cast<std::uintptr_t>(LockResource(load));
    if (!resource) {
        return 1;
    }

    memcpy(reinterpret_cast<void*>(new_alloc), reinterpret_cast<void*>(resource), size);

    while (!GetModuleHandleA("serverbrowser.dll")) Sleep(100);

    uintptr_t addr_wolfssl_read = new_alloc + 0xCE1A0;
    uintptr_t addr_wolfssl_send = new_alloc + 0xCE140;
    orig_wolfconnect = (wolfssl_connect)(new_alloc + 0xD0D30); 
    uintptr_t jsparse = new_alloc + 0x147b50;
    HMODULE ws232mod = GetModuleHandle(L"ws2_32.dll");
    if (!ws232mod) {
        return 0;
    }

    void* ws2_32_recv = GetProcAddress(ws232mod, "recv");
    void* ws2_32_send = GetProcAddress(ws232mod, "send");
    void* ws2_32_connect = GetProcAddress(ws232mod, "connect");


    if (MH_Initialize() != MH_OK)
    {
        return 1;
    }

    if (MH_CreateHook((void*)addr_wolfssl_read, &hooked_wolfssl_read, NULL) != MH_OK)
    {
        return 1;
    }


    if (MH_CreateHook((void*)orig_wolfconnect, &hooked_wolfssl_connect, NULL) != MH_OK)
    {
        return 1;
    }

    if (MH_CreateHook((void*)addr_wolfssl_send, &wolfsend, NULL) != MH_OK)
    {
        return 1;
    }

    if (MH_CreateHookApi(L"ws2_32.dll", "connect", hooked_connect, reinterpret_cast<LPVOID*>(&oConnect)) != MH_OK)
    {
        return 1;
    }


    MH_CreateHook( reinterpret_cast< void* >( jsparse ), hooked_parse, &orig_json_sstream );


    if (MH_EnableHook(MH_ALL_HOOKS) != MH_OK)
    {
        return 1;
    }
    

    for (const auto& CurrentImport : g_aImports) {
        HMODULE hModule = GetCachedModule(std::get<1>(CurrentImport));
        if (!hModule) continue;

        uint32_t pFunction = reinterpret_cast<uint32_t>(GetCachedFunction(hModule, std::get<2>(CurrentImport)));
        if (!pFunction) continue;

        *reinterpret_cast<uint32_t*>(std::get<0>(CurrentImport) + new_alloc) = pFunction;
    }

    for (const auto& imp : g_inline) {

        HMODULE hModule = GetCachedModule(imp.mod);
        if (!hModule) continue;

        if (imp.type == call || imp.type == jmp)
        {
            uintptr_t calc = reinterpret_cast<uintptr_t>(GetCachedFunction(hModule, imp.func)) - (imp.offset + new_alloc) - 0x5;
            *reinterpret_cast<uintptr_t*>(new_alloc + imp.offset + 0x1) = calc;
        }

        else if (imp.type == iat)
        {
            uintptr_t calc = reinterpret_cast<uintptr_t>(GetCachedFunction(hModule, imp.func));
            *reinterpret_cast<uintptr_t*>(new_alloc + imp.offset) = calc;
        }
    }


    for (const auto offset : g_offsets_table) 
    {
        uintptr_t rand = (uintptr_t)std::rand();
        if (offset.hasdll) {
            *reinterpret_cast<uintptr_t*>(new_alloc + offset.xor_offset) = rand;
            *reinterpret_cast<uintptr_t*>(new_alloc + offset.value_offset) = ((uintptr_t)GetModuleHandleA(offset.mod) + offset.offset) ^ rand;
        }
        else {
            *reinterpret_cast<uintptr_t*>(new_alloc + offset.xor_offset) = rand;
            *reinterpret_cast<uintptr_t*>(new_alloc + offset.value_offset) = offset.offset ^ rand;
        }
    }

    {
        uint32_t hMod = reinterpret_cast<uint32_t>(GetModuleHandleA(("engine.dll")));
        uint32_t address = (uint32_t)hMod + 0x2288eb;
        DWORD dwOldValue, dwTemp;
        VirtualProtect((LPVOID)address, 6, PAGE_EXECUTE_READWRITE, &dwOldValue);

        memset((void*)address, 0x90, 0x6);

        VirtualProtect((LPVOID)address, 6, dwOldValue, &dwTemp);
    }
    {
        uint32_t hMod = reinterpret_cast<uint32_t>(GetModuleHandleA(("engine.dll")));
        uint32_t address = (uint32_t)hMod + 0xdd3a3;
        DWORD dwOldValue, dwTemp;
        VirtualProtect((LPVOID)address, 1, PAGE_EXECUTE_READWRITE, &dwOldValue);

        memset((void*)address, 0x0, 0x1);

        VirtualProtect((LPVOID)address, 1, dwOldValue, &dwTemp);
    }

    {
        uint32_t hMod = reinterpret_cast<uint32_t>(GetModuleHandleA(("engine.dll")));
        uint32_t address = (uint32_t)hMod + 0xdd185;
        DWORD dwOldValue, dwTemp;
        VirtualProtect((LPVOID)address, 4, PAGE_EXECUTE_READWRITE, &dwOldValue);

        *(uintptr_t*)address = 0xff;

        VirtualProtect((LPVOID)address, 4, dwOldValue, &dwTemp);
    }

    {
        uint32_t hMod = reinterpret_cast<uint32_t>(GetModuleHandleA(("engine.dll")));
        uint32_t address = (uint32_t)hMod + 0xdd1a9;
        DWORD dwOldValue, dwTemp;
        VirtualProtect((LPVOID)address, 4, PAGE_EXECUTE_READWRITE, &dwOldValue);

        memset((void*)address, 0x0, 0x4);

        VirtualProtect((LPVOID)address, 4, dwOldValue, &dwTemp);
    }

    {
        uint32_t hMod = reinterpret_cast<uint32_t>(GetModuleHandleA(("engine.dll")));
        uint32_t address = (uint32_t)hMod + 0xdd1a5;
        DWORD dwOldValue, dwTemp;
        VirtualProtect((LPVOID)address, 6, PAGE_EXECUTE_READWRITE, &dwOldValue);

        memcpy((void*)address, "\x46\xC7\x45\xB4\x00\x00", 0x6);

        VirtualProtect((LPVOID)address, 6, dwOldValue, &dwTemp);
    }

    std::vector< uint8_t > patch =
    {
     0x6A, 0x00, 0xE9, 0x80, 0x00, 0x00, 0x00, 0x90, 0x90, 0x90
    };

    memcpy((void*)(new_alloc + 0x21c477), patch.data(), patch.size());

    std::string name = "t.me/underical_leaks";
    memcpy((void*)(new_alloc + 0x9824d0), name.c_str(), name.size());

    *(uint8_t*)(new_alloc + 0x9826d4) = 0x1;
    *(uint8_t*)(new_alloc + 0x9826d5) = 0x1;


   // printf("[+] ep - 0x%x\n", entrypoint);
    ((void(_stdcall*)(HMODULE, DWORD, LPVOID))(entrypoint))(0, 1, reinterpret_cast<HMODULE>(new_alloc));
    printf("t.me/underical_leaks\n");

    hooks_shit();
   
    return 0;
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        AllocConsole();
        freopen("CONOUT$", "w", stdout);
        CreateThread(0, 0, (LPTHREAD_START_ROUTINE)main, hModule, 0, 0);
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

