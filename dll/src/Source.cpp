#include "stdio.h"
#include "windows.h"

void __stdcall Run(void* a_voidptr_guid) {
    WCHAR l_wchar_buffer[1024];
    RtlZeroMemory(l_wchar_buffer, sizeof(l_wchar_buffer));
    wsprintf(l_wchar_buffer, L"[InjectDll]I'm Running now! --> 0x%p\n", a_voidptr_guid);
    while (true)
    {
        OutputDebugString(l_wchar_buffer);
        Sleep(2000);
    }
}

bool CompareMemory(char *a_charptr_destMemory, char* a_charptr_sourceMemory, ULONG a_ulong_memoryLen) {
    for (size_t i = 0; i < a_ulong_memoryLen; i++)
    {
        if (a_charptr_destMemory[i] != a_charptr_sourceMemory[i])
        {
            return false;
        }
    }

    return true;
}

void* ScanRpcCode() {
    // rpc guid -> "{367abb81-9844-35f1-ad32-98f038001003}"
    // dd 367ABB81h
    // dw 9844h
    // dw 35F1h
    // dw 32ADh
    // dw 0F098h
    // dd 3100038h
    char* l_charptr_pebase = (char*)GetModuleHandle(NULL);
    IMAGE_DOS_HEADER* l_dos_header = (IMAGE_DOS_HEADER*)l_charptr_pebase;
    IMAGE_NT_HEADERS* l_nt_header = (IMAGE_NT_HEADERS *)((char*)l_dos_header + l_dos_header->e_lfanew);
    ULONG l_ulong_numberOfSections = l_nt_header->FileHeader.NumberOfSections;
    IMAGE_SECTION_HEADER* l_imagesection_header = (IMAGE_SECTION_HEADER*)((char*)l_nt_header + sizeof(IMAGE_NT_HEADERS));
    char l_chararray_compareBytes[] = { 0x81,0xbb, 0x7a,0x36, 0x44,0x98, 0xF1, 0x35, 0xAD, 0x32, 0x98, 0xF0, 0x38, 0x00, 0x10, 0x03 };

    for (size_t i = 0; i < l_ulong_numberOfSections; i++)
    {
        long long l_ll_curentlength = l_imagesection_header[i].SizeOfRawData > l_imagesection_header[i].Misc.VirtualSize ? l_imagesection_header[i].SizeOfRawData : l_imagesection_header[i].Misc.VirtualSize;
        char* l_charptr_sectionAddress = l_charptr_pebase + l_imagesection_header[i].VirtualAddress;
        for (long long t = 0; t < l_ll_curentlength - sizeof(l_chararray_compareBytes); t++)
        {
            if (CompareMemory(l_charptr_sectionAddress + t, l_chararray_compareBytes, sizeof(l_chararray_compareBytes)))
            {
                return (l_charptr_sectionAddress + t);
            }
        }
    }
    return 0;
}

BOOL WINAPI DllMain(
    HINSTANCE hinstDLL,  // handle to DLL module
    DWORD fdwReason,     // reason for calling function
    LPVOID lpvReserved)  // reserved
{
    // Perform actions based on the reason for calling.
    switch (fdwReason)
    {
    case DLL_PROCESS_ATTACH:
        // Initialize once for each new process.
        // Return FALSE to fail DLL load.
        CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)Run, ScanRpcCode(), NULL, NULL);
        break;

    case DLL_THREAD_ATTACH:
        // Do thread-specific initialization.
        break;

    case DLL_THREAD_DETACH:
        // Do thread-specific cleanup.
        break;

    case DLL_PROCESS_DETACH:

        if (lpvReserved != nullptr)
        {
            break; // do not do cleanup if process termination scenario
        }

        // Perform any necessary cleanup.
        break;
    }
    return TRUE;  // Successful DLL_PROCESS_ATTACH.
}