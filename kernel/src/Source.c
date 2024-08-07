#include "preHeader.h"
#include "PEHeader.h"
#include "ntddk.h"
#include "AsmFunc.h"

#define DebugPrint(...) \
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, __VA_ARGS__)

HANDLE g_handle_ntdllBase = 0;

void* ScanExportFunction(char* a_charptr_peBase, const char *a_constchar_funcName) {
	PIMAGE_DOS_HEADER l_header_peBase = (PIMAGE_DOS_HEADER)a_charptr_peBase;
	PIMAGE_NT_HEADERS_64 l_ntheader_nt = (PIMAGE_NT_HEADERS_64)(a_charptr_peBase + l_header_peBase->e_lfanew);
	
	IMAGE_DATA_DIRECTORY l_dataDir_export = l_ntheader_nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	ANSI_STRING l_ansi_findFuncName;
	RtlInitAnsiString(&l_ansi_findFuncName, a_constchar_funcName);
	if (l_dataDir_export.Size == 0)
	{
		DebugPrint("[KernelInsert]ScanExportFunction l_dataDir_export.Size: %d\n", l_dataDir_export.Size);
	}
	else {
		PIMAGE_EXPORT_DIRECTORY l_export_dirctory = (PIMAGE_EXPORT_DIRECTORY)(l_dataDir_export.VirtualAddress + a_charptr_peBase);
		if (l_export_dirctory->AddressOfNames)
		{
			ULONG* l_ulongptr_funcNamesOffset = (ULONG*)(a_charptr_peBase + l_export_dirctory->AddressOfNames);
			DebugPrint("[KernelInsert]l_header_peBase -->: 0x%p\n", l_header_peBase);
			DebugPrint("[KernelInsert]l_ntheader_nt -->: 0x%p\n", l_ntheader_nt);
			DebugPrint("[KernelInsert]l_dataDir_export.VirtualAddress -->: 0x%X  Address -->: 0x%p\n", l_dataDir_export.VirtualAddress, l_export_dirctory);
			DebugPrint("[KernelInsert]l_export_dirctory.NumberOfNames -->: 0x%X\n", l_export_dirctory->NumberOfNames);
			DebugPrint("[KernelInsert] l_export_dirctory->AddressOfNames -->: 0x%X  l_ulongptr_funcNamesOffset -->: 0x%p\n", l_export_dirctory->AddressOfNames, l_ulongptr_funcNamesOffset);
			USHORT* l_ushort_oridinalExport = (USHORT*)(a_charptr_peBase + l_export_dirctory->AddressOfNameOrdinals);
			DebugPrint("[KernelInsert] l_export_dirctory->AddressOfNameOrdinals -->: 0x%X  l_ushort_oridinalExport -->: 0x%p\n", l_export_dirctory->AddressOfNameOrdinals, l_ushort_oridinalExport);
			for (ULONG i = 0; i < l_export_dirctory->NumberOfNames; i++)
			{
				char* l_charptr_funcNames = a_charptr_peBase + *l_ulongptr_funcNamesOffset;
				ANSI_STRING l_ansi_funcName;
				RtlInitAnsiString(&l_ansi_funcName, l_charptr_funcNames);
				if (RtlCompareString(&l_ansi_findFuncName, &l_ansi_funcName, FALSE) == 0)
				{	
					DebugPrint("[KernelInsert]ScanExportFunction[%d][0x%p] -->: %hZ\n", i, l_charptr_funcNames, &l_ansi_funcName);

					USHORT l_ushort_funcIndex = l_ushort_oridinalExport[i];
					DebugPrint("[KernelInsert]ScanExportFunction[%d] oridinal -->: 0x%x\n", i, l_ushort_funcIndex);

					ULONG* l_ulongptr_funcAddressOffset = (ULONG*)(a_charptr_peBase + l_export_dirctory->AddressOfFunctions);
					DebugPrint("[KernelInsert]ScanExportFunction l_export_dirctory->AddressOfFunctions:0x%x l_ulongptr_funcAddressOffset -->: 0x%p\n", l_export_dirctory->AddressOfFunctions, l_ulongptr_funcAddressOffset);
					
					void* l_voidptr_result = a_charptr_peBase + l_ulongptr_funcAddressOffset[l_ushort_funcIndex];
					DebugPrint("[KernelInsert]ScanExportFunction Address offset --> 0x%x  Address -->: 0x%p\n", l_ulongptr_funcAddressOffset[l_ushort_funcIndex], l_voidptr_result);
					return l_voidptr_result;
				}
				
				l_charptr_funcNames += l_ansi_funcName.Length + 1;
				l_ulongptr_funcNamesOffset++;
			}
		}
	}

	return 0;
}

UNICODE_STRING GetProcessFileName(PEPROCESS a_peprocess_instance) {
	UNICODE_STRING l_unicodestring_ret;
	BOOLEAN l_bool_findProcessName = FALSE;
	if (a_peprocess_instance)
	{
		PCHAR pImageName = PsGetProcessImageFileName(a_peprocess_instance);
		if (NULL != pImageName)
		{
			ANSI_STRING l_ansistring_instance;
			RtlInitAnsiString(&l_ansistring_instance, pImageName);
			RtlAnsiStringToUnicodeString(&l_unicodestring_ret, &l_ansistring_instance, TRUE);
			l_bool_findProcessName = TRUE;
		}
	}

	if (!l_bool_findProcessName)
	{
		ANSI_STRING l_ansistring_instance;
		RtlInitAnsiString(&l_ansistring_instance, "");
		RtlAnsiStringToUnicodeString(&l_unicodestring_ret, &l_ansistring_instance, TRUE);
	}
	return l_unicodestring_ret;
}

HANDLE HandleGetModuleBase(PEPROCESS Process, LPCWSTR moduleName) {

	BOOLEAN returnFirstModule = !moduleName;
	UNICODE_STRING l_unicodestring_moduleName;
	RtlInitUnicodeString(&l_unicodestring_moduleName, moduleName);

	PPEB peb = PsGetProcessPeb(Process);
	if (!peb) {
		DebugPrint("[KernelInsert]HandleGetModuleBase: peb == 0\n");
		return 0;
	}

	KAPC_STATE state;
	KeStackAttachProcess(Process, &state);

	PPEB_LDR_DATA ldr = peb->Ldr;


	if (!ldr) {
		DebugPrint("[KernelInsert]HandleGetModuleBase: ldr == 0\n");
		return 0;
	}

	if (!ldr->Initialized) {
		DebugPrint("[KernelInsert]HandleGetModuleBase: ldr Not initialized!\n");
		return 0;
	}

	HANDLE l_handle_result = 0;

	for (PLIST_ENTRY listEntry = (PLIST_ENTRY)ldr->InLoadOrderModuleList.Flink;
		listEntry != &ldr->InLoadOrderModuleList;
		listEntry = (PLIST_ENTRY)listEntry->Flink) {

		PLDR_DATA_TABLE_ENTRY ldrEntry = CONTAINING_RECORD(listEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

		if (returnFirstModule) {
			l_handle_result = (HANDLE)ldrEntry->DllBase;
			DebugPrint("[KernelInsert]return first Module: 0x%p\n", l_handle_result);
			break;
		}
		else {
			if (!RtlCompareUnicodeString(&(ldrEntry->BaseDllName), &l_unicodestring_moduleName, FALSE)) {
				l_handle_result = (HANDLE)ldrEntry->DllBase;
				DebugPrint("[KernelInsert]Find Module: %wZ --> 0x%p  FullName: %wZ\n",&l_unicodestring_moduleName, l_handle_result, &(ldrEntry->FullDllName));
				break;
			}
		}
	}

	KeUnstackDetachProcess(&state);

	return l_handle_result;
}

void PloadImageNotifyRoutine(
	_In_ PUNICODE_STRING FullImageName,
	_In_         HANDLE ProcessId,
	_In_           PIMAGE_INFO ImageInfo
)
{
	PEPROCESS l_peprocess_instance = 0;
	if (FullImageName != NULL && ProcessId != 0 && NT_SUCCESS(PsLookupProcessByProcessId(ProcessId, &l_peprocess_instance)) && l_peprocess_instance) {
		UNICODE_STRING l_unicode_string = GetProcessFileName(l_peprocess_instance);
		UNICODE_STRING l_unicode_processname;
		RtlInitUnicodeString(&l_unicode_processname, L"services.exe");

		if (RtlCompareUnicodeString(&l_unicode_processname, &l_unicode_string, FALSE) == 0)
		{
			if (!g_handle_ntdllBase)
			{
				g_handle_ntdllBase = HandleGetModuleBase(l_peprocess_instance, L"KERNELBASE.dll");
				DebugPrint("[KernelInsert]Get kernelbase base: 0x%p\n", g_handle_ntdllBase);
				if (g_handle_ntdllBase != 0)
				{
					// ban SectionSignatureLevel
					*((unsigned char*)l_peprocess_instance + 0x6f9) = 0;
					KAPC_STATE state;
					KeStackAttachProcess(l_peprocess_instance, &state);
					void *funcAddress = ScanExportFunction(g_handle_ntdllBase, "LoadLibraryW");
					if (funcAddress != 0)
					{
						HANDLE l_handle_process = 0;

						OBJECT_ATTRIBUTES l_objattr_temp;
						CLIENT_ID l_clientid_cid;

						l_clientid_cid.UniqueProcess = (HANDLE)ProcessId;
						l_clientid_cid.UniqueThread = (HANDLE)0;
						InitializeObjectAttributes(&l_objattr_temp, NULL, 0, NULL, NULL);

						if (NT_SUCCESS(ZwOpenProcess(&l_handle_process, PROCESS_ALL_ACCESS, &l_objattr_temp, &l_clientid_cid))) {
							void* l_voidptr_baseAddress = 0;
							ULONG_PTR l_ULONGPTR_zeroBits = 0;
							ULONG_PTR l_ULONGPTR_reginSize = 0x1000;
							NTSTATUS l_ntstatus_ret = ZwAllocateVirtualMemory(l_handle_process, &l_voidptr_baseAddress, l_ULONGPTR_zeroBits, &l_ULONGPTR_reginSize, MEM_COMMIT, PAGE_READWRITE);
							if (NT_SUCCESS(l_ntstatus_ret)) {
								UNICODE_STRING l_unicodestr_mem;
								DebugPrint("[KernelInsert]Allocate process memory success --> 0x%p size:0x%I64x!\n", l_voidptr_baseAddress, l_ULONGPTR_reginSize);
								RtlInitUnicodeString(&l_unicodestr_mem, L"C:\\p_minimal.dll");
								RtlZeroBytes(l_voidptr_baseAddress, l_unicodestr_mem.Length + 4);
								RtlCopyMemory(l_voidptr_baseAddress, l_unicodestr_mem.Buffer, l_unicodestr_mem.Length);
								ULONG stackReserved = 0x1000, stackCommit = 0x1000;
								HANDLE l_handle_thread = 0;
								CLIENT_ID l_clientid_instance;
								l_ntstatus_ret = RtlCreateUserThread(l_handle_process, 0, FALSE, 0, 0,0, funcAddress, l_voidptr_baseAddress, &l_handle_thread, 0);
								DebugPrint("[KernelInsert]RtlCreateUserThread --> 0x%x!\n", l_ntstatus_ret);
								//STATUS_SUCCESS
								//
								//// copy Shellcode
								//RtlCopyMemory(l_voidptr_baseAddress, funcAddress, GetHookFunAsmSize());
								////RtlCopyMemory(l_voidptr_baseAddress, GetHookFunctionAddress(), GetHookFunAsmSize());
								//RtlCopyMemory(((char *)l_voidptr_baseAddress + GetHookFunAsmSize()), GetHookFunctionAddress(), GetHookFunAsmSize());
								//void* l_voidptr_realFunctionAddr = (char*)funcAddress + GetHookFunAsmSize();
								//RtlCopyMemory(((char*)l_voidptr_baseAddress + GetHookFunAsmSize() + GetHookFunctionJmpDataOffset()), &l_voidptr_realFunctionAddr, sizeof(l_voidptr_realFunctionAddr));

								//SIZE_T funcSize = GetHookFunAsmSize();
								//ULONG_PTR l_ulong_oldVal = 0;
								//
								//void* funcProtectTempAddress = funcAddress;
								//l_ntstatus_ret =  ZwProtectVirtualMemory(l_handle_process, &funcProtectTempAddress, &funcSize, PAGE_EXECUTE_READWRITE, &l_ulong_oldVal);
								//DebugPrint("[KernelInsert]ZwProtectVirtualMemory status : 0x%x\n", l_ntstatus_ret);
								//if (NT_SUCCESS(l_ntstatus_ret))
								//{
								//	RtlCopyMemory(funcAddress, GetHookFunctionAddress(), GetHookFunAsmSize());
								//	RtlCopyMemory((char*)funcAddress + GetHookFunctionJmpDataOffset(), &l_voidptr_baseAddress, sizeof(l_voidptr_baseAddress));

								//	ZwProtectVirtualMemory(l_handle_process, &funcProtectTempAddress, &funcSize, l_ulong_oldVal, &l_ulong_oldVal);
								//}
								//DbgBreakPoint();
							}
							else {
								DebugPrint("[KernelInsert]Allocate process memory failed: 0x%x\n", l_ntstatus_ret);
							}

							ZwClose(l_handle_process);
						}
						else {
							DebugPrint("[KernelInsert]Open process failed\n");
						}
					}
					KeUnstackDetachProcess(&state);
				}
			}

			//DebugPrint("[KernelInsert]%wZ -> %wZ\n", &l_unicode_string, FullImageName );
			*((UCHAR *)l_peprocess_instance + 0x6f9) = 0;
		}
		
		RtlFreeUnicodeString(&l_unicode_string);
		ObDereferenceObject(l_peprocess_instance);
	}
}

void DriverUnload(_In_ PDRIVER_OBJECT  DriverObject) {
	PsRemoveLoadImageNotifyRoutine(PloadImageNotifyRoutine);
	UNICODE_STRING l_unicodestring_msg;
	RtlInitUnicodeString(&l_unicodestring_msg, L"bye!");
	DebugPrint("[KernelInsert]%wZ\n", &l_unicodestring_msg);
	return;
}

NTSTATUS DriverEntry(
	_In_ PDRIVER_OBJECT  DriverObject,
	_In_ PUNICODE_STRING RegistryPath
) {
	DriverObject->DriverUnload = DriverUnload;
	UNICODE_STRING l_unicodestring_msg;
	RtlInitUnicodeString(&l_unicodestring_msg, L"Hello World!");
	DebugPrint("[KernelInsert]%wZ\n", &l_unicodestring_msg);

	PsSetLoadImageNotifyRoutineEx(PloadImageNotifyRoutine,PS_IMAGE_NOTIFY_CONFLICTING_ARCHITECTURE);
	return STATUS_SUCCESS;
}