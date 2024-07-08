#include "preHeader.h"
#include "PEHeader.h"
#include "ntddk.h"

#define DebugPrint(...) \
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, __VA_ARGS__)

HANDLE g_handle_ntdllBase = 0;



void* ScanExportFunction(char* a_charptr_peBase, const char *a_constchar_funcName) {
	PIMAGE_DOS_HEADER l_header_peBase = (PIMAGE_DOS_HEADER)a_charptr_peBase;
	PIMAGE_NT_HEADERS_64 l_ntheader_nt = (PIMAGE_NT_HEADERS_64)(a_charptr_peBase + l_header_peBase->e_lfanew);
	
	IMAGE_DATA_DIRECTORY l_dataDir_export = l_ntheader_nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];


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

	INT waitCount = 0;

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
				DebugPrint("[KernelInsert]Find Module: %wZ --> 0x%p\n",&l_unicodestring_moduleName, l_handle_result);
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

		if (RtlCompareString(&l_unicode_processname, &l_unicode_string, FALSE) == 0)
		{
			if (!g_handle_ntdllBase)
			{
				g_handle_ntdllBase = HandleGetModuleBase(PsGetCurrentProcess(), L"ntdll.dll");
				DebugPrint("[KernelInsert]Get Ntdll base: 0x%p\n", g_handle_ntdllBase);
			}

			DebugPrint("[KernelInsert]%wZ -> %wZ\n", &l_unicode_string, FullImageName );
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