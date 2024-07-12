#include "ntddk.h"

#define IMAGE_DIRECTORY_ENTRY_EXPORT 0
#define IMAGE_DIRECTORY_ENTRY_IMPORT 1
#define IMAGE_DIRECTORY_ENTRY_RESOURCE 2
#define IMAGE_DIRECTORY_ENTRY_EXCEPTION 3
#define IMAGE_DIRECTORY_ENTRY_SECURITY 4
#define IMAGE_DIRECTORY_ENTRY_BASERELOC 5
#define IMAGE_DIRECTORY_ENTRY_DEBUG 6
#define IMAGE_DIRECTORY_ENTRY_ARCHITECTURE 7
#define IMAGE_DIRECTORY_ENTRY_GLOBALPTR 8
#define IMAGE_DIRECTORY_ENTRY_TLS 9
#define IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG 10
#define IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT 11
#define IMAGE_DIRECTORY_ENTRY_IAT 12
#define IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT 13
#define IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR 14
#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES 15

#define DWORD ULONG
#define WORD  USHORT

typedef struct _IMAGE_DOS_HEADER
{
	unsigned short e_magic;
	unsigned short e_cblp;
	unsigned short e_cp;
	unsigned short e_crlc;
	unsigned short e_cparhdr;
	unsigned short e_minalloc;
	unsigned short e_maxalloc;
	unsigned short e_ss;
	unsigned short e_sp;
	unsigned short e_csum;
	unsigned short e_ip;
	unsigned short e_cs;
	unsigned short e_lfarlc;
	unsigned short e_ovno;
	unsigned short e_res[4];
	unsigned short e_oemid;
	unsigned short e_oeminfo;
	unsigned short e_res2[10];
	LONG e_lfanew;
} IMAGE_DOS_HEADER, * PIMAGE_DOS_HEADER;

typedef struct _IMAGE_FILE_HEADER {
	USHORT  Machine;
	USHORT  NumberOfSections;
	ULONG TimeDateStamp;
	ULONG PointerToSymbolTable;
	ULONG NumberOfSymbols;
	USHORT  SizeOfOptionalHeader;
	USHORT  Characteristics;
} IMAGE_FILE_HEADER, * PIMAGE_FILE_HEADER;

typedef struct _IMAGE_DATA_DIRECTORY {
	ULONG VirtualAddress;
	ULONG Size;
} IMAGE_DATA_DIRECTORY, * PIMAGE_DATA_DIRECTORY;

typedef struct _IMAGE_OPTIONAL_HEADER64 {
	USHORT        Magic;
	UCHAR        MajorLinkerVersion;
	UCHAR        MinorLinkerVersion;
	ULONG       SizeOfCode;
	ULONG       SizeOfInitializedData;
	ULONG       SizeOfUninitializedData;
	ULONG       AddressOfEntryPoint;
	ULONG       BaseOfCode;
	ULONGLONG   ImageBase;
	ULONG       SectionAlignment;
	ULONG       FileAlignment;
	USHORT        MajorOperatingSystemVersion;
	USHORT        MinorOperatingSystemVersion;
	USHORT        MajorImageVersion;
	USHORT        MinorImageVersion;
	USHORT        MajorSubsystemVersion;
	USHORT        MinorSubsystemVersion;
	ULONG       Win32VersionValue;
	ULONG       SizeOfImage;
	ULONG       SizeOfHeaders;
	ULONG       CheckSum;
	USHORT        Subsystem;
	USHORT        DllCharacteristics;
	ULONGLONG   SizeOfStackReserve;
	ULONGLONG   SizeOfStackCommit;
	ULONGLONG   SizeOfHeapReserve;
	ULONGLONG   SizeOfHeapCommit;
	ULONG       LoaderFlags;
	ULONG       NumberOfRvaAndSizes;
	IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER64, * PIMAGE_OPTIONAL_HEADER64;

typedef struct _IMAGE_NT_HEADERS_64 {
	ULONG                   Signature;
	IMAGE_FILE_HEADER       FileHeader;
	IMAGE_OPTIONAL_HEADER64 OptionalHeader;
} IMAGE_NT_HEADERS_64, * PIMAGE_NT_HEADERS_64;

typedef struct _IMAGE_EXPORT_DIRECTORY {
	DWORD   Characteristics;          // 1) 保留，恒为0x00000000
	DWORD   TimeDateStamp;            // 2) 时间戳
	WORD    MajorVersion;             // 3) 主版本号，一般不赋值
	WORD    MinorVersion;             // 4) 子版本号，一般不赋值
	DWORD   Name;                     // 5) 模块名称
	DWORD   Base;                     // 6) 索引基数
	DWORD   NumberOfFunctions;        // 7) 导出地址表中的成员个数
	DWORD   NumberOfNames;            // 8) 导出名称表中的成员个数
	DWORD   AddressOfFunctions;       // 9) 导出地址表（EAT）
	DWORD   AddressOfNames;           // 10) 导出名称表（ENT）
	DWORD   AddressOfNameOrdinals;    // 11) 指向导出序列号数组
} IMAGE_EXPORT_DIRECTORY, * PIMAGE_EXPORT_DIRECTORY;