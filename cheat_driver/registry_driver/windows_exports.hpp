#pragma once
#include <ntifs.h>
#include <cstdint>

typedef struct _IMAGE_FILE_HEADER
{
	USHORT Machine;
	USHORT NumberOfSections;
	ULONG TimeDateStamp;
	ULONG PointerToSymbolTable;
	ULONG NumberOfSymbols;
	USHORT SizeOfOptionalHeader;
	USHORT Characteristics;
} IMAGE_FILE_HEADER, * PIMAGE_FILE_HEADER;

typedef struct _IMAGE_DATA_DIRECTORY
{
	ULONG VirtualAddress;
	ULONG Size;
} IMAGE_DATA_DIRECTORY, * PIMAGE_DATA_DIRECTORY;

typedef struct _IMAGE_SECTION_HEADER
{
	UCHAR  Name[ 8 ];
	union
	{
		ULONG PhysicalAddress;
		ULONG VirtualSize;
	} Misc;
	ULONG VirtualAddress;
	ULONG SizeOfRawData;
	ULONG PointerToRawData;
	ULONG PointerToRelocations;
	ULONG PointerToLinenumbers;
	USHORT NumberOfRelocations;
	USHORT NumberOfLinenumbers;
	ULONG Characteristics;
} IMAGE_SECTION_HEADER, * PIMAGE_SECTION_HEADER;

typedef struct _IMAGE_OPTIONAL_HEADER64
{
	USHORT Magic;
	UCHAR MajorLinkerVersion;
	UCHAR MinorLinkerVersion;
	ULONG SizeOfCode;
	ULONG SizeOfInitializedData;
	ULONG SizeOfUninitializedData;
	ULONG AddressOfEntryPoint;
	ULONG BaseOfCode;
	ULONGLONG ImageBase;
	ULONG SectionAlignment;
	ULONG FileAlignment;
	USHORT MajorOperatingSystemVersion;
	USHORT MinorOperatingSystemVersion;
	USHORT MajorImageVersion;
	USHORT MinorImageVersion;
	USHORT MajorSubsystemVersion;
	USHORT MinorSubsystemVersion;
	ULONG Win32VersionValue;
	ULONG SizeOfImage;
	ULONG SizeOfHeaders;
	ULONG CheckSum;
	USHORT Subsystem;
	USHORT DllCharacteristics;
	ULONGLONG SizeOfStackReserve;
	ULONGLONG SizeOfStackCommit;
	ULONGLONG SizeOfHeapReserve;
	ULONGLONG SizeOfHeapCommit;
	ULONG LoaderFlags;
	ULONG NumberOfRvaAndSizes;
	struct _IMAGE_DATA_DIRECTORY DataDirectory[ 16 ];
} IMAGE_OPTIONAL_HEADER64, * PIMAGE_OPTIONAL_HEADER64;

typedef struct _IMAGE_NT_HEADERS64
{
	ULONG Signature;
	struct _IMAGE_FILE_HEADER FileHeader;
	struct _IMAGE_OPTIONAL_HEADER64 OptionalHeader;
} IMAGE_NT_HEADERS64, * PIMAGE_NT_HEADERS64;

//
typedef IMAGE_NT_HEADERS64 IMAGE_NT_HEADERS;

#define IMAGE_FIRST_SECTION( ntheader ) ((PIMAGE_SECTION_HEADER)        \
    ((ULONG_PTR)(ntheader) +                                            \
     FIELD_OFFSET( IMAGE_NT_HEADERS, OptionalHeader ) +                 \
     ((ntheader))->FileHeader.SizeOfOptionalHeader   \
    ))

typedef struct _LDR_DATA_TABLE_ENTRY
{
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

typedef struct _PEB_LDR_DATA
{
	unsigned int Length;
	int Initialized;
	void* SSHandle;
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

typedef struct _PEB64
{
	unsigned char InheritedAddressSpace;
	unsigned char ReadImageFileExecOptions;
	unsigned char BeingDebugged;
	unsigned char BitField;
	unsigned char pad_0x0004[ 0x4 ];
	PVOID Mutant;
	PVOID ImageBaseAddress;
	PPEB_LDR_DATA Ldr;	
} PEB64, * PPEB64;

struct PiDDBCacheEntry
{
	LIST_ENTRY		List;
	UNICODE_STRING	DriverName;
	ULONG			TimeDateStamp;
	NTSTATUS		LoadStatus;
	char			_0x0028[ 16 ];
};

extern "C"
{
	__declspec( dllimport ) PLIST_ENTRY NTAPI PsLoadedModuleList;
	__declspec( dllimport ) POBJECT_TYPE* IoDriverObjectType;
	__declspec( dllimport ) PVOID NTAPI RtlFindExportedRoutineByName( PVOID, PCCH );
	__declspec( dllimport ) PVOID NTAPI PsGetProcessSectionBaseAddress( PEPROCESS );
	__declspec( dllimport ) PPEB NTAPI PsGetProcessPeb( PEPROCESS );
	__declspec( dllimport ) NTSTATUS NTAPI MmCopyVirtualMemory( PEPROCESS, PVOID, PEPROCESS, PVOID, SIZE_T, KPROCESSOR_MODE, PSIZE_T );
	__declspec( dllimport ) NTSTATUS NTAPI ZwProtectVirtualMemory( HANDLE, PVOID*, PSIZE_T, ULONG, PULONG );
	__declspec( dllimport ) PIMAGE_NT_HEADERS NTAPI RtlImageNtHeader( PVOID );
	__declspec( dllimport ) NTSTATUS NTAPI ObReferenceObjectByName( PUNICODE_STRING, ULONG, PACCESS_STATE, ACCESS_MASK, POBJECT_TYPE, KPROCESSOR_MODE, PVOID OPTIONAL, PVOID* );
}