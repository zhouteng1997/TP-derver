#include <ntifs.h>
#include <ntimage.h>
#include "memory.h"

#define PE_ERROR_VALUE (ULONG)-1
unsigned char* FileData = 0;
ULONG FileSize = 0;

typedef enum _SYSTEM_INFORMATION_CLASS {
	SystemBasicInformation = 0,
	SystemPerformanceInformation = 2,
	SystemTimeOfDayInformation = 3,
	SystemProcessInformation = 5,
	SystemProcessorPerformanceInformation = 8,
	SystemModuleInformation = 11,
	SystemInterruptInformation = 23,
	SystemExceptionInformation = 33,
	SystemKernelDebuggerInformation = 35,
	SystemRegistryQuotaInformation = 37,
	SystemLookasideInformation = 45,
	SystemCodeIntegrityInformation = 103,
	SystemPolicyInformation = 134,
} SYSTEM_INFORMATION_CLASS;
//structures
struct SSDTStruct
{
	LONG* pServiceTable;
	PVOID pCounterTable;
#ifdef _WIN64
	ULONGLONG NumberOfServices;
#else
	ULONG NumberOfServices;
#endif
	PCHAR pArgumentTable;
};

typedef NTSTATUS(NTAPI* ZWQUERYSYSTEMINFORMATION)(
	IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
	OUT PVOID SystemInformation,
	IN ULONG SystemInformationLength,
	OUT PULONG ReturnLength OPTIONAL
	);

PVOID GetKernelBase(PULONG pImageSize)
{
	UNICODE_STRING routineName;
	RtlInitUnicodeString(&routineName, L"ZwQuerySystemInformation");
	ZWQUERYSYSTEMINFORMATION ZwQSI = (ZWQUERYSYSTEMINFORMATION)MmGetSystemRoutineAddress(&routineName);
	if (!ZwQSI)
		return false;
	typedef struct _SYSTEM_MODULE_ENTRY
	{
		HANDLE Section;
		PVOID MappedBase;
		PVOID ImageBase;
		ULONG ImageSize;
		ULONG Flags;
		USHORT LoadOrderIndex;
		USHORT InitOrderIndex;
		USHORT LoadCount;
		USHORT OffsetToFileName;
		UCHAR FullPathName[256];
	} SYSTEM_MODULE_ENTRY, * PSYSTEM_MODULE_ENTRY;

#pragma warning(disable:4200)
	typedef struct _SYSTEM_MODULE_INFORMATION
	{
		ULONG Count;
		SYSTEM_MODULE_ENTRY Module[0];
	} SYSTEM_MODULE_INFORMATION, * PSYSTEM_MODULE_INFORMATION;

	PVOID pModuleBase = NULL;
	PSYSTEM_MODULE_INFORMATION pSystemInfoBuffer = NULL;

	ULONG SystemInfoBufferSize = 0;

	NTSTATUS status = 0;


	ZwQSI(SystemModuleInformation,
		&SystemInfoBufferSize,
		0,
		&SystemInfoBufferSize);

	if (!SystemInfoBufferSize)
	{
		return NULL;
	}

	pSystemInfoBuffer = (PSYSTEM_MODULE_INFORMATION)ExAllocatePoolZero(NonPagedPool, SystemInfoBufferSize * 2, 'tag');
	if (!pSystemInfoBuffer)
	{
		return NULL;
	}

	memset(pSystemInfoBuffer, 0, SystemInfoBufferSize * 2);

	status = ZwQSI(SystemModuleInformation,
		pSystemInfoBuffer,
		SystemInfoBufferSize * 2,
		&SystemInfoBufferSize);

	if (NT_SUCCESS(status))
	{
		pModuleBase = pSystemInfoBuffer->Module[0].ImageBase;
		if (pImageSize)
			*pImageSize = pSystemInfoBuffer->Module[0].ImageSize;
	}

	ExFreePool(pSystemInfoBuffer);

	return pModuleBase;
}

SSDTStruct* SSDTfind()
{
	static SSDTStruct* SSDT = 0;
	if (!SSDT)
	{
#ifndef _WIN64
		//x86 code
		UNICODE_STRING routineName;
		RtlInitUnicodeString(&routineName, L"KeServiceDescriptorTable");
		SSDT = (SSDTStruct*)MmGetSystemRoutineAddress(&routineName);
#else
		//x64 code
		ULONG kernelSize = 0;
		ULONG_PTR kernelBase = (ULONG_PTR)GetKernelBase(&kernelSize);
		if (kernelBase == 0 || kernelSize == 0)
			return NULL;

		// Find KiSystemServiceStart
		const unsigned char KiSystemServiceStartPattern[] = { 0x8B, 0xF8, 0xC1, 0xEF, 0x07, 0x83, 0xE7, 0x20, 0x25, 0xFF, 0x0F, 0x00, 0x00 };
		const ULONG signatureSize = sizeof(KiSystemServiceStartPattern);
		bool found = false;
		ULONG KiSSSOffset;
		for (KiSSSOffset = 0; KiSSSOffset < kernelSize - signatureSize; KiSSSOffset++)
		{
			if (RtlCompareMemory(((unsigned char*)kernelBase + KiSSSOffset), KiSystemServiceStartPattern, signatureSize) == signatureSize)
			{
				found = true;
				break;
			}
		}
		if (!found)
			return NULL;

		// lea r10, KeServiceDescriptorTable
		ULONG_PTR address = kernelBase + KiSSSOffset + signatureSize;
		LONG relativeOffset = 0;
		if ((*(unsigned char*)address == 0x4c) &&
			(*(unsigned char*)(address + 1) == 0x8d) &&
			(*(unsigned char*)(address + 2) == 0x15))
		{
			relativeOffset = *(LONG*)(address + 3);
		}
		if (relativeOffset == 0)
			return NULL;

		SSDT = (SSDTStruct*)(address + relativeOffset + 7);
#endif
	}
	return SSDT;
}

ULONG RvaToOffset(PIMAGE_NT_HEADERS pnth, ULONG Rva, ULONG Size)
{
	PIMAGE_SECTION_HEADER psh = IMAGE_FIRST_SECTION(pnth);
	USHORT NumberOfSections = pnth->FileHeader.NumberOfSections;
	for (int i = 0; i < NumberOfSections; i++)
	{
		if (psh->VirtualAddress <= Rva)
		{
			if ((psh->VirtualAddress + psh->Misc.VirtualSize) > Rva)
			{
				Rva -= psh->VirtualAddress;
				Rva += psh->PointerToRawData;
				return Rva < Size ? Rva : PE_ERROR_VALUE;
			}
		}
		psh++;
	}
	return PE_ERROR_VALUE;
}

ULONG GetExportOffset(const unsigned char* FileDataNew, ULONG FileSizeNew, const char* ExportName)
{
	//Verify DOS Header
	PIMAGE_DOS_HEADER pdh = (PIMAGE_DOS_HEADER)FileDataNew;
	if (pdh->e_magic != IMAGE_DOS_SIGNATURE)
	{
		return PE_ERROR_VALUE;
	}

	//Verify PE Header
	PIMAGE_NT_HEADERS pnth = (PIMAGE_NT_HEADERS)(FileDataNew + pdh->e_lfanew);
	if (pnth->Signature != IMAGE_NT_SIGNATURE)
	{
		return PE_ERROR_VALUE;
	}

	//Verify Export Directory
	PIMAGE_DATA_DIRECTORY pdd = NULL;
	if (pnth->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
		pdd = ((PIMAGE_NT_HEADERS64)pnth)->OptionalHeader.DataDirectory;
	else
		pdd = ((PIMAGE_NT_HEADERS32)pnth)->OptionalHeader.DataDirectory;
	ULONG ExportDirRva = pdd[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	ULONG ExportDirSize = pdd[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
	ULONG ExportDirOffset = RvaToOffset(pnth, ExportDirRva, FileSizeNew);
	if (ExportDirOffset == PE_ERROR_VALUE)
	{
		return PE_ERROR_VALUE;
	}

	//Read Export Directory
	PIMAGE_EXPORT_DIRECTORY ExportDir = (PIMAGE_EXPORT_DIRECTORY)(FileDataNew + ExportDirOffset);
	ULONG NumberOfNames = ExportDir->NumberOfNames;
	ULONG AddressOfFunctionsOffset = RvaToOffset(pnth, ExportDir->AddressOfFunctions, FileSizeNew);
	ULONG AddressOfNameOrdinalsOffset = RvaToOffset(pnth, ExportDir->AddressOfNameOrdinals, FileSizeNew);
	ULONG AddressOfNamesOffset = RvaToOffset(pnth, ExportDir->AddressOfNames, FileSizeNew);
	if (AddressOfFunctionsOffset == PE_ERROR_VALUE ||
		AddressOfNameOrdinalsOffset == PE_ERROR_VALUE ||
		AddressOfNamesOffset == PE_ERROR_VALUE)
	{
		return PE_ERROR_VALUE;
	}
	ULONG* AddressOfFunctions = (ULONG*)(FileDataNew + AddressOfFunctionsOffset);
	USHORT* AddressOfNameOrdinals = (USHORT*)(FileDataNew + AddressOfNameOrdinalsOffset);
	ULONG* AddressOfNames = (ULONG*)(FileDataNew + AddressOfNamesOffset);

	//Find Export
	ULONG ExportOffset = PE_ERROR_VALUE;
	for (ULONG i = 0; i < NumberOfNames; i++)
	{
		ULONG CurrentNameOffset = RvaToOffset(pnth, AddressOfNames[i], FileSizeNew);
		if (CurrentNameOffset == PE_ERROR_VALUE)
			continue;
		const char* CurrentName = (const char*)(FileDataNew + CurrentNameOffset);
		ULONG CurrentFunctionRva = AddressOfFunctions[AddressOfNameOrdinals[i]];
		if (CurrentFunctionRva >= ExportDirRva && CurrentFunctionRva < ExportDirRva + ExportDirSize)
			continue; //we ignore forwarded exports
		if (!strcmp(CurrentName, ExportName))  //compare the export name to the requested export
		{
			ExportOffset = RvaToOffset(pnth, CurrentFunctionRva, FileSizeNew);
			break;
		}
	}

	return ExportOffset;
}

int GetExportSsdtIndex(const char* ExportName)
{
	ULONG_PTR ExportOffset = GetExportOffset(FileData, FileSize, ExportName);
	if (ExportOffset == PE_ERROR_VALUE)
		return -1;

	int SsdtOffset = -1;
	unsigned char* ExportData = FileData + ExportOffset;
	for (int i = 0; i < 32 && ExportOffset + i < FileSize; i++)
	{
		if (ExportData[i] == 0xC2 || ExportData[i] == 0xC3)  //RET
			break;
		if (ExportData[i] == 0xB8)  //mov eax,X
		{
			SsdtOffset = *(int*)(ExportData + i + 1);
			break;
		}
	}
	return SsdtOffset;
}

PVOID GetFunctionAddress(const char* apiname)
{
	apiname;
	//read address from SSDT
	SSDTStruct* SSDT = SSDTfind();
	if (!SSDT)
	{
		return 0;
	}
	ULONG_PTR SSDTbase = (ULONG_PTR)SSDT->pServiceTable;
	if (!SSDTbase)
	{
		return 0;
	}
	ULONG readOffset = GetExportSsdtIndex(apiname);
	if (readOffset == -1)
		return 0;
	if (readOffset >= SSDT->NumberOfServices)
	{
		return 0;
	}
#ifdef _WIN64
	return (PVOID)((SSDT->pServiceTable[readOffset] >> 4) + SSDTbase);
#else
	return (PVOID)SSDT->pServiceTable[readOffset];
#endif
}

NTSTATUS Initialize()
{
	UNICODE_STRING FileName;
	OBJECT_ATTRIBUTES ObjectAttributes;
	RtlInitUnicodeString(&FileName, L"\\SystemRoot\\system32\\ntdll.dll");
	InitializeObjectAttributes(&ObjectAttributes, &FileName,
		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
		NULL, NULL);

	if (KeGetCurrentIrql() != PASSIVE_LEVEL)
	{
#ifdef _DEBUG
		DPRINT("[DeugMessage] KeGetCurrentIrql != PASSIVE_LEVEL!\n");
#endif
		return STATUS_UNSUCCESSFUL;
	}

	HANDLE FileHandle;
	IO_STATUS_BLOCK IoStatusBlock;
	NTSTATUS NtStatus = ZwCreateFile(&FileHandle,
		GENERIC_READ,
		&ObjectAttributes,
		&IoStatusBlock, NULL,
		FILE_ATTRIBUTE_NORMAL,
		FILE_SHARE_READ,
		FILE_OPEN,
		FILE_SYNCHRONOUS_IO_NONALERT,
		NULL, 0);
	if (NT_SUCCESS(NtStatus))
	{
		FILE_STANDARD_INFORMATION StandardInformation = { 0 };
		NtStatus = ZwQueryInformationFile(FileHandle, &IoStatusBlock, &StandardInformation, sizeof(FILE_STANDARD_INFORMATION), FileStandardInformation);
		if (NT_SUCCESS(NtStatus))
		{
			FileSize = StandardInformation.EndOfFile.LowPart;
			FileData = (unsigned char*)RtlAllocateMemory(true, FileSize);

			LARGE_INTEGER ByteOffset;
			ByteOffset.LowPart = ByteOffset.HighPart = 0;
			NtStatus = ZwReadFile(FileHandle,
				NULL, NULL, NULL,
				&IoStatusBlock,
				FileData,
				FileSize,
				&ByteOffset, NULL);

			if (!NT_SUCCESS(NtStatus))
			{
				RtlFreeMemory(FileData);
			}
		}
		ZwClose(FileHandle);
	}
	return NtStatus;
}

void Deinitialize()
{
	RtlFreeMemory(FileData);
}