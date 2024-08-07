#include <ntifs.h>

VOID LoadImageNotify(
	_In_ PUNICODE_STRING FullImageName,
	_In_ HANDLE ProcessId,
	_In_ PIMAGE_INFO ImageInfo
);

VOID CreateProcessNotify(
	_In_ HANDLE ParentId,
	_In_ HANDLE ProcessId,
	_In_ BOOLEAN Create
);