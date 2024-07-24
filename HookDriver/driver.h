#pragma once

#include <ntifs.h>

#ifdef __cplusplus
extern "C" {
#endif

	VOID DriverUnload(PDRIVER_OBJECT DriverObject);
	NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath);

#ifdef __cplusplus
}
#endif
