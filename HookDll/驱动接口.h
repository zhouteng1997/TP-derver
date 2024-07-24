static HANDLE DeviceHandle;//存放驱动设备句柄
static HANDLE OpenDevice();
static struct _TROAPI {
	BOOL WINAPI ReadProcessMemory(
		[in]  HANDLE  hProcess,
		[in]  LPCVOID lpBaseAddress,
		[out] LPVOID  lpBuffer,
		[in]  SIZE_T  nSize,
		[out] SIZE_T* lpNumberOfBytesRead
	);
}TROAPI;