
namespace TROAPI {
    extern HANDLE DeviceHandle; // ���������豸���
    HANDLE OpenDevice();
    HANDLE CloseDevice();
    BOOL WINAPI MyReadProcessMemory(
		_In_ HANDLE hProcess,
		_In_ LPCVOID lpBaseAddress,
		_Out_writes_bytes_to_(nSize, *lpNumberOfBytesRead) LPVOID lpBuffer,
		_In_ SIZE_T nSize,
		_Out_opt_ SIZE_T* lpNumberOfBytesRead
    );
}