
namespace TROAPI {
    extern HANDLE DeviceHandle; // ���������豸���
    HANDLE OpenDevice();
    BOOL WINAPI ReadProcessMemory(
        IN  HANDLE  hProcess,
        IN  LPCVOID lpBaseAddress,
        OUT LPVOID  lpBuffer,
        IN  SIZE_T  nSize,
        OUT SIZE_T* lpNumberOfBytesRead
    );
}