// injectDllDemo.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <iostream>
#include <devioctl.h>
#include <windows.h>


#define 符号链接名 L"\\??\\InjectDriver"

#define InjectDll_X64 CTL_CODE(FILE_DEVICE_UNKNOWN, 0x900, METHOD_BUFFERED,FILE_ANY_ACCESS) //控制码测试

PVOID MyReadFile(WCHAR* fileName, PULONG fileSize) {
	HANDLE fileHandle = NULL;
	DWORD read = 0;
	PVOID fileBufPtr = NULL;

	fileHandle = CreateFile(
		fileName,
		GENERIC_READ,
		FILE_SHARE_READ,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL
	);

	if (fileHandle == INVALID_HANDLE_VALUE) {
		*fileSize = 0;
		return NULL;
	}

	*fileSize = GetFileSize(fileHandle, NULL);
	fileBufPtr = calloc(1, *fileSize);

	if (!ReadFile(fileHandle, fileBufPtr, *fileSize, &read, NULL)) {
		free(fileBufPtr);
		fileBufPtr = NULL;
		*fileSize = 0;
	}

	CloseHandle(fileHandle);
	return fileBufPtr;
}




int main()
{

	HINSTANCE hinstDLL =LoadLibrary(L"InjectDll.dll");
	printf("已将dll传递给驱动 %p", hinstDLL);
	while (true)
	{
		Sleep(1000);
	}
	hinstDLL;
	return 0;

	//打开驱动设备
	HANDLE DeviceHandle = CreateFileW(
		符号链接名,
		GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL, NULL);
	if (DeviceHandle == NULL) {
		printf("驱动未加载");
		return 0;
	}

	ULONG fileSize;
	WCHAR fileName[] = L"InjectDll.dll";
	PVOID dllx64Ptr = MyReadFile(fileName, &fileSize);
	if (dllx64Ptr == NULL) {
		return 0;
	}

	DWORD retSize = sizeof(INT64);
	INT64 ret = 0;//输出缓冲区

	BOOL result = DeviceIoControl(
		DeviceHandle,//CreateFile打开驱动设备返回的句柄
		InjectDll_X64,//控制码CTL_CODE
		dllx64Ptr,//输入缓冲区指针
		fileSize,//输入缓冲区大小
		&ret,//返回缓冲区
		sizeof(ret),//返回缓冲区大小
		&retSize,//返回字节数
		NULL);

	if (DeviceHandle != NULL)
		CloseHandle(DeviceHandle);
	if (dllx64Ptr != NULL)
		free(dllx64Ptr);

	printf("已将dll传递给驱动");
	getchar();
}

// 运行程序: Ctrl + F5 或调试 >“开始执行(不调试)”菜单
// 调试程序: F5 或调试 >“开始调试”菜单

// 入门使用技巧: 
//   1. 使用解决方案资源管理器窗口添加/管理文件
//   2. 使用团队资源管理器窗口连接到源代码管理
//   3. 使用输出窗口查看生成输出和其他消息
//   4. 使用错误列表窗口查看错误
//   5. 转到“项目”>“添加新项”以创建新的代码文件，或转到“项目”>“添加现有项”以将现有代码文件添加到项目
//   6. 将来，若要再次打开此项目，请转到“文件”>“打开”>“项目”并选择 .sln 文件
