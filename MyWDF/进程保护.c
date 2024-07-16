#include "进程保护.h" //包含自定义的头文件 "进程保护.h"
#include <ntifs.h> //包含 Windows 内核模式的头文件

#pragma warning(disable : 4505) //禁用未引用的静态函数警告

static UINT64 受保护的进程PID[256] = { 0 };//保存被保护PID的数组
static UINT64 需提权的进程PID[256] = { 0 };//保存被保护PID的数组

void 清空受保护数组()
{
	memset(受保护的进程PID, 0, sizeof(受保护的进程PID));
}
void 添加受保护的PID(UINT64 pid)
{
	for (size_t i = 0; i < 256; i++)
	{

		if (受保护的进程PID[i] == 0 || 受保护的进程PID[i] == pid)
		{
			//是空位置
			受保护的进程PID[i] = pid;
			break;
		}
	}
}
void 删除受保护的PID(UINT64 pid)
{
	for (size_t i = 0; i < 256; i++)
	{
		if (受保护的进程PID[i] == pid)//相等表示找到了
		{
			受保护的进程PID[i] = 0;
		}
	}
	return;
}
int 判断受保护的PID(UINT64 pid)
{
	for (size_t i = 0; i < 256; i++) {
		if (受保护的进程PID[i] == pid)//相等表示找到了{
		{
			return 1;
		}
	}
	return 0;
}


void 清空需提权数组()
{
	memset(需提权的进程PID, 0, sizeof(需提权的进程PID));
}
void 添加需提权的PID(UINT64 pid)
{
	for (size_t i = 0; i < 256; i++)
	{

		if (需提权的进程PID[i] == 0 || 需提权的进程PID[i] == pid)
		{
			//是空位置
			需提权的进程PID[i] = pid;
			break;
		}
	}
}
void 删除需提权的PID(UINT64 pid)
{
	for (size_t i = 0; i < 256; i++)
	{
		if (需提权的进程PID[i] == pid)//相等表示找到了
		{
			需提权的进程PID[i] = 0;
		}
	}
	return;
}
int 判断需提权的PID(UINT64 pid)
{
	for (size_t i = 0; i < 256; i++) {
		if (需提权的进程PID[i] == pid)//相等表示找到了{
		{
			return 1;
		}
	}
	return 0;
}

const char* PsGetProcessImageFileName(PEPROCESS arg1);

//函数: GetProcessName
//功能: 根据进程ID获取进程名称
//参数: 
//     ProcessId - 要查询的进程ID
//返回值: 
//     成功时返回进程名称的指针，失败时返回NULL
const char* GetProcessName(HANDLE ProcessId) {  //windbg断点命令 bu MyWDF!GetProcessName
	NTSTATUS st = STATUS_UNSUCCESSFUL; //定义并初始化状态变量为STATUS_UNSUCCESSFUL
	PEPROCESS ProcessObj = NULL;       //定义并初始化EPROCESS指针为NULL
	const char* imagename = NULL;      //定义并初始化指向进程名称的指针为NULL
	//通过进程ID查找EPROCESS对象
	st = PsLookupProcessByProcessId(ProcessId, &ProcessObj);
	//检查查找是否成功
	if (NT_SUCCESS(st)) {
		//获取进程的图像文件名
		imagename = PsGetProcessImageFileName(ProcessObj);

		//解除对EPROCESS对象的引用
		ObfDereferenceObject(ProcessObj);
	}
	//返回进程名称
	return imagename;
}

//定义回调函数 my_pre_callback，用于处理预操作回调
OB_PREOP_CALLBACK_STATUS my_pre_callback(
	PVOID RegistrationContext, //注册上下文
	POB_PRE_OPERATION_INFORMATION OperationInformation //预操作信息
)
{
	RegistrationContext;

	//断点调式
	//DbgBreakPoint();

	//判断句柄是否为内核创建
	if (OperationInformation->KernelHandle)
	{
		//如果是内核创建的句柄，不做任何操作
	}
	else
	{

		//用户层调用了OpenProcess NtOpenProcess进程名
		const char* 进程名 = PsGetProcessImageFileName(PsGetCurrentProcess()); //11个有效的字符
		//KdPrint(("驱动 进程名=%s \n ", 进程名));//11个节字长度是有效
		HANDLE pid = PsGetProcessId((PEPROCESS)OperationInformation->Object);
		const char* 目标进程名 = GetProcessName(pid);
		进程名;
		目标进程名;
		//KdPrint(("驱动 进程名=%s 目标进程名=%s \n ", 进程名, 目标进程名));//11个节字长度是有效

		if (判断受保护的PID((UINT64)pid) == 1)
		{
			//用户层
			ACCESS_MASK 获取权限 = OperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess;
			ACCESS_MASK 获取新权限 = OperationInformation->Parameters->CreateHandleInformation.DesiredAccess;//将句柄权限清零
			获取新权限;
			//让结束进程的功能失效
			获取权限 &= ~PROCESS_TERMINATE;
			//不允许内存被读写
			获取权限 &= ~PROCESS_VM_READ;
			获取权限 &= ~PROCESS_VM_WRITE;
			//返回我们修改过的权限 OpenProcess
			OperationInformation->Parameters->CreateHandleInformation.DesiredAccess = 获取权限;
			KdPrint(("驱动 获取权限=%X 获取新权限=%X", 获取权限, 获取新权限));
		}
	}
	//返回操作成功
	return OB_PREOP_SUCCESS;
}



//定义全局变量 gs_HandleCallback，用于存放返回的句柄，以方便卸载对应功能
HANDLE gs_HandleCallback = NULL;

//定义安装内存保护的函数
void 安装进程保护()
{
	//初始化 OB_CALLBACK_REGISTRATION 结构体
	OB_CALLBACK_REGISTRATION obCallbackReg = { 0 };
	//初始化 OB_OPERATION_REGISTRATION 结构体
	OB_OPERATION_REGISTRATION obOperation = { 0 };

	//设置注册的高度
	RtlInitUnicodeString(&obCallbackReg.Altitude, L"321000");
	//设置注册上下文
	obCallbackReg.RegistrationContext = NULL;
	//设置注册版本
	obCallbackReg.Version = OB_FLT_REGISTRATION_VERSION;
	//设置操作注册计数
	obCallbackReg.OperationRegistrationCount = 1;
	//设置操作注册
	obCallbackReg.OperationRegistration = &obOperation;

	//初始化 obOperation 结构体
	obOperation.ObjectType = PsProcessType; //设置对象类型为进程
	obOperation.Operations = OB_OPERATION_HANDLE_CREATE; //设置操作为句柄创建
	obOperation.PostOperation = NULL; //不需要后操作回调
	obOperation.PreOperation = my_pre_callback; //设置预操作回调为 my_pre_callback

	//注册回调函数  ObRegisterCallbacks需要添加命令行 /INTEGRITYCHECK
	NTSTATUS status = ObRegisterCallbacks(&obCallbackReg, &gs_HandleCallback);
	if (NT_SUCCESS(status)) {
		//打印调试信息，显示注册回调的句柄
		KdPrint(("驱动 安装内存保护gs_HandleCallback=%p", gs_HandleCallback));
	}
	else {
		//打印调试信息，显示注册失败的错误代码
		KdPrint(("驱动 安装内存保护失败, 错误代码=%x", status));
	}
}

//定义卸载内存保护的函数
void 卸载进程保护()
{
	if (gs_HandleCallback)
	{
		//注销回调函数
		ObUnRegisterCallbacks(gs_HandleCallback);
		//打印调试信息，显示内存保护已卸载
		KdPrint(("驱动 卸载内存保护"));
	}
}