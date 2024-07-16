#include <ntifs.h>

//声明全局变量和函数原型
static ULONG ObjectCallbackListOffset = 0;  //对象回调列表偏移量
extern PSHORT NtBuildNumber;  //NtBuildNumber的外部声明


PVOID GetUndocumentFunctionAddress(IN PUNICODE_STRING pFunName,
	IN PUCHAR pStartAddress,
	IN UCHAR* pFeatureCode,
	IN ULONG FeatureCodeNum,
	ULONG SerSize,
	UCHAR SegCode,
	ULONG AddNum,
	BOOLEAN ByName);

//LDR_DATA结构体的定义
typedef struct _LDR_DATA {
	struct _LIST_ENTRY InLoadOrderLinks;
	struct _LIST_ENTRY InMemoryOrderLinks;
	struct _LIST_ENTRY InInitializationOrderLinks;
	VOID* DllBase;  //模块基址
	VOID* EntryPoint;  //入口点
	ULONG32 SizeOfImage;  //模块大小
	UINT8 _PADDING0_[0x4];  //填充字节
	struct _UNICODE_STRING FullDllName;  //完整的DLL名称
	struct _UNICODE_STRING BaseDllName;  //基本的DLL名称
	ULONG32 Flags;  //标志
	UINT16 LoadCount;  //加载计数
	UINT16 TlsIndex;  //TLS索引
	union {
		struct _LIST_ENTRY HashLinks;
		struct {
			VOID* SectionPointer;  //段指针
			ULONG32 CheckSum;  //校验和
			UINT8 _PADDING1_[0x4];  //填充字节
		}LDR_DATA_1;
	}LDR_DATA_2;
	union {
		ULONG32 TimeDateStamp;  //时间戳
		VOID* LoadedImports;  //已加载的导入项
	}LDR_DATA_3;
	struct _ACTIVATION_CONTEXT* EntryPointActivationContext;  //入口点激活上下文
	VOID* PatchInformation;  //补丁信息
	struct _LIST_ENTRY ForwarderLinks;  //转发链接
	struct _LIST_ENTRY ServiceTagLinks;  //服务标签链接
	struct _LIST_ENTRY StaticLinks;  //静态链接
	VOID* ContextInformation;  //上下文信息
	UINT64 OriginalBase;  //原始基址
	union _LARGE_INTEGER LoadTime;  //加载时间
} LDR_DATA, * PLDR_DATA;

//LDR_DATA_TABLE_ENTRY结构体的定义
typedef struct _LDR_DATA_TABLE_ENTRY {
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	PVOID DllBase;  //模块基址
	PVOID EntryPoint;  //入口点
	ULONG SizeOfImage;  //模块大小
	UNICODE_STRING FullDllName;  //完整的DLL名称
	UNICODE_STRING BaseDllName;  //基本的DLL名称
	ULONG Flags;  //标志
	USHORT LoadCount;  //加载计数
	USHORT TlsIndex;  //TLS索引
	union {
		LIST_ENTRY HashLinks;
		struct {
			PVOID SectionPointer;  //段指针
			ULONG CheckSum;  //校验和
		}LDR_DATA_TABLE_ENTRY_1;
	}LDR_DATA_TABLE_ENTRY_2;
	union {
		struct {
			ULONG TimeDateStamp;  //时间戳
		}LDR_DATA_TABLE_ENTRY_3;
		struct {
			PVOID LoadedImports;  //已加载的导入项
		}LDR_DATA_TABLE_ENTRY_4;
	}LDR_DATA_TABLE_ENTRY_5;
	struct _ACTIVATION_CONTEXT* EntryPointActivationContext;  //入口点激活上下文
	PVOID PatchInformation;  //补丁信息
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

//OPERATION_INFO_ENTRY结构体的定义
typedef struct _OPERATION_INFO_ENTRY {
	LIST_ENTRY ListEntry;
	OB_OPERATION Operation;  //操作
	ULONG Flags;  //标志
	PVOID Object;  //对象
	POBJECT_TYPE ObjectType;  //对象类型
	ACCESS_MASK AccessMask;  //访问掩码
	ULONG32 time;  //时间
} OPERATION_INFO_ENTRY, * POPERATION_INFO_ENTRY;

//CALL_BACK_INFO结构体的定义
typedef struct _CALL_BACK_INFO {
	ULONG64 Unknow;
	ULONG64 Unknow1;
	UNICODE_STRING AltitudeString;  //高度字符串
	LIST_ENTRY NextEntryItemList;  //下一个项列表
	ULONG64 Operations;  //操作
	PVOID ObHandle;  //对象句柄
	PVOID ObjectType;  //对象类型
	ULONG64 PreCallbackAddr;  //前回调地址
	ULONG64 PostCallbackAddr;  //后回调地址
} CALL_BACK_INFO, * PCALL_BACK_INFO;

//OB_CALLBACK结构体的定义
typedef struct _OB_CALLBACK {
	LIST_ENTRY ListEntry;
	ULONG64 Operations;  //操作
	PCALL_BACK_INFO ObHandle;  //对象句柄
	ULONG64 ObjTypeAddr;  //对象类型地址
	ULONG64 PreCall;  //前调用
	ULONG64 PostCall;  //后调用
} OB_CALLBACK, * POB_CALLBACK;

//获取版本号并硬编码
BOOLEAN GetVersionAndHardCode() {
	BOOLEAN b = FALSE;
	switch (*NtBuildNumber) {
	case 7600:
	case 7601:
		ObjectCallbackListOffset = 0xC0;  //Win7
		b = TRUE;
		break;
	case 9200:
		ObjectCallbackListOffset = 0xC8;  //OBJECT_TYPE.CallbackList
		b = TRUE;
		break;
	case 9600:
		ObjectCallbackListOffset = 0xC8;  //OBJECT_TYPE.CallbackList
		b = TRUE;
		break;
	default:
		if (*NtBuildNumber > 10000) {
			ObjectCallbackListOffset = 0xc8;
			b = TRUE;
		}
		break;
	}
	return b;
}

//获取函数中的调用点处的跳转地址
PVOID GetCallPoint(PVOID pCallPoint)
{
	ULONG dwOffset = 0;  //初始化函数偏移为0
	ULONG_PTR returnAddress = 0;  //初始化返回地址为0
	LARGE_INTEGER returnAddressTemp = { 0 };  //初始化返回地址临时变量为0
	PUCHAR pFunAddress = NULL;  //初始化函数地址为NULL

	if (pCallPoint == NULL || !MmIsAddressValid(pCallPoint))  //如果传入的函数地址为NULL或者不是有效地址，则返回NULL
		return NULL;

	pFunAddress = pCallPoint;  //将传入的函数地址赋值给函数地址变量

	//从函数地址的下一个字节开始，复制4字节数据到函数偏移变量
	RtlCopyMemory(&dwOffset, (PVOID)(pFunAddress + 1), sizeof(ULONG));

	//判断是否为向上跳转指令（JMP）
	if ((dwOffset & 0x10000000) == 0x10000000)
	{
		//我修改过的代码 dwOffset = dwOffset + 5 + pFunAddress;  // 计算实际函数地址
		dwOffset = dwOffset + 5 + *(ULONG*)pFunAddress;  // 计算实际函数地址
		returnAddressTemp.QuadPart = (ULONG_PTR)pFunAddress & 0xFFFFFFFF00000000;  //提取函数地址的高32位
		returnAddressTemp.LowPart = dwOffset;  //将计算后的偏移设置到临时返回地址变量的低32位
		returnAddress = returnAddressTemp.QuadPart;  //将临时返回地址变量转换为返回地址
		return (PVOID)returnAddress;  //返回计算后的函数地址
	}
	//我修改过的代码 returnAddress = (ULONG_PTR)dwOffset + 5 + pFunAddress;  //计算实际函数地址
	returnAddress = (ULONG_PTR)dwOffset + 5 + (ULONG_PTR)pFunAddress;  //计算实际函数地址
	return (PVOID)returnAddress;  //返回计算后的函数地址
}

//获取函数中的跳转地址
PVOID GetMovPoint(PVOID pCallPoint) //指向调用点的指针，用于获取跳转地址
{
	ULONG dwOffset = 0; //函数偏移量，初始化为 0
	ULONG_PTR returnAddress = 0; //返回地址，初始化为 0
	LARGE_INTEGER returnAddressTemp = { 0 }; //临时返回地址结构体，全部初始化为 0
	PUCHAR pFunAddress = NULL; //指向函数地址的指针，初始化为 NULL

	//检查调用点是否为 NULL 或者地址无效，如果是则返回 NULL
	if (pCallPoint == NULL || !MmIsAddressValid(pCallPoint))
		return NULL;

	pFunAddress = pCallPoint; //设置函数地址指针为调用点地址

	//复制调用点地址后 3 字节的内容到 dwOffset，即获取函数偏移量
	RtlCopyMemory(&dwOffset, (PVOID)(pFunAddress + 3), sizeof(ULONG));

	//判断是否为 JMP 向上跳转指令
	if ((dwOffset & 0x10000000) == 0x10000000)
	{
		//我修改的
		dwOffset = dwOffset + 7 + *(ULONG*)pFunAddress; //计算实际偏移地址
		returnAddressTemp.QuadPart = (ULONG_PTR)pFunAddress & 0xFFFFFFFF00000000; //获取函数地址的高 32 位
		returnAddressTemp.LowPart = dwOffset; //设置函数地址的低 32 位为偏移地址
		returnAddress = returnAddressTemp.QuadPart; //合并高低位得到返回地址
		return (PVOID)returnAddress; //返回函数中的跳转地址
	}

	returnAddress = (ULONG_PTR)dwOffset + 7 + (ULONG_PTR)pFunAddress; //计算实际偏移地址
	return (PVOID)returnAddress; //返回函数中的跳转地址
}

//获取PsLoadedModuleList地址，方便判断地址所属模块
PVOID GetPsLoadedListModule()
{
	UNICODE_STRING usRtlPcToFileHeader = RTL_CONSTANT_STRING(L"RtlPcToFileHeader"); //指向字符串 "RtlPcToFileHeader"
	UNICODE_STRING usPsLoadedModuleList = RTL_CONSTANT_STRING(L"PsLoadedModuleList"); //指向字符串 "PsLoadedModuleList"
	PVOID Point = NULL; //指向内存地址的指针，初始化为 NULL
	static PVOID PsLoadedListModule = NULL; //静态指向内存地址的指针，初始化为 NULL
	UCHAR shellcode[11] = "\x48\x8b\x0d\x60\x60\x60\x60" "\x48\x85\xc9"; //用于定位的特征码数组

	//如果 PsLoadedListModule 不为空，直接返回 PsLoadedListModule
	if (PsLoadedListModule)
		return PsLoadedListModule;

	//如果操作系统版本大于 9600（Win10），获取 PsLoadedModuleList 模块地址并返回
	if (*NtBuildNumber > 9600)
	{
		PsLoadedListModule = MmGetSystemRoutineAddress(&usPsLoadedModuleList); //获取 PsLoadedModuleList 模块地址
		return PsLoadedListModule;
	}

	//获取 PsLoadedModuleList 模块地址（Win7）
	Point = GetUndocumentFunctionAddress(&usRtlPcToFileHeader, NULL, shellcode, 10, 0xff, 0x60, 0, TRUE);
	if (Point == NULL || !MmIsAddressValid(Point))
		return NULL;
	Point = GetMovPoint(Point);
	if (Point == NULL || !MmIsAddressValid(Point))
		return NULL;
	PsLoadedListModule = Point;
	return PsLoadedListModule;
}

//根据地址 判断所属驱动模块
BOOLEAN ObGetDriverNameByPoint(ULONG_PTR Point, OUT WCHAR* szDriverName)
{
	PLDR_DATA_TABLE_ENTRY Begin = NULL; //指向加载的模块的 LDR_DATA_TABLE_ENTRY 结构的指针，初始化为 NULL
	PLIST_ENTRY Head = NULL; //指向链表头部的指针，初始化为 NULL
	PLIST_ENTRY Next = NULL; //指向链表下一个元素的指针，初始化为 NULL

	//获取 PsLoadedModuleList 的头部节点
	Begin = GetPsLoadedListModule();
	if (Begin == NULL)
		return FALSE; //如果获取失败，返回 FALSE

	//获取链表头部和下一个元素的指针
	Head = (PLIST_ENTRY)Begin->InLoadOrderLinks.Flink;
	Next = Head->Flink;

	//开始循环遍历链表
	do
	{
		//将 Next 指针转换为 LDR_DATA_TABLE_ENTRY 结构的指针
		PLDR_DATA_TABLE_ENTRY Entry = CONTAINING_RECORD(Next, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
		Next = Next->Flink; //指向下一个节点

		//判断给定的地址 Point 是否在模块地址范围内
		if ((ULONG_PTR)Entry->DllBase <= Point && Point <= ((ULONG_PTR)Entry->DllBase + Entry->SizeOfImage))
		{
			if (szDriverName == NULL)
				return FALSE; //如果传入的 szDriverName 为 NULL，返回 FALSE

			//清空 szDriverName 的内存
			RtlZeroMemory(szDriverName, 600);
			//复制模块名称到 szDriverName 中
			RtlCopyMemory(szDriverName, Entry->BaseDllName.Buffer, Entry->BaseDllName.Length);
			return TRUE; //返回找到驱动程序名称
		}
	} while (Next != Head->Flink); //循环链表，直到下一个指针再次指向首结点，则遍历结束

	return FALSE; //如果没有找到匹配的驱动程序名称，返回 FALSE
}

//遍历所有回调函数
ULONG EnumObRegisterCallBacks()
{
	ULONG c = 0;  //回调累加计数
	PLIST_ENTRY CurrEntry = NULL;  //当前遍历的链表项指针
	POB_CALLBACK pObCallback;  //指向回调结构的指针
	ULONG64 ObProcessCallbackListHead = 0;  //进程回调列表头
	ULONG64 ObThreadCallbackListHead = 0;  //线程回调列表头
	PVOID szDriverBaseName = ExAllocatePool(NonPagedPool, (SIZE_T)600);  //驱动程序基本名称

	//分配内存给驱动程序基本名称 //我修改
	//szDriverBaseName = ExAllocatePool(NonPagedPool, (SIZE_T)600);
	//szDriverBaseName = ExAllocatePool(NonPagedPool, (SIZE_T)600);

	if (szDriverBaseName == NULL)
		return 0;  //分配失败则返回

	//清空驱动程序基本名称的内存
	RtlZeroMemory(szDriverBaseName, 600);
	GetVersionAndHardCode();  //获取版本信息和硬编码

	//计算进程回调列表头和线程回调列表头的地址
	ObProcessCallbackListHead = *(ULONG64*)PsProcessType + ObjectCallbackListOffset;
	ObThreadCallbackListHead = *(ULONG64*)PsThreadType + ObjectCallbackListOffset;

	//输出调试信息
	KdPrint(("驱动：SYS->遍历开始+++++++++++++++++++++++++++++++++++++++++>\n"));

	//遍历进程回调列表
	KdPrint(("驱动：SYS 进程回调遍历开始-----------------------------》:\n"));
	CurrEntry = ((PLIST_ENTRY)ObProcessCallbackListHead)->Flink;
	if (CurrEntry == NULL || !MmIsAddressValid(CurrEntry))
	{
		ExFreePool(szDriverBaseName);  //释放内存
		return 0;  //返回0
	}
	do
	{
		//获取当前回调项
		pObCallback = (POB_CALLBACK)CurrEntry;
		if (pObCallback->ObHandle != 0)
		{
			//如果回调项有效，则获取驱动程序名称并输出调试信息
			if (ObGetDriverNameByPoint(pObCallback->PreCall, szDriverBaseName))
				DbgPrint("驱动：SYS>DriverName=%S ObHandle=%p Index=%wZ PreCall=%p PostCall=%p \n",
					szDriverBaseName,
					pObCallback->ObHandle,
					&pObCallback->ObHandle->AltitudeString,
					pObCallback->PreCall,
					pObCallback->PostCall);
			c++;  //计数器加1
		}
		CurrEntry = CurrEntry->Flink;  //指向下一个链表项
	} while (CurrEntry != (PLIST_ENTRY)ObProcessCallbackListHead);  //当前项不等于进程回调列表头时继续遍历

	//输出调试信息
	KdPrint(("驱动：SYS 进程回调遍历结束-----------------------------》:\n"));

	//遍历线程回调列表
	DbgPrint("驱动：SYS->线程对象回调 遍历开始------------------->:\n");
	CurrEntry = ((PLIST_ENTRY)ObThreadCallbackListHead)->Flink;
	if (CurrEntry == NULL || !MmIsAddressValid(CurrEntry))
	{
		ExFreePool(szDriverBaseName);  //释放内存
		return c;  //返回计数器值
	}
	do
	{
		//获取当前回调项
		pObCallback = (POB_CALLBACK)CurrEntry;
		if (pObCallback->ObHandle != 0)
		{
			//如果回调项有效，则获取驱动程序名称并输出调试信息
			if (ObGetDriverNameByPoint(pObCallback->PreCall, szDriverBaseName))
				DbgPrint("驱动：SYS>DriverName=%S ObHandle=%p Index=%wZ PreCall=%p PostCall=%p \n",
					szDriverBaseName,
					pObCallback->ObHandle,
					&pObCallback->ObHandle->AltitudeString,
					pObCallback->PreCall,
					pObCallback->PostCall);
			c++;  //计数器加1
		}
		CurrEntry = CurrEntry->Flink;  //指向下一个链表项
	} while (CurrEntry != (PLIST_ENTRY)ObThreadCallbackListHead);  //当前项不等于线程回调列表头时继续遍历

	//输出调试信息和计数器值
	DbgPrint("驱动：SYS->线程对象回调 遍历结束------------------->:\n");
	DbgPrint("驱动：SYS 注册回调的数量: %ld\n", c);

	ExFreePool(szDriverBaseName);  //释放内存
	KdPrint(("驱动：SYS->遍历结束+++++++++++++++++++++++++++++++++++++++++>\n"));
	return c;  //返回计数器值
}

//获取对象回调的高度字符串并检查驱动名称是否匹配。
BOOLEAN ObGetCallBacksAltitude2(WCHAR* szDriverName, PUNICODE_STRING usAltitudeString, BOOLEAN bGetProcess)
{
	BOOLEAN bRet = FALSE;  //初始化返回值为FALSE
	PLIST_ENTRY CurrEntry = NULL;  //初始化链表当前节点为NULL
	POB_CALLBACK pObCallback;  //定义对象回调结构体指针
	ULONG_PTR ObCallbackListHead = 0;  //初始化对象回调列表头地址为0
	//PVOID szDriverBaseName = NULL;  //初始化驱动基本名称指针为NULL

	GetVersionAndHardCode();  //获取版本和硬编码信息

	//根据参数选择对象回调列表头地址
	if (bGetProcess)
		ObCallbackListHead = *(ULONG_PTR*)PsProcessType + ObjectCallbackListOffset;
	else
		ObCallbackListHead = *(ULONG_PTR*)PsThreadType + ObjectCallbackListOffset;

	CurrEntry = ((PLIST_ENTRY)ObCallbackListHead)->Flink;  //获取链表当前节点指针

	//如果当前节点为空或者不是有效地址，则返回FALSE
	if (CurrEntry == NULL || !MmIsAddressValid(CurrEntry))
		return bRet;

	//如果传入的字符串指针为空，或者Unicode字符串指针为空，或者Unicode字符串的缓冲区为空，则返回FALSE
	if (szDriverName == NULL || usAltitudeString == NULL || usAltitudeString->Buffer == NULL)
		return FALSE;

	PVOID szDriverBaseName = ExAllocatePool(NonPagedPool, (SIZE_T)600);  //分配内存用于驱动基本名称

	//如果分配内存失败，则返回FALSE
	if (szDriverBaseName == NULL)
		return FALSE;

	RtlZeroMemory(szDriverBaseName, 600);  //将分配的内存清零

	do
	{
		pObCallback = (POB_CALLBACK)CurrEntry;  //获取当前节点对应的对象回调结构体指针

		if (pObCallback->ObHandle != 0)  //如果对象句柄不为0
		{
			DbgPrint("驱动：SYSObHandle: %p\n", pObCallback->ObHandle);  //打印对象句柄
			DbgPrint("驱动：SYSIndex: %wZ\n", &pObCallback->ObHandle->AltitudeString);  //打印对象句柄的高度字符串
			DbgPrint("驱动：SYSPreCall: %lld\n", pObCallback->PreCall);  //打印预调用函数地址
			DbgPrint("驱动：SYSPostCall: %lld\n", pObCallback->PostCall);  //打印后调用函数地址

			//如果获取驱动名称失败，则跳出循环
			if (!ObGetDriverNameByPoint(pObCallback->PreCall, szDriverBaseName))
				break;

			DbgPrint("驱动：SYSDriverName: %p\n", szDriverBaseName);  //打印获取到的驱动名称

			//如果传入的驱动名称与获取到的驱动名称匹配
			if (!_wcsnicmp(szDriverBaseName, szDriverName, wcslen(szDriverName) * 2))
			{
				bRet = TRUE;  //设置返回值为TRUE
				RtlCopyMemory(usAltitudeString->Buffer, pObCallback->ObHandle->AltitudeString.Buffer, pObCallback->ObHandle->AltitudeString.Length);  //复制高度字符串到Unicode字符串缓冲区
				usAltitudeString->Length = pObCallback->ObHandle->AltitudeString.Length;  //设置Unicode字符串长度
				usAltitudeString->MaximumLength = 600;  //设置Unicode字符串最大长度
				break;  //跳出循环
			}
		}

		CurrEntry = CurrEntry->Flink;  //将当前节点指针移动到下一个节点
	} while (CurrEntry != (PLIST_ENTRY)ObCallbackListHead);  //循环直到当前节点指针指向对象回调列表头

	ExFreePool(szDriverBaseName);  //释放分配的内存
	return bRet;  //返回结果
}

//获取未文档化的函数地址
PVOID GetUndocumentFunctionAddress(IN PUNICODE_STRING pFunName, //指向 Unicode 字符串结构的指针，用于指定函数名称
	IN PUCHAR pStartAddress, //指向函数起始地址的指针，用于指定函数的起始地址
	IN UCHAR* pFeatureCode, //指向特征码数组的指针，用于指定要匹配的特征码序列
	IN ULONG FeatureCodeNum, //特征码数量，用于指定特征码序列的长度
	ULONG SerSize, //序列大小，用于指定要遍历的序列的长度
	UCHAR SegCode, //分隔码，用于指定特征码数组中的分隔标记
	ULONG AddNum, //偏移量，用于指定返回地址的偏移量
	BOOLEAN ByName) //布尔值，指示是否通过函数名称获取地址
{
	ULONG dwIndex = 0; //循环计数器，初始化为 0
	PUCHAR pFunAddress = NULL; //指向函数地址的指针，初始化为 NULL
	ULONG dwCodeNum = 0; //特征码匹配计数器，初始化为 0

	//检查特征码数组是否为 NULL，如果是则返回 NULL
	if (pFeatureCode == NULL)
		return NULL;
	//检查特征码数量是否大于等于 15，如果是则返回 NULL
	if (FeatureCodeNum >= 15)
		return NULL;
	//检查序列大小是否大于 0x1024，如果是则返回 NULL
	if (SerSize > 0x1024)
		return NULL;

	//根据 ByName 的值确定获取函数地址的方式
	if (ByName)
	{
		//如果 ByName 为 TRUE，则通过函数名称获取地址
		if (pFunName == NULL || !MmIsAddressValid(pFunName->Buffer))
			return NULL; //检查函数名称是否有效，如果无效则返回 NULL
		pFunAddress = (PUCHAR)MmGetSystemRoutineAddress(pFunName); //获取函数地址
		if (pFunAddress == NULL)
			return NULL; //如果获取失败，返回 NULL
	}
	else
	{
		//如果 ByName 为 FALSE，则使用传入的函数起始地址
		if (pStartAddress == NULL || !MmIsAddressValid(pStartAddress))
			return NULL; //检查函数起始地址是否有效，如果无效则返回 NULL
		pFunAddress = pStartAddress; //使用传入的函数起始地址
	}

	//循环遍历序列进行特征码匹配
	for (dwIndex = 0; dwIndex < SerSize; dwIndex++)
	{
		__try
		{
			//检查特征码是否匹配或者等于分隔码
			if (pFunAddress[dwIndex] == pFeatureCode[dwCodeNum] || pFeatureCode[dwCodeNum] == SegCode)
			{
				dwCodeNum++; //特征码匹配计数器加一
				if (dwCodeNum == FeatureCodeNum)
					//如果特征码匹配计数器等于特征码数量，返回匹配到的函数地址加上偏移量
					return pFunAddress + dwIndex - dwCodeNum + 1 + AddNum;
				continue; //继续匹配下一个特征码
			}
			dwCodeNum = 0; //如果不匹配，则特征码匹配计数器清零
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			return 0; //如果发生异常，返回 0
		}
	}

	return 0; //如果遍历完整个序列都没有匹配到特征码序列，返回 0
}