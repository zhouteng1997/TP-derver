#include "IO_ReadProcessMemory.h"
#include "win10api.h"


BOOLEAN IsOkWritePrt(UINT_PTR base) {
	__try {
		*(UINT64*)base;
		return TRUE;
	}
	__except (1) {
		return FALSE;
	}
}

//读取进程内存的函数
NTSTATUS KReadProcessMemory2(
	IN PEPROCESS Process,    //目标进程
	IN PVOID Address,        //要读取的地址
	IN UINT32 Length,        //要读取的数据长度
	IN PVOID UserBuffer      //存放读取数据的缓冲区
) {
	KAPC_STATE apc_state;              //APC 状态用于进程附加
	PVOID tmpBuf_Kernel = NULL;
	NTSTATUS status = STATUS_SUCCESS;
	// 附加到目标进程的地址空间
	KeStackAttachProcess((PVOID)Process, &apc_state);
	// 检查地址是否有效
	if (MmIsAddressValid(Address)) {
		// 检查地址是否可以写入
		if (IsOkWritePrt((UINT_PTR)Address)) {
			__try {
				// 分配内存并检查是否成功
				PVOID tmpBuf_Kerne2 = ExAllocatePool(NonPagedPool, Length);
				tmpBuf_Kernel = tmpBuf_Kerne2;
				if (tmpBuf_Kernel == NULL) {
					status = STATUS_INSUFFICIENT_RESOURCES;
				}
				else {
					// 读取内存
					RtlCopyMemory(tmpBuf_Kernel, Address, Length);
				}
			}
			__except (EXCEPTION_EXECUTE_HANDLER) {
				KdPrint(("驱动: sys64: 错误行 %d\n", __LINE__));
				status = STATUS_ACCESS_VIOLATION;
			}
		}
		else {
			status = STATUS_ACCESS_DENIED;
		}
	}
	else {
		KdPrint(("驱动: sys64: 错误行 %d\n", __LINE__));
		status = STATUS_INVALID_ADDRESS;
	}
	// 从目标进程分离
	KeUnstackDetachProcess(&apc_state);
	if (NT_SUCCESS(status) && tmpBuf_Kernel != NULL) {
		// 拷贝至指定用户缓冲区
		__try {
			RtlCopyMemory(UserBuffer, tmpBuf_Kernel, Length);
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			KdPrint(("驱动: sys64: 错误行 %d\n", __LINE__));
			status = STATUS_ACCESS_VIOLATION;
		}
		// 释放分配的内存
		ExFreePool(tmpBuf_Kernel);
	}
	return status;  // 返回结果
}

//根据进程 ID 读取进程内存
int ReadProcessMemoryForPid2(HANDLE dwPid, PVOID pBase, PVOID lpBuffer, UINT32 nSize) {
	PEPROCESS Seleted_pEPROCESS = NULL;  //目标进程指针
	DbgPrint("驱动: sys64 %s 行号 = %d\n", __FUNCDNAME__, __LINE__);
	if (PsLookupProcessByProcessId((PVOID)(UINT_PTR)(dwPid), &Seleted_pEPROCESS) == STATUS_SUCCESS) {  //查找进程
		NTSTATUS br = KReadProcessMemory2(Seleted_pEPROCESS, pBase, nSize, lpBuffer);  //读取进程内存
		ObDereferenceObject(Seleted_pEPROCESS);  //取消引用进程对象
		if (NT_SUCCESS(br)) {
			return nSize;  //返回读取的大小
		}
	}
	else {
		KdPrint(("驱动 sys64 PsLookupProcessByProcessId 失败\n"));  //打印错误信息
	}
	return 0;  //返回失败
}


int ReadProcessMemoryForHandle(HANDLE handle, PVOID pBase, PVOID lpBuffer, UINT32 nSize) {
	HANDLE pid = HandleToPid(PsGetCurrentProcessId(), handle);
	return ReadProcessMemoryForPid2(pid, pBase, lpBuffer, nSize);
}

//处理 IRP 读取进程内存
NTSTATUS IRP_ReadProcessMemory(PIRP pirp) {
	PIO_STACK_LOCATION irpStack = IoGetCurrentIrpStackLocation(pirp);//获取应用层传来的参数
	irpStack;
	UINT64* 缓冲区 = (UINT64*)(pirp->AssociatedIrp.SystemBuffer);
	if (缓冲区)
	{
#pragma pack(push)
#pragma pack(8)
		//输入缓冲区结构体
		typedef struct TINPUT_BUF {
			HANDLE handle;   //目标进程 ID
			PVOID pBase;    //目标进程地址
			UINT32 nSize;   //要读取的数据长度
		} TINPUT_BUF;
#pragma pack(pop)
		TINPUT_BUF* bufInput = (TINPUT_BUF*)缓冲区;  //获取输入缓冲区
		UINT32 ReadSize = ReadProcessMemoryForHandle(bufInput->handle, bufInput->pBase, 缓冲区, bufInput->nSize);  //读取进程内存
		ReadSize;
		pirp->IoStatus.Status = STATUS_SUCCESS;
		pirp->IoStatus.Information = bufInput->nSize;  //设置返回缓冲区大小
		IoCompleteRequest(pirp, IO_NO_INCREMENT);  //完成请求
		if (ReadSize)
		{
			return STATUS_SUCCESS;
		}
		else {
			return -1;
		}
	}
	return -1;  //返回状态
}
