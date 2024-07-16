#include <ntifs.h>
#include "Cr0_HEAD.h"

//向指定进程内存写入数据
BOOLEAN KWriteProcessMemory2(
	IN PEPROCESS Process,    //目标进程
	IN PVOID Address,        //要写入的地址
	IN UINT32 Length,        //要写入的数据长度
	IN PVOID UserBuffer      //待写入数据的缓冲区
) {
	unsigned char* Mapped = NULL;      //映射内存指针
	PMDL g_pmdl = NULL;                //内存描述符列表指针
	KAPC_STATE apc_state;              //APC 状态用于进程附加
	RtlZeroMemory(&apc_state, sizeof(KAPC_STATE));  //清零 APC 状态结构体
	KdPrint(("驱动: sys64 %s 行号 = %d (Process = %p, Address = %p, Length = %d, UserBuffer = %p)\n", __FUNCDNAME__, __LINE__, Process, Address, Length, UserBuffer));

	//附加到目标进程的地址空间
	KeStackAttachProcess((PVOID)Process, &apc_state);
	BOOLEAN dwRet = MmIsAddressValid(Address);  //检查地址是否有效

	if (dwRet) {
		//分配内存描述符列表 (MDL)
		g_pmdl = IoAllocateMdl(Address, Length, 0, 0, NULL);

		if (!g_pmdl) {  //如果分配失败
			KeUnstackDetachProcess(&apc_state);  //从目标进程分离
			return FALSE;  //返回失败
		}

		//构建用于非分页池的 MDL
		MmBuildMdlForNonPagedPool(g_pmdl);

		//仅读权限修改的另一种方法，等同于 #include "Cr0_HEAD.h"中的方法
		//g_pmdl->MdlFlags = MDL_WRITE_OPERATION | MDL_ALLOCATED_FIXED_SIZE | MDL_PAGES_LOCKED;

		//将 MDL 映射到内核空间
		unsigned char* Mapped1 = (unsigned char*)MmMapLockedPages(g_pmdl, KernelMode);
		Mapped = Mapped1;  //更新映射内存指针
		if (!Mapped) {  //如果映射失败
			IoFreeMdl(g_pmdl);  //释放 MDL
			KeUnstackDetachProcess(&apc_state);  //从目标进程分离
			return FALSE;  //返回失败
		}
	}
	else {
		KdPrint(("驱动: sys64: 错误行 37\n"));  //打印错误信息
	}

	//从目标进程分离
	KeUnstackDetachProcess(&apc_state);
	KdPrint(("驱动: sys 分离目标进程\n"));  //打印分离信息

	if (Mapped) {  //如果内存映射成功
		KIRQL kirql = WP_OFF();  //禁用写保护
		RtlCopyMemory(Mapped, UserBuffer, Length);  //将数据从 UserBuffer 复制到目标地址
		WP_ON(kirql);  //重新启用写保护
		KdPrint(("驱动 Mapped = %p UserBuffer = %p Length = %d\n", Mapped, UserBuffer, Length));  //打印拷贝信息
	}
	else {
		KdPrint(("驱动: sys64: 错误行 37\n"));  //打印错误信息
	}

	if (Mapped && g_pmdl) {  //如果内存映射和 MDL 存在
		MmUnmapLockedPages((PVOID)Mapped, g_pmdl);  //取消 MDL 的内存映射
	}
	if (g_pmdl) {  //如果 MDL 存在
		IoFreeMdl(g_pmdl);  //释放 MDL
	}

	return dwRet;  //返回结果
}

//根据进程 ID 向进程内存写入数据
int WriteProcessMemoryForPid2(UINT32 dwPid, PVOID pBase, PVOID lpBuffer, UINT32 nSize) {
	PEPROCESS Seleted_pEPROCESS = NULL;  //目标进程指针
	KdPrint(("驱动: sys64 %s 行号 = %d\n", __FUNCDNAME__, __LINE__));
	if (PsLookupProcessByProcessId((PVOID)(UINT_PTR)(dwPid), &Seleted_pEPROCESS) == STATUS_SUCCESS) {  //查找进程
		BOOLEAN br = KWriteProcessMemory2(Seleted_pEPROCESS, pBase, nSize, lpBuffer);  //写入进程内存
		ObDereferenceObject(Seleted_pEPROCESS);  //取消引用进程对象
		if (br) {
			return nSize;  //返回写入的大小
		}
	}
	else {
		KdPrint(("驱动 sys64 PsLookupProcessByProcessId 失败\n"));  //打印错误信息
	}
	return 0;  //返回失败
}

//处理写入进程内存的 IRP 请求
NTSTATUS IRP_WriteProcessMemory2(PIRP pirp) {
	KdPrint(("驱动: sys64 %s 行号 = %d\n", __FUNCDNAME__, __LINE__));
	NTSTATUS ntStatus = STATUS_SUCCESS;  //初始化状态为成功
	PIO_STACK_LOCATION irpStack = IoGetCurrentIrpStackLocation(pirp);  //获取当前 IRP 堆栈位置

#pragma pack(push)
#pragma pack(8)
	//输入缓冲区结构体
	typedef struct TINPUT_BUF {
		UINT32 dwPid;   //目标进程 ID
		PVOID pBase;    //目标进程地址
		UINT32 nSize;   //要写入的数据长度
		PVOID pbuf;     //要写入数据的缓冲区地址
	} TINPUT_BUF;
#pragma pack(pop)

	TINPUT_BUF* bufInput = (TINPUT_BUF*)(pirp->AssociatedIrp.SystemBuffer);  //获取输入缓冲区
	WriteProcessMemoryForPid2(bufInput->dwPid, bufInput->pBase, bufInput->pbuf, bufInput->nSize);  //写入进程内存

	KdPrint(("驱动: sys64 dwPid = %d pBase = %p pbuf = %p nSize = %d\n", bufInput->dwPid, bufInput->pBase, bufInput->pbuf, bufInput->nSize));  //打印写入信息

	if (irpStack) {
		if (ntStatus == STATUS_SUCCESS) {  //如果操作成功
			pirp->IoStatus.Information = irpStack->Parameters.DeviceIoControl.OutputBufferLength;  //设置返回缓冲区大小
		}
		else {
			pirp->IoStatus.Information = 0;  //设置返回为 0
		}
		IoCompleteRequest(pirp, IO_NO_INCREMENT);  //完成请求
	}

	pirp->IoStatus.Status = ntStatus;  //设置 IRP 状态
	return ntStatus;  //返回状态
}
