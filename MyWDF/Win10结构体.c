#include <ntifs.h>
#include "Win10结构体.h"
//#include <wincrypt.h>
//#include "../EmProcess/D035-NtDefs.h"

UINT_PTR RP(UINT_PTR base) {
	__try {
		return *(UINT_PTR*)base;
	}
	__except (1) {
		return 0;
	}
}

UINT_PTR MyExpLookupHandleTableEntry(UINT_PTR tableCode, UINT_PTR handle) {
	int index = tableCode & 0x3;
	int 句柄 = handle & 0x0FFFFFFFFFFFFFFFC; //后两位清零
	UINT_PTR r8 = tableCode;
	UINT_PTR rdx = 句柄;
	UINT_PTR rax;
	UINT_PTR rcx;
	switch (index)
	{
	case 0://表0
		rax = r8 + rdx * 4;					//fffff806`03f52b89 498d0490        lea     rax, [r8 + rdx * 4]
		break;
	case 1://表1
		rax = rdx;							//fffff806`03f52b6a 488bc2          mov     rax, rdx                                                								_句柄 0x234
		rax = rax >> 0x0A;					//fffff806`03f52b6d 48c1e80a        shr     rax, 0Ah																			//shr     rax,0Ah 把 rax右移10位   rax是句柄，句柄的区间为1024bit，
		rax = RP(r8 + rax * 8 - 1);			//fffff806`03f52b71 498b44c0ff      mov     rax, qword ptr[r8 + rax * 8 - 1]															这个rax实际地址，r8为基址表[r8 + rax * 8 - 1] 是基址表的位置偏移，这个基质表存储的是地址x
		*((UINT32*)&rdx) = rdx & 0x3FF;		//fffff806`03f52b76 81e2ff030000	and edx, 3FFh															0f85e5021300的返回
		rax = rax + rdx * 4;				//fffff806`03f52b7c 488d0490        lea     rax, [rax + rdx * 4]    
		break;
	case 2://表2
		rcx = rdx;							//fffff805`3d7e3e6e 488bca          mov     rcx, rdx
		rcx = rcx >> 0x0A;					//fffff805`3d7e3e71 48c1e90a        shr     rcx, 0Ah
		rax = rcx;							//fffff805`3d7e3e75 488bc1          mov     rax, rcx
		rax = rax >> 9;						//fffff805`3d7e3e78 48c1e809        shr     rax, 9
		*((UINT32*)&rcx) = rcx & 0x1FF;		//fffff805`3d7e3e7c 81e1ff010000 and ecx, 1FFh
		rax = RP(r8 + rax * 8 - 2);			//fffff805`3d7e3e82 498b44c0fe      mov     rax, qword ptr[r8 + rax * 8 - 2]
		rax = RP(rax + rcx * 8);			//fffff805`3d7e3e87 488b04c8        mov     rax, qword ptr[rax + rcx * 8]
		*((UINT32*)&rdx) = rdx & 0x3FF;		//fffff806`03f52b76 81e2ff030000 and edx, 3FFh															0f85e5021300的返回
		rax = rax + rdx * 4;				//fffff806`03f52b7c 488d0490        lea     rax, [rax + rdx * 4]                 		//编号2的表
		break;
	default:
		rax = 0;
		break;
	}
	return rax;
}

//nt!ExpLookupHandleTableEntry:
//fffff806`03f52b50 8b01            mov     eax, dword ptr[rcx]        rcx的地址是_HANDLE_TABLE, eax取_HANDLE_TABLE结构的NextHandleNeedingPool，无意义	_HANDLE_TABLE   最后一位为0，1，2，对应这个进程的句柄表
//fffff806`03f52b52 4883e2fc and rdx, 0FFFFFFFFFFFFFFFCh     C = 1100，这句话为最后两位清零
//fffff806`03f52b56 483bd0          cmp     rdx, rax					 cmp  rdx = 句柄 rax = 最大句柄数量jae 大于等于则跳转 跳转说明异常   _句柄 0x234
//fffff806`03f52b59 7333            jae     nt!ExpLookupHandleTableEntry + 0x3e (fffff806`03f52b8e)
//fffff806`03f52b5b 4c8b4108        mov     r8, qword ptr[rcx + 8]																	_HANDLE_TABLE->tableCode
//fffff806`03f52b5f 418bc0          mov     eax, r8d
//fffff806`03f52b62 83e003 and eax, 3
//fffff806`03f52b65 83f801          cmp     eax, 1   eax = 0 | 1 | 2   如果是1，往下走， 否则跳转
//fffff806`03f52b68 7517            jne     nt!ExpLookupHandleTableEntry + 0x31 (fffff806`03f52b81)
//fffff806`03f52b6a 488bc2          mov     rax, rdx                                                								_句柄 0x234
//fffff806`03f52b6d 48c1e80a        shr     rax, 0Ah																			//shr     rax,0Ah 把 rax右移10位   rax是句柄，句柄的区间为1024bit，
//fffff806`03f52b71 498b44c0ff      mov     rax, qword ptr[r8 + rax * 8 - 1]															这个rax实际地址，r8为基址表[r8 + rax * 8 - 1] 是基址表的位置偏移，这个基质表存储的是地址x
//fffff806`03f52b76 81e2ff030000 and edx, 3FFh															0f85e5021300的返回
//fffff806`03f52b7c 488d0490        lea     rax, [rax + rdx * 4]                 		//编号1的表
//fffff806`03f52b80 c3              ret
//fffff806`03f52b81 85c0            test    eax, eax    如果不是1，在这里，是0往下走，是2跳转
//fffff806`03f52b83 0f85e5021300    jne     nt!ExpLookupHandleTableEntry + 0x13031e (fffff806`04082e6e)    结束后会返回fffff806`03f52b76 81e2ff030000 and edx, 3FFh
//fffff806`03f52b89 498d0490        lea     rax, [r8 + rdx * 4]                     //编号0的表                                        
//fffff806`03f52b8d c3              ret
//fffff806`03f52b8e 33c0 xor eax, eax
//fffff806`03f52b90 c3              ret

//0: kd > u nt!ExpLookupHandleTableEntry + 0x13031e l 100
//nt!ExpLookupHandleTableEntry + 0x13031e:
//fffff805`3d7e3e6e 488bca          mov     rcx, rdx
//fffff805`3d7e3e71 48c1e90a        shr     rcx, 0Ah
//fffff805`3d7e3e75 488bc1          mov     rax, rcx
//fffff805`3d7e3e78 48c1e809        shr     rax, 9
//fffff805`3d7e3e7c 81e1ff010000 and ecx, 1FFh
//fffff805`3d7e3e82 498b44c0fe      mov     rax, qword ptr[r8 + rax * 8 - 2]
//fffff805`3d7e3e87 488b04c8        mov     rax, qword ptr[rax + rcx * 8]
//fffff805`3d7e3e8b e9e6fcecff      jmp     nt!ExpLookupHandleTableEntry + 0x26 (fffff805`3d6b3b76)

//######################################下面代码是由上面代码拆出来的##############################################

//r8 = tableCode的地址  rdx = 句柄
// 
//表0
//fffff806`03f52b89 498d0490        lea     rax, [r8 + rdx * 4]
//fffff806`03f52b8d c3              ret
//
//表1
//fffff806`03f52b6a 488bc2          mov     rax, rdx                                                								_句柄 0x234
//fffff806`03f52b6d 48c1e80a        shr     rax, 0Ah																			//shr     rax,0Ah 把 rax右移10位   rax是句柄，句柄的区间为1024bit，
//fffff806`03f52b71 498b44c0ff      mov     rax, qword ptr[r8 + rax * 8 - 1]															这个rax实际地址，r8为基址表[r8 + rax * 8 - 1] 是基址表的位置偏移，这个基质表存储的是地址x
//fffff806`03f52b76 81e2ff030000 and edx, 3FFh															0f85e5021300的返回
//fffff806`03f52b7c 488d0490        lea     rax, [rax + rdx * 4]                 		//编号1的表
//fffff806`03f52b80 c3              ret
//
//表2
//fffff805`3d7e3e6e 488bca          mov     rcx, rdx
//fffff805`3d7e3e71 48c1e90a        shr     rcx, 0Ah
//fffff805`3d7e3e75 488bc1          mov     rax, rcx
//fffff805`3d7e3e78 48c1e809        shr     rax, 9
//fffff805`3d7e3e7c 81e1ff010000 and ecx, 1FFh
//fffff805`3d7e3e82 498b44c0fe      mov     rax, qword ptr[r8 + rax * 8 - 2]
//fffff805`3d7e3e87 488b04c8        mov     rax, qword ptr[rax + rcx * 8]
//fffff806`03f52b76 81e2ff030000 and edx, 3FFh															0f85e5021300的返回
//fffff806`03f52b7c 488d0490        lea     rax, [rax + rdx * 4]                 		//编号2的表
//fffff806`03f52b80 c3              ret




