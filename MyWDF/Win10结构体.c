#include <ntifs.h>
#include "Win10�ṹ��.h"
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
	int ��� = handle & 0x0FFFFFFFFFFFFFFFC; //����λ����
	UINT_PTR r8 = tableCode;
	UINT_PTR rdx = ���;
	UINT_PTR rax;
	UINT_PTR rcx;
	switch (index)
	{
	case 0://��0
		rax = r8 + rdx * 4;					//fffff806`03f52b89 498d0490        lea     rax, [r8 + rdx * 4]
		break;
	case 1://��1
		rax = rdx;							//fffff806`03f52b6a 488bc2          mov     rax, rdx                                                								_��� 0x234
		rax = rax >> 0x0A;					//fffff806`03f52b6d 48c1e80a        shr     rax, 0Ah																			//shr     rax,0Ah �� rax����10λ   rax�Ǿ�������������Ϊ1024bit��
		rax = RP(r8 + rax * 8 - 1);			//fffff806`03f52b71 498b44c0ff      mov     rax, qword ptr[r8 + rax * 8 - 1]															���raxʵ�ʵ�ַ��r8Ϊ��ַ��[r8 + rax * 8 - 1] �ǻ�ַ���λ��ƫ�ƣ�������ʱ�洢���ǵ�ַx
		*((UINT32*)&rdx) = rdx & 0x3FF;		//fffff806`03f52b76 81e2ff030000	and edx, 3FFh															0f85e5021300�ķ���
		rax = rax + rdx * 4;				//fffff806`03f52b7c 488d0490        lea     rax, [rax + rdx * 4]    
		break;
	case 2://��2
		rcx = rdx;							//fffff805`3d7e3e6e 488bca          mov     rcx, rdx
		rcx = rcx >> 0x0A;					//fffff805`3d7e3e71 48c1e90a        shr     rcx, 0Ah
		rax = rcx;							//fffff805`3d7e3e75 488bc1          mov     rax, rcx
		rax = rax >> 9;						//fffff805`3d7e3e78 48c1e809        shr     rax, 9
		*((UINT32*)&rcx) = rcx & 0x1FF;		//fffff805`3d7e3e7c 81e1ff010000 and ecx, 1FFh
		rax = RP(r8 + rax * 8 - 2);			//fffff805`3d7e3e82 498b44c0fe      mov     rax, qword ptr[r8 + rax * 8 - 2]
		rax = RP(rax + rcx * 8);			//fffff805`3d7e3e87 488b04c8        mov     rax, qword ptr[rax + rcx * 8]
		*((UINT32*)&rdx) = rdx & 0x3FF;		//fffff806`03f52b76 81e2ff030000 and edx, 3FFh															0f85e5021300�ķ���
		rax = rax + rdx * 4;				//fffff806`03f52b7c 488d0490        lea     rax, [rax + rdx * 4]                 		//���2�ı�
		break;
	default:
		rax = 0;
		break;
	}
	return rax;
}

//nt!ExpLookupHandleTableEntry:
//fffff806`03f52b50 8b01            mov     eax, dword ptr[rcx]        rcx�ĵ�ַ��_HANDLE_TABLE, eaxȡ_HANDLE_TABLE�ṹ��NextHandleNeedingPool��������	_HANDLE_TABLE   ���һλΪ0��1��2����Ӧ������̵ľ����
//fffff806`03f52b52 4883e2fc and rdx, 0FFFFFFFFFFFFFFFCh     C = 1100����仰Ϊ�����λ����
//fffff806`03f52b56 483bd0          cmp     rdx, rax					 cmp  rdx = ��� rax = ���������jae ���ڵ�������ת ��ת˵���쳣   _��� 0x234
//fffff806`03f52b59 7333            jae     nt!ExpLookupHandleTableEntry + 0x3e (fffff806`03f52b8e)
//fffff806`03f52b5b 4c8b4108        mov     r8, qword ptr[rcx + 8]																	_HANDLE_TABLE->tableCode
//fffff806`03f52b5f 418bc0          mov     eax, r8d
//fffff806`03f52b62 83e003 and eax, 3
//fffff806`03f52b65 83f801          cmp     eax, 1   eax = 0 | 1 | 2   �����1�������ߣ� ������ת
//fffff806`03f52b68 7517            jne     nt!ExpLookupHandleTableEntry + 0x31 (fffff806`03f52b81)
//fffff806`03f52b6a 488bc2          mov     rax, rdx                                                								_��� 0x234
//fffff806`03f52b6d 48c1e80a        shr     rax, 0Ah																			//shr     rax,0Ah �� rax����10λ   rax�Ǿ�������������Ϊ1024bit��
//fffff806`03f52b71 498b44c0ff      mov     rax, qword ptr[r8 + rax * 8 - 1]															���raxʵ�ʵ�ַ��r8Ϊ��ַ��[r8 + rax * 8 - 1] �ǻ�ַ���λ��ƫ�ƣ�������ʱ�洢���ǵ�ַx
//fffff806`03f52b76 81e2ff030000 and edx, 3FFh															0f85e5021300�ķ���
//fffff806`03f52b7c 488d0490        lea     rax, [rax + rdx * 4]                 		//���1�ı�
//fffff806`03f52b80 c3              ret
//fffff806`03f52b81 85c0            test    eax, eax    �������1���������0�����ߣ���2��ת
//fffff806`03f52b83 0f85e5021300    jne     nt!ExpLookupHandleTableEntry + 0x13031e (fffff806`04082e6e)    ������᷵��fffff806`03f52b76 81e2ff030000 and edx, 3FFh
//fffff806`03f52b89 498d0490        lea     rax, [r8 + rdx * 4]                     //���0�ı�                                        
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

//######################################������������������������##############################################

//r8 = tableCode�ĵ�ַ  rdx = ���
// 
//��0
//fffff806`03f52b89 498d0490        lea     rax, [r8 + rdx * 4]
//fffff806`03f52b8d c3              ret
//
//��1
//fffff806`03f52b6a 488bc2          mov     rax, rdx                                                								_��� 0x234
//fffff806`03f52b6d 48c1e80a        shr     rax, 0Ah																			//shr     rax,0Ah �� rax����10λ   rax�Ǿ�������������Ϊ1024bit��
//fffff806`03f52b71 498b44c0ff      mov     rax, qword ptr[r8 + rax * 8 - 1]															���raxʵ�ʵ�ַ��r8Ϊ��ַ��[r8 + rax * 8 - 1] �ǻ�ַ���λ��ƫ�ƣ�������ʱ�洢���ǵ�ַx
//fffff806`03f52b76 81e2ff030000 and edx, 3FFh															0f85e5021300�ķ���
//fffff806`03f52b7c 488d0490        lea     rax, [rax + rdx * 4]                 		//���1�ı�
//fffff806`03f52b80 c3              ret
//
//��2
//fffff805`3d7e3e6e 488bca          mov     rcx, rdx
//fffff805`3d7e3e71 48c1e90a        shr     rcx, 0Ah
//fffff805`3d7e3e75 488bc1          mov     rax, rcx
//fffff805`3d7e3e78 48c1e809        shr     rax, 9
//fffff805`3d7e3e7c 81e1ff010000 and ecx, 1FFh
//fffff805`3d7e3e82 498b44c0fe      mov     rax, qword ptr[r8 + rax * 8 - 2]
//fffff805`3d7e3e87 488b04c8        mov     rax, qword ptr[rax + rcx * 8]
//fffff806`03f52b76 81e2ff030000 and edx, 3FFh															0f85e5021300�ķ���
//fffff806`03f52b7c 488d0490        lea     rax, [rax + rdx * 4]                 		//���2�ı�
//fffff806`03f52b80 c3              ret




