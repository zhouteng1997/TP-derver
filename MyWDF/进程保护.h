#include <basetsd.h> 

#define PROCESS_TERMINATE                  (0x0001)  
//����Ȩ��
#define PROCESS_CREATE_THREAD              (0x0002)  
#define PROCESS_SET_SESSIONID              (0x0004)  
#define PROCESS_VM_OPERATION               (0x0008)  
#define PROCESS_VM_READ                    (0x0010)  
#define PROCESS_VM_WRITE                   (0x0020)  
#define PROCESS_DUP_HANDLE                 (0x0040)  
#define PROCESS_CREATE_PROCESS             (0x0080)  
#define PROCESS_SET_QUOTA                  (0x0100)  
#define PROCESS_SET_INFORMATION            (0x0200)  
#define PROCESS_QUERY_INFORMATION          (0x0400)  
#define PROCESS_SUSPEND_RESUME             (0x0800)  
#define PROCESS_QUERY_LIMITED_INFORMATION  (0x1000)  
#define PROCESS_SET_LIMITED_INFORMATION    (0x2000)  

void ��װ���̱���();
void ж�ؽ��̱���();

void ����ܱ�������();
void ����ܱ�����PID(UINT64 pid);
int  �ж��ܱ�����PID(UINT64 pid);//����1��ʾ�ܱ��� ����0���ܱ���
void ɾ���ܱ�����PID(UINT64 pid);

void �������Ȩ����();
void �������Ȩ��PID(UINT64 pid);
int  �ж�����Ȩ��PID(UINT64 pid);//����1��ʾ�ܱ��� ����0
void ɾ������Ȩ��PID(UINT64 pid);


