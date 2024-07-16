#include "���̱���.h" //�����Զ����ͷ�ļ� "���̱���.h"
#include <ntifs.h> //���� Windows �ں�ģʽ��ͷ�ļ�

#pragma warning(disable : 4505) //����δ���õľ�̬��������

static UINT64 �ܱ����Ľ���PID[256] = { 0 };//���汻����PID������
static UINT64 ����Ȩ�Ľ���PID[256] = { 0 };//���汻����PID������

void ����ܱ�������()
{
	memset(�ܱ����Ľ���PID, 0, sizeof(�ܱ����Ľ���PID));
}
void ����ܱ�����PID(UINT64 pid)
{
	for (size_t i = 0; i < 256; i++)
	{

		if (�ܱ����Ľ���PID[i] == 0 || �ܱ����Ľ���PID[i] == pid)
		{
			//�ǿ�λ��
			�ܱ����Ľ���PID[i] = pid;
			break;
		}
	}
}
void ɾ���ܱ�����PID(UINT64 pid)
{
	for (size_t i = 0; i < 256; i++)
	{
		if (�ܱ����Ľ���PID[i] == pid)//��ȱ�ʾ�ҵ���
		{
			�ܱ����Ľ���PID[i] = 0;
		}
	}
	return;
}
int �ж��ܱ�����PID(UINT64 pid)
{
	for (size_t i = 0; i < 256; i++) {
		if (�ܱ����Ľ���PID[i] == pid)//��ȱ�ʾ�ҵ���{
		{
			return 1;
		}
	}
	return 0;
}


void �������Ȩ����()
{
	memset(����Ȩ�Ľ���PID, 0, sizeof(����Ȩ�Ľ���PID));
}
void �������Ȩ��PID(UINT64 pid)
{
	for (size_t i = 0; i < 256; i++)
	{

		if (����Ȩ�Ľ���PID[i] == 0 || ����Ȩ�Ľ���PID[i] == pid)
		{
			//�ǿ�λ��
			����Ȩ�Ľ���PID[i] = pid;
			break;
		}
	}
}
void ɾ������Ȩ��PID(UINT64 pid)
{
	for (size_t i = 0; i < 256; i++)
	{
		if (����Ȩ�Ľ���PID[i] == pid)//��ȱ�ʾ�ҵ���
		{
			����Ȩ�Ľ���PID[i] = 0;
		}
	}
	return;
}
int �ж�����Ȩ��PID(UINT64 pid)
{
	for (size_t i = 0; i < 256; i++) {
		if (����Ȩ�Ľ���PID[i] == pid)//��ȱ�ʾ�ҵ���{
		{
			return 1;
		}
	}
	return 0;
}

const char* PsGetProcessImageFileName(PEPROCESS arg1);

//����: GetProcessName
//����: ���ݽ���ID��ȡ��������
//����: 
//     ProcessId - Ҫ��ѯ�Ľ���ID
//����ֵ: 
//     �ɹ�ʱ���ؽ������Ƶ�ָ�룬ʧ��ʱ����NULL
const char* GetProcessName(HANDLE ProcessId) {  //windbg�ϵ����� bu MyWDF!GetProcessName
	NTSTATUS st = STATUS_UNSUCCESSFUL; //���岢��ʼ��״̬����ΪSTATUS_UNSUCCESSFUL
	PEPROCESS ProcessObj = NULL;       //���岢��ʼ��EPROCESSָ��ΪNULL
	const char* imagename = NULL;      //���岢��ʼ��ָ��������Ƶ�ָ��ΪNULL
	//ͨ������ID����EPROCESS����
	st = PsLookupProcessByProcessId(ProcessId, &ProcessObj);
	//�������Ƿ�ɹ�
	if (NT_SUCCESS(st)) {
		//��ȡ���̵�ͼ���ļ���
		imagename = PsGetProcessImageFileName(ProcessObj);

		//�����EPROCESS���������
		ObfDereferenceObject(ProcessObj);
	}
	//���ؽ�������
	return imagename;
}

//����ص����� my_pre_callback�����ڴ���Ԥ�����ص�
OB_PREOP_CALLBACK_STATUS my_pre_callback(
	PVOID RegistrationContext, //ע��������
	POB_PRE_OPERATION_INFORMATION OperationInformation //Ԥ������Ϣ
)
{
	RegistrationContext;

	//�ϵ��ʽ
	//DbgBreakPoint();

	//�жϾ���Ƿ�Ϊ�ں˴���
	if (OperationInformation->KernelHandle)
	{
		//������ں˴����ľ���������κβ���
	}
	else
	{

		//�û��������OpenProcess NtOpenProcess������
		const char* ������ = PsGetProcessImageFileName(PsGetCurrentProcess()); //11����Ч���ַ�
		//KdPrint(("���� ������=%s \n ", ������));//11�����ֳ�������Ч
		HANDLE pid = PsGetProcessId((PEPROCESS)OperationInformation->Object);
		const char* Ŀ������� = GetProcessName(pid);
		������;
		Ŀ�������;
		//KdPrint(("���� ������=%s Ŀ�������=%s \n ", ������, Ŀ�������));//11�����ֳ�������Ч

		if (�ж��ܱ�����PID((UINT64)pid) == 1)
		{
			//�û���
			ACCESS_MASK ��ȡȨ�� = OperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess;
			ACCESS_MASK ��ȡ��Ȩ�� = OperationInformation->Parameters->CreateHandleInformation.DesiredAccess;//�����Ȩ������
			��ȡ��Ȩ��;
			//�ý������̵Ĺ���ʧЧ
			��ȡȨ�� &= ~PROCESS_TERMINATE;
			//�������ڴ汻��д
			��ȡȨ�� &= ~PROCESS_VM_READ;
			��ȡȨ�� &= ~PROCESS_VM_WRITE;
			//���������޸Ĺ���Ȩ�� OpenProcess
			OperationInformation->Parameters->CreateHandleInformation.DesiredAccess = ��ȡȨ��;
			KdPrint(("���� ��ȡȨ��=%X ��ȡ��Ȩ��=%X", ��ȡȨ��, ��ȡ��Ȩ��));
		}
	}
	//���ز����ɹ�
	return OB_PREOP_SUCCESS;
}



//����ȫ�ֱ��� gs_HandleCallback�����ڴ�ŷ��صľ�����Է���ж�ض�Ӧ����
HANDLE gs_HandleCallback = NULL;

//���尲װ�ڴ汣���ĺ���
void ��װ���̱���()
{
	//��ʼ�� OB_CALLBACK_REGISTRATION �ṹ��
	OB_CALLBACK_REGISTRATION obCallbackReg = { 0 };
	//��ʼ�� OB_OPERATION_REGISTRATION �ṹ��
	OB_OPERATION_REGISTRATION obOperation = { 0 };

	//����ע��ĸ߶�
	RtlInitUnicodeString(&obCallbackReg.Altitude, L"321000");
	//����ע��������
	obCallbackReg.RegistrationContext = NULL;
	//����ע��汾
	obCallbackReg.Version = OB_FLT_REGISTRATION_VERSION;
	//���ò���ע�����
	obCallbackReg.OperationRegistrationCount = 1;
	//���ò���ע��
	obCallbackReg.OperationRegistration = &obOperation;

	//��ʼ�� obOperation �ṹ��
	obOperation.ObjectType = PsProcessType; //���ö�������Ϊ����
	obOperation.Operations = OB_OPERATION_HANDLE_CREATE; //���ò���Ϊ�������
	obOperation.PostOperation = NULL; //����Ҫ������ص�
	obOperation.PreOperation = my_pre_callback; //����Ԥ�����ص�Ϊ my_pre_callback

	//ע��ص�����  ObRegisterCallbacks��Ҫ��������� /INTEGRITYCHECK
	NTSTATUS status = ObRegisterCallbacks(&obCallbackReg, &gs_HandleCallback);
	if (NT_SUCCESS(status)) {
		//��ӡ������Ϣ����ʾע��ص��ľ��
		KdPrint(("���� ��װ�ڴ汣��gs_HandleCallback=%p", gs_HandleCallback));
	}
	else {
		//��ӡ������Ϣ����ʾע��ʧ�ܵĴ������
		KdPrint(("���� ��װ�ڴ汣��ʧ��, �������=%x", status));
	}
}

//����ж���ڴ汣���ĺ���
void ж�ؽ��̱���()
{
	if (gs_HandleCallback)
	{
		//ע���ص�����
		ObUnRegisterCallbacks(gs_HandleCallback);
		//��ӡ������Ϣ����ʾ�ڴ汣����ж��
		KdPrint(("���� ж���ڴ汣��"));
	}
}