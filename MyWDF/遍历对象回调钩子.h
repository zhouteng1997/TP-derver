#include <ntdef.h>


//�������� ���� �߳� ע���ObRegisterCallBacks�ص�
ULONG EnumObRegisterCallBacks(); 

//���ݵ�ַ �ж���������ģ��
BOOLEAN ObGetDriverNameByPoint(ULONG_PTR Point, OUT WCHAR* szDriverName);

//��ȡ�����е���ת��ַ
PVOID GetMovPoint(PVOID pCallPoint);

//��ȡPsLoadedModuleList��ַ�������жϵ�ַ����ģ��
PVOID GetPsLoadedListModule();