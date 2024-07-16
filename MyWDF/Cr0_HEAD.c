#include<ntifs.h>
#include<intrin.h>//�򿪿�д�ڴ�ļ��

//cr0Ȩ�޻�ԭ
UINT64 WP_ON(KIRQL irql)
{
	UINT64 cr0 = __readcr0();
	UINT64 old_cr0 = cr0;
	cr0 |= 0x10000;
	_enable();
	__writecr0(cr0);
	KeLowerIrql(irql);
	return old_cr0;

}

//�رտ�д�ڴ�ļ��
KIRQL WP_OFF()
{
	KIRQL irql = KeRaiseIrqlToDpcLevel();
	UINT64 cr0 = __readcr0();
	cr0 &= 0xfffffffffffeffff;
	__writecr0(cr0);
	_disable();
	return irql;
}