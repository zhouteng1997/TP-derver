#include "hooklib.h"


static HOOK hook_internal(ULONG_PTR addr, void* newfunc)
{
    //����һ��HOOK�Ŀռ䲢��䳤��
    HOOK hook = (HOOK)RtlAllocateMemory(true, sizeof(HOOKSTRUCT));
    //��¼hook��Դ��ַ   (��ʲôλ��)
    hook->addr = addr;
    //����һ���ṹ�������滻��Դ�ṹ  (Ҫ�滻�Ķ���)
#ifdef _WIN64
    hook->hook.mov = 0xB848;
#else
    hook->hook.mov = 0xB8;
#endif
    hook->hook.addr = (ULONG_PTR)newfunc;
    hook->hook.push = 0x50;
    hook->hook.ret = 0xc3;
    //����Դ�ṹ��orig   (���滻�Ķ�����Ҫ����)
    RtlCopyMemory(&hook->orig, (const void*)addr, sizeof(HOOKOPCODES));
    //�ڵ�ַд�϶�Ӧ�Ľṹ ���滻�Ķ����滻����Ӧ��λ�ã�
    if(!NT_SUCCESS(RtlSuperCopyMemory((void*)addr, &hook->hook, sizeof(HOOKOPCODES))))
    {
        RtlFreeMemory(hook);
        return 0;
    }
    return hook;
}

HOOK Hooklib::Hook(PVOID api, void* newfunc)
{
    ULONG_PTR addr = (ULONG_PTR)api;
    if(!addr)
        return 0;
    DPRINT("[DeugMessage] hook(0x%p, 0x%p)\r\n", addr, newfunc);
    return hook_internal(addr, newfunc);
}

bool Hooklib::Hook(HOOK hook)
{
    if(!hook)
        return false;
    return (NT_SUCCESS(RtlSuperCopyMemory((void*)hook->addr, &hook->hook, sizeof(HOOKOPCODES))));
}

bool Hooklib::Unhook(HOOK hook, bool free)
{
    if(!hook || !hook->addr)
        return false;
    if(NT_SUCCESS(RtlSuperCopyMemory((void*)hook->addr, hook->orig, sizeof(HOOKOPCODES))))
    {
        if(free)
            RtlFreeMemory(hook);
        return true;
    }
    return false;
}
