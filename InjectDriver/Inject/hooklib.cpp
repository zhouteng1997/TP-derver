#include "hooklib.h"


static HOOK hook_internal(ULONG_PTR addr, void* newfunc)
{
    //分配一个HOOK的空间并填充长度
    HOOK hook = (HOOK)RtlAllocateMemory(true, sizeof(HOOKSTRUCT));
    //记录hook的源地址   (在什么位置)
    hook->addr = addr;
    //整理一个结构，将其替换到源结构  (要替换的东西)
#ifdef _WIN64
    hook->hook.mov = 0xB848;
#else
    hook->hook.mov = 0xB8;
#endif
    hook->hook.addr = (ULONG_PTR)newfunc;
    hook->hook.push = 0x50;
    hook->hook.ret = 0xc3;
    //拷贝源结构到orig   (被替换的东西需要保存)
    RtlCopyMemory(&hook->orig, (const void*)addr, sizeof(HOOKOPCODES));
    //在地址写上对应的结构 （替换的东西替换到对应的位置）
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
