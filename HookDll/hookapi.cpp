#include "pch.h"
#include "hookapi.h"
#include "Detours/detours.h" // Detours library for hooking

// Function to install the hook
void hookapi(PVOID* oldFunc, PVOID newFunc)
{
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    DetourAttach(oldFunc, newFunc);
    DetourTransactionCommit();
}

// Function to uninstall the hook
void unhookapi(PVOID* oldFunc, PVOID newFunc)
{
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    DetourDetach(oldFunc, newFunc);
    DetourTransactionCommit();
}