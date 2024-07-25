#include "pch.h"
#include <Windows.h>

extern "C" __declspec(dllexport) void hookapi(PVOID * oldFunc, PVOID newFunc);
extern "C" __declspec(dllexport) void unhookapi(PVOID * oldFunc, PVOID newFunc);