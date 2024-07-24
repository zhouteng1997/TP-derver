#include "pch.h"
#include <windows.h>
#include <iostream>

// 临界区对象用于线程同步
extern  CRITICAL_SECTION cs;

void hookapi(PVOID* ppOriginal, PVOID pHook);

void unhookapi(PVOID* ppOriginal, PVOID pHook);
