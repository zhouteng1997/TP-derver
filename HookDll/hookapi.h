#include "pch.h"
#include <windows.h>
#include <iostream>

// �ٽ������������߳�ͬ��
extern  CRITICAL_SECTION cs;

void hookapi(PVOID* ppOriginal, PVOID pHook);

void unhookapi(PVOID* ppOriginal, PVOID pHook);
