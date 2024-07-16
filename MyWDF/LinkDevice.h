#include<wdm.h>

//创建设备
NTSTATUS CreateDevice(PDRIVER_OBJECT driver);

//删除设备
void DeleteDriver(PDRIVER_OBJECT pDriver);