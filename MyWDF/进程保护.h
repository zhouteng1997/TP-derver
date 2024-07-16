#include <basetsd.h> 

#define PROCESS_TERMINATE                  (0x0001)  
//进程权限
#define PROCESS_CREATE_THREAD              (0x0002)  
#define PROCESS_SET_SESSIONID              (0x0004)  
#define PROCESS_VM_OPERATION               (0x0008)  
#define PROCESS_VM_READ                    (0x0010)  
#define PROCESS_VM_WRITE                   (0x0020)  
#define PROCESS_DUP_HANDLE                 (0x0040)  
#define PROCESS_CREATE_PROCESS             (0x0080)  
#define PROCESS_SET_QUOTA                  (0x0100)  
#define PROCESS_SET_INFORMATION            (0x0200)  
#define PROCESS_QUERY_INFORMATION          (0x0400)  
#define PROCESS_SUSPEND_RESUME             (0x0800)  
#define PROCESS_QUERY_LIMITED_INFORMATION  (0x1000)  
#define PROCESS_SET_LIMITED_INFORMATION    (0x2000)  

void 安装进程保护();
void 卸载进程保护();

void 清空受保护数组();
void 添加受保护的PID(UINT64 pid);
int  判断受保护的PID(UINT64 pid);//返回1表示受保护 返回0不受保护
void 删除受保护的PID(UINT64 pid);

void 清空需提权数组();
void 添加需提权的PID(UINT64 pid);
int  判断需提权的PID(UINT64 pid);//返回1表示受保护 返回0
void 删除需提权的PID(UINT64 pid);


