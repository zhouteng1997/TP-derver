//��ݴ�����Դ��windbug������  ��Ҫ�鿴�ĸ��ṹ�壬��ʹ��dt������ݽṹ�����ɶ�Ӧ��C����
//ʾ����dt _HANDLE_TRACE_DEBUG_INFO

#include<wdm.h>

#define Win10_EPROCESS_HANDLE_TABLE_OFFSET 0x418; //��Դ�ڽṹ��  dt _EPROCESS  ����Ҫ֪����Դ����ȫ������_EPROCESS
#define Win10_HANDLE_TABLE_TableCode_OFFSET 0x008; //��Դ�ڽṹ��  dt _HANDLE_TABLE  ����Ҫ֪����Դ����ȫ������_HANDLE_TABLE   +0x008 TableCode  : Uint8B
#define Win10_ExpLookupHandleTableEntry 0xfffff80542a86b10; //�����ַ���ڵ����б仯������ʱ�޸�
UINT_PTR RP(UINT_PTR base);
UINT_PTR MyExpLookupHandleTableEntry(UINT_PTR tableCode, UINT_PTR handle);

//Definition for _EXHANDLE
typedef union _EXHANDLE {
	struct {
		ULONG64 TagBits : 2;
		ULONG64 Index : 30;
	}name1;
	PVOID GenericHandleOverlay;
	ULONG64 Value;
} EXHANDLE, * PEXHANDLE;

// Definition for _HANDLE_TABLE_ENTRY_INFO
typedef struct _HANDLE_TABLE_ENTRY_INFO {
	ULONG AuditMask;
	ULONG MaxRelativeAccessMask;
} HANDLE_TABLE_ENTRY_INFO, * PHANDLE_TABLE_ENTRY_INFO;

// Definition for _HANDLE_TABLE_ENTRY
typedef struct _HANDLE_TABLE_ENTRY {
	union {
		LONGLONG VolatileLowValue;
		LONGLONG LowValue;
		HANDLE_TABLE_ENTRY_INFO* InfoTable;
	}name1;
	union {
		LONGLONG HighValue;
		struct _HANDLE_TABLE_ENTRY* NextFreeHandleEntry;
		EXHANDLE LeafHandleValue;
	}name2;
	union {
		LONGLONG RefCountField;
		struct {
			ULONG64 Unlocked : 1;
			ULONG64 RefCnt : 16;
			ULONG64 Attributes : 3;
			ULONG64 ObjectPointerBits : 44;
		}name1;
	}name3;
	union {
		struct {
			ULONG GrantedAccessBits : 25;
			ULONG NoRightsUpgrade : 1;
			ULONG Spare1 : 6;
		}name1;
		ULONG Spare2;
	}name4;
} HANDLE_TABLE_ENTRY, *PHANDLE_TABLE_ENTRY;


// Definition for _HANDLE_TABLE_FREE_LIST
typedef struct _HANDLE_TABLE_FREE_LIST {
	EX_PUSH_LOCK FreeListLock;            // 0x000
	HANDLE_TABLE_ENTRY* FirstFreeHandleEntry; // 0x008
	HANDLE_TABLE_ENTRY* LastFreeHandleEntry;  // 0x010
	LONG HandleCount;                     // 0x018
	ULONG HighWaterMark;                  // 0x01c
} HANDLE_TABLE_FREE_LIST,*PHANDLE_TABLE_FREE_LIST;

// Definition for _HANDLE_TRACE_DB_ENTRY
typedef struct _HANDLE_TRACE_DB_ENTRY {
	CLIENT_ID ClientId;             // 0x000
	PVOID Handle;                   // 0x010
	ULONG Type;                     // 0x018
	PVOID StackTrace[16];           // 0x020
} HANDLE_TRACE_DB_ENTRY;

// Definition for _HANDLE_TRACE_DEBUG_INFO
typedef struct _HANDLE_TRACE_DEBUG_INFO {
	LONG RefCount;                  // 0x000
	ULONG TableSize;                // 0x004
	ULONG BitMaskFlags;             // 0x008
	FAST_MUTEX CloseCompactionLock; // 0x010
	ULONG CurrentStackIndex;        // 0x048
	HANDLE_TRACE_DB_ENTRY TraceDb[1];// 0x050
} HANDLE_TRACE_DEBUG_INFO;

// Forward declarations
typedef struct _HANDLE_TABLE {
	ULONG NextHandleNeedingPool;  // 0x000
	LONG ExtraInfoPages;          // 0x004
	ULONG64 TableCode;            // 0x008
	struct EPROCESS* QuotaProcess;       // 0x010
	LIST_ENTRY HandleTableList;   // 0x018
	ULONG UniqueProcessId;        // 0x028
	union {
		ULONG Flags;              // 0x02c
		struct {
			ULONG StrictFIFO : 1;
			ULONG EnableHandleExceptions : 1;
			ULONG Rundown : 1;
			ULONG Duplicated : 1;
			ULONG RaiseUMExceptionOnInvalidHandleClose : 1;
		}name1;
	}name1;
	EX_PUSH_LOCK HandleContentionEvent; // 0x030
	EX_PUSH_LOCK HandleTableLock;       // 0x038
	union {
		HANDLE_TABLE_FREE_LIST FreeLists[1]; // 0x040
		UCHAR ActualEntry[32];              // 0x040
	}name2;
	HANDLE_TRACE_DEBUG_INFO* DebugInfo;   // 0x060
} HANDLE_TABLE,*PHANDLE_TABLE;



// ����_OBJECT_TYPE_INITIALIZER�ṹ�������Ҫ��
typedef struct _OBJECT_TYPE_INITIALIZER {
	USHORT Length;
	UCHAR ObjectTypeFlags;
	ULONG CaseInsensitive : 1;
	ULONG UnnamedObjectsOnly : 1;
	ULONG UseDefaultObject : 1;
	ULONG SecurityRequired : 1;
	ULONG MaintainHandleCount : 1;
	ULONG MaintainTypeList : 1;
	ULONG SupportsObjectCallbacks : 1;
	ULONG CacheAligned : 1;
	ULONG Reserved : 23;
	LONG InvalidAttributes;
	GENERIC_MAPPING GenericMapping;
	ULONG ValidAccessMask;
	POOL_TYPE PoolType;
	ULONG DefaultPagedPoolCharge;
	ULONG DefaultNonPagedPoolCharge;
	PVOID DumpProcedure;
	PVOID OpenProcedure;
	PVOID CloseProcedure;
	PVOID DeleteProcedure;
	PVOID ParseProcedure;
	PVOID SecurityProcedure;
	PVOID QueryNameProcedure;
	PVOID OkayToCloseProcedure;
} OBJECT_TYPE_INITIALIZER, * POBJECT_TYPE_INITIALIZER;

// ����_OBJECT_TYPE�ṹ
typedef struct _OBJECT_TYPE {
	LIST_ENTRY TypeList;
	UNICODE_STRING Name;
	PVOID DefaultObject;
	UCHAR Index;
	ULONG TotalNumberOfObjects;
	ULONG TotalNumberOfHandles;
	ULONG HighWaterNumberOfObjects;
	ULONG HighWaterNumberOfHandles;
	OBJECT_TYPE_INITIALIZER TypeInfo;
	EX_PUSH_LOCK TypeLock;
	ULONG Key;
	LIST_ENTRY CallbackList;
} OBJECT_TYPE, * POBJECT_TYPE;


// ���� _OBJECT_CREATE_INFORMATION �ṹ�壬����������Ķ�������
typedef struct _OBJECT_CREATE_INFORMATION {
	ULONG Attributes;                    // +0x000 Attributes
	PVOID RootDirectory;                 // +0x008 RootDirectory
	CHAR ProbeMode;                      // +0x010 ProbeMode
	ULONG PagedPoolCharge;               // +0x014 PagedPoolCharge
	ULONG NonPagedPoolCharge;            // +0x018 NonPagedPoolCharge
	ULONG SecurityDescriptorCharge;      // +0x01c SecurityDescriptorCharge
	PVOID SecurityDescriptor;            // +0x020 SecurityDescriptor
	PSECURITY_QUALITY_OF_SERVICE SecurityQos; // +0x028 SecurityQos
	SECURITY_QUALITY_OF_SERVICE SecurityQualityOfService; // +0x030 SecurityQualityOfService
} OBJECT_CREATE_INFORMATION,*POBJECT_CREATE_INFORMATION;

typedef struct _OBJECT_HEADER {
	ULONG64 PointerCount;              // +0x000 PointerCount
	ULONG64 HandleCount;               // +0x008 HandleCount
	PVOID NextToFree;                 // +0x010 NextToFree
	EX_PUSH_LOCK Lock;                // +0x018 Lock
	UCHAR TypeIndex;                  // +0x018 TypeIndex
	UCHAR TraceFlags;                 // +0x019 TraceFlags
	struct {
		UCHAR DbgRefTrace : 1;        // +0x019 DbgRefTrace (1 bit)
		UCHAR DbgTracePermanent : 1; // +0x019 DbgTracePermanent (1 bit)
	} DbgFlags;
	UCHAR InfoMask;                  // +0x01a InfoMask
	UCHAR Flags;                     // +0x01b Flags
	struct {
		UCHAR NewObject : 1;        // +0x01b NewObject (1 bit)
		UCHAR KernelObject : 1;     // +0x01b KernelObject (1 bit)
		UCHAR KernelOnlyAccess : 1; // +0x01b KernelOnlyAccess (1 bit)
		UCHAR ExclusiveObject : 1;  // +0x01b ExclusiveObject (1 bit)
		UCHAR PermanentObject : 1;  // +0x01b PermanentObject (1 bit)
		UCHAR DefaultSecurityQuota : 1; // +0x01b DefaultSecurityQuota (1 bit)
		UCHAR SingleHandleEntry : 1; // +0x01b SingleHandleEntry (1 bit)
		UCHAR DeletedInline : 1;    // +0x01b DeletedInline (1 bit)
	} ObjectFlags;
	ULONG Reserved;                // +0x01c Reserved
	OBJECT_CREATE_INFORMATION* ObjectCreateInfo; // +0x020 ObjectCreateInfo
	PVOID QuotaBlockCharged;          // +0x020 QuotaBlockCharged
	PVOID SecurityDescriptor;        // +0x028 SecurityDescriptor
	ULONG64 Body;                    // +0x030 Body
} OBJECT_HEADER,*POBJECT_HEADER;




