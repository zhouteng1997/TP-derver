#include <basetsd.h>
#include <iostream>
#include <string>
#include <windows.h>
//#include <winternl.h>

namespace NTDEFS
{

#define IN
#define OUT
#define OPTIONAL
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#define MAX_STACK_DEPTH 32
#define MAXIMUM_NUMA_NODES 16
#define STATUS_SUCCESS                   ((NTSTATUS)0x00000000L)    // ntsubauth

#define WINAPI __stdcall
	typedef unsigned long BOOL;

	typedef unsigned long ULONG;
	typedef unsigned int DWORD;
	typedef unsigned short WORD;
	typedef unsigned char UCHAR;
	typedef unsigned short USHORT;
	typedef long LONG;
	typedef LONG NTSTATUS;
	typedef void* PVOID;
	typedef ULONG* PULONG;
	typedef ULONG_PTR KAFFINITY;
	typedef char CCHAR;
	typedef void* HANDLE;
	typedef HANDLE HLOCAL;
	typedef HANDLE* LPHANDLE;
	typedef UCHAR* PUCHAR;
	typedef unsigned int UINT;
	typedef void* LPVOID;
	typedef SIZE_T SYSINF_PAGE_COUNT;
	typedef LONG KPRIORITY;
	typedef wchar_t WCHAR;
	typedef WCHAR* NWPSTR, * LPWSTR, * PWSTR;
	typedef char CHAR;
	typedef CHAR* PCHAR, * LPCH, * PCH;
	typedef DWORD ACCESS_MASK;

	typedef struct _UNICODE_STRING {
		USHORT Length;
		USHORT MaximumLength;
#ifdef MIDL_PASS
		[size_is(MaximumLength / 2), length_is((Length) / 2)] USHORT* Buffer;
#else // MIDL_PASS
		PWSTR  Buffer;
#endif // MIDL_PASS
	} UNICODE_STRING;
	typedef UNICODE_STRING* PUNICODE_STRING;

#if (!defined (_MAC) && (!defined(MIDL_PASS) || defined(__midl)) && (!defined(_M_IX86) || (defined(_INTEGRAL_MAX_BITS) && _INTEGRAL_MAX_BITS >= 64)))
	typedef __int64 LONGLONG;
	typedef unsigned __int64 ULONGLONG;
#define MAXLONGLONG                         (0x7fffffffffffffff)
#else
#if defined(_MAC) && defined(_MAC_INT_64)
	typedef __int64 LONGLONG;
	typedef unsigned __int64 ULONGLONG;
#define MAXLONGLONG                      (0x7fffffffffffffff)
#else
	typedef double LONGLONG;
	typedef double ULONGLONG;
#endif //_MAC and int64
#endif

#if defined(MIDL_PASS)
	typedef struct _LARGE_INTEGER
	{
#else // MIDL_PASS
	typedef union _LARGE_INTEGER
	{
		struct
		{
			DWORD LowPart;
			LONG HighPart;
		} DUMMYSTRUCTNAME;
		struct
		{
			DWORD LowPart;
			LONG HighPart;
		} u;
#endif //MIDL_PASS
		LONGLONG QuadPart;
	} LARGE_INTEGER;

	typedef unsigned char BYTE;
	typedef BYTE BOOLEAN;

#define FLG_STOP_ON_EXCEPTION           0x00000001      // user and kernel mode
#define FLG_SHOW_LDR_SNAPS              0x00000002      // user and kernel mode
#define FLG_DEBUG_INITIAL_COMMAND       0x00000004      // kernel mode only up until WINLOGON started
#define FLG_STOP_ON_HUNG_GUI            0x00000008      // kernel mode only while running

#define FLG_HEAP_ENABLE_TAIL_CHECK      0x00000010      // user mode only
#define FLG_HEAP_ENABLE_FREE_CHECK      0x00000020      // user mode only
#define FLG_HEAP_VALIDATE_PARAMETERS    0x00000040      // user mode only
#define FLG_HEAP_VALIDATE_ALL           0x00000080      // user mode only

#define FLG_APPLICATION_VERIFIER        0x00000100      // user mode only
#define FLG_POOL_ENABLE_TAGGING         0x00000400      // kernel mode only
#define FLG_HEAP_ENABLE_TAGGING         0x00000800      // user mode only

#define FLG_USER_STACK_TRACE_DB         0x00001000      // x86 user mode only
#define FLG_KERNEL_STACK_TRACE_DB       0x00002000      // x86 kernel mode only at boot time
#define FLG_MAINTAIN_OBJECT_TYPELIST    0x00004000      // kernel mode only at boot time
#define FLG_HEAP_ENABLE_TAG_BY_DLL      0x00008000      // user mode only

#define FLG_DISABLE_STACK_EXTENSION     0x00010000      // user mode only
#define FLG_ENABLE_CSRDEBUG             0x00020000      // kernel mode only at boot time
#define FLG_ENABLE_KDEBUG_SYMBOL_LOAD   0x00040000      // kernel mode only
#define FLG_DISABLE_PAGE_KERNEL_STACKS  0x00080000      // kernel mode only at boot time

#define FLG_ENABLE_SYSTEM_CRIT_BREAKS   0x00100000      // user mode only
#define FLG_HEAP_DISABLE_COALESCING     0x00200000      // user mode only
#define FLG_ENABLE_CLOSE_EXCEPTIONS     0x00400000      // kernel mode only
#define FLG_ENABLE_EXCEPTION_LOGGING    0x00800000      // kernel mode only

#define FLG_ENABLE_HANDLE_TYPE_TAGGING  0x01000000      // kernel mode only
#define FLG_HEAP_PAGE_ALLOCS            0x02000000      // user mode only
#define FLG_DEBUG_INITIAL_COMMAND_EX    0x04000000      // kernel mode only up until WINLOGON started
#define FLG_DISABLE_DBGPRINT            0x08000000      // kernel mode only

#define FLG_CRITSEC_EVENT_CREATION      0x10000000      // user mode only, Force early creation of resource events
#define FLG_LDR_TOP_DOWN                0x20000000      // user mode only, win64 only
#define FLG_ENABLE_HANDLE_EXCEPTIONS    0x40000000      // kernel mode only
#define FLG_DISABLE_PROTDLLS            0x80000000      // user mode only (smss/winlogon)

#define PROCESSOR_ARCHITECTURE_INTEL            0
#define PROCESSOR_ARCHITECTURE_MIPS             1
#define PROCESSOR_ARCHITECTURE_ALPHA            2
#define PROCESSOR_ARCHITECTURE_PPC              3
#define PROCESSOR_ARCHITECTURE_SHX              4
#define PROCESSOR_ARCHITECTURE_ARM              5
#define PROCESSOR_ARCHITECTURE_IA64             6
#define PROCESSOR_ARCHITECTURE_ALPHA64          7
#define PROCESSOR_ARCHITECTURE_MSIL             8
#define PROCESSOR_ARCHITECTURE_AMD64            9
#define PROCESSOR_ARCHITECTURE_IA32_ON_WIN64    10

#define STATUS_INFO_LENGTH_MISMATCH      ((NTSTATUS)0xC0000004L)
#define STATUS_INVALID_INFO_CLASS ((NTSTATUS)0xC0000003L) 
#define STATUS_ACCESS_VIOLATION ((DWORD )0xC0000005L)
#define STATUS_INSUFFICIENT_RESOURCES ((NTSTATUS)0xC000009AL) 
#define STATUS_WORKING_SET_QUOTA ((NTSTATUS)0xC00000A1L)
#define STATUS_NOT_IMPLEMENTED ((NTSTATUS)0xC0000002L)

	typedef enum _SYSTEM_INFORMATION_CLASS
	{
		SystemBasicInformation,
		SystemProcessorInformation,              // obsolete...delete
		SystemPerformanceInformation,
		SystemTimeOfDayInformation,
		SystemPathInformation,
		SystemProcessInformation,                //系统进程信息
		SystemCallCountInformation,
		SystemDeviceInformation,
		SystemProcessorPerformanceInformation,
		SystemFlagsInformation,
		SystemCallTimeInformation,
		SystemModuleInformation,     //系统模块
		SystemLocksInformation,
		SystemStackTraceInformation,
		SystemPagedPoolInformation,
		SystemNonPagedPoolInformation,
		SystemHandleInformation,
		SystemObjectInformation,
		SystemPageFileInformation,
		SystemVdmInstemulInformation,
		SystemVdmBopInformation,
		SystemFileCacheInformation,
		SystemPoolTagInformation,
		SystemInterruptInformation,
		SystemDpcBehaviorInformation,
		SystemFullMemoryInformation,
		SystemLoadGdiDriverInformation,
		SystemUnloadGdiDriverInformation,
		SystemTimeAdjustmentInformation,
		SystemSummaryMemoryInformation,
		SystemMirrorMemoryInformation,
		SystemPerformanceTraceInformation,
		SystemObsolete0,
		SystemExceptionInformation,
		SystemCrashDumpStateInformation,
		SystemKernelDebuggerInformation,
		SystemContextSwitchInformation,
		SystemRegistryQuotaInformation,
		SystemExtendServiceTableInformation,
		SystemPrioritySeperation,
		SystemVerifierAddDriverInformation,
		SystemVerifierRemoveDriverInformation,
		SystemProcessorIdleInformation,
		SystemLegacyDriverInformation,
		SystemCurrentTimeZoneInformation,
		SystemLookasideInformation,
		SystemTimeSlipNotification,
		SystemSessionCreate,
		SystemSessionDetach,
		SystemSessionInformation,
		SystemRangeStartInformation,
		SystemVerifierInformation,
		SystemVerifierThunkExtend,
		SystemSessionProcessInformation,
		SystemLoadGdiDriverInSystemSpace,
		SystemNumaProcessorMap,
		SystemPrefetcherInformation,
		SystemExtendedProcessInformation,
		SystemRecommendedSharedDataAlignment,
		SystemComPlusPackage,
		SystemNumaAvailableMemory,
		SystemProcessorPowerInformation,
		SystemEmulationBasicInformation,//=SystemBasicInformation
		SystemEmulationProcessorInformation,//=SystemProcessorInformation
		SystemExtendedHandleInformation,
		SystemLostDelayedWriteInformation,
		SystemBigPoolInformation,
		SystemSessionPoolTagInformation,
		SystemSessionMappedViewInformation,
		SystemHotpatchInformation,
		SystemObjectSecurityMode,
		SystemWatchdogTimerHandler,
		SystemWatchdogTimerInformation,
		SystemLogicalProcessorInformation,
		SystemWow64SharedInformation,
		SystemRegisterFirmwareTableInformationHandler,
		SystemFirmwareTableInformation,
		SystemModuleInformationEx,
		SystemVerifierTriageInformation,
		SystemSuperfetchInformation,
		SystemMemoryListInformation,
		SystemFileCacheInformationEx,

		//100?
		SystemPageMemoryInformation = 123,//自定义
		SystemPolicyInformation = 134,

	} SYSTEM_INFORMATION_CLASS, * PSYSTEM_INFORMATION_CLASS;

	typedef struct _SYSTEM_BASIC_INFORMATION
	{
		ULONG Reserved;
		ULONG TimerResolution;
		ULONG PageSize;
		SYSINF_PAGE_COUNT NumberOfPhysicalPages;
		SYSINF_PAGE_COUNT LowestPhysicalPageNumber;
		SYSINF_PAGE_COUNT HighestPhysicalPageNumber;
		ULONG AllocationGranularity;
		ULONG_PTR MinimumUserModeAddress;
		ULONG_PTR MaximumUserModeAddress;
		ULONG_PTR ActiveProcessorsAffinityMask;
		CCHAR NumberOfProcessors;
	} SYSTEM_BASIC_INFORMATION, * PSYSTEM_BASIC_INFORMATION;

	typedef struct _SYSTEM_PROCESSOR_INFORMATION
	{
		USHORT ProcessorArchitecture;
		USHORT ProcessorLevel;
		USHORT ProcessorRevision;
		USHORT Reserved;
		ULONG ProcessorFeatureBits;
	} SYSTEM_PROCESSOR_INFORMATION, * PSYSTEM_PROCESSOR_INFORMATION;

	typedef struct _SYSTEM_PERFORMANCE_INFORMATION
	{
		LARGE_INTEGER IdleProcessTime;
		LARGE_INTEGER IoReadTransferCount;
		LARGE_INTEGER IoWriteTransferCount;
		LARGE_INTEGER IoOtherTransferCount;
		ULONG IoReadOperationCount;
		ULONG IoWriteOperationCount;
		ULONG IoOtherOperationCount;
		ULONG AvailablePages;
		SYSINF_PAGE_COUNT CommittedPages;
		SYSINF_PAGE_COUNT CommitLimit;
		SYSINF_PAGE_COUNT PeakCommitment;
		ULONG PageFaultCount;
		ULONG CopyOnWriteCount;
		ULONG TransitionCount;
		ULONG CacheTransitionCount;
		ULONG DemandZeroCount;
		ULONG PageReadCount;
		ULONG PageReadIoCount;
		ULONG CacheReadCount;
		ULONG CacheIoCount;
		ULONG DirtyPagesWriteCount;
		ULONG DirtyWriteIoCount;
		ULONG MappedPagesWriteCount;
		ULONG MappedWriteIoCount;
		ULONG PagedPoolPages;
		ULONG NonPagedPoolPages;
		ULONG PagedPoolAllocs;
		ULONG PagedPoolFrees;
		ULONG NonPagedPoolAllocs;
		ULONG NonPagedPoolFrees;
		ULONG FreeSystemPtes;
		ULONG ResidentSystemCodePage;
		ULONG TotalSystemDriverPages;
		ULONG TotalSystemCodePages;
		ULONG NonPagedPoolLookasideHits;
		ULONG PagedPoolLookasideHits;
		ULONG AvailablePagedPoolPages;
		ULONG ResidentSystemCachePage;
		ULONG ResidentPagedPoolPage;
		ULONG ResidentSystemDriverPage;
		ULONG CcFastReadNoWait;
		ULONG CcFastReadWait;
		ULONG CcFastReadResourceMiss;
		ULONG CcFastReadNotPossible;
		ULONG CcFastMdlReadNoWait;
		ULONG CcFastMdlReadWait;
		ULONG CcFastMdlReadResourceMiss;
		ULONG CcFastMdlReadNotPossible;
		ULONG CcMapDataNoWait;
		ULONG CcMapDataWait;
		ULONG CcMapDataNoWaitMiss;
		ULONG CcMapDataWaitMiss;
		ULONG CcPinMappedDataCount;
		ULONG CcPinReadNoWait;
		ULONG CcPinReadWait;
		ULONG CcPinReadNoWaitMiss;
		ULONG CcPinReadWaitMiss;
		ULONG CcCopyReadNoWait;
		ULONG CcCopyReadWait;
		ULONG CcCopyReadNoWaitMiss;
		ULONG CcCopyReadWaitMiss;
		ULONG CcMdlReadNoWait;
		ULONG CcMdlReadWait;
		ULONG CcMdlReadNoWaitMiss;
		ULONG CcMdlReadWaitMiss;
		ULONG CcReadAheadIos;
		ULONG CcLazyWriteIos;
		ULONG CcLazyWritePages;
		ULONG CcDataFlushes;
		ULONG CcDataPages;
		ULONG ContextSwitches;
		ULONG FirstLevelTbFills;
		ULONG SecondLevelTbFills;
		ULONG SystemCalls;
	} SYSTEM_PERFORMANCE_INFORMATION, * PSYSTEM_PERFORMANCE_INFORMATION;

	typedef struct _SYSTEM_TIMEOFDAY_INFORMATION
	{
		LARGE_INTEGER BootTime;
		LARGE_INTEGER CurrentTime;
		LARGE_INTEGER TimeZoneBias;
		ULONG TimeZoneId;
		ULONG Reserved;
		ULONGLONG BootTimeBias;
		ULONGLONG SleepTimeBias;
	} SYSTEM_TIMEOFDAY_INFORMATION, * PSYSTEM_TIMEOFDAY_INFORMATION;

	typedef struct _SYSTEM_PROCESS_INFORMATION
	{
		ULONG NextEntryOffset;
		ULONG NumberOfThreads;
		LARGE_INTEGER SpareLi1;
		LARGE_INTEGER SpareLi2;
		LARGE_INTEGER SpareLi3;
		LARGE_INTEGER CreateTime;
		LARGE_INTEGER UserTime;
		LARGE_INTEGER KernelTime;
		UNICODE_STRING ImageName;
		KPRIORITY BasePriority;
		HANDLE UniqueProcessId;
		HANDLE InheritedFromUniqueProcessId;
		ULONG HandleCount;
		ULONG SessionId;
		ULONG_PTR PageDirectoryBase;
		SIZE_T PeakVirtualSize;
		SIZE_T VirtualSize;
		ULONG PageFaultCount;
		SIZE_T PeakWorkingSetSize;
		SIZE_T WorkingSetSize;
		SIZE_T QuotaPeakPagedPoolUsage;
		SIZE_T QuotaPagedPoolUsage;
		SIZE_T QuotaPeakNonPagedPoolUsage;
		SIZE_T QuotaNonPagedPoolUsage;
		SIZE_T PagefileUsage;
		SIZE_T PeakPagefileUsage;
		SIZE_T PrivatePageCount;
		LARGE_INTEGER ReadOperationCount;
		LARGE_INTEGER WriteOperationCount;
		LARGE_INTEGER OtherOperationCount;
		LARGE_INTEGER ReadTransferCount;
		LARGE_INTEGER WriteTransferCount;
		LARGE_INTEGER OtherTransferCount;
	} SYSTEM_PROCESS_INFORMATION, * PSYSTEM_PROCESS_INFORMATION;

	typedef struct _SYSTEM_CALL_COUNT_INFORMATION
	{
		ULONG Length;
		ULONG NumberOfTables;
	} SYSTEM_CALL_COUNT_INFORMATION, * PSYSTEM_CALL_COUNT_INFORMATION;

	typedef struct _SYSTEM_DEVICE_INFORMATION
	{
		ULONG NumberOfDisks;
		ULONG NumberOfFloppies;
		ULONG NumberOfCdRoms;
		ULONG NumberOfTapes;
		ULONG NumberOfSerialPorts;
		ULONG NumberOfParallelPorts;
	} SYSTEM_DEVICE_INFORMATION, * PSYSTEM_DEVICE_INFORMATION;

	typedef struct _SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION
	{
		LARGE_INTEGER IdleTime;
		LARGE_INTEGER KernelTime;
		LARGE_INTEGER UserTime;
		LARGE_INTEGER DpcTime;          // DEVL only
		LARGE_INTEGER InterruptTime;    // DEVL only
		ULONG InterruptCount;
	} SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION, * PSYSTEM_PROCESSOR_PERFORMANCE_INFORMATION;

	typedef struct _SYSTEM_FLAGS_INFORMATION
	{
		ULONG Flags;
	} SYSTEM_FLAGS_INFORMATION, * PSYSTEM_FLAGS_INFORMATION;

	typedef struct _RTL_PROCESS_MODULE_INFORMATION
	{
		HANDLE Section;                 // Not filled in
		PVOID MappedBase;
		PVOID ImageBase;
		ULONG ImageSize;
		ULONG Flags;
		USHORT LoadOrderIndex;
		USHORT InitOrderIndex;
		USHORT LoadCount;
		USHORT OffsetToFileName;
		UCHAR  FullPathName[256];
	} RTL_PROCESS_MODULE_INFORMATION, * PRTL_PROCESS_MODULE_INFORMATION;

	typedef struct _RTL_PROCESS_MODULES
	{
		ULONG NumberOfModules;
		RTL_PROCESS_MODULE_INFORMATION Modules[1];
	} RTL_PROCESS_MODULES, * PRTL_PROCESS_MODULES;

	typedef struct _RTL_PROCESS_LOCK_INFORMATION
	{
		PVOID Address;
		USHORT Type;
		USHORT CreatorBackTraceIndex;
		HANDLE OwningThread;        // from the thread's ClientId->UniqueThread
		LONG LockCount;
		ULONG ContentionCount;
		ULONG EntryCount;
		LONG RecursionCount;
		ULONG NumberOfWaitingShared;
		ULONG NumberOfWaitingExclusive;
	} RTL_PROCESS_LOCK_INFORMATION, * PRTL_PROCESS_LOCK_INFORMATION;

	typedef struct _RTL_PROCESS_LOCKS
	{
		ULONG NumberOfLocks;
		RTL_PROCESS_LOCK_INFORMATION Locks[1];
	} RTL_PROCESS_LOCKS, * PRTL_PROCESS_LOCKS;


	typedef struct _RTL_PROCESS_BACKTRACE_INFORMATION
	{
		PCHAR SymbolicBackTrace;        // Not filled in
		ULONG TraceCount;
		USHORT Index;
		USHORT Depth;
		PVOID BackTrace[MAX_STACK_DEPTH];
	} RTL_PROCESS_BACKTRACE_INFORMATION, * PRTL_PROCESS_BACKTRACE_INFORMATION;

	typedef struct _RTL_PROCESS_BACKTRACES
	{
		ULONG CommittedMemory;
		ULONG ReservedMemory;
		ULONG NumberOfBackTraceLookups;
		ULONG NumberOfBackTraces;
		RTL_PROCESS_BACKTRACE_INFORMATION BackTraces[1];
	} RTL_PROCESS_BACKTRACES, * PRTL_PROCESS_BACKTRACES;

	typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO
	{
		USHORT UniqueProcessId;
		USHORT CreatorBackTraceIndex;
		UCHAR ObjectTypeIndex;
		UCHAR HandleAttributes;
		USHORT HandleValue;
		PVOID Object;
		ULONG GrantedAccess;
	} SYSTEM_HANDLE_TABLE_ENTRY_INFO, * PSYSTEM_HANDLE_TABLE_ENTRY_INFO;

	typedef struct _SYSTEM_HANDLE_INFORMATION
	{
		ULONG NumberOfHandles;
		SYSTEM_HANDLE_TABLE_ENTRY_INFO Handles[1];
	} SYSTEM_HANDLE_INFORMATION, * PSYSTEM_HANDLE_INFORMATION;

	typedef struct _GENERIC_MAPPING
	{
		ACCESS_MASK GenericRead;
		ACCESS_MASK GenericWrite;
		ACCESS_MASK GenericExecute;
		ACCESS_MASK GenericAll;
	} GENERIC_MAPPING;
	typedef GENERIC_MAPPING* PGENERIC_MAPPING;

	typedef struct _SYSTEM_OBJECTTYPE_INFORMATION
	{
		ULONG NextEntryOffset;
		ULONG NumberOfObjects;
		ULONG NumberOfHandles;
		ULONG TypeIndex;
		ULONG InvalidAttributes;
		GENERIC_MAPPING GenericMapping;
		ULONG ValidAccessMask;
		ULONG PoolType;
		BOOLEAN SecurityRequired;
		BOOLEAN WaitableObject;
		UNICODE_STRING TypeName;
	} SYSTEM_OBJECTTYPE_INFORMATION, * PSYSTEM_OBJECTTYPE_INFORMATION;

	typedef struct _OBJECT_NAME_INFORMATION
	{
		UNICODE_STRING Name;
	} OBJECT_NAME_INFORMATION, * POBJECT_NAME_INFORMATION;

	typedef struct _SYSTEM_OBJECT_INFORMATION
	{
		ULONG NextEntryOffset;
		PVOID Object;
		HANDLE CreatorUniqueProcess;
		USHORT CreatorBackTraceIndex;
		USHORT Flags;
		LONG PointerCount;
		LONG HandleCount;
		ULONG PagedPoolCharge;
		ULONG NonPagedPoolCharge;
		HANDLE ExclusiveProcessId;
		PVOID SecurityDescriptor;
		OBJECT_NAME_INFORMATION NameInfo;
	} SYSTEM_OBJECT_INFORMATION, * PSYSTEM_OBJECT_INFORMATION;

	typedef struct _SYSTEM_PAGEFILE_INFORMATION
	{
		ULONG NextEntryOffset;
		ULONG TotalSize;
		ULONG TotalInUse;
		ULONG PeakUsage;
		UNICODE_STRING PageFileName;
	} SYSTEM_PAGEFILE_INFORMATION, * PSYSTEM_PAGEFILE_INFORMATION;

	typedef struct _SYSTEM_VDM_INSTEMUL_INFO
	{
		ULONG SegmentNotPresent;
		ULONG VdmOpcode0F;
		ULONG OpcodeESPrefix;
		ULONG OpcodeCSPrefix;
		ULONG OpcodeSSPrefix;
		ULONG OpcodeDSPrefix;
		ULONG OpcodeFSPrefix;
		ULONG OpcodeGSPrefix;
		ULONG OpcodeOPER32Prefix;
		ULONG OpcodeADDR32Prefix;
		ULONG OpcodeINSB;
		ULONG OpcodeINSW;
		ULONG OpcodeOUTSB;
		ULONG OpcodeOUTSW;
		ULONG OpcodePUSHF;
		ULONG OpcodePOPF;
		ULONG OpcodeINTnn;
		ULONG OpcodeINTO;
		ULONG OpcodeIRET;
		ULONG OpcodeINBimm;
		ULONG OpcodeINWimm;
		ULONG OpcodeOUTBimm;
		ULONG OpcodeOUTWimm;
		ULONG OpcodeINB;
		ULONG OpcodeINW;
		ULONG OpcodeOUTB;
		ULONG OpcodeOUTW;
		ULONG OpcodeLOCKPrefix;
		ULONG OpcodeREPNEPrefix;
		ULONG OpcodeREPPrefix;
		ULONG OpcodeHLT;
		ULONG OpcodeCLI;
		ULONG OpcodeSTI;
		ULONG BopCount;
	} SYSTEM_VDM_INSTEMUL_INFO, * PSYSTEM_VDM_INSTEMUL_INFO;

	typedef struct _SYSTEM_FILECACHE_INFORMATION
	{
		SIZE_T CurrentSize;
		SIZE_T PeakSize;
		ULONG PageFaultCount;
		SIZE_T MinimumWorkingSet;
		SIZE_T MaximumWorkingSet;
		SIZE_T CurrentSizeIncludingTransitionInPages;
		SIZE_T PeakSizeIncludingTransitionInPages;
		ULONG TransitionRePurposeCount;
		ULONG Flags;
	} SYSTEM_FILECACHE_INFORMATION, * PSYSTEM_FILECACHE_INFORMATION;

	typedef struct _SYSTEM_POOLTAG
	{
		union
		{
			UCHAR Tag[4];
			ULONG TagUlong;
		};
		ULONG PagedAllocs;
		ULONG PagedFrees;
		SIZE_T PagedUsed;
		ULONG NonPagedAllocs;
		ULONG NonPagedFrees;
		SIZE_T NonPagedUsed;
	} SYSTEM_POOLTAG, * PSYSTEM_POOLTAG;

	typedef struct _SYSTEM_POOLTAG_INFORMATION
	{
		ULONG Count;
		SYSTEM_POOLTAG TagInfo[1];
	} SYSTEM_POOLTAG_INFORMATION, * PSYSTEM_POOLTAG_INFORMATION;

	typedef struct _SYSTEM_INTERRUPT_INFORMATION
	{
		ULONG ContextSwitches;
		ULONG DpcCount;
		ULONG DpcRate;
		ULONG TimeIncrement;
		ULONG DpcBypassCount;
		ULONG ApcBypassCount;
	} SYSTEM_INTERRUPT_INFORMATION, * PSYSTEM_INTERRUPT_INFORMATION;

	typedef struct _SYSTEM_DPC_BEHAVIOR_INFORMATION
	{
		ULONG Spare;
		ULONG DpcQueueDepth;
		ULONG MinimumDpcRate;
		ULONG AdjustDpcThreshold;
		ULONG IdealDpcRate;
	} SYSTEM_DPC_BEHAVIOR_INFORMATION, * PSYSTEM_DPC_BEHAVIOR_INFORMATION;

	typedef struct _SYSTEM_MEMORY_INFO
	{
		PUCHAR StringOffset;
		USHORT ValidCount;
		USHORT TransitionCount;
		USHORT ModifiedCount;
		USHORT PageTableCount;
	} SYSTEM_MEMORY_INFO, * PSYSTEM_MEMORY_INFO;

	typedef struct _SYSTEM_MEMORY_INFORMATION
	{
		ULONG InfoSize;
		ULONG_PTR StringStart;
		SYSTEM_MEMORY_INFO Memory[1];
	} SYSTEM_MEMORY_INFORMATION, * PSYSTEM_MEMORY_INFORMATION;

	typedef struct _IMAGE_EXPORT_DIRECTORY
	{
		DWORD   Characteristics;
		DWORD   TimeDateStamp;
		WORD    MajorVersion;
		WORD    MinorVersion;
		DWORD   Name;
		DWORD   Base;
		DWORD   NumberOfFunctions;
		DWORD   NumberOfNames;
		DWORD   AddressOfFunctions;     // RVA from base of image
		DWORD   AddressOfNames;         // RVA from base of image
		DWORD   AddressOfNameOrdinals;  // RVA from base of image
	} IMAGE_EXPORT_DIRECTORY, * PIMAGE_EXPORT_DIRECTORY;

	typedef struct _SYSTEM_GDI_DRIVER_INFORMATION
	{
		UNICODE_STRING DriverName;
		PVOID ImageAddress;
		PVOID SectionPointer;
		PVOID EntryPoint;
		PIMAGE_EXPORT_DIRECTORY ExportSectionPointer;
		ULONG ImageLength;
	} SYSTEM_GDI_DRIVER_INFORMATION, * PSYSTEM_GDI_DRIVER_INFORMATION;

	typedef struct _SYSTEM_SET_TIME_ADJUST_INFORMATION
	{
		ULONG TimeAdjustment;
		BOOLEAN Enable;
	} SYSTEM_SET_TIME_ADJUST_INFORMATION, * PSYSTEM_SET_TIME_ADJUST_INFORMATION;

	typedef struct _KSERVICE_TABLE_DESCRIPTOR
	{
		PULONG_PTR Base;
		PULONG Count;
		ULONG Limit;
		PUCHAR Number;
	} KSERVICE_TABLE_DESCRIPTOR, * PKSERVICE_TABLE_DESCRIPTOR;

	typedef struct _CLIENT_ID
	{
		HANDLE UniqueProcess;
		HANDLE UniqueThread;
	} CLIENT_ID;
	typedef CLIENT_ID* PCLIENT_ID;

	typedef struct _SYSTEM_THREAD_INFORMATION
	{
		LARGE_INTEGER KernelTime;
		LARGE_INTEGER UserTime;
		LARGE_INTEGER CreateTime;
		ULONG WaitTime;
		PVOID StartAddress;
		CLIENT_ID ClientId;
		KPRIORITY Priority;
		LONG BasePriority;
		ULONG ContextSwitches;
		ULONG ThreadState;
		ULONG WaitReason;
	} SYSTEM_THREAD_INFORMATION, * PSYSTEM_THREAD_INFORMATION;

	typedef struct _SYSTEM_EXTENDED_THREAD_INFORMATION
	{
		SYSTEM_THREAD_INFORMATION ThreadInfo;
		PVOID StackBase;
		PVOID StackLimit;
		PVOID Win32StartAddress;
		ULONG_PTR Reserved1;
		ULONG_PTR Reserved2;
		ULONG_PTR Reserved3;
		ULONG_PTR Reserved4;
	} SYSTEM_EXTENDED_THREAD_INFORMATION, * PSYSTEM_EXTENDED_THREAD_INFORMATION;

	typedef struct _SYSTEM_EXCEPTION_INFORMATION
	{
		ULONG AlignmentFixupCount;
		ULONG ExceptionDispatchCount;
		ULONG FloatingEmulationCount;
		ULONG ByteWordEmulationCount;
	} SYSTEM_EXCEPTION_INFORMATION, * PSYSTEM_EXCEPTION_INFORMATION;

	typedef struct _SYSTEM_KERNEL_DEBUGGER_INFORMATION
	{
		BOOLEAN KernelDebuggerEnabled;
		BOOLEAN KernelDebuggerNotPresent;
	} SYSTEM_KERNEL_DEBUGGER_INFORMATION, * PSYSTEM_KERNEL_DEBUGGER_INFORMATION;

	typedef struct _SYSTEM_CONTEXT_SWITCH_INFORMATION
	{
		ULONG ContextSwitches;
		ULONG FindAny;
		ULONG FindLast;
		ULONG FindIdeal;
		ULONG IdleAny;
		ULONG IdleCurrent;
		ULONG IdleLast;
		ULONG IdleIdeal;
		ULONG PreemptAny;
		ULONG PreemptCurrent;
		ULONG PreemptLast;
		ULONG SwitchToIdle;
	} SYSTEM_CONTEXT_SWITCH_INFORMATION, * PSYSTEM_CONTEXT_SWITCH_INFORMATION;

	typedef struct _SYSTEM_REGISTRY_QUOTA_INFORMATION
	{
		ULONG  RegistryQuotaAllowed;
		ULONG  RegistryQuotaUsed;
		SIZE_T PagedPoolSize;
	} SYSTEM_REGISTRY_QUOTA_INFORMATION, * PSYSTEM_REGISTRY_QUOTA_INFORMATION;

	typedef struct _SYSTEM_PROCESSOR_IDLE_INFORMATION
	{
		ULONGLONG IdleTime;
		ULONGLONG C1Time;
		ULONGLONG C2Time;
		ULONGLONG C3Time;
		ULONG     C1Transitions;
		ULONG     C2Transitions;
		ULONG     C3Transitions;
		ULONG     Padding;
	} SYSTEM_PROCESSOR_IDLE_INFORMATION, * PSYSTEM_PROCESSOR_IDLE_INFORMATION;

	typedef struct _SYSTEM_LEGACY_DRIVER_INFORMATION
	{
		ULONG VetoType;
		UNICODE_STRING VetoList;
	} SYSTEM_LEGACY_DRIVER_INFORMATION, * PSYSTEM_LEGACY_DRIVER_INFORMATION;

	typedef short CSHORT;

	typedef struct _TIME_FIELDS
	{
		CSHORT Year;        // range [1601...]
		CSHORT Month;       // range [1..12]
		CSHORT Day;         // range [1..31]
		CSHORT Hour;        // range [0..23]
		CSHORT Minute;      // range [0..59]
		CSHORT Second;      // range [0..59]
		CSHORT Milliseconds;// range [0..999]
		CSHORT Weekday;     // range [0..6] == [Sunday..Saturday]
	} TIME_FIELDS;

	typedef struct _RTL_TIME_ZONE_INFORMATION
	{
		LONG Bias;
		WCHAR StandardName[32];
		TIME_FIELDS StandardStart;
		LONG StandardBias;
		WCHAR DaylightName[32];
		TIME_FIELDS DaylightStart;
		LONG DaylightBias;
	} RTL_TIME_ZONE_INFORMATION, * PRTL_TIME_ZONE_INFORMATION;

	typedef struct _SYSTEM_LOOKASIDE_INFORMATION
	{
		USHORT CurrentDepth;
		USHORT MaximumDepth;
		ULONG TotalAllocates;
		ULONG AllocateMisses;
		ULONG TotalFrees;
		ULONG FreeMisses;
		ULONG Type;
		ULONG Tag;
		ULONG Size;
	} SYSTEM_LOOKASIDE_INFORMATION, * PSYSTEM_LOOKASIDE_INFORMATION;

	typedef struct _SYSTEM_VERIFIER_INFORMATION
	{
		ULONG NextEntryOffset;
		ULONG Level;
		UNICODE_STRING DriverName;
		ULONG RaiseIrqls;
		ULONG AcquireSpinLocks;
		ULONG SynchronizeExecutions;
		ULONG AllocationsAttempted;
		ULONG AllocationsSucceeded;
		ULONG AllocationsSucceededSpecialPool;
		ULONG AllocationsWithNoTag;
		ULONG TrimRequests;
		ULONG Trims;
		ULONG AllocationsFailed;
		ULONG AllocationsFailedDeliberately;
		ULONG Loads;
		ULONG Unloads;
		ULONG UnTrackedPool;
		ULONG CurrentPagedPoolAllocations;
		ULONG CurrentNonPagedPoolAllocations;
		ULONG PeakPagedPoolAllocations;
		ULONG PeakNonPagedPoolAllocations;
		SIZE_T PagedPoolUsageInBytes;
		SIZE_T NonPagedPoolUsageInBytes;
		SIZE_T PeakPagedPoolUsageInBytes;
		SIZE_T PeakNonPagedPoolUsageInBytes;
	} SYSTEM_VERIFIER_INFORMATION, * PSYSTEM_VERIFIER_INFORMATION;

	typedef struct _SYSTEM_SESSION_PROCESS_INFORMATION
	{
		ULONG SessionId;
		ULONG SizeOfBuf;
		PVOID Buffer;
	} SYSTEM_SESSION_PROCESS_INFORMATION, * PSYSTEM_SESSION_PROCESS_INFORMATION;

	typedef struct _SYSTEM_SESSION_POOLTAG_INFORMATION
	{
		SIZE_T NextEntryOffset;
		ULONG SessionId;
		ULONG Count;
		SYSTEM_POOLTAG TagInfo[1];
	} SYSTEM_SESSION_POOLTAG_INFORMATION, * PSYSTEM_SESSION_POOLTAG_INFORMATION;

	typedef struct _SYSTEM_NUMA_INFORMATION
	{
		ULONG       HighestNodeNumber;
		ULONG       Reserved;
		union
		{
			ULONGLONG   ActiveProcessorsAffinityMask[MAXIMUM_NUMA_NODES];
			ULONGLONG   AvailableMemory[MAXIMUM_NUMA_NODES];
		};
	} SYSTEM_NUMA_INFORMATION, * PSYSTEM_NUMA_INFORMATION;

	typedef struct _SYSTEM_PROCESSOR_POWER_INFORMATION
	{
		UCHAR       CurrentFrequency;
		UCHAR       ThermalLimitFrequency;
		UCHAR       ConstantThrottleFrequency;
		UCHAR       DegradedThrottleFrequency;
		UCHAR       LastBusyFrequency;
		UCHAR       LastC3Frequency;
		UCHAR       LastAdjustedBusyFrequency;
		UCHAR       ProcessorMinThrottle;
		UCHAR       ProcessorMaxThrottle;
		ULONG       NumberOfFrequencies;
		ULONG       PromotionCount;
		ULONG       DemotionCount;
		ULONG       ErrorCount;
		ULONG       RetryCount;
		ULONGLONG   CurrentFrequencyTime;
		ULONGLONG   CurrentProcessorTime;
		ULONGLONG   CurrentProcessorIdleTime;
		ULONGLONG   LastProcessorTime;
		ULONGLONG   LastProcessorIdleTime;
	} SYSTEM_PROCESSOR_POWER_INFORMATION, * PSYSTEM_PROCESSOR_POWER_INFORMATION;

	typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX
	{
		PVOID Object;
		ULONG_PTR UniqueProcessId;
		ULONG_PTR HandleValue;
		ULONG GrantedAccess;
		USHORT CreatorBackTraceIndex;
		USHORT ObjectTypeIndex;
		ULONG  HandleAttributes;
		ULONG  Reserved;
	} SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX, * PSYSTEM_HANDLE_TABLE_ENTRY_INFO_EX;

	typedef struct _SYSTEM_HANDLE_INFORMATION_EX
	{
		ULONG_PTR NumberOfHandles;
		ULONG_PTR Reserved;
		SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX Handles[1];
	} SYSTEM_HANDLE_INFORMATION_EX, * PSYSTEM_HANDLE_INFORMATION_EX;

	typedef struct _SYSTEM_BIGPOOL_ENTRY
	{
		union
		{
			PVOID VirtualAddress;
			ULONG_PTR NonPaged : 1;     // Set to 1 if entry is nonpaged.
		};
		SIZE_T SizeInBytes;
		union
		{
			UCHAR Tag[4];
			ULONG TagUlong;
		};
	} SYSTEM_BIGPOOL_ENTRY, * PSYSTEM_BIGPOOL_ENTRY;

	typedef struct _SYSTEM_BIGPOOL_INFORMATION
	{
		ULONG Count;
		SYSTEM_BIGPOOL_ENTRY AllocatedInfo[1];
	} SYSTEM_BIGPOOL_INFORMATION, * PSYSTEM_BIGPOOL_INFORMATION;

	typedef struct _SYSTEM_SESSION_MAPPED_VIEW_INFORMATION
	{
		SIZE_T NextEntryOffset;
		ULONG SessionId;
		ULONG ViewFailures;
		SIZE_T NumberOfBytesAvailable;
		SIZE_T NumberOfBytesAvailableContiguous;
	} SYSTEM_SESSION_MAPPED_VIEW_INFORMATION, * PSYSTEM_SESSION_MAPPED_VIEW_INFORMATION;

	typedef enum _WATCHDOG_HANDLER_ACTION
	{
		WdActionSetTimeoutValue,
		WdActionQueryTimeoutValue,
		WdActionResetTimer,
		WdActionStopTimer,
		WdActionStartTimer,
		WdActionSetTriggerAction,
		WdActionQueryTriggerAction,
		WdActionQueryState
	} WATCHDOG_HANDLER_ACTION;

	typedef enum _WATCHDOG_INFORMATION_CLASS
	{
		WdInfoTimeoutValue,
		WdInfoResetTimer,
		WdInfoStopTimer,
		WdInfoStartTimer,
		WdInfoTriggerAction,
		WdInfoState
	} WATCHDOG_INFORMATION_CLASS;

	typedef NTSTATUS(*PWD_HANDLER)(IN WATCHDOG_HANDLER_ACTION Action, IN PVOID Context, IN OUT PULONG DataValue, IN BOOLEAN NoLocks);

	typedef struct _SYSTEM_WATCHDOG_HANDLER_INFORMATION
	{
		PWD_HANDLER WdHandler;
		PVOID       Context;
	} SYSTEM_WATCHDOG_HANDLER_INFORMATION, * PSYSTEM_WATCHDOG_HANDLER_INFORMATION;

	typedef struct _SYSTEM_WATCHDOG_TIMER_INFORMATION
	{
		WATCHDOG_INFORMATION_CLASS  WdInfoClass;
		ULONG                       DataValue;
	} SYSTEM_WATCHDOG_TIMER_INFORMATION, * PSYSTEM_WATCHDOG_TIMER_INFORMATION;

	typedef enum _LOGICAL_PROCESSOR_RELATIONSHIP
	{
		RelationProcessorCore,
		RelationNumaNode,
		RelationCache,
		RelationProcessorPackage,
		RelationGroup,
		RelationAll = 0xffff
	} LOGICAL_PROCESSOR_RELATIONSHIP;

	typedef enum _PROCESSOR_CACHE_TYPE
	{
		CacheUnified,
		CacheInstruction,
		CacheData,
		CacheTrace
	} PROCESSOR_CACHE_TYPE;

	typedef struct _CACHE_DESCRIPTOR
	{
		BYTE   Level;
		BYTE   Associativity;
		WORD   LineSize;
		DWORD  Size;
		PROCESSOR_CACHE_TYPE Type;
	} CACHE_DESCRIPTOR, * PCACHE_DESCRIPTOR;

	typedef struct _SYSTEM_LOGICAL_PROCESSOR_INFORMATION
	{
		ULONG_PTR   ProcessorMask;
		LOGICAL_PROCESSOR_RELATIONSHIP Relationship;
		union
		{
			struct
			{
				BYTE  Flags;
			} ProcessorCore;
			struct
			{
				DWORD NodeNumber;
			} NumaNode;
			CACHE_DESCRIPTOR Cache;
			ULONGLONG  Reserved[2];
		} DUMMYUNIONNAME;
	} SYSTEM_LOGICAL_PROCESSOR_INFORMATION, * PSYSTEM_LOGICAL_PROCESSOR_INFORMATION;

	typedef enum _SYSTEM_FIRMWARE_TABLE_ACTION
	{
		SystemFirmwareTable_Enumerate,
		SystemFirmwareTable_Get
	} SYSTEM_FIRMWARE_TABLE_ACTION;

#ifndef ANYSIZE_ARRAY
#define ANYSIZE_ARRAY 1       // winnt
#endif

	typedef struct _SYSTEM_FIRMWARE_TABLE_INFORMATION
	{
		ULONG                           ProviderSignature;
		SYSTEM_FIRMWARE_TABLE_ACTION    Action;
		ULONG                           TableID;
		ULONG                           TableBufferLength;
		UCHAR                           TableBuffer[ANYSIZE_ARRAY];
	} SYSTEM_FIRMWARE_TABLE_INFORMATION, * PSYSTEM_FIRMWARE_TABLE_INFORMATION;

	typedef NTSTATUS(__cdecl* PFNFTH)(PSYSTEM_FIRMWARE_TABLE_INFORMATION);

	typedef struct _SYSTEM_FIRMWARE_TABLE_HANDLER
	{
		ULONG       ProviderSignature;
		BOOLEAN     Register;
		PFNFTH      FirmwareTableHandler;
		PVOID       DriverObject;
	} SYSTEM_FIRMWARE_TABLE_HANDLER, * PSYSTEM_FIRMWARE_TABLE_HANDLER;


	//extern "C"	BOOL WINAPI DuplicateHandle(
	//	_In_   HANDLE hSourceProcessHandle,
	//	_In_   HANDLE hSourceHandle,
	//	_In_   HANDLE hTargetProcessHandle,
	//	_Out_  LPHANDLE lpTargetHandle,
	//	_In_   DWORD dwDesiredAccess,
	//	_In_   BOOL bInheritHandle,
	//	_In_   DWORD dwOptions
	//);

	typedef enum _OBJECT_INFORMATION_CLASS {
		ObjectBasicInformation,
		ObjectNameInformation,
		ObjectTypeInformation,
		ObjectAllInformation,
		ObjectDataInformation,
	} OBJECT_INFORMATION_CLASS;

	//typedef struct _OBJECT_NAME_INFORMATION
	//{
	//	UNICODE_STRING ObjectName;
	//}OBJECT_NAME_INFORMATION;

	extern "C"		NTSTATUS WINAPI NtQueryObject(
		_In_opt_   HANDLE Handle,
		_In_       OBJECT_INFORMATION_CLASS ObjectInformationClass,
		_Out_opt_  PVOID ObjectInformation,
		_In_       ULONG ObjectInformationLength,
		_Out_opt_  PULONG ReturnLength
	);

}

extern "C"
{
	NTDEFS::KSERVICE_TABLE_DESCRIPTOR* KeServiceDescriptorTableShadow;
	NTSTATUS __stdcall NtQuerySystemInformation(IN NTDEFS::SYSTEM_INFORMATION_CLASS SystemInformationClass, OUT PVOID SystemInformation, IN ULONG SystemInformationLength, OUT PULONG ReturnLength OPTIONAL);
	HLOCAL __stdcall LocalAlloc(IN UINT uFlags, SIZE_T uBytes);
	LPVOID __stdcall LocalLock(IN HLOCAL hMem);
	HLOCAL __stdcall LocalFree(IN HLOCAL hMem);
}


extern "C" NTSTATUS NTAPI NtQueryInformationProcess(
	IN HANDLE ProcessHandle, // 进程句柄
	IN UINT InformationClass, // 信息类型
	OUT PVOID ProcessInformation, // 缓冲指针
	IN ULONG ProcessInformationLength, // 以字节为单位的缓冲大小
	OUT PULONG ReturnLength OPTIONAL // 写入缓冲的字节数
);


typedef PVOID PPEB;
typedef struct _PROCESS_BASIC_INFORMATION {
	PVOID Reserved1;
	PPEB PebBaseAddress;
	PVOID Reserved2[2];
	ULONG_PTR UniqueProcessId;
	PVOID Reserved3;
} PROCESS_BASIC_INFORMATION;
