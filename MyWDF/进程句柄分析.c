#pragma once
#include <ntifs.h>


//ProtectProcessHandleByEprocess(eprocess);  //这是开始位置

#define WIN10_21H1_X64_OBJECTTABLE_OFFSET 0x570
#define WIN10_21H1_X64_HANDLETABLELIST_OFFSET 0x18
#define WIN10_21H1_X64_TABLECODE_OFFSET 0x8
#define WIN10_21H1_X64_QUOTOPROCESS_OFFSET 0x10
#define TABLE_LEVEL_MASK 3
#define TABLE_LEVEL_ZERO 0
#define TABLE_LEVEL_ONE 1
#define TABLE_LEVEL_TWO 2
#define PAGE_HANDLE_MAX 256
#define EPROCESS_IMAGE_OFFSET 0x5A8
#define HANDLE_BODY_OFFSET 0x30
#define TYPE_INDEX_OFFSET 0x18
#define TABLE_CODE_MASK 0xFFFFFFFFFFFFFFF8
#define POOL_TAG 'axe'

// GrantedAccessBits
#define PROCESS_VM_READ (0x0010)
#define PROCESS_VM_WRITE (0x0020)

/**
 * 下面两个值是通过调试系统得到的
 *  OB_HEADER_COOKIE可以使用`db nt!ObHeaderCookie l1`得到
 *  PROCESS_TYPE通过计算得到当前系统的PROCESS的type index值为7
 * */
#define OB_HEADER_COOKIE 0x21
#define PROCESS_TYPE 7

#define kprintf(...) \
    KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, __VA_ARGS__))

typedef struct HANDLE_TABLE_ENTRY
{
    UINT64 LowValue;
    UINT32 GrantedAccessBits;
    UINT32 Spare2;
} *PHANDLE_TABLE_ENTRY, HANDLE_TABLE_ENTRY;

/// @brief 存放每个进程的信息
typedef struct PROCESS_HANDLE_OBJECT
{
    PEPROCESS           eprocess;
    PHANDLE_TABLE_ENTRY table_code;
} *PPROCESS_HANDLE_OBJECT, PROCESS_HANDLE_OBJECT;

VOID DisplayProcessHandleObj(PPROCESS_HANDLE_OBJECT pHandleObj)
{
    kprintf("[+] eprocess: %p; table_code: %p; image_name: %15s\r\n",
        pHandleObj->eprocess,
        pHandleObj->table_code,
        (PUCHAR)(pHandleObj->eprocess) + EPROCESS_IMAGE_OFFSET);
}

/// @brief
/// 检查一个PHANDLE_TABLE_ENTRY中的数值是否合法，LowValue是否为0，合法返回TRUE，否则返回FALSE
/// @param pHandleTableEntry PHANDLE_TABLE_ENTRY指针
/// @return 合法返回TRUE，否则返回FALSE
BOOLEAN CheckHandleTableEntry(PHANDLE_TABLE_ENTRY pHandleTableEntry)
{
    if (!pHandleTableEntry->LowValue) {
        return FALSE;
    }

    return TRUE;
}

/// @brief
/// 新建一个PROCESS_HANDLE_OBJECT结构体。传入eprocess地址或者handle_table地址，二者至少其一
/// 创建成功返回结构体指针，失败则返回NULL
/// @param pEprocess eprocess地址或者NULL
/// @param pHandleTable _handle_table地址或者NULL
/// @return 创建成功返回结构体指针，失败则返回NULL
PPROCESS_HANDLE_OBJECT NewProcessHandleObject(PEPROCESS pEprocess,
    PVOID64   pHandleTable)
{
    UINT64                 uTableCode;
    PPROCESS_HANDLE_OBJECT ptr;

    if (pEprocess == NULL && pHandleTable == NULL) {
        return NULL;
    }

    if (pEprocess == NULL) {
        pEprocess = *(PUINT64)((PUCHAR)pHandleTable +
            WIN10_21H1_X64_QUOTOPROCESS_OFFSET);
    }

    if (pHandleTable == NULL) {
        pHandleTable =
            *(PUINT64)((PUCHAR)pEprocess + WIN10_21H1_X64_OBJECTTABLE_OFFSET);
    }

    uTableCode =
        *(PUINT64)((PUINT8)pHandleTable + WIN10_21H1_X64_TABLECODE_OFFSET);
    ptr = ExAllocatePool(NonPagedPool, sizeof(PROCESS_HANDLE_OBJECT));
    if (ptr == NULL) {
        kprintf("[!] Alloc struct PROCESS_HANDLE_OBJECT faild\r\n");
        return NULL;
    }

    ptr->eprocess = pEprocess;
    ptr->table_code = uTableCode;
}

/// @brief 销毁PROCESS_HANDLE_OBJECT结构体，传入一个对应指针
/// @param pProcessHandlePbject PROCESS_HANDLE_OBJECT的指针
/// @return
VOID FreeProcessHandleObject(PPROCESS_HANDLE_OBJECT pProcessHandlePbject)
{
    pProcessHandlePbject->eprocess = NULL;
    pProcessHandlePbject->table_code = 0;

    ExFreePool(pProcessHandlePbject);
}

/// @brief 传入一个HANDLE_TABLE_ENTRY结构体的地址，计算出ObjectHeader地址
/// @param addr HANDLE_TABLE_ENTRY结构体的地址
/// @return 返回ObjectHeader地址
ULONG64 HandleEntryTable2ObjectHeader(PHANDLE_TABLE_ENTRY addr)
{
    return ((addr->LowValue >> 0x10) & 0xFFFFFFFFFFFFFFF0) + 0xFFFF000000000000;
}

/// @brief 传入一个ObjectHeader地址，判断是否是进程对象，如果是则返回TRUE,
/// 不是则返回FALSE
/// @param Address 句柄头的地址，也就是_object_header结构体地址
/// @return 如果是则返回TRUE, 不是则返回FALSE
BOOLEAN IsProcess(PVOID64 Address)
{
    UINT8 uTypeIndex;
    UINT8 uByte;

    uByte = ((ULONG64)Address >> 8) & 0xff;
    uTypeIndex = *(PCHAR)((PCHAR)Address + TYPE_INDEX_OFFSET);
    uTypeIndex = uTypeIndex ^ OB_HEADER_COOKIE ^ uByte;

    if (uTypeIndex == PROCESS_TYPE) {
        return TRUE;
    }

    return FALSE;
}

/// @brief 匹配进程的imageName,如果和指定的ImageName相同则返回
/// @param Address _object_header的地址
/// @param Name 需要匹配的程序名称
/// @return 如果这个是进程句柄且是目标进程则返回TRUE，否则返回FALSE
BOOLEAN IsProcessName(PVOID64 Address, PUCHAR Name)
{
    PVOID64 pEprocess;
    PUCHAR  ImageName;

    if (!IsProcess(Address)) {
        return FALSE;
    }

    pEprocess = ((PCHAR)Address + HANDLE_BODY_OFFSET);
    ImageName = (PUCHAR)pEprocess + EPROCESS_IMAGE_OFFSET;

    if (strstr(ImageName, Name) == NULL) {
        return FALSE;
    }

    return TRUE;
}

/// @brief
/// 传入一个PLIST_ENTRY64，会遍历这个链表，每个链表节点会生成一个对应的PROCESS_HANDLE_OBJECT指针
/// 组成一个数组，存放指针，存放到ObjArr
/// @param pHandleList Handle_list链表
/// @param ObjArr PPROCESS_HANDLE_OBJECT* 指针
/// @return 返回一个指针数组，数组元素是PROCESS_HANDLE_OBJECT指针
NTSTATUS CreateProcessObjArrByHandleList(PLIST_ENTRY64            pHandleList,
    PPROCESS_HANDLE_OBJECT** ObjArr)
{
    PLIST_ENTRY64           pTmp;
    UINT64                  cout = 0;
    PPROCESS_HANDLE_OBJECT* pProcessObjArr;

    // 获取链表节点数量，用于申请内存块大小
    pTmp = pHandleList;
    do {
        pTmp = pTmp->Flink;
        cout += 1;
    } while (pTmp != pHandleList);
    pProcessObjArr = ExAllocatePoolZero(
        NonPagedPool, (cout + 1) * sizeof(PPROCESS_HANDLE_OBJECT), POOL_TAG);
    if (!pProcessObjArr) {
        kprintf("[!] Alloc process handle obj array failed\r\n");
        return STATUS_ALLOCATE_BUCKET;
    }

    // 遍历链表获取节点信息，并创建ProcessHandleObject结构体
    for (size_t i = 0; i < cout; i++) {
        pProcessObjArr[i] = NewProcessHandleObject(
            NULL, ((PUCHAR)pTmp - WIN10_21H1_X64_HANDLETABLELIST_OFFSET));
        pTmp = pTmp->Flink;
    }

    *ObjArr = pProcessObjArr;
    return STATUS_SUCCESS;
}

/// @brief 释放ProcessObject指针数组的内容
/// @param ObjArr PPROCESS_HANDLE_OBJECT数组
/// @return
VOID FreeProcessObjArr(PPROCESS_HANDLE_OBJECT* ObjArr)
{
    for (size_t i = 0; ObjArr[i] != 0; i++) {
        FreeProcessHandleObject(ObjArr[i]);
        ObjArr[i] = NULL;
    }

    // ExFreePoolWithTag(&ObjArr, POOL_TAG);
}

/// @brief 传入一个_object_header指针打印body是_eprocess的ImageName字符内容
/// @param ObjectHeader
/// @return
VOID ShowImageNameByObjectHeader(PVOID64 ObjectHeader)
{
    PVOID64 pEprocess;
    PUCHAR  ImageName;

    pEprocess = ((PUCHAR)ObjectHeader + HANDLE_BODY_OFFSET);
    ImageName = (PUCHAR)pEprocess + EPROCESS_IMAGE_OFFSET;

    kprintf("[+] ImageName: %15s\r\n", ImageName);
}

/// @brief 修改handle_entry_table的GrantedAccessBits权限，句柄的内存读写权限
/// @param pHandleTableEntry
/// @return
NTSTATUS ModfiyGrantedAccessBits(PHANDLE_TABLE_ENTRY pHandleTableEntry)
{
    pHandleTableEntry->GrantedAccessBits &=
        ~(PROCESS_VM_READ | PROCESS_VM_WRITE);
    return STATUS_SUCCESS;
}

/// @brief 针对单张句柄表的情况，匹配目标eprocess，如果匹配到则修改句柄权限
/// @param pEprocess 目标eprocess结构体指针
/// @param tablecode 单张句柄表的tablecode
/// @return
BOOLEAN FilterOneTableByEprocess(PEPROCESS pEprocess, UINT64 tablecode) {
    PHANDLE_TABLE_ENTRY pHandleTableEntry;
    PVOID64             pObjHeader;

    pHandleTableEntry = tablecode;
    for (size_t i = 0; i < PAGE_HANDLE_MAX; i++) {
        // 如果tablecode有异常则跳过这个
        if (!CheckHandleTableEntry(&pHandleTableEntry[i])) {
            continue;
        }

        // 通过_handle_table_entry计算_object_header地址
        pObjHeader = HandleEntryTable2ObjectHeader(&pHandleTableEntry[i]);

        // Option: Check this object is process?
        if (!IsProcess(pObjHeader)) {
            continue;
        }

        // Compare whether the two eprocess variables are the same
        if ((PVOID64)((PUCHAR)pObjHeader + HANDLE_BODY_OFFSET) == pEprocess) {
            kprintf("[+] Found tablecode: %llx; object_handle: %p; "
                "handle_table_entry: %p;\r\n",
                tablecode,
                pObjHeader,
                &pHandleTableEntry[i]);
            // 取消句柄的读写权限
            ModfiyGrantedAccessBits(&pHandleTableEntry[i]);
            return TRUE;
        }
    }

    return FALSE;
}

/// @brief 遍历两层的句柄表，判断其中是否有目标句柄进程pEprocess
/// 如果有则返回TRUE, 否则返回FALSE
/// @param pProcessHandleObj 需要遍历的pProcessHandleObj的结构体
/// @param pEprocess 目标进程句柄
/// @return
BOOLEAN FilterTWOTabelByEprocess(PEPROCESS pEprocess, UINT64 tablecode) {
    PUINT64 tables;

    tables = tablecode & TABLE_CODE_MASK;

    for (size_t i = 0; tables[i] != 0; i++) {
        if (FilterOneTableByEprocess(pEprocess, tables[i])) {
            return TRUE;
        }
    }

    return FALSE;
}

/// @brief 遍历一层/两层句柄表，判断其中是否有目标句柄进程pEprocess
/// 如果有则返回TRUE, 否则返回FALSE
/// @param pProcessHandleObj 需要遍历的pProcessHandleObj的结构体
/// @param pEprocess 目标进程句柄
/// @return
BOOLEAN FilterObjByEprocess(PPROCESS_HANDLE_OBJECT pProcessHandleObj,
    PEPROCESS              pEprocess)
{
    UINT64              tablecode;
    PHANDLE_TABLE_ENTRY pHandleTableEntry;
    PVOID64             pObjHeader;

    tablecode = pProcessHandleObj->table_code;

    switch (tablecode & TABLE_LEVEL_MASK)
    {
    case TABLE_LEVEL_ZERO:
        return FilterOneTableByEprocess(pEprocess, tablecode);
        break;
    case TABLE_LEVEL_ONE:
        return FilterTWOTabelByEprocess(pEprocess, tablecode);
        break;
    default:
        break;
    }

    return FALSE;
}

/// @brief 传入需要保护的进程eprocess，保护程序句柄
/// @param pEprocess PEPROCESS地址
/// @return
NTSTATUS ProtectProcessHandleByEprocess(PEPROCESS pEprocess)
{
    PVOID64                 pHandleTable;
    PLIST_ENTRY64           pPriList, pTmp;
    UINT64                  cout;
    PPROCESS_HANDLE_OBJECT* ObjArr;
    NTSTATUS                status;

    pHandleTable =
        *(PUINT64)((PCHAR)pEprocess + WIN10_21H1_X64_OBJECTTABLE_OFFSET);
    pPriList = (PLIST_ENTRY64)((PUCHAR)pHandleTable +
        WIN10_21H1_X64_HANDLETABLELIST_OFFSET);

    kprintf("[+] EPROCESS: %p\r\n[+] handle object: %p\r\n[+] handle table "
        "list: %p\r\n",
        pEprocess,
        pHandleTable,
        pPriList);

    status = CreateProcessObjArrByHandleList(pPriList, &ObjArr);
    if (!NT_SUCCESS(status)) {
        kprintf("[!] CreateProcessObjArrByHandleList error");
        return STATUS_UNSUCCESSFUL;
    }

    for (size_t i = 0; ObjArr[i] != 0; i++) {
        // kprintf("[+] Obj[%d]: %llx\r\n", i, ObjArr[i]);
        // DisplayProcessHandleObj(ObjArr[i]);
        kprintf("[+] Use handle process imagename: %s; eprocess: %p\r\n",
            (PUCHAR)ObjArr[i]->eprocess + EPROCESS_IMAGE_OFFSET,
            ObjArr[i]->eprocess);
        FilterObjByEprocess(ObjArr[i], pEprocess);
    }

    FreeProcessObjArr(ObjArr);

    return STATUS_SUCCESS;
}