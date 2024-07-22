#pragma once
#include <ntifs.h>


//ProtectProcessHandleByEprocess(eprocess);  //���ǿ�ʼλ��

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
 * ��������ֵ��ͨ������ϵͳ�õ���
 *  OB_HEADER_COOKIE����ʹ��`db nt!ObHeaderCookie l1`�õ�
 *  PROCESS_TYPEͨ������õ���ǰϵͳ��PROCESS��type indexֵΪ7
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

/// @brief ���ÿ�����̵���Ϣ
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
/// ���һ��PHANDLE_TABLE_ENTRY�е���ֵ�Ƿ�Ϸ���LowValue�Ƿ�Ϊ0���Ϸ�����TRUE�����򷵻�FALSE
/// @param pHandleTableEntry PHANDLE_TABLE_ENTRYָ��
/// @return �Ϸ�����TRUE�����򷵻�FALSE
BOOLEAN CheckHandleTableEntry(PHANDLE_TABLE_ENTRY pHandleTableEntry)
{
    if (!pHandleTableEntry->LowValue) {
        return FALSE;
    }

    return TRUE;
}

/// @brief
/// �½�һ��PROCESS_HANDLE_OBJECT�ṹ�塣����eprocess��ַ����handle_table��ַ������������һ
/// �����ɹ����ؽṹ��ָ�룬ʧ���򷵻�NULL
/// @param pEprocess eprocess��ַ����NULL
/// @param pHandleTable _handle_table��ַ����NULL
/// @return �����ɹ����ؽṹ��ָ�룬ʧ���򷵻�NULL
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

/// @brief ����PROCESS_HANDLE_OBJECT�ṹ�壬����һ����Ӧָ��
/// @param pProcessHandlePbject PROCESS_HANDLE_OBJECT��ָ��
/// @return
VOID FreeProcessHandleObject(PPROCESS_HANDLE_OBJECT pProcessHandlePbject)
{
    pProcessHandlePbject->eprocess = NULL;
    pProcessHandlePbject->table_code = 0;

    ExFreePool(pProcessHandlePbject);
}

/// @brief ����һ��HANDLE_TABLE_ENTRY�ṹ��ĵ�ַ�������ObjectHeader��ַ
/// @param addr HANDLE_TABLE_ENTRY�ṹ��ĵ�ַ
/// @return ����ObjectHeader��ַ
ULONG64 HandleEntryTable2ObjectHeader(PHANDLE_TABLE_ENTRY addr)
{
    return ((addr->LowValue >> 0x10) & 0xFFFFFFFFFFFFFFF0) + 0xFFFF000000000000;
}

/// @brief ����һ��ObjectHeader��ַ���ж��Ƿ��ǽ��̶���������򷵻�TRUE,
/// �����򷵻�FALSE
/// @param Address ���ͷ�ĵ�ַ��Ҳ����_object_header�ṹ���ַ
/// @return ������򷵻�TRUE, �����򷵻�FALSE
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

/// @brief ƥ����̵�imageName,�����ָ����ImageName��ͬ�򷵻�
/// @param Address _object_header�ĵ�ַ
/// @param Name ��Ҫƥ��ĳ�������
/// @return �������ǽ��̾������Ŀ������򷵻�TRUE�����򷵻�FALSE
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
/// ����һ��PLIST_ENTRY64��������������ÿ������ڵ������һ����Ӧ��PROCESS_HANDLE_OBJECTָ��
/// ���һ�����飬���ָ�룬��ŵ�ObjArr
/// @param pHandleList Handle_list����
/// @param ObjArr PPROCESS_HANDLE_OBJECT* ָ��
/// @return ����һ��ָ�����飬����Ԫ����PROCESS_HANDLE_OBJECTָ��
NTSTATUS CreateProcessObjArrByHandleList(PLIST_ENTRY64            pHandleList,
    PPROCESS_HANDLE_OBJECT** ObjArr)
{
    PLIST_ENTRY64           pTmp;
    UINT64                  cout = 0;
    PPROCESS_HANDLE_OBJECT* pProcessObjArr;

    // ��ȡ����ڵ����������������ڴ���С
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

    // ���������ȡ�ڵ���Ϣ��������ProcessHandleObject�ṹ��
    for (size_t i = 0; i < cout; i++) {
        pProcessObjArr[i] = NewProcessHandleObject(
            NULL, ((PUCHAR)pTmp - WIN10_21H1_X64_HANDLETABLELIST_OFFSET));
        pTmp = pTmp->Flink;
    }

    *ObjArr = pProcessObjArr;
    return STATUS_SUCCESS;
}

/// @brief �ͷ�ProcessObjectָ�����������
/// @param ObjArr PPROCESS_HANDLE_OBJECT����
/// @return
VOID FreeProcessObjArr(PPROCESS_HANDLE_OBJECT* ObjArr)
{
    for (size_t i = 0; ObjArr[i] != 0; i++) {
        FreeProcessHandleObject(ObjArr[i]);
        ObjArr[i] = NULL;
    }

    // ExFreePoolWithTag(&ObjArr, POOL_TAG);
}

/// @brief ����һ��_object_headerָ���ӡbody��_eprocess��ImageName�ַ�����
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

/// @brief �޸�handle_entry_table��GrantedAccessBitsȨ�ޣ�������ڴ��дȨ��
/// @param pHandleTableEntry
/// @return
NTSTATUS ModfiyGrantedAccessBits(PHANDLE_TABLE_ENTRY pHandleTableEntry)
{
    pHandleTableEntry->GrantedAccessBits &=
        ~(PROCESS_VM_READ | PROCESS_VM_WRITE);
    return STATUS_SUCCESS;
}

/// @brief ��Ե��ž����������ƥ��Ŀ��eprocess�����ƥ�䵽���޸ľ��Ȩ��
/// @param pEprocess Ŀ��eprocess�ṹ��ָ��
/// @param tablecode ���ž�����tablecode
/// @return
BOOLEAN FilterOneTableByEprocess(PEPROCESS pEprocess, UINT64 tablecode) {
    PHANDLE_TABLE_ENTRY pHandleTableEntry;
    PVOID64             pObjHeader;

    pHandleTableEntry = tablecode;
    for (size_t i = 0; i < PAGE_HANDLE_MAX; i++) {
        // ���tablecode���쳣���������
        if (!CheckHandleTableEntry(&pHandleTableEntry[i])) {
            continue;
        }

        // ͨ��_handle_table_entry����_object_header��ַ
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
            // ȡ������Ķ�дȨ��
            ModfiyGrantedAccessBits(&pHandleTableEntry[i]);
            return TRUE;
        }
    }

    return FALSE;
}

/// @brief ��������ľ�����ж������Ƿ���Ŀ��������pEprocess
/// ������򷵻�TRUE, ���򷵻�FALSE
/// @param pProcessHandleObj ��Ҫ������pProcessHandleObj�Ľṹ��
/// @param pEprocess Ŀ����̾��
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

/// @brief ����һ��/���������ж������Ƿ���Ŀ��������pEprocess
/// ������򷵻�TRUE, ���򷵻�FALSE
/// @param pProcessHandleObj ��Ҫ������pProcessHandleObj�Ľṹ��
/// @param pEprocess Ŀ����̾��
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

/// @brief ������Ҫ�����Ľ���eprocess������������
/// @param pEprocess PEPROCESS��ַ
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