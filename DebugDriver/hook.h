#include <ntifs.h>

#pragma pack(push,1)
struct HOOKOPCODES
{
#ifdef _WIN64
	unsigned short int mov;
#else
	unsigned char mov;
#endif
	ULONG_PTR addr;
	unsigned char push;
	unsigned char ret;
};
#pragma pack(pop)

typedef struct HOOKSTRUCT
{
	ULONG_PTR addr;
	HOOKOPCODES hook;
	unsigned char orig[sizeof(HOOKOPCODES)];
	//SSDT extension
	int SSDTindex;
	LONG SSDTold;
	LONG SSDTnew;
	ULONG_PTR SSDTaddress;
}*HOOK;

HOOK Hook(PVOID api, void* newfunc);
bool Hook(HOOK hook);
bool Unhook(HOOK hook, bool free = false);

