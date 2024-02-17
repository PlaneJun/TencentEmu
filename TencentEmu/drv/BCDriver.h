#include <iostream>
#include <string>
#include <Windows.h>
#include <stdint.h>
#include <TlHelp32.h>
#include <direct.h>

class BC
{
public:

	typedef struct _DATA_PARAMENTS_ {

		ULONG64			code;
		ULONG64			pid;
		PVOID64			address;
		PVOID64			buffer;
		ULONG64			length;
		PVOID64			output;
		ULONG64			allocTop;
		ULONG64			newProtect;
	}DataParams, * PDataParams;

	typedef struct _IO_STATUS_BLOCK
	{
		union
		{
			LONG Status;                                                        //0x0
			PVOID Pointer;                                                      //0x0
		};
		ULONGLONG Information;                                                  //0x8
	}IO_STATUS_BLOCK, * PIO_STATUS_BLOCK;

	enum CMD
	{
		MAP_CONTROL = 9000, 
		MAP_GetProcessModules,
		MAP_GetProcessPEB,
		MAP_ReadMemory,
		MAP_WriteMemory,
		MAP_AllocMemory,
		MAP_FreeMemory,
		MAP_QueryVirtualMemory,
		MAP_ProtectVirtualMemory,
		MAP_MouseEvent,
		MAP_DeleteFile,
		MAP_DumpExe
	};

public:
	int DriverFile();
	void InitializeDriver();
	int GetProcessIDByName(std::wstring pname);
	BOOL Control();
	void SetPid(DWORD pid);
	ULONG64 GetProcessModuleBase(PCCH ModuleName);
	ULONG64 GetProcessPEB();
	BOOL ReadMemory(PVOID64 Address, ULONG ReadSize, PVOID64 Output);
	BOOL WriteMemory(PVOID64 Address, ULONG WriteSize, PVOID64 WriteBuffer);
	BOOL AllocateVirtualMemory(PVOID64 Address, ULONG Size, PVOID64 Output, BOOL top);
	BOOL ProtectVirtualMemory(PVOID64 Address, ULONG Size, ULONG64 newProtect);
	ULONG64 AllocateVirtualMemoryNearby(ULONG64 Address, ULONG Size);
	BOOL FreeVirtualMemory(PVOID64 Address, ULONG Size);
	BOOL QueryVirtualMemory(PVOID64 Address, PVOID64 Output);
	BOOL MouseEvent(DWORD x, DWORD y, USHORT flag);
	int KDeleteFile();
	int KDumpExe(DWORD pid, const char* ModuleName);

	template <typename T>
	T read(uintptr_t address) {
		T buffer{};
		ReadMemory((PVOID64)address, sizeof(buffer), &buffer);
		return buffer;
	}

	template <typename T>
	void write(uintptr_t address, T buffer)
	{
		WriteMemory((PVOID64)address, sizeof(T), &buffer);
	}

private:
	HANDLE hFile;
	DWORD pid;

	CHAR* m_csServiceName = (char*)"LKSafeDrv5";
	CHAR cwdPath[MAX_PATH];
	CHAR DRVPath[MAX_PATH];
	auto installDvr(const char drvPath[50], const char serviceName[20]) -> BOOL;
	auto startDvr(const char serviceName[20]) -> BOOL;
};