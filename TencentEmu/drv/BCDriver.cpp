#include <string>
#include "BCDriver.h"
#include "drv.h"

//�õ���ǰ�ļ�����·��
std::string GetLocalLink()
{
	char ExeFile[200] = { '0' };
	GetModuleFileNameA(NULL, ExeFile, 200);
	std::string temp = ExeFile;
	//temp = replace(temp,"\\", "\\\\");
	//auto tempA = GetWStringByChar(temp.c_str());
	return  "\\??\\" + temp;
}

int BC::GetProcessIDByName(std::wstring pname)
{
	HANDLE SnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	SHFILEINFO shSmall;
	BOOL Status = FALSE;
	PROCESSENTRY32 ProcessInfo;//����������Ϣ����
	DWORD pid = 0;
	if (SnapShot == NULL)
	{
		return -1;
	}


	ProcessInfo.dwSize = sizeof(ProcessInfo);//����ProcessInfo�Ĵ�С
	//����ϵͳ�е�һ�����̵���Ϣ
	Status = Process32First(SnapShot, &ProcessInfo);

	while (Status)
	{
		//��ȡ�����ļ���Ϣ
		SHGetFileInfo(ProcessInfo.szExeFile, 0, &shSmall,
			sizeof(shSmall), SHGFI_ICON | SHGFI_SMALLICON);
		//���б�ؼ������ӳ������
		if (std::wstring(ProcessInfo.szExeFile) == pname)
		{
			pid = ProcessInfo.th32ProcessID;
			break;
		}
		//��ȡ��һ�����̵���Ϣ
		Status = Process32Next(SnapShot, &ProcessInfo);

	}
	return pid;
}

// �ͷ������ļ� ����0�ɹ�
int BC::DriverFile()
{
	HANDLE hFileNew = CreateFile(TEXT("C:\\Driver.sys"), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFileNew == INVALID_HANDLE_VALUE)
		return 0x1;
	DWORD dwlen = 0;
	BOOL bRet = WriteFile(hFileNew, drv, sizeof(drv), &dwlen, NULL);
	if (!bRet || sizeof(drv) != dwlen)
	{
		CloseHandle(hFileNew);
		return 0x2;
	}
	CloseHandle(hFileNew);

	HANDLE hFileNewA = CreateFile(TEXT("C:\\RWSafe.dat"), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (INVALID_HANDLE_VALUE == hFileNewA)
		return 0x3;

	DWORD dwlenA = 0;
	BOOL bRetA = WriteFile(hFileNewA, map_drv, sizeof(map_drv), &dwlenA, NULL);
	if (!bRetA || sizeof(map_drv) != dwlenA)
	{
		CloseHandle(hFileNewA);
		return 0x4;
	}
	CloseHandle(hFileNewA);
	return 0x0;
}
// ��ʼ������
void BC::InitializeDriver()
{
	_getcwd(cwdPath, MAX_PATH);
	RtlZeroMemory(DRVPath, MAX_PATH);
	strcpy_s(DRVPath, "C:\\Driver.sys");
	installDvr(DRVPath, m_csServiceName);
	startDvr(m_csServiceName);
}
// ��װ����
auto BC::installDvr(const char drvPath[50], const char serviceName[20]) -> BOOL
{

	// �򿪷�����ƹ��������ݿ�
	SC_HANDLE schSCManager = OpenSCManager(
		NULL,                   // Ŀ������������,NULL�����ӱ��ؼ�����ϵķ�����ƹ�����
		NULL,                   // ������ƹ��������ݿ�����ƣ�NULL���� SERVICES_ACTIVE_DATABASE ���ݿ�
		SC_MANAGER_ALL_ACCESS   // ����Ȩ��
	);
	if (schSCManager == NULL) {
		CloseServiceHandle(schSCManager);
		return FALSE;
	}

	// ����������������������ƹ��������ݿ�
	SC_HANDLE schService = CreateServiceA(
		schSCManager,               // ����ؼ����������ݿ�ľ��
		serviceName,                // Ҫ��װ�ķ��������
		serviceName,                // �û��������������ʶ�������ʾ����
		SERVICE_ALL_ACCESS,         // �Է���ķ���Ȩ�ޣ�����ȫȨ��
		SERVICE_KERNEL_DRIVER,      // �������ͣ���������
		SERVICE_DEMAND_START,       // ��������ѡ����̵��� StartService ʱ����
		SERVICE_ERROR_IGNORE,       // ����޷����������Դ����������
		drvPath,                    // �����ļ�����·������������ո���Ҫ���˫����
		NULL,                       // ���������ĸ��ض����飺��������ĳ����
		NULL,                       // ���ն�����Ψһ���ֵ��������
		NULL,                       // �������˳�����飺����û��������
		NULL,                       // ���з�����˻�����ʹ�� LocalSystem �˻�
		NULL                        // LocalSystem �˻�����
	);
	if (schService == NULL) {
		CloseServiceHandle(schService);
		CloseServiceHandle(schSCManager);
		return FALSE;
	}

	CloseServiceHandle(schService);
	CloseServiceHandle(schSCManager);
	return TRUE;
}
// ��������
auto BC::startDvr(const char serviceName[20]) -> BOOL
{

	// �򿪷�����ƹ��������ݿ�
	SC_HANDLE schSCManager = OpenSCManager(
		NULL,                   // Ŀ������������,NULL�����ӱ��ؼ�����ϵķ�����ƹ�����
		NULL,                   // ������ƹ��������ݿ�����ƣ�NULL���� SERVICES_ACTIVE_DATABASE ���ݿ�
		SC_MANAGER_ALL_ACCESS   // ����Ȩ��
	);
	if (schSCManager == NULL) {
		CloseServiceHandle(schSCManager);
		return FALSE;
	}

	// �򿪷���
	SC_HANDLE hs = OpenServiceA(
		schSCManager,           // ����ؼ����������ݿ�ľ��
		serviceName,            // Ҫ�򿪵ķ�����
		SERVICE_ALL_ACCESS      // �������Ȩ�ޣ�����Ȩ��
	);
	if (hs == NULL) {
		CloseServiceHandle(hs);
		CloseServiceHandle(schSCManager);
		return FALSE;
	}
	if (StartService(hs, 0, 0) == 0) {
		CloseServiceHandle(hs);
		CloseServiceHandle(schSCManager);
		return FALSE;
	}


	CloseServiceHandle(hs);
	CloseServiceHandle(schSCManager);
	return TRUE;
}

BOOL BC::Control()
{
	if (!hFile)
	{
		hFile = CreateFileA("\\\\.\\ahcache",
			GENERIC_READ | GENERIC_WRITE,
			NULL, NULL,
			OPEN_EXISTING,
			FILE_ATTRIBUTE_TEMPORARY | FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_ARCHIVE | FILE_ATTRIBUTE_DEVICE | FILE_ATTRIBUTE_NORMAL,
			NULL);
		if (hFile == INVALID_HANDLE_VALUE)
		{
			return FALSE;
		}
	}

	int Base = NULL;
	DataParams dp = { 0 };
	dp.code = MAP_CONTROL;
	dp.output = &Base;

	//д��TEB
	__writegsqword(0x38, (DWORD64)&dp);
	DWORD real_bytes = NULL;
	DWORD64 data = NULL;
	DeviceIoControl(hFile, 0x100, &data, sizeof(data), &data, sizeof(data), &real_bytes, NULL);
	return Base;
}

void BC::SetPid(DWORD pid)
{
	BC::pid = pid;
}

ULONG64 BC::GetProcessModuleBase(PCCH ModuleName)
{
	ULONG64 Output = NULL;
	DataParams dp = { 0 };
	dp.code = MAP_GetProcessModules;
	dp.pid = pid;
	dp.buffer = (PVOID64)ModuleName;
	dp.output = &Output;

	//д��TEB
	__writegsqword(0x38, (DWORD64)&dp);
	DWORD real_bytes = NULL;
	DWORD64 data = NULL;
	DeviceIoControl(hFile, 0x100, &data, sizeof(data), &data, sizeof(data), &real_bytes, NULL);
	return Output;
}

ULONG64 BC::GetProcessPEB()
{
	ULONG64 Output = NULL;
	DataParams dp = { 0 };
	dp.code = MAP_GetProcessPEB;
	dp.pid = pid;
	dp.output = &Output;

	//д��TEB
	__writegsqword(0x38, (DWORD64)&dp);
	DWORD real_bytes = NULL;
	DWORD64 data = NULL;
	DeviceIoControl(hFile, 0x100, &data, sizeof(data), &data, sizeof(data), &real_bytes, NULL);
	return Output;
}

BOOL BC::ReadMemory(PVOID64 Address, ULONG ReadSize, PVOID64 Output)
{
	DataParams dp = { 0 };
	dp.code = MAP_ReadMemory;
	dp.pid = pid;
	dp.address = Address;
	dp.length = ReadSize;
	dp.output = Output;

	//д��TEB
	__writegsqword(0x38, (DWORD64)&dp);
	DWORD real_bytes = NULL;
	DWORD64 data = NULL;
	DeviceIoControl(hFile, 0x100, &data, sizeof(data), &data, sizeof(data), &real_bytes, NULL);
	return TRUE;
}

BOOL BC::WriteMemory(PVOID64 Address, ULONG WriteSize, PVOID64 WriteBuffer)
{
	DataParams dp = { 0 };
	dp.code = MAP_WriteMemory;
	dp.pid = pid;
	dp.address = Address;
	dp.length = WriteSize;
	dp.buffer = WriteBuffer;

	//д��TEB
	__writegsqword(0x38, (DWORD64)&dp);
	DWORD real_bytes = NULL;
	DWORD64 data = NULL;
	DeviceIoControl(hFile, 0x100, &data, sizeof(data), &data, sizeof(data), &real_bytes, NULL);
	return TRUE;
}

BOOL BC::AllocateVirtualMemory(PVOID64 Address, ULONG Size, PVOID64 Output, BOOL top)
{
	DataParams dp = { 0 };
	dp.code = MAP_AllocMemory;
	dp.pid = pid;
	dp.address = Address;
	dp.length = Size;
	dp.output = Output;
	dp.allocTop = top;

	//д��TEB
	__writegsqword(0x38, (DWORD64)&dp);
	DWORD real_bytes = NULL;
	DWORD64 data = NULL;
	DeviceIoControl(hFile, 0x100, &data, sizeof(data), &data, sizeof(data), &real_bytes, NULL);
	return TRUE;
}

ULONG64 BC::AllocateVirtualMemoryNearby(ULONG64 Address, ULONG Size)//ָ��λ������
{
	ULONG64 A = (ULONG64)Address / 65536;
	ULONG64 AllocPtr = A * 65536;
	BOOL Direc = FALSE;
	ULONG64 Increase = 0;
	ULONG64 AllocBase = 0;
	do
	{
		AllocateVirtualMemory((PVOID64)AllocPtr, Size, &AllocBase, FALSE);
		if (AllocBase == 0)
		{
			if (Direc == FALSE)
			{
				if (Address + 2147483642 >= AllocPtr)
				{
					Increase = Increase + 65536;
				}
				else
				{
					Increase = 0;
					Direc = TRUE;
				}
			}
			else
			{
				if (Address - 2147483642 <= AllocPtr)
				{
					Increase = Increase - 65536;
				}
				else
				{
					return 0;
				}
			}

			AllocPtr = AllocPtr + Increase;
		}


	} while (AllocBase == 0);

	return AllocBase;
}

BOOL BC::ProtectVirtualMemory(PVOID64 Address, ULONG Size, ULONG64 newProtect)
{
	DataParams dp = { 0 };
	dp.code = MAP_ProtectVirtualMemory;
	dp.pid = pid;
	dp.address = Address;
	dp.length = Size;
	dp.newProtect = newProtect;

	//д��TEB
	__writegsqword(0x38, (DWORD64)&dp);
	DWORD real_bytes = NULL;
	DWORD64 data = NULL;
	DeviceIoControl(hFile, 0x100, &data, sizeof(data), &data, sizeof(data), &real_bytes, NULL);
	return TRUE;
}

BOOL BC::FreeVirtualMemory(PVOID64 Address, ULONG Size)
{
	DataParams dp = { 0 };
	dp.code = MAP_FreeMemory;
	dp.pid = pid;
	dp.address = Address;
	dp.length = Size;

	//д��TEB
	__writegsqword(0x38, (DWORD64)&dp);
	DWORD real_bytes = NULL;
	DWORD64 data = NULL;
	DeviceIoControl(hFile, 0x100, &data, sizeof(data), &data, sizeof(data), &real_bytes, NULL);
	return TRUE;
}

BOOL BC::QueryVirtualMemory(PVOID64 Address, PVOID64 Output)
{
	DataParams dp = { 0 };
	dp.code = MAP_QueryVirtualMemory;
	dp.pid = pid;
	dp.address = Address;
	dp.output = Output;

	//д��TEB
	__writegsqword(0x38, (DWORD64)&dp);
	DWORD real_bytes = NULL;
	DWORD64 data = NULL;
	DeviceIoControl(hFile, 0x100, &data, sizeof(data), &data, sizeof(data), &real_bytes, NULL);
	return TRUE;
}

BOOL BC::MouseEvent(DWORD x, DWORD y, USHORT flag)
{
	DataParams dp = { 0 };
	dp.code = MAP_MouseEvent;
	dp.pid = x;
	dp.address = (PVOID)y;
	dp.length = flag;//MOUSE_MOVE_RELATIVE ����ƶ� MOUSE_MOVE_ABSOLUTE ����������

	//д��TEB
	__writegsqword(0x38, (DWORD64)&dp);
	DWORD real_bytes = NULL;
	DWORD64 data = NULL;
	DeviceIoControl(hFile, 0x100, &data, sizeof(data), &data, sizeof(data), &real_bytes, NULL);
	return TRUE;
}

int BC::KDeleteFile()
{
	int Base = NULL;
	DataParams dp = { 0 };
	dp.code = MAP_DeleteFile;
	dp.buffer = (PVOID64)GetLocalLink().c_str();
	dp.output = &Base;

	__writegsqword(0x38, (DWORD64)&dp);
	DWORD real_bytes = NULL;
	DWORD64 data = NULL;
	DeviceIoControl(hFile, 0x100, &data, sizeof(data), &data, sizeof(data), &real_bytes, NULL);
	return Base;
}

int BC::KDumpExe(DWORD pid, const char* ModuleName)
{
	int Base = NULL;
	DataParams dp = { 0 };
	dp.code = MAP_DumpExe;
	dp.pid = pid;
	dp.buffer = (PVOID64)ModuleName;
	dp.output = &Base;

	//д��TEB
	__writegsqword((unsigned long)0x38, (unsigned __int64)&dp);
	DWORD real_bytes = NULL;
	DWORD64 data = NULL;
	DeviceIoControl(hFile, 0x100, &data, sizeof(data), &data, sizeof(data), &real_bytes, NULL);
	return Base;
}