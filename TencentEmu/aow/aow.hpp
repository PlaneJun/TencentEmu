#pragma once
#include <vector>
#include <string>
#include <sstream>
#include <filesystem>
#include <windows.h>
#include <TlHelp32.h>
#include <psapi.h>
#include <stdint.h>
#pragma  comment(lib,"Psapi.lib")

typedef struct _TEnumHWndsArg
{
	std::vector<HWND>* vecHWnds;
	DWORD dwProcessId;
}EnumHWndsArg, * LPEnumHWndsArg;

typedef struct _TPROCESS_INFO
{
	std::string user;	// 进程当前用户
	uint32_t pid;		// 当前进程id
	uint32_t ppid;		// 父进程ID
	uint32_t vsize;		// 当前进程虚拟内存的大小
	uint32_t rss;		// 实际驻留在内存中的没存大小
	std::string wchan;	// 休眠进程在内核中的地址
	std::string pc;		// 计算机中提供要从[存储器]中取出的下一个指令地址的[寄存器] 
	std::string name;	// 计算机名
}ProcessInfo;

BOOL CALLBACK cb_get_game_hwnd(HWND hwndChild, LPARAM lParam)
{
	wchar_t childWindowClassName[50];
	wchar_t childWindowTextName[50];

	GetWindowText(hwndChild, childWindowTextName, 50);
	GetClassName(hwndChild, childWindowClassName, 50);
	if (wcscmp(childWindowClassName, L"AEngineRenderWindowClass") == 0 || wcscmp(childWindowClassName, L"subWin") == 0 ||
		wcscmp(childWindowTextName, L"AEngineRenderWindow") == 0 || wcscmp(childWindowTextName, L"sub") == 0)
	{
		*(HWND*)lParam = hwndChild;
		return false;
	}

}

BOOL CALLBACK cb_enum_hwnd_by_pid(HWND hwnd, LPARAM lParam)
{
	EnumHWndsArg* pArg = (LPEnumHWndsArg)lParam;
	DWORD  processId;
	GetWindowThreadProcessId(hwnd, &processId);
	if (processId == pArg->dwProcessId)
	{
		pArg->vecHWnds->push_back(hwnd);
	}
	return TRUE;
}

uint32_t get_pid_by_name(LPCTSTR lpszProcessName)
{
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	PROCESSENTRY32 pe;
	pe.dwSize = sizeof(PROCESSENTRY32);

	if (!Process32First(hSnapshot, &pe))
	{
		MessageBox(NULL, (LPCTSTR)"The frist entry of the process list has not been copyied to the buffer", (LPCTSTR)"Notice", MB_ICONINFORMATION | MB_OK);
		return 0;
	}

	while (Process32Next(hSnapshot, &pe))
	{
		if (!wcscmp(lpszProcessName, pe.szExeFile))
		{
			return pe.th32ProcessID;
		}
	}
	return 0;
}

void enum_hwnd_by_pid(DWORD processID, std::vector<HWND>& vecHWnds)
{
	EnumHWndsArg wi;
	wi.dwProcessId = processID;
	wi.vecHWnds = &vecHWnds;
	EnumWindows(cb_enum_hwnd_by_pid, (LPARAM)&wi);
}

std::string get_dos_execute_result(std::string cmd)
{
	std::string cmd_result = std::string();

	HANDLE hReadPipe{}, hWritePipe{};
	SECURITY_ATTRIBUTES saAttr{};
	saAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
	saAttr.bInheritHandle = TRUE;
	saAttr.lpSecurityDescriptor = NULL;

	if (!CreatePipe(&hReadPipe, &hWritePipe, &saAttr, 0))
	{
		return "";
	}

	STARTUPINFOA si{};
	PROCESS_INFORMATION pi{};
	si.cb = sizeof(si);
	si.hStdError = hWritePipe;
	si.hStdOutput = hWritePipe;
	si.dwFlags = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES;
	si.wShowWindow = SW_HIDE;
	if (!CreateProcessA(NULL, (LPSTR)cmd.c_str(), NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi))
	{
		printf("create process failed");
		return "";
	}
	CloseHandle(hWritePipe);

	char psBuffer[0x2000] = { 0 };
	DWORD dwRead;
	BOOL bSuccess = FALSE;
	while (bSuccess = ReadFile(hReadPipe, psBuffer, sizeof(psBuffer), &dwRead, NULL))
	{
		if (dwRead == 0)
		{
			break;
		}
		cmd_result += psBuffer;
		memset(psBuffer, 0, 0x2000);
	}

	int closeReturnVal = 0;
	if (!GetExitCodeProcess(pi.hProcess, (LPDWORD)&closeReturnVal))
	{
		printf("Error: Failed to read the pipe to the end.\n");
	}

	CloseHandle(hReadPipe);
	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);
	return cmd_result;

}

namespace aow
{
	bool init_work_dir()
	{
		uint32_t pid_android_emulator = get_pid_by_name(L"AndroidEmulator.exe");
		if (pid_android_emulator <= 0)
			return false;

		auto hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid_android_emulator);
		char file_path[MAX_PATH]{};
		GetModuleFileNameExA(hProc, NULL, file_path, MAX_PATH);
		CloseHandle(hProc);

		// 设置工作目录
		auto new_dir = std::filesystem::path(file_path).remove_filename();
		if (!SetCurrentDirectoryA(new_dir.string().c_str()))
		{
			printf("set dir failed!%d\n", GetLastError());
			return false;
		}

		return true;
	}

	HWND get_game_hwnd()
	{
		HWND game_hwnd = NULL;
		static std::vector<std::wstring> titles = { L"腾讯手游助手(64位)",L"腾讯手游助手【极速傲引擎】" , L"Tencent Gaming Buddy【Turbo AOW Engine】",L"Gameloop【Turbo AOW Engine】" , L"Gameloop【極速傲引擎】"};
		HWND  temp_hwnd = NULL;
		for (auto i : titles)
		{
			temp_hwnd = FindWindow(L"TXGuiFoundation", i.c_str());
			if (temp_hwnd)
				break;
		}

		if (!temp_hwnd)
		{
			uint32_t processID = get_pid_by_name(L"AndroidEmulator.exe");
			std::vector<HWND> vecHWnds{};
			enum_hwnd_by_pid(processID, vecHWnds);
			for (const HWND& h : vecHWnds)
			{
				HWND parent = GetParent(h);
				if (parent == NULL)
				{
					EnumChildWindows(h, cb_get_game_hwnd, (LPARAM)&game_hwnd);
				}
			}
			return game_hwnd;
		}
		else
		{
			EnumChildWindows(temp_hwnd, cb_get_game_hwnd, (LPARAM) & game_hwnd);
			if (game_hwnd)
			{
				return game_hwnd;
			}
			game_hwnd = FindWindowEx(temp_hwnd, NULL, L"AEngineRenderWindowClass", NULL);;
			return  game_hwnd;
		}
		
	}

	uint32_t get_game_pid()
	{
		PROCESSENTRY32 pe;
		pe.dwSize = sizeof(PROCESSENTRY32);

		HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		if (!Process32First(hSnapshot, &pe)) 
		{
			MessageBox(NULL,(LPCTSTR)"The frist entry of the process list has not been copyied to the buffer",(LPCTSTR)"Notice", MB_ICONINFORMATION | MB_OK);
			return 0;
		}

		while (Process32Next(hSnapshot, &pe))
		{
			if (!wcscmp(L"aow_exe.exe", pe.szExeFile))
			{
				if (pe.cntThreads > 80)
					return pe.th32ProcessID;
			}
		}
	}

	std::vector<std::string> get_all_pkgs()
	{
		std::vector<std::string> ret{};
		std::string dos_result = get_dos_execute_result("cmd.exe /c adb shell pm list packages");
		if (dos_result.empty())
		{
			return ret;
		}
		
		std::istringstream iss(dos_result);
		std::string line;

		while (std::getline(iss, line)) {
			line = line.substr(strlen("package:"));
			if (line.find('\r') != std::string::npos)
			{
				line = line.substr(0, line.length() - 1);
			}
			ret.push_back(line);
		}

		return ret;
	}

	std::vector<ProcessInfo> get_all_process()
	{
		std::vector<ProcessInfo> ret{};
		std::string dos_result = get_dos_execute_result("cmd.exe /c adb shell ps");
		if (dos_result.empty())
		{
			return ret;
		}

		std::istringstream iss(dos_result);
		std::string line;

		while (std::getline(iss, line)) {
			std::istringstream lineStream(line);
			ProcessInfo pkg_info{};
			lineStream >>	pkg_info.user >> 
							pkg_info.pid >> 
							pkg_info.ppid >> 
							pkg_info.vsize >> 
							pkg_info.rss >> 
							pkg_info.wchan >> 
							pkg_info.pc >>
							pkg_info.name;
			ret.push_back(pkg_info);
		}

		return ret;
	}

	uint32_t get_pid_by_name(const char* pkg_name)
	{
		auto ps = get_all_process();
		for (auto i : ps)
		{
			if (i.name == pkg_name)
				return i.pid;
		}
		return 0;
	}
	
	uint64_t get_so_base(uint32_t pid, const char* so_name)
	{
		std::string dos_result = get_dos_execute_result("cmd.exe /c adb shell cat /proc/"+std::to_string(pid).append("/maps"));
		if (dos_result.empty())
		{
			return 0;
		}

		std::istringstream iss(dos_result);
		std::string line;

		while (std::getline(iss, line)) {

			// 就找第一个
			if (line.find(so_name) != std::string::npos)
			{
				int index = line.find('-');
				line = line.substr(0, index);
				
				std::stringstream ss2;
				uint64_t d2;
				ss2 << std::hex << line; //选用十六进制输出
				ss2 >> d2;
				return d2;
			}

		}
	}
}