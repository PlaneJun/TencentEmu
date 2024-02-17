// NoBanMe.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <iostream>
#include "xorstr.hpp"
#include "./aow/aow.hpp"
#include "./drv/BCDriver.h"


BC bc{};
int main()
{
	bool bInit = false;
	int Device = bc.Control();
	if (Device != 0xBCDE)
	{
		auto filecode = bc.DriverFile();
		if (filecode != 0)
		{
			printf(xorstr_("驱动失败！错误代码: 0x%x\n"), filecode);
		}
		else
		{
			bc.InitializeDriver();
			Device = bc.Control();
			if (Device == 0xBCDE)
			{
				printf(xorstr_("驱动成功\n"));
				bInit = true;
			}
			else
			{
				printf(xorstr_("驱动失败\n"));
			}
		}
	}
	else
	{
		printf(xorstr_("驱动已经安装！\n"));
		bInit = true;
	}

	if (bInit == true)
	{
		aow::init_work_dir();

		HWND aow_hwnd = aow::get_game_hwnd();
		uint32_t aow_pid = aow::get_game_pid();
		if (!aow_hwnd || !aow_pid)
		{
			return 0;
		}

		printf("aow -> hwnd = 0x%x, pid = 0x%x\n", aow_hwnd, aow_pid);

		auto game_pid = aow::get_pid_by_name("com.tencent.tmgp.sgame");
		printf("game pid = %d\n", game_pid);

		auto libgamecore_base = aow::get_so_base(game_pid, "libGameCore.so");
		if (libgamecore_base <= 0)
		{
			return 0;
		}
		printf("libGameCore.so = %p\n", libgamecore_base);

		bc.SetPid(aow_pid);

		uint64_t ptr = bc.read<uint64_t>(libgamecore_base+0x3700AA0);
		ptr = bc.read<uint64_t>(ptr);
		ptr = bc.read<uint64_t>(ptr);
		ptr = bc.read<uint64_t>(ptr+0x2C8);
		ptr = bc.read<uint64_t>(ptr+0x48);
		uint64_t self_ptr = bc.read<uint64_t>(ptr + 0xD8);
		ptr = bc.read<uint64_t>(ptr + 0x18);

		uint64_t addr_my = bc.read<uint64_t>(ptr + bc.read<uint32_t>(self_ptr+0x10) * 0x18);

		uint32_t hp = bc.read<uint32_t>(bc.read<uint64_t>(bc.read<uint64_t>(addr_my+0x10)+0x160)+0x98) / 8192;


		printf("%d\n", hp);
		
	}

	return 0;
}


