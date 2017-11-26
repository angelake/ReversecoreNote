/*
A:
1.Inject Dll tool by wjllz
2.Copyright:www.reversecore.com
3.Author:reversecore@gmail.com
4.使用功能：将指定的DLL注入指定的进程 也可以注入所有进程 or 将指定的DLL从指定的进程中卸载 或者从所有的进程中卸载
5.使用指南:
a.打开WINDOWS：以管理员身份运行cmd 切换至当前文件的目录 以命令行方式注入
b.输入以一下格式：注入工具程序名 目标进程名字|或者PID(如果以* 代表注入所有的程序) -e|-i(e i 分别代表 卸载和注入) szDllPath(Dll所在路径)
c.例子：Inject.exe * -i Myhack.dll(将myhack.dll 注入当前系统所有进程)
6.remarks：
程序来源于李承远老师的<<逆向工程核心原理>>44章
本程序对一些API函数 函数功能进行了注释 由于为了锻炼个人英文阅读文档能力 注释采用翻墙查用MSDN文档 个别国外黑客网站完成 翻译理解能力有限
难免出现错误 请谅解 如果对个别地方有更好的理解 请联系 1214wllz@gmail.com 万分感谢
*/


/*
B:
`	头文件声明 调用API需要使用
*/
#include	"windows.h"
#include	"stdio.h"
#include	"tlhelp32.h"
#include	"io.h"
#include	"tchar.h"

/*
C:
全局变量声明
1.INJECTION_MODE: 代表注入DLL
2.EJECTION_MODE : 代表卸载DLL
*/
enum { INJECTION_MODE = 0, EJECTION_MODE };

/*
D:
提高权限 获取能注入远程EXE的访问令牌
1.lpszPrivilege:SE_DEBUG_NAME
2.bEnablePrvilege:TRUE
*/
BOOL	SetPrivilege(LPCTSTR lpszPrivilege, BOOL bEnablePrivilege)
{
	/*
	变量初始化
	1.tp:
	2.hToken:
	3.luid:
	*/
	TOKEN_PRIVILEGES	tp;
	HANDLE				hToken;
	LUID				luid;

	/*
	1.OpenProcessToken:
	a.打开一个与进程关联的access token
	b.acess token:令牌标识用户，用户的组和用户的权限。
	c.参数1：ProcessHandle-->访问令牌被打开的进程的句柄。
	d.参数2：DesiredAccess-->指定一个访问掩码，指定访问令牌的请求访问类型。
	e.参数3：TokenHandle-->指向一个句柄的指针，用于在函数返回时标识新打开的访问令牌
	f.如果成功 返回非0值

	2.GetCurrentProcess: 返回当前进程的一个伪句柄
	*/
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
	{
		_tprintf(L"OpenProcessToken error: %u\n", GetLastError());
		return	FALSE;
	}

	/*
	LookupPrvilegeValue:
	a.指定为NULL 返回查询第二个参数的本地系统的一个LUID结构体
	*/
	if (!LookupPrivilegeValue(NULL, lpszPrivilege, &luid))
	{
		_tprintf(L"LookupPrivilegeValue error : %u\n", GetLastError());
		return	FALSE;
	}

	/*
	以下部分没懂
	*/
	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;

	if (bEnablePrivilege)
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	else
		tp.Privileges[0].Attributes = 0;

	if (!AdjustTokenPrivileges(
		hToken,
		FALSE,
		&tp,
		sizeof(TOKEN_PRIVILEGES),
		(PTOKEN_PRIVILEGES)NULL,
		(PDWORD)NULL))
	{
		_tprintf(L"AdjustTokenPrvileges error: %u\n", GetLastError());
		return FALSE;
	}

	if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)
	{
		_tprintf(L"The token does not have the specified privilege. \n");
		return	FALSE;
	}

	return	TRUE;

}

/*
E:
Windows 高的版本采用新的会话机制 所以要采用特殊的手段 此函数用来判断是否高于6版本
1.为特殊情况返回真
2.非特殊情况返回假
*/
BOOL	IsVistaLater()
{
	/*
	OSVERSIONINFO 操作系统信息的结构体
	*/
	OSVERSIONINFO	osvi;
	ZeroMemory(&osvi, sizeof(OSVERSIONINFO));
	osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);

	GetVersionEx(&osvi);

	if (osvi.dwMajorVersion >= 6) return TRUE;

	return	FALSE;
}

/*
F:
未知 未能完全理解此处 估计是函数指针
1.Remarks:拆分 PF + NtCreateThreadEX
*/
typedef	DWORD(WINAPI *PFNTCREATETHREADEX)
(
	PHANDLE								ThreadHandle,
	ACCESS_MASK							DesiredAcess,
	LPVOID								ObjectAttributes,
	HANDLE								ProcessHandle,
	LPTHREAD_START_ROUTINE				lpStartAddress,
	LPVOID								lpParameter,
	BOOL								CreateSuspended,
	DWORD								dwStackSize,
	DWORD								dw1,
	DWORD								dw2,
	LPVOID								Unkown
	);

/*
G:
由于windows版本的升高 高级版本采用新的会话机制 普通的Dll注入CreateRemoteThread不再适用 所以此函数用于处理这两种情况
较低的版本用CreateRemoteThread即可，较高的版本则采用NtCreateThreadEx 注入
1.hProcess:指定注入的进程
2.pThreadProc:指定线程-->loadLibrary
3.pRemoteBuf:指定的DLL
*/
BOOL	MyCreateRemoteThread
(
	HANDLE	hProcess,
	LPTHREAD_START_ROUTINE	pThreadProc,
	LPVOID	pRemoteBuf
)
{
	/*
	变量初始化
	1.hThead: 挂起线程的句柄
	2.pFunc:NtCreateThreadEx 函数指针
	*/
	HANDLE	hThread = NULL;
	FARPROC pFunc = NULL;

	if (IsVistaLater())//如果版本过高 采用NeCreateThreadEx() 函数进行注入
	{
		pFunc = GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtCreateThreadEx");

		if (pFunc == NULL)
		{
			_tprintf(L"MyCreateRemoteThread() : "\
				L"GetProcAddress(\"NtCreateThreadEx\") failed!!! [%d]", GetLastError());
			return	FALSE;
		}

		((PFNTCREATETHREADEX)pFunc)(&hThread,
			0x1FFFFF,
			NULL,
			hProcess,
			pThreadProc,
			pRemoteBuf,
			FALSE,
			NULL,
			NULL,
			NULL,
			NULL);

		if (hThread == NULL)
		{
			_tprintf(L"MyCeateRemoteThead() : NtCreateThreadEx() failed!!! [%d]\n", GetLastError());
			return	FALSE;
		}
	}
	else//普通版本 采用普通注入
	{

		/*
		在指定的进程中运行想要执行的进程
		*/
		hThread = CreateRemoteThread(hProcess, NULL, 0, pThreadProc, pRemoteBuf, 0, NULL);

		if (hThread == NULL)
		{
			_tprintf(L"MyCreateRemoteThread() : CreateRemoteThread() failed!!! [%d]\n", GetLastError());
			return	FALSE;
		}
	}

	if (WAIT_FAILED == WaitForSingleObject(hThread, INFINITE))
	{
		_tprintf(L"MyCreateRemoteThread(): WaitForSingleObject() failed!!! [%d]\n", GetLastError());
		return	FALSE;
	}

	return	TRUE;
}

/*
H:
根据PID获取进程对应的ASCII名称
1.dwPID : 进程的PID
*/
LPCTSTR	GetProcName(DWORD dwPID)
{
	/*
	类似 循环遍历 找值
	*/
	HANDLE	hSnapshot = INVALID_HANDLE_VALUE;
	PROCESSENTRY32	pe;
	BOOL			bMore = FALSE;

	pe.dwSize = sizeof(PROCESSENTRY32);
	hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPALL, NULL);

	if (hSnapshot == INVALID_HANDLE_VALUE)
	{
		_tprintf(L"GetProcName() : CreateToolhep32Snapshot() failed!!! [%d]", GetLastError());
		return	NULL;
	}

	bMore = Process32First(hSnapshot, &pe);
	for (; bMore; bMore = Process32Next(hSnapshot, &pe))
	{
		if (dwPID == pe.th32ProcessID)
		{
			CloseHandle(hSnapshot);
			return	pe.szExeFile;
		}
	}

	CloseHandle(hSnapshot);

	return	NULL;

}

/*
I:
检测DLL是否注入到目标进程
*/
BOOL	CheckDllInProcess(DWORD dwPID, LPCTSTR szDllPath)
{
	/*
	类似 不做解释
	*/
	BOOL	bMore = FALSE;
	HANDLE	hSnapshot = INVALID_HANDLE_VALUE;
	MODULEENTRY32	me = { sizeof(me), };

	if (INVALID_HANDLE_VALUE == (hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwPID)))
	{
		_tprintf(L"CheckDllInProcess() : CreateToolhep32Snapshot(%d) failed!!! [%d]\n", dwPID, GetLastError());
		return	FALSE;
	}

	bMore = Module32First(hSnapshot, &me);

	for (; bMore; bMore = Module32Next(hSnapshot, &me))
	{
		if (!_tcsicmp(me.szModule, szDllPath) || !_tcsicmp(me.szExePath, szDllPath))
		{
			CloseHandle(hSnapshot);
			return	TRUE;
		}
	}

	CloseHandle(hSnapshot);
	return	FALSE;
}

/*
J:
针对指定的进程注入 如果注入所有进程 循环使用
1.dwPID:指定需注入的进程的PID
2.szDllPath:待注入的DLL的路径
*/
BOOL	InjectDll(DWORD dwPID, LPCTSTR szDllPath)
{
	/*
	变量初始化
	1.hProcess:获取要注入的进程的句柄
	2.hThread:
	3.pRemoteBuf:分配页的基地址
	4.dwBufSize:以字节为单位，指定分配空间的大小
	5.pThreadProc:所需函数的地址
	6.bRet:检测注入的DLL是否在目标进程当中
	7.hMod:获取当前kernel32.dll的句柄
	8.dwDesiredAccess:所需访问的令牌
	9.szProcName[MAX_PATH]:存储PID对应的名字 用来检测是否存在PID对应的应用程序
	*/
	HANDLE					hProcess = NULL;
	HANDLE					hThread = NULL;
	LPVOID					pRemoteBuf = NULL;
	DWORD					dwBufSize = (DWORD)(_tcslen(szDllPath) + 1) * sizeof(TCHAR);
	LPTHREAD_START_ROUTINE	pThreadProc = NULL;
	BOOL					bRet = FALSE;
	HMODULE					hMod = NULL;
	DWORD					dwDesiredAccess = 0;
	TCHAR					szProcName[MAX_PATH] = { 0, };

	/*
	1.PRCOESS_ALL_ACCESS:
	a.一个过程对象的所有可能的访问权限。
	2.OpenProcess:
	a.打开一个现有的本地进程对象。
	b.参数1：dwDesiredAccess-->如果调用者启用了SeDebugPrivilege权限，则不管安全描述符的内容如何，所请求的访问都被授予。
	c.参数2：bInheritHandle-->:是否被继承
	d.参数3：dwProcessID-->需要打开的进程标识：PUD
	e.return:PID->对应的进程的句柄
	*/
	dwDesiredAccess = PROCESS_ALL_ACCESS;

	if (!(hProcess = OpenProcess(dwDesiredAccess, FALSE, dwPID)))
	{
		_tprintf(L"InjectDll() : OpenProcess(%d) failed!!! [%d]\n", dwPID, GetLastError());
		goto INJECTDLL_EXIT;
	}

	/*
	VirtualAllocEx:
	a.保留，提交或更改指定进程的虚拟地址空间内的内存区域的状态。
	b.参数1：hProcess-->指定的进程 在此分配空间
	c:参数2：lpAddress-->指定想分配空间的起始地址，如果指定为NULL，由函数自行决定
	d:参数3：dwSize-->以字节为单位，指定分配空间的大小
	e:参数4：flAlloctionType-->分配内存空间的类型
	I:	MEM_COMMIT:提交
	II:	MEM_RESERVE:保留
	III:MEM_RESET:更改
	f:参数5：flProtect-->要分配的页面区域的内存保护模式。
	g:returan:返回分配页的基地址
	*/

	pRemoteBuf = VirtualAllocEx(hProcess, NULL, dwBufSize, MEM_COMMIT, PAGE_READWRITE);

	if (pRemoteBuf == NULL)
	{
		_tprintf(L"InjectDll() : VirtualAllocEx() failed!!! [%d]\n", GetLastError());
		goto	INJECTDLL_EXIT;
	}

	/*
	WriteProcessMemory:
	a.对特定进程进行写入数据操作
	b.参数1：hProcess-->要进行数据操作的进程
	c:参数2：lpBaseAddress-->指定数据写向何处
	d:参数3：lpBuffer-->要进行写入的数据
	e:参数4：nSize-->写入多少
	f.参数5：lpNumberOfBytesWritten -->指向一个变量的指针，
	它接收传入指定进程的字节数。 该参数是可选的。 如果lpNumberOfBytesWritten为NULL，则该参数被忽略。
	*/
	if (!WriteProcessMemory(hProcess, pRemoteBuf, (LPVOID)szDllPath, dwBufSize, NULL))
	{
		_tprintf(L"InjectDll() WirteProcessMemory() failed!!! [%d]\n", GetLastError());
		goto	INJECTDLL_EXIT;
	}

	/*
	1.获取kernel32.dll的句柄 调用GetProcAddress获取LoadLibraryW的地址
	2.LPTHREAD_START_ROUTINE:LPTHREAD_START_ROUTINE指向的函数是回调函数，必须由宿主应用程序的编写者实现。
	*/
	hMod = GetModuleHandle(L"kernel32.dll");

	if (hMod == NULL)
	{
		_tprintf(L"InjectDll() : GetModuleHandle(\"kernel32.dll\") failed!!! [%d]\n", GetLastError());
		goto	INJECTDLL_EXIT;
	}

	pThreadProc = (LPTHREAD_START_ROUTINE)GetProcAddress(hMod, "LoadLibraryW");
	if (pThreadProc == NULL)
	{
		_tprintf(L"InjectDll() : GetProcAddress(\"LoadLibraryW\") failed!!! [%d]\n", GetLastError());
		goto	INJECTDLL_EXIT;
	}

	/*
	将LoadLibrary以线程的方式注入，因为版本不同引入新的会话机制 所以采用单独函数，封装处理，进行注入
	*/
	if (!MyCreateRemoteThread(hProcess, pThreadProc, pRemoteBuf))
	{
		_tprintf(L"InjectDll() : MyCreateRemoteThread() failed!!!\n");
		goto	INJECTDLL_EXIT;
	}

	/*
	检测注入的DLL是否在目标进程当中
	*/
	bRet = CheckDllInProcess(dwPID, szDllPath);
INJECTDLL_EXIT:

	/*
	异常处理和收尾处理 如：重新恢复内存空间 关闭相应句柄等
	*/
	wsprintf(szProcName, L"%s", GetProcName(dwPID));
	if (szProcName[0] == '\0')
		_tcscpy_s(szProcName, L"(no_prcoess)");

	_tprintf(L"%s(%d) %s!!! [%d]\n", szProcName, dwPID, bRet ? L"SUCESS" : L"-->>FAILURE", GetLastError());

	if (pRemoteBuf)
		VirtualFreeEx(hProcess, pRemoteBuf, 0, MEM_RELEASE);

	if (hThread)
		CloseHandle(hThread);

	if (hProcess)
		CloseHandle(hProcess);

	return	bRet;


}

/*
K:
针对制定的进程和DLL卸载 如果卸载所有进程 循环使用
*/
BOOL	EjectDll(DWORD dwPID, LPCTSTR szDllPath)
{
	/*
	变量初始化
	1.bFound:判断是否有对应的DLL
	2.其余类似
	*/
	BOOL					bMore = FALSE, bFound = FALSE, bRet = FALSE;
	HANDLE					hSnapshot = INVALID_HANDLE_VALUE;
	HANDLE					hProcess = NULL;
	HANDLE					hThread = NULL;
	MODULEENTRY32			me = { sizeof(me), };
	LPTHREAD_START_ROUTINE	pThreadProc = NULL;
	HMODULE					hMod = NULL;
	DWORD					dwDesiredAccess = 0;
	TCHAR					szProcName[MAX_PATH] = { 0, };

	/*
	获取指定PID的镜像
	*/
	if (INVALID_HANDLE_VALUE == (hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwPID)))
	{
		_tprintf(L"EjectDll() : CreateToolhelpSnapshot(%d) failed!!! [%d]\n", dwPID, GetLastError());
		goto	EJECTDLL_EXIT;
	}

	/*结构同PE处的检索 此时是检验特定DLL而已*/
	bMore = Module32First(hSnapshot, &me);

	for (; bMore; bMore = Module32Next(hSnapshot, &me))
		if (!_tcsicmp(me.szModule, szDllPath) || !_tcsicmp(me.szExePath, szDllPath))
		{
			bFound = TRUE;
			break;
		}

	if (!bFound)
	{
		_tprintf(L"EjectDll() : There is not %s module in process(%d) memory!!!\n", szDllPath, dwPID);
		goto	EJECTDLL_EXIT;
	}

	/*
	结构与InjectDll类似
	*/
	dwDesiredAccess = PROCESS_ALL_ACCESS;
	if (!(hProcess = OpenProcess(dwDesiredAccess, FALSE, dwPID)))
	{
		_tprintf(L"EjectDll() : OpenProcess(%d) failed!!! [%d]\n", dwPID, GetLastError());
		goto	EJECTDLL_EXIT;
	}

	hMod = GetModuleHandle(L"kernel32.dll");
	if (hMod == NULL)
	{
		_tprintf(L"EjectDll() : GetModuleHandle(\"kernel32.dll\") failed!!! [%d]\n", GetLastError());
		goto	EJECTDLL_EXIT;
	}
	pThreadProc = (LPTHREAD_START_ROUTINE)GetProcAddress(hMod, "FreeLibrary");

	if (pThreadProc == NULL)
	{
		_tprintf(L"EjectDll() GetProcAddress(\"FreeLibrary\") failed!!! [%d]\n", GetLastError());
		goto	EJECTDLL_EXIT;
	}

	if (!MyCreateRemoteThread(hProcess, pThreadProc, me.modBaseAddr))
	{
		_tprintf(L"IjectDll() : MyCreateRemoteThread() failed!!!\n");
		goto	EJECTDLL_EXIT;
	}

	bRet = TRUE;


EJECTDLL_EXIT:
	_tcscpy_s(szProcName, GetProcName(dwPID));
	_tprintf(L"%s(%d) %s!!! [%d]\n", szProcName, dwPID, bRet ? L"SUCESS" : L"-->>FAILURE", GetLastError());
	if (hThread)
		CloseHandle(hThread);

	if (hProcess)
		CloseHandle(hProcess);

	if (hSnapshot != INVALID_HANDLE_VALUE)
		CloseHandle(hSnapshot);

	return	bRet;
}

/*
L:
将DLL 注入/卸载所有进程
a.nMode --> 决定是注入还是卸载DLL
b.szDllPath-->指定Dll的路径

*/
BOOL	InjectDllToAll(int nMode, LPCTSTR szDllPath)
{
	/*
	变量初始化
	1.dwPID-->获取当前进程的PID
	2.hSnapShot-->获得系统快照
	3.pe-->快照里面的当前进程
	4.bMode-->循环时判断句柄的存在与否
	*/
	DWORD			dwPID;
	HANDLE			hSnapShot = INVALID_HANDLE_VALUE;
	PROCESSENTRY32	pe;
	BOOL			bMore = FALSE;

	pe.dwSize = sizeof(PROCESSENTRY32);

	/*
	CreateToolhelp32Snapshot:
	a.获取指定进程的快照，以及这些进程使用的堆，模块和线程。
	b.TH32CS_SNAPALL-->
	*/
	hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPALL, NULL);
	if (hSnapShot == INVALID_HANDLE_VALUE)
	{
		_tprintf(L"InjectDllToAll() : CreateToolhelp32Snapshot() failed!!! [%d]", GetLastError());
		return	FALSE;
	}

	/*
	1.Process32First:
	a.检索有关系统快照中遇到的第一个进程的信息。
	b.参数1：hSnapshot-->从之前调用CreateToolhelp32Snapshot函数返回的快照句柄。
	c.参数2：lppe-->指向一个PROCESSENTRY32结构体
	d.returns:如果存在返回TRUE 否则返回FALSE
	e.Remarks:必须计算出dwSize

	2.PROCESSENTRY32:
	a.返回一个PE的各种信息
	b.dwSize-->结构体的大小
	c.th32ProcessID-->PID
	d.szExeFile-->name
	*/
	bMore = Process32First(hSnapShot, &pe);

	for (; bMore; bMore = Process32Next(hSnapShot, &pe))
	{
		dwPID = pe.th32ProcessID;
		/*
		满足一下条件为系统进程 无权注入
		*/
		if (dwPID < 100 || _tcsicmp(pe.szExeFile, L"smss.exe") || !_tcsicmp(pe.szExeFile, L"csrss.exe"))
		{
			_tprintf(L"%s(%d) => System:Process...Dll %s is impossible!\n", pe.szExeFile, dwPID, nMode == INJECTION_MODE ? L"Injection" : L"Ejectioin");
			continue;
		}

		/*
		根据nMode的值 进行卸载或者注入操作
		*/
		if (nMode == INJECTION_MODE)
			InjectDll(dwPID, szDllPath);
		else
			EjectDll(dwPID, szDllPath);
	}

	CloseHandle(hSnapShot);
	return	TRUE;
}

/*
M:
针对单一进程注入\卸载
1.szProc-->目标注入进程
2.nMode-->确定是注入还是卸载
3.szDllPath-->目的DLL
*/
BOOL	InjectDllToOne(LPCTSTR	szProc, int nMode, LPCTSTR szDllPath)
{
	/*
	变量声明
	a.nLen-->获取目标进程的长度 检索是否为PID时使用
	b.其余声明与上文InjectDllToAll类似
	*/
	int			    i = 0, nLen = (int)_tcslen(szProc);
	DWORD			dwPID = 0;
	HANDLE			hSnapShot = INVALID_HANDLE_VALUE;
	PROCESSENTRY32	pe;
	BOOL			bMore = FALSE;

	/*
	如果一直到最后都为数字 则为PID 否则是名字
	*/
	for (i = 0; i < nLen; i++)
		if (!_istdigit(szProc[i]))
			break;

	if (i == nLen)//PID形式
	{
		/*
		根据nMode的值进行处理
		*/
		dwPID = (DWORD)_tstol(szProc);

		if (nMode == INJECTION_MODE)
			InjectDll(dwPID, szDllPath);
		else
			EjectDll(dwPID, szDllPath);

	}
	else//name 形式
	{
		/*
		获取系统快照 循环检索比较后去PID 然后根据nMode 的值 进行卸载或者注入的处理
		*/
		pe.dwSize = sizeof(PROCESSENTRY32);
		hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPALL, NULL);

		if (hSnapShot == INVALID_HANDLE_VALUE)
		{
			_tprintf(L"InjectDllToOne() : CreateToolhelp32Snapshot() failed!!! [%d]", GetLastError());
			return	FALSE;
		}

		bMore = Process32First(hSnapShot, &pe);

		for (; bMore; bMore = Process32Next(hSnapShot, &pe))
		{
			dwPID = pe.th32ProcessID;

			if (dwPID < 100) continue;

			if (!_tcsicmp(pe.szExeFile, szProc))
			{
				if (nMode == INJECTION_MODE)
					InjectDll(dwPID, szDllPath);
				else
					EjectDll(dwPID, szDllPath);
			}
		}
		CloseHandle(hSnapShot);
	}

	return	TRUE;
}

/*
N:
后期使用
*/
BOOL	Initialize(LPCTSTR	szOption, LPCTSTR szDllPath)
{
	/*
	相应变量检查
	*/
	if (_tcsicmp(szOption, L"-i") && _tcsicmp(szOption, L"-e"))	return FALSE;

	if (_taccess(szDllPath, 0) == -1) return FALSE;

	return TRUE;
}

/*主要函数流程MAIN*/
int	_tmain(int argc, TCHAR *argv[])
{
	/*
	变量初始化
	1.BUSIZE:用于接收驱动器和路径的以空字符结尾的字符串(szPath)的缓冲区的大小
	2.nMode:用来判断当前程序是卸载DLL还是注入DLL 初始值为注入DLL
	3.szPath[MAX_SIZE]:指向缓冲区的指针，该缓冲区接收驱动器和路径的以空字符结尾的字符串。
	*/
#define	BUFSIZE			(1024)
	int		nMode = INJECTION_MODE;
	TCHAR	szPath[BUFSIZE] = L"";

	/*
	判断用户的输入是否正确 如果不正确 则提示正确的输入格式
	*/
	if (argc != 4 || (_tcsicmp(argv[2], L"-i") && _tcsicmp(argv[2], L"-e")))
	{
		_tprintf(L"\n %s (Ver 1.1.1) - Dll injection/Ejection Utility!!!\n"\
			L"	www.reversecore.com\n"\
			L"	reversecore@gmail.com\n"\
			L"\n USAGE: %s <procname|pid|*> <-i|-e> <dll path>\n\n",
			argv[0], argv[0]);
		return 1;
	}

	/*
	GetFullPathName:
	a.检索指定文件的完整路径和文件名 如果失败 输出信息提示用户
	b.注意GetFullPathName函数不建议用于多线程应用程序或共享库代码。
	c.参数1：lpFileName--> 指定需要获取路径的名字
	参数2：nBufferLength-->用于接收驱动器和路径的以空字符结尾的字符串(szPath)的缓冲区的大小。
	参数3：lpBuffer-->指向缓冲区的指针，该缓冲区接收驱动器和路径的以空字符结尾的字符串。
	参数4：lpFilePart-->指向缓冲区的指针，该缓冲区接收路径中最终文件名称组件的地址（在lpBuffer内）。
	该参数可以是NULL。
	如果lpBuffer引用目录而不是文件，lpFilePart接收零。
	d.返回值：
	如果失败：返回0
	如果参数3太小了 则返回所需的长度
	如果成功 则返回获得字符串的长度
	*/
	if (!GetFullPathName(argv[3], BUFSIZE, szPath, NULL))
	{
		_tprintf(L"GetFullPathName() failed! [%d]", GetLastError());
		return	1;
	}

	/*
	_tacess:
	a.对返回的szPath进行检验 判断是否存在 如果失败 输出信息提示用户
	b.使用时要包含头文件(#include "io.h")
	c.返回-1说明不存在 参数0表示是否存在
	*/
	if (_taccess(szPath, 0) == -1)
	{
		_tprintf(L"There is no \"%s\" file!\n", szPath);
		return FALSE;
	}

	/*
	SetPrivilege:
	a.提升权限 以确定对目标进程有足够的权限进行注入/卸载DLL处理 如果失败 输出信息提示用户
	b.
	*/
	if (!SetPrivilege(SE_DEBUG_NAME, TRUE))
		return	1;

	/*
	_tcsicmp:
	a.判断用户的操作是卸载还是注入 默认为卸载 如果为注入 改变nMode的值
	b.返回值为参数1-参数2 所以如果为0 则证明他们相等
	*/
	if (!_tcsicmp(argv[2], L"-e"))	nMode = EJECTION_MODE;

	/*
	根据用户输入的参数进行判断是否为全局注入/卸载
	1.'*' 代表全局
	2.InjectDllToAll 对所有进程注入/卸载
	3.InjectDllToOne 对指定进程注入/卸载
	*/
	if (!_tcsicmp(argv[1], L"*"))
		InjectDllToAll(nMode, szPath);
	else
		InjectDllToOne(argv[1], nMode, szPath);

	/*程序终止*/
	return 0;
}
