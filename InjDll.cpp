/*
A:
1.Inject Dll tool by wjllz
2.Copyright:www.reversecore.com
3.Author:reversecore@gmail.com
4.ʹ�ù��ܣ���ָ����DLLע��ָ���Ľ��� Ҳ����ע�����н��� or ��ָ����DLL��ָ���Ľ�����ж�� ���ߴ����еĽ�����ж��
5.ʹ��ָ��:
a.��WINDOWS���Թ���Ա�������cmd �л�����ǰ�ļ���Ŀ¼ �������з�ʽע��
b.������һ�¸�ʽ��ע�빤�߳����� Ŀ���������|����PID(�����* ����ע�����еĳ���) -e|-i(e i �ֱ���� ж�غ�ע��) szDllPath(Dll����·��)
c.���ӣ�Inject.exe * -i Myhack.dll(��myhack.dll ע�뵱ǰϵͳ���н���)
6.remarks��
������Դ�����Զ��ʦ��<<���򹤳̺���ԭ��>>44��
�������һЩAPI���� �������ܽ�����ע�� ����Ϊ�˶�������Ӣ���Ķ��ĵ����� ע�Ͳ��÷�ǽ����MSDN�ĵ� �������ڿ���վ��� ���������������
������ִ��� ���½� ����Ը���ط��и��õ���� ����ϵ 1214wllz@gmail.com ��ָ�л
*/


/*
B:
`	ͷ�ļ����� ����API��Ҫʹ��
*/
#include	"windows.h"
#include	"stdio.h"
#include	"tlhelp32.h"
#include	"io.h"
#include	"tchar.h"

/*
C:
ȫ�ֱ�������
1.INJECTION_MODE: ����ע��DLL
2.EJECTION_MODE : ����ж��DLL
*/
enum { INJECTION_MODE = 0, EJECTION_MODE };

/*
D:
���Ȩ�� ��ȡ��ע��Զ��EXE�ķ�������
1.lpszPrivilege:SE_DEBUG_NAME
2.bEnablePrvilege:TRUE
*/
BOOL	SetPrivilege(LPCTSTR lpszPrivilege, BOOL bEnablePrivilege)
{
	/*
	������ʼ��
	1.tp:
	2.hToken:
	3.luid:
	*/
	TOKEN_PRIVILEGES	tp;
	HANDLE				hToken;
	LUID				luid;

	/*
	1.OpenProcessToken:
	a.��һ������̹�����access token
	b.acess token:���Ʊ�ʶ�û����û�������û���Ȩ�ޡ�
	c.����1��ProcessHandle-->�������Ʊ��򿪵Ľ��̵ľ����
	d.����2��DesiredAccess-->ָ��һ���������룬ָ���������Ƶ�����������͡�
	e.����3��TokenHandle-->ָ��һ�������ָ�룬�����ں�������ʱ��ʶ�´򿪵ķ�������
	f.����ɹ� ���ط�0ֵ

	2.GetCurrentProcess: ���ص�ǰ���̵�һ��α���
	*/
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
	{
		_tprintf(L"OpenProcessToken error: %u\n", GetLastError());
		return	FALSE;
	}

	/*
	LookupPrvilegeValue:
	a.ָ��ΪNULL ���ز�ѯ�ڶ��������ı���ϵͳ��һ��LUID�ṹ��
	*/
	if (!LookupPrivilegeValue(NULL, lpszPrivilege, &luid))
	{
		_tprintf(L"LookupPrivilegeValue error : %u\n", GetLastError());
		return	FALSE;
	}

	/*
	���²���û��
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
Windows �ߵİ汾�����µĻỰ���� ����Ҫ����������ֶ� �˺��������ж��Ƿ����6�汾
1.Ϊ�������������
2.������������ؼ�
*/
BOOL	IsVistaLater()
{
	/*
	OSVERSIONINFO ����ϵͳ��Ϣ�Ľṹ��
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
δ֪ δ����ȫ���˴� �����Ǻ���ָ��
1.Remarks:��� PF + NtCreateThreadEX
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
����windows�汾������ �߼��汾�����µĻỰ���� ��ͨ��Dllע��CreateRemoteThread�������� ���Դ˺������ڴ������������
�ϵ͵İ汾��CreateRemoteThread���ɣ��ϸߵİ汾�����NtCreateThreadEx ע��
1.hProcess:ָ��ע��Ľ���
2.pThreadProc:ָ���߳�-->loadLibrary
3.pRemoteBuf:ָ����DLL
*/
BOOL	MyCreateRemoteThread
(
	HANDLE	hProcess,
	LPTHREAD_START_ROUTINE	pThreadProc,
	LPVOID	pRemoteBuf
)
{
	/*
	������ʼ��
	1.hThead: �����̵߳ľ��
	2.pFunc:NtCreateThreadEx ����ָ��
	*/
	HANDLE	hThread = NULL;
	FARPROC pFunc = NULL;

	if (IsVistaLater())//����汾���� ����NeCreateThreadEx() ��������ע��
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
	else//��ͨ�汾 ������ͨע��
	{

		/*
		��ָ���Ľ�����������Ҫִ�еĽ���
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
����PID��ȡ���̶�Ӧ��ASCII����
1.dwPID : ���̵�PID
*/
LPCTSTR	GetProcName(DWORD dwPID)
{
	/*
	���� ѭ������ ��ֵ
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
���DLL�Ƿ�ע�뵽Ŀ�����
*/
BOOL	CheckDllInProcess(DWORD dwPID, LPCTSTR szDllPath)
{
	/*
	���� ��������
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
���ָ���Ľ���ע�� ���ע�����н��� ѭ��ʹ��
1.dwPID:ָ����ע��Ľ��̵�PID
2.szDllPath:��ע���DLL��·��
*/
BOOL	InjectDll(DWORD dwPID, LPCTSTR szDllPath)
{
	/*
	������ʼ��
	1.hProcess:��ȡҪע��Ľ��̵ľ��
	2.hThread:
	3.pRemoteBuf:����ҳ�Ļ���ַ
	4.dwBufSize:���ֽ�Ϊ��λ��ָ������ռ�Ĵ�С
	5.pThreadProc:���躯���ĵ�ַ
	6.bRet:���ע���DLL�Ƿ���Ŀ����̵���
	7.hMod:��ȡ��ǰkernel32.dll�ľ��
	8.dwDesiredAccess:������ʵ�����
	9.szProcName[MAX_PATH]:�洢PID��Ӧ������ ��������Ƿ����PID��Ӧ��Ӧ�ó���
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
	a.һ�����̶�������п��ܵķ���Ȩ�ޡ�
	2.OpenProcess:
	a.��һ�����еı��ؽ��̶���
	b.����1��dwDesiredAccess-->���������������SeDebugPrivilegeȨ�ޣ��򲻹ܰ�ȫ��������������Σ�������ķ��ʶ������衣
	c.����2��bInheritHandle-->:�Ƿ񱻼̳�
	d.����3��dwProcessID-->��Ҫ�򿪵Ľ��̱�ʶ��PUD
	e.return:PID->��Ӧ�Ľ��̵ľ��
	*/
	dwDesiredAccess = PROCESS_ALL_ACCESS;

	if (!(hProcess = OpenProcess(dwDesiredAccess, FALSE, dwPID)))
	{
		_tprintf(L"InjectDll() : OpenProcess(%d) failed!!! [%d]\n", dwPID, GetLastError());
		goto INJECTDLL_EXIT;
	}

	/*
	VirtualAllocEx:
	a.�������ύ�����ָ�����̵������ַ�ռ��ڵ��ڴ������״̬��
	b.����1��hProcess-->ָ���Ľ��� �ڴ˷���ռ�
	c:����2��lpAddress-->ָ�������ռ����ʼ��ַ�����ָ��ΪNULL���ɺ������о���
	d:����3��dwSize-->���ֽ�Ϊ��λ��ָ������ռ�Ĵ�С
	e:����4��flAlloctionType-->�����ڴ�ռ������
	I:	MEM_COMMIT:�ύ
	II:	MEM_RESERVE:����
	III:MEM_RESET:����
	f:����5��flProtect-->Ҫ�����ҳ��������ڴ汣��ģʽ��
	g:returan:���ط���ҳ�Ļ���ַ
	*/

	pRemoteBuf = VirtualAllocEx(hProcess, NULL, dwBufSize, MEM_COMMIT, PAGE_READWRITE);

	if (pRemoteBuf == NULL)
	{
		_tprintf(L"InjectDll() : VirtualAllocEx() failed!!! [%d]\n", GetLastError());
		goto	INJECTDLL_EXIT;
	}

	/*
	WriteProcessMemory:
	a.���ض����̽���д�����ݲ���
	b.����1��hProcess-->Ҫ�������ݲ����Ľ���
	c:����2��lpBaseAddress-->ָ������д��δ�
	d:����3��lpBuffer-->Ҫ����д�������
	e:����4��nSize-->д�����
	f.����5��lpNumberOfBytesWritten -->ָ��һ��������ָ�룬
	�����մ���ָ�����̵��ֽ����� �ò����ǿ�ѡ�ġ� ���lpNumberOfBytesWrittenΪNULL����ò��������ԡ�
	*/
	if (!WriteProcessMemory(hProcess, pRemoteBuf, (LPVOID)szDllPath, dwBufSize, NULL))
	{
		_tprintf(L"InjectDll() WirteProcessMemory() failed!!! [%d]\n", GetLastError());
		goto	INJECTDLL_EXIT;
	}

	/*
	1.��ȡkernel32.dll�ľ�� ����GetProcAddress��ȡLoadLibraryW�ĵ�ַ
	2.LPTHREAD_START_ROUTINE:LPTHREAD_START_ROUTINEָ��ĺ����ǻص�����������������Ӧ�ó���ı�д��ʵ�֡�
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
	��LoadLibrary���̵߳ķ�ʽע�룬��Ϊ�汾��ͬ�����µĻỰ���� ���Բ��õ�����������װ��������ע��
	*/
	if (!MyCreateRemoteThread(hProcess, pThreadProc, pRemoteBuf))
	{
		_tprintf(L"InjectDll() : MyCreateRemoteThread() failed!!!\n");
		goto	INJECTDLL_EXIT;
	}

	/*
	���ע���DLL�Ƿ���Ŀ����̵���
	*/
	bRet = CheckDllInProcess(dwPID, szDllPath);
INJECTDLL_EXIT:

	/*
	�쳣�������β���� �磺���»ָ��ڴ�ռ� �ر���Ӧ�����
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
����ƶ��Ľ��̺�DLLж�� ���ж�����н��� ѭ��ʹ��
*/
BOOL	EjectDll(DWORD dwPID, LPCTSTR szDllPath)
{
	/*
	������ʼ��
	1.bFound:�ж��Ƿ��ж�Ӧ��DLL
	2.��������
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
	��ȡָ��PID�ľ���
	*/
	if (INVALID_HANDLE_VALUE == (hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwPID)))
	{
		_tprintf(L"EjectDll() : CreateToolhelpSnapshot(%d) failed!!! [%d]\n", dwPID, GetLastError());
		goto	EJECTDLL_EXIT;
	}

	/*�ṹͬPE���ļ��� ��ʱ�Ǽ����ض�DLL����*/
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
	�ṹ��InjectDll����
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
��DLL ע��/ж�����н���
a.nMode --> ������ע�뻹��ж��DLL
b.szDllPath-->ָ��Dll��·��

*/
BOOL	InjectDllToAll(int nMode, LPCTSTR szDllPath)
{
	/*
	������ʼ��
	1.dwPID-->��ȡ��ǰ���̵�PID
	2.hSnapShot-->���ϵͳ����
	3.pe-->��������ĵ�ǰ����
	4.bMode-->ѭ��ʱ�жϾ���Ĵ������
	*/
	DWORD			dwPID;
	HANDLE			hSnapShot = INVALID_HANDLE_VALUE;
	PROCESSENTRY32	pe;
	BOOL			bMore = FALSE;

	pe.dwSize = sizeof(PROCESSENTRY32);

	/*
	CreateToolhelp32Snapshot:
	a.��ȡָ�����̵Ŀ��գ��Լ���Щ����ʹ�õĶѣ�ģ����̡߳�
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
	a.�����й�ϵͳ�����������ĵ�һ�����̵���Ϣ��
	b.����1��hSnapshot-->��֮ǰ����CreateToolhelp32Snapshot�������صĿ��վ����
	c.����2��lppe-->ָ��һ��PROCESSENTRY32�ṹ��
	d.returns:������ڷ���TRUE ���򷵻�FALSE
	e.Remarks:��������dwSize

	2.PROCESSENTRY32:
	a.����һ��PE�ĸ�����Ϣ
	b.dwSize-->�ṹ��Ĵ�С
	c.th32ProcessID-->PID
	d.szExeFile-->name
	*/
	bMore = Process32First(hSnapShot, &pe);

	for (; bMore; bMore = Process32Next(hSnapShot, &pe))
	{
		dwPID = pe.th32ProcessID;
		/*
		����һ������Ϊϵͳ���� ��Ȩע��
		*/
		if (dwPID < 100 || _tcsicmp(pe.szExeFile, L"smss.exe") || !_tcsicmp(pe.szExeFile, L"csrss.exe"))
		{
			_tprintf(L"%s(%d) => System:Process...Dll %s is impossible!\n", pe.szExeFile, dwPID, nMode == INJECTION_MODE ? L"Injection" : L"Ejectioin");
			continue;
		}

		/*
		����nMode��ֵ ����ж�ػ���ע�����
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
��Ե�һ����ע��\ж��
1.szProc-->Ŀ��ע�����
2.nMode-->ȷ����ע�뻹��ж��
3.szDllPath-->Ŀ��DLL
*/
BOOL	InjectDllToOne(LPCTSTR	szProc, int nMode, LPCTSTR szDllPath)
{
	/*
	��������
	a.nLen-->��ȡĿ����̵ĳ��� �����Ƿ�ΪPIDʱʹ��
	b.��������������InjectDllToAll����
	*/
	int			    i = 0, nLen = (int)_tcslen(szProc);
	DWORD			dwPID = 0;
	HANDLE			hSnapShot = INVALID_HANDLE_VALUE;
	PROCESSENTRY32	pe;
	BOOL			bMore = FALSE;

	/*
	���һֱ�����Ϊ���� ��ΪPID ����������
	*/
	for (i = 0; i < nLen; i++)
		if (!_istdigit(szProc[i]))
			break;

	if (i == nLen)//PID��ʽ
	{
		/*
		����nMode��ֵ���д���
		*/
		dwPID = (DWORD)_tstol(szProc);

		if (nMode == INJECTION_MODE)
			InjectDll(dwPID, szDllPath);
		else
			EjectDll(dwPID, szDllPath);

	}
	else//name ��ʽ
	{
		/*
		��ȡϵͳ���� ѭ�������ȽϺ�ȥPID Ȼ�����nMode ��ֵ ����ж�ػ���ע��Ĵ���
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
����ʹ��
*/
BOOL	Initialize(LPCTSTR	szOption, LPCTSTR szDllPath)
{
	/*
	��Ӧ�������
	*/
	if (_tcsicmp(szOption, L"-i") && _tcsicmp(szOption, L"-e"))	return FALSE;

	if (_taccess(szDllPath, 0) == -1) return FALSE;

	return TRUE;
}

/*��Ҫ��������MAIN*/
int	_tmain(int argc, TCHAR *argv[])
{
	/*
	������ʼ��
	1.BUSIZE:���ڽ�����������·�����Կ��ַ���β���ַ���(szPath)�Ļ������Ĵ�С
	2.nMode:�����жϵ�ǰ������ж��DLL����ע��DLL ��ʼֵΪע��DLL
	3.szPath[MAX_SIZE]:ָ�򻺳�����ָ�룬�û�����������������·�����Կ��ַ���β���ַ�����
	*/
#define	BUFSIZE			(1024)
	int		nMode = INJECTION_MODE;
	TCHAR	szPath[BUFSIZE] = L"";

	/*
	�ж��û��������Ƿ���ȷ �������ȷ ����ʾ��ȷ�������ʽ
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
	a.����ָ���ļ�������·�����ļ��� ���ʧ�� �����Ϣ��ʾ�û�
	b.ע��GetFullPathName�������������ڶ��߳�Ӧ�ó���������롣
	c.����1��lpFileName--> ָ����Ҫ��ȡ·��������
	����2��nBufferLength-->���ڽ�����������·�����Կ��ַ���β���ַ���(szPath)�Ļ������Ĵ�С��
	����3��lpBuffer-->ָ�򻺳�����ָ�룬�û�����������������·�����Կ��ַ���β���ַ�����
	����4��lpFilePart-->ָ�򻺳�����ָ�룬�û���������·���������ļ���������ĵ�ַ����lpBuffer�ڣ���
	�ò���������NULL��
	���lpBuffer����Ŀ¼�������ļ���lpFilePart�����㡣
	d.����ֵ��
	���ʧ�ܣ�����0
	�������3̫С�� �򷵻�����ĳ���
	����ɹ� �򷵻ػ���ַ����ĳ���
	*/
	if (!GetFullPathName(argv[3], BUFSIZE, szPath, NULL))
	{
		_tprintf(L"GetFullPathName() failed! [%d]", GetLastError());
		return	1;
	}

	/*
	_tacess:
	a.�Է��ص�szPath���м��� �ж��Ƿ���� ���ʧ�� �����Ϣ��ʾ�û�
	b.ʹ��ʱҪ����ͷ�ļ�(#include "io.h")
	c.����-1˵�������� ����0��ʾ�Ƿ����
	*/
	if (_taccess(szPath, 0) == -1)
	{
		_tprintf(L"There is no \"%s\" file!\n", szPath);
		return FALSE;
	}

	/*
	SetPrivilege:
	a.����Ȩ�� ��ȷ����Ŀ��������㹻��Ȩ�޽���ע��/ж��DLL���� ���ʧ�� �����Ϣ��ʾ�û�
	b.
	*/
	if (!SetPrivilege(SE_DEBUG_NAME, TRUE))
		return	1;

	/*
	_tcsicmp:
	a.�ж��û��Ĳ�����ж�ػ���ע�� Ĭ��Ϊж�� ���Ϊע�� �ı�nMode��ֵ
	b.����ֵΪ����1-����2 �������Ϊ0 ��֤���������
	*/
	if (!_tcsicmp(argv[2], L"-e"))	nMode = EJECTION_MODE;

	/*
	�����û�����Ĳ��������ж��Ƿ�Ϊȫ��ע��/ж��
	1.'*' ����ȫ��
	2.InjectDllToAll �����н���ע��/ж��
	3.InjectDllToOne ��ָ������ע��/ж��
	*/
	if (!_tcsicmp(argv[1], L"*"))
		InjectDllToAll(nMode, szPath);
	else
		InjectDllToOne(argv[1], nMode, szPath);

	/*������ֹ*/
	return 0;
}
