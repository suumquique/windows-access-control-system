#ifndef UNICODE
#define UNICODE
#endif

#ifndef MAIN_MODULE
#define MAN_MODULE

#pragma comment(lib, "Advapi32.lib")
#include <stdio.h>
#include <windows.h>
#include <lm.h>
#include <sddl.h>
#include <AclAPI.h>
#include <fileapi.h>

typedef struct _account {
	wchar_t* userName;
	wchar_t* domainName;
} Account;

HANDLE createFileAndGetDescriptor();
Account getUserAccountFromSID(PSID lpSID);
DWORD printFileSecurityInfo(HANDLE fileDescriptor);

#endif // !MAIN_MODULE