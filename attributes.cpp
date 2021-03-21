#ifndef UNICODE
#define UNICODE
#endif
#include <stdio.h>
#include <windows.h>
#include <lm.h>
#include <sddl.h>
#include <AclAPI.h>

typedef struct _account {
	wchar_t* userName;
	wchar_t* domainName;
} Account;

Account getUserAccountFromSID(PSID lpSID);

int main(){
	
}

Account getUserAccountFromSID(PSID lpSID) {
	LPTSTR lpDomainName = NULL, userName = NULL;

	DWORD dwErrCode;
	DWORD dwLengthOfUserName = 0, dwLengthOfDomainName = 0;
	SID_NAME_USE type_of_SID;
	if (!LookupAccountSid(
		NULL, // ищем на локальном компьютере
		lpSID, // указатель на SID
		userName, // имя пользователя
		&dwLengthOfUserName, // длина имени пользователя
		lpDomainName, // определяем имя домена
		&dwLengthOfDomainName, // длина имени домена
		&type_of_SID)) // тип учетной записи
	{
		dwErrCode = GetLastError();
		if (dwErrCode == ERROR_INSUFFICIENT_BUFFER) {
			// распределяем память под имя домена
			lpDomainName = (LPTSTR) new wchar_t[dwLengthOfDomainName];
			userName = (LPTSTR) new wchar_t[dwLengthOfUserName];
		}
		else{
			printf("Lookup account SID for length failed.\n");
			printf("Error code: %d\n", dwErrCode);
		}
	}
	// определяем имя учетной записи по SID
	if (!LookupAccountSid(
		NULL, // ищем на локальном компьютере
		lpSID, // указатель на SID
		userName, // имя пользователя
		&dwLengthOfUserName, // длина имени пользователя
		lpDomainName, // определяем имя домена 
		&dwLengthOfDomainName, // длина имени домена
		&type_of_SID)) // тип учетной записи
	{
		dwErrCode = GetLastError();
		printf("Lookup account SID failed.\n");
		printf("Error code: %d\n", dwErrCode);
	}

	Account currentSIDOwner = { userName, lpDomainName };
	return currentSIDOwner;
}