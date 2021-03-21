#ifndef UNICODE
#define UNICODE
#endif
#include <stdio.h>
#include <windows.h>
#include <lm.h>
#include <sddl.h>
#include <AclAPI.h>
#include <fileapi.h>

#pragma comment(lib, "Advapi32.lib")

#define MAX_FILE_PATH_LEN 1000

typedef struct _account {
	wchar_t* userName;
	wchar_t* domainName;
} Account;

Account getUserAccountFromSID(PSID lpSID);
HANDLE createFileAndGetDescriptor();

int main(){
	HANDLE fileDescriptor = createFileAndGetDescriptor();
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

HANDLE createFileAndGetDescriptor() {
	wchar_t fileName[MAX_FILE_PATH_LEN];
	wprintf(L"Input a file name to create (with extension): ");
	if (!wscanf(L"%s", fileName)) {
		wprintf(L"Cannot read file name.\n");
		exit(1);
	}

	SECURITY_DESCRIPTOR sd;
	SECURITY_ATTRIBUTES sa;

	DWORD dwErrCode; // код возврата
 // инициализируем версию дескриптора безопасности
	if (!InitializeSecurityDescriptor(
		& sd,
		SECURITY_DESCRIPTOR_REVISION))
	{
		dwErrCode = GetLastError();
		printf("Initialize security descroptor failed.\n");
		printf("Error code: %d\n", dwErrCode);
		exit(dwErrCode);
	}
	// устанавливаем SID владельца объекта
	if (!SetSecurityDescriptorOwner(
		&sd, // адрес дескриптора безопасности
		NULL, // не задаем владельца
		SE_OWNER_DEFAULTED)) // определить владельца по умолчанию
	{
		dwErrCode = GetLastError();
		perror("Set security descriptor owner failed.\n");
		printf("The last error code: %u\n", dwErrCode);
		exit(dwErrCode);
	}
	// устанавливаем SID первичной группы владельца
	if (!SetSecurityDescriptorGroup(
		&sd, // адрес дескриптора безопасности
		NULL, // не задаем первичную группу
		SE_GROUP_DEFAULTED)) // определить первичную группу по умолчанию
	{
		dwErrCode = GetLastError();
		perror("Set security descriptor group failed.\n");
		printf("The last error code: %u\n", dwErrCode);
		exit(dwErrCode);
	}
	// проверяем структуру дескриптора безопасности
	if (!IsValidSecurityDescriptor(&sd)){
		dwErrCode = GetLastError();
		perror("Security descriptor is invalid.\n");
		printf("The last error code: %u\n", dwErrCode);
		exit(dwErrCode);
	}
	// инициализируем атрибуты безопасности
	sa.nLength = sizeof(sa); // устанавливаем длину атрибутов защиты
	sa.lpSecurityDescriptor = &sd; // устанавливаем адрес SD
	sa.bInheritHandle = FALSE;

	HANDLE fileHandle = CreateFileW(fileName, GENERIC_READ | GENERIC_WRITE, 0, &sa, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (fileHandle == INVALID_HANDLE_VALUE) {
		wprintf(L"Cannot create file with current security attributes.\n");
		exit(1);
	}

	wprintf(L"File with specified security attributes was successfully created");

	return fileHandle;
}