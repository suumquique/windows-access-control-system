#include "main.hpp"

#define MAX_FILE_PATH_LEN 1000

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
		&sd,
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

	// провер¤ем структуру дескриптора безопасности
	if (!IsValidSecurityDescriptor(&sd)) {
		dwErrCode = GetLastError();
		perror("Security descriptor is invalid.\n");
		printf("The last error code: %u\n", dwErrCode);
		exit(dwErrCode);
	}
	// инициализируем атрибуты безопасности
	sa.nLength = sizeof(sa); // устанавливаем длину атрибутов защиты
	sa.lpSecurityDescriptor = &sd; // устанавливаем адрес SD
	sa.bInheritHandle = FALSE;

	DWORD dwDesiredAccess = STANDARD_RIGHTS_ALL | GENERIC_ALL | ACCESS_SYSTEM_SECURITY; // ”станавливаем параметры доступа к файлу
	DWORD dwShareMode = 0; // ”станаливаем, что доступа к файлу не будет, пока его дескриптор не закрыт
	HANDLE fileHandle = CreateFileW(fileName, dwDesiredAccess, dwShareMode, &sa, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (fileHandle == INVALID_HANDLE_VALUE) {
		wprintf(L"Cannot create file with current security attributes.\n");
		exit(1);
	}

	wprintf(L"File with specified security attributes was successfully created.\n\n\n");

	return fileHandle;
}