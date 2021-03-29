#include "main.h"

PISECURITY_DESCRIPTOR getSecurityDescriptor(HANDLE fileDescriptor) {
	PISECURITY_DESCRIPTOR pSecurityDescriptor; // указатель на SD
	DWORD dwErrCode; // код возможной ошибки

	// получаем дескриптор безопасности файла
	dwErrCode = GetSecurityInfo(
		fileDescriptor, // дескриптор файла
		SE_FILE_OBJECT, // объект файл
		GROUP_SECURITY_INFORMATION | OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION | SACL_SECURITY_INFORMATION |
		BACKUP_SECURITY_INFORMATION | ATTRIBUTE_SECURITY_INFORMATION | LABEL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION |
		PROTECTED_SACL_SECURITY_INFORMATION | SCOPE_SECURITY_INFORMATION,
		NULL, // адрес указателя на SID владельца не нужен
		NULL, // адрес указателя на первичную группу не нужен
		NULL, // указатель на DACL не нужен
		NULL, // указатель на SACL не нужен
		(PSECURITY_DESCRIPTOR*) &pSecurityDescriptor); // адрес указателя на SD
	if (dwErrCode != ERROR_SUCCESS) {
		printf("Get security info failed.\n");
		printf("Error code: %u\n", dwErrCode);
		exit(dwErrCode);
	}
	
	// Проверяем, получили ли мы валидный дескриптор безопасности
	if (!IsValidSecurityDescriptor(pSecurityDescriptor))
	{
		dwErrCode = GetLastError();
		perror("Security descriptor is invalid.\n");
		printf("The last error code: %u\n", dwErrCode);
		exit(dwErrCode); // Если невалидный - выходим из программы
	}

	return pSecurityDescriptor;
}

DWORD getAccessToSACL() {
	HANDLE hProcess; // дескриптор процесса
	HANDLE hTokenHandle; // дескриптор маркера доступа
	struct {
		DWORD PrivilegeCount;
		LUID_AND_ATTRIBUTES Privileges[2];
	} tp; // Делаем свою структуру вместо TOKEN_PRIVILEGES, поскольку требуется массив из двух привилегий
	DWORD dwErrCode; // код возврата

	// получаем дескриптор процесса
	hProcess = GetCurrentProcess();
	// получаем маркер доступа процесса
	if (!OpenProcessToken(
		hProcess, // дескриптор процесса
		TOKEN_ALL_ACCESS, // полный доступ к маркеру доступа
		&hTokenHandle)) // дескриптор маркера
	{
		dwErrCode = GetLastError();
		printf("Open process token failed: %u\n", dwErrCode);
		return dwErrCode;
	}

	// устанавливаем общее количество привилегий
	tp.PrivilegeCount = 2;
	// определяем идентификатор привилегии для установки аудита
	if (!LookupPrivilegeValue(
		NULL, // ищем идентификатор привилегии на локальном компьютере
		SE_SECURITY_NAME, // привилегия для аудита
		&(tp.Privileges[0].Luid)))
	{
		dwErrCode = GetLastError();
		printf("Lookup privilege value failed.\n");
		printf("Error code: %d\n", dwErrCode);
		return dwErrCode;
	}
	// разрешаем привилегию аудита
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	// определяем идентификатор привилегии для установки новых овнеров
	if (!LookupPrivilegeValue(
		NULL, // ищем идентификатор привилегии на локальном компьютере
		SE_TAKE_OWNERSHIP_NAME, // привилегия для измнения овнеров
		&(tp.Privileges[1].Luid)))
	{
		dwErrCode = GetLastError();
		printf("Lookup privilege value failed.\n");
		printf("Error code: %d\n", dwErrCode);
		return dwErrCode;
	}
	// разрешаем привилегию установки новых владельцев
	tp.Privileges[1].Attributes = SE_PRIVILEGE_ENABLED;

	// Устанавливаем токен с привилегиями для текущего процесса
	if (!AdjustTokenPrivileges(
		hTokenHandle, // дескриптор маркера доступа процесса
		FALSE, // не запрещаем все привилегии
		(PTOKEN_PRIVILEGES)&tp, // адрес привилегий
		0, // длины буфера нет
		NULL, // предыдущее состояние привилегий не нужно
		NULL)) // длина буфера не нужна
	{
		dwErrCode = GetLastError();
		printf("Lookup privilege value failed.\n");
		printf("Error code: %d\n", dwErrCode);
		return dwErrCode;
	}

	return ERROR_SUCCESS;
}