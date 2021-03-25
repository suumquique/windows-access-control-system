#include "main.h"


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