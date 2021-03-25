// Файл с заголовками всех функций и библиотек проекта
#include "main.h"

int main(){
	DWORD dwErrCode = getAccessToSACL();
	if (dwErrCode != ERROR_SUCCESS) {
		wprintf(L"Cannot get access to SACL\n");
		wprintf(L"Error code: %d\n", dwErrCode);
		return dwErrCode;
	}

	HANDLE fileDescriptor = createFileAndGetDescriptor();
	printFileSecurityInfo(fileDescriptor);
	changeOwner(fileDescriptor);
}

DWORD getAccessToSACL() {
	HANDLE hProcess; // дескриптор процесса
	HANDLE hTokenHandle; // дескриптор маркера доступа
	TOKEN_PRIVILEGES tp; // привилегии маркера доступа 
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
	tp.PrivilegeCount = 1;
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
	// разрешаем привилегию для установки аудита 
	if (!AdjustTokenPrivileges(
		hTokenHandle, // дескриптор маркера доступа процесса
		FALSE, // не запрещаем все привилегии
		&tp, // адрес привилегий
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