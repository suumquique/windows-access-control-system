#include "main.h"

PSID getUserSIDByAccountName(wchar_t* accountName) {
	wchar_t* lpDomainName = NULL;
	DWORD dwErrCode; // код ошибки
	DWORD dwLengthOfSID = 0; // длина SID
	DWORD dwDomainLength = 0;
	DWORD dwLengthOfUserName = UNLEN; // длина имени учетной записи
	SID* lpSID = NULL; // указатель на SID
	SID_NAME_USE type_of_SID; // тип учетной записи

	// определяем длину SID пользователя
	if (!LookupAccountName(
		NULL, // ищем имя на локальном компьютере
		accountName, // имя пользователя
		NULL, // определяем длину SID 
		&dwLengthOfSID, // длина SID
		lpDomainName, // определяем имя домена
		&dwDomainLength, // длина имени домена
		&type_of_SID)) // тип учетной записи
	{
		dwErrCode = GetLastError();
		if (dwErrCode == ERROR_INSUFFICIENT_BUFFER) {
			// распределяем память для SID
			lpSID = (SID*) new char[dwLengthOfSID];
			lpDomainName = new wchar_t[dwDomainLength];
		}
		else {
			// выходим из программы
			printf("Lookup account name failed.\n");
			printf("Error code: %d\n", dwErrCode);
			return NULL;
		}
	}
	// определяем SID и имя домена пользователя
	if (!LookupAccountNameW(
		NULL, // ищем имя на локальном компьютере
		accountName, // имя пользователя
		lpSID, // указатель на SID
		&dwLengthOfSID, // длина SID
		lpDomainName, // домен не нужен
		&dwDomainLength, // длину длмена не указываем
		&type_of_SID)) // тип учетной записи
	{
		dwErrCode = GetLastError();
		printf("Lookup account name failed.\n");
		printf("Error code: %d\n", dwErrCode);
		return NULL;
	}

	return lpSID;
}

DWORD changeOwner(HANDLE fileDescriptor) {
	wchar_t userName[UNLEN]; // Имя нового владельца файла
	BOOL tryAgain = FALSE; // Спрашивать ли имя нового владельца файла при неудаче
	DWORD dwErrCode; // Код возврата
	wprintf(L"\nEnter the username of the new owner of the file: ");
	wscanf(L"%s", userName);
	// Получаем указатель на SID юзера по имени
	PSID fileOwnerPSID = getUserSIDByAccountName(userName);
	// Если имя введено неверно, спрашиваем пользователя, попробовать ли еще раз
	while (fileOwnerPSID == NULL) {
		wprintf(L"Incorrect account name. Try again? Yes - 1, No - 0: ");
		wscanf(L"%d", tryAgain);
		if (tryAgain) {
			wscanf(L"%s", userName);
			fileOwnerPSID = getUserSIDByAccountName(userName);
		}
		else return 1;
	}

	// устанавливаем нового владельца файла
	dwErrCode = SetSecurityInfo(
		fileDescriptor, // дескриптор файла
		SE_FILE_OBJECT, // объект файл
		OWNER_SECURITY_INFORMATION, // изменяем только имя владельца файла
		fileOwnerPSID, // адрес на SID нового владельца
		NULL, // первичную группу не изменяем
		NULL, // DACL не изменяем
		NULL); // SACL не изменяем
	if (dwErrCode != ERROR_SUCCESS)
	{
		printf("Set named security info failed.\n");
		printf("Error code: %u\n", dwErrCode);
		return dwErrCode;
	}
	printf("The new owner of the file is set.\n");

}