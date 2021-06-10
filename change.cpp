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
		wscanf(L"%d", &tryAgain);
		if (tryAgain) {
			wprintf(L"\nEnter the username of the new owner of the file: ");
			wscanf(L"\n%s", userName);
			fileOwnerPSID = getUserSIDByAccountName(userName);
		}
		else return 1;
	}
	getwchar(); // Считываем оставшийся в потоке перенос строки

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
	printf("The new owner of the file is successfully set.\n\n");

	return ERROR_SUCCESS;
}

DWORD changeACL(HANDLE fileDescriptor) {
	PSECURITY_DESCRIPTOR pSecurityDescriptor; // получаем дескриптор безопасности файла
	PACL pDacl; // Указатель на DACL файла
	PACL pSacl; // Указатель на SACL файла
	DWORD dwRetCode; // Код возврата
	DWORD flags[] = { SE_DACL_PROTECTED, SE_DACL_AUTO_INHERITED, SE_DACL_AUTO_INHERIT_REQ, SE_SACL_PROTECTED, SE_SACL_AUTO_INHERITED, SE_SACL_AUTO_INHERIT_REQ };
	SECURITY_DESCRIPTOR_CONTROL allFlagsBitmask = 0; // Флаги DACL и SACL, которые будем устанавливать или обнулять
	SECURITY_DESCRIPTOR_CONTROL flagsToSetBitmask = 0; // Флаги DACL и SACl, которые будем устанавливать (создавать)
	size_t index; // Номер, по которому будем получать из массива flags флаг для удаления или добавления
	WCHAR choice; // Выбор пользователя, который будем преобразовывать в число (индекс)
	

	dwRetCode = GetSecurityInfo(
		fileDescriptor, // дескриптор файла
		SE_FILE_OBJECT, // объект файл
		DACL_SECURITY_INFORMATION | SACL_SECURITY_INFORMATION, // тип информации
		NULL, // указатель на SID владельца не нужен
		NULL, // указатель на первичную группу не нужен 
		&pDacl, // указатель на DACL
		&pSacl, // указатель на SACL
		&pSecurityDescriptor); // адрес указателя на SD
	if (dwRetCode != ERROR_SUCCESS)
	{
		printf("Get named security info failed.\n");
		printf("Error code: %u\n", dwRetCode);
		return dwRetCode;
	}
 
	wprintf(L"\nEnter the security descriptor flags you want to set \
(SE_DACL_PROTECTED - 1, SE_DACL_INHERITED - 2, SE_DACL_AUTO_INHERIT_REQ - 3, SE_SACL_PROTECTED - 4, SE_SACL_INHERITED - 5, SE_SACL_AUTO_INHERIT_REQ - 6).\n\
For example, to set flags 1, 4 and 6, you need to enter 146: ");
	choice = getwchar(); // Считываем один символ
	while (choice >= '1' && choice <= '6') { // Если пользователь ввел не цифру, прекращаем считывание
		index = choice - '0' - 1; // Преобразуем символ char в цифру (int) вычитанием '0' и вычитаем единицу для получения индекса
		allFlagsBitmask |= flags[index]; // Добавляем в битовую маску всех флагов соотвествующий флаг
		flagsToSetBitmask |= flags[index]; // Добавляем в битовую маску флагов для установки текущий флаг
		choice = getwchar();
	}

	wprintf(L"\nEnter the security descriptor flags you want to delete \
(SE_DACL_PROTECTED - 1, SE_DACL_INHERITED - 2, SE_DACL_AUTO_INHERIT_REQ - 3, SE_SACL_PROTECTED - 4, SE_SACL_INHERITED - 5, SE_SACL_AUTO_INHERIT_REQ - 6).\n\
For example, to set flags 1, 4 and 6, you need to enter 146: ");
	choice = getwchar(); // Считываем один символ
	while (choice >= '1' && choice <= '6') { // Если пользователь ввел не цифру, прекращаем считывание
		index = choice - '0' - 1; // Преобразуем символ char в цифру (int) вычитанием '0' и вычитаем единицу для получения индекса
		allFlagsBitmask |= flags[index]; // Добавляем в битовую маску всех флагов соотвествующий флаг
		choice = getwchar();
	}

	if (!SetSecurityDescriptorControl(
		pSecurityDescriptor,
		allFlagsBitmask,
		flagsToSetBitmask))
	{
		dwRetCode = GetLastError();
		printf("Set security descriptor control failed.");
		printf("Error code: %u\n", dwRetCode);
		return dwRetCode;
	}

	SECURITY_DESCRIPTOR_CONTROL wControl; // управляющие флаги из SD 
	DWORD dwRevision; // версия дескриптора безопасности 

	if (!GetSecurityDescriptorControl(
		pSecurityDescriptor,
		&wControl,
		&dwRevision))
	{
		dwRetCode = GetLastError();
		printf("Get security descriptor control failed.\n");
		printf("Error code: %u\n", dwRetCode);
		return dwRetCode;
	}

	dwRetCode = SetSecurityInfo(
		fileDescriptor, // дескриптор файла
		SE_FILE_OBJECT, // объект файл
		DACL_SECURITY_INFORMATION | SACL_SECURITY_INFORMATION |
		PROTECTED_DACL_SECURITY_INFORMATION | PROTECTED_SACL_SECURITY_INFORMATION, // изменяем информацию о DACL
		NULL, // владельца не изменяем
		NULL, // первичную группу не изменяем
		pDacl, // DACL изменяем
		pSacl); // SACL изменяем
	if (dwRetCode != ERROR_SUCCESS)
	{
		printf("Set named security info failed.\n");
		printf("Error code: %u\n", dwRetCode);
		return dwRetCode;
	}

	return ERROR_SUCCESS;
}