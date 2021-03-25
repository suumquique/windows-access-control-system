#include "main.h"

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
		else {
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

DWORD printAllSecurityDescriptorInformation(PSECURITY_DESCRIPTOR securityDescriptorPtr) {
	BOOL bOwnerDefaulted = FALSE; // флаг владельца по умолчанию
	BOOL bGroupDefaulted = FALSE; // флаг первичной группы по умолчанию
	PSID pSidOwner = NULL; // указатель на SID владельца объекта 
	PSID pSidGroup = NULL; // указатель на SID первичной группы объекта
	SECURITY_DESCRIPTOR_CONTROL wControl; // управляющие флаги из SD 
	LPWSTR StringSecurityDescriptor; // строка с SD
	DWORD StringSecurityDescriptorLen; // длина строки с SD 
	DWORD dwRevision; // версия дескриптора безопасности 
	DWORD dwRetCode; // код возврата

	// Получаем SD владельца объекта
	if (!GetSecurityDescriptorOwner(
		securityDescriptorPtr,
		&pSidOwner,
		&bOwnerDefaulted))
	{
		printf("Get security descriptor owner failed.\n");
		dwRetCode = GetLastError();
		printf("Error code: %u\n", dwRetCode);
		return dwRetCode;
	}
	// получаем SD первичной группы владельца объекта
	if (!GetSecurityDescriptorGroup(
		securityDescriptorPtr,
		&pSidGroup,
		&bGroupDefaulted))
	{
		printf("Get security descriptor group failed.\n");
		dwRetCode = GetLastError();
		printf("Error code: %u\n", dwRetCode);
		return dwRetCode;
	}
	
	wprintf(L"File owner %s set by default\n", bOwnerDefaulted ? L"is" : L"isn`t");
	wprintf(L"File group-owner %s set by default\n", bGroupDefaulted ? L"is" : L"isn`t");

	if (!GetSecurityDescriptorControl(
		securityDescriptorPtr,
		&wControl,
		&dwRevision))
	{
		dwRetCode = GetLastError();
		printf("Get security descriptor control failed.\n");
		printf("Error code: %u\n", dwRetCode);
		return dwRetCode;
	}
	printf("\nThe following control flags are set: \n");
	// определяем информацию из управляющего слова
	if (wControl & SE_DACL_AUTO_INHERITED)
		printf("SE_DACL_AUTO_INHERITED\n");
	if (wControl & SE_DACL_DEFAULTED)
		printf("SE_DACL_DEFAULTED\n");
	if (wControl & SE_DACL_PRESENT)
		printf("SE_DACL_PRESENT\n");
	if (wControl & SE_DACL_PROTECTED)
		printf("SE_DACL_PROTECTED\n");
	if (wControl & SE_GROUP_DEFAULTED)
		printf("SE_GROUP_DEFAULTED\n");
	if (wControl & SE_OWNER_DEFAULTED)
		printf("SE_OWNER_DEFAULTED\n");
	if (wControl & SE_SACL_AUTO_INHERITED)
		printf("SE_SACL_AUTO_INHERITED\n");
	if (wControl & SE_SACL_DEFAULTED)
		printf("SE_SACL_DEFAULTED\n");
	if (wControl & SE_SACL_PRESENT)
		printf("SE_SACL_PRESENT\n");
	if (wControl & SE_SACL_PROTECTED)
		printf("SE_SACL_PROTECTED\n");
	if (wControl & SE_SELF_RELATIVE)
		printf("SE_SELF_RELATIVE\n");
	// выводим на печать версию дескриптора безопасности
	printf("\nDescriptor revision: %u\n", dwRevision);
	if (!ConvertSecurityDescriptorToStringSecurityDescriptorW(
		securityDescriptorPtr, // адрес дескриптора безопасности
		SDDL_REVISION_1, // версия языка описания
		OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION |
		DACL_SECURITY_INFORMATION | SACL_SECURITY_INFORMATION,
		&StringSecurityDescriptor, // буфер для строки
		&StringSecurityDescriptorLen)) // длина буфера
	{
		dwRetCode = GetLastError();
		wprintf(L"Convert security descriptor to string security descriptor failed.");
		printf("Error code: %u\n", dwRetCode);
		return dwRetCode;
	}
	wprintf(L"String security descriptor length: %u\n",
		StringSecurityDescriptorLen);
	wprintf(L"String security desriptor: %s\n", StringSecurityDescriptor);

}

DWORD printFileSecurityInfo(HANDLE fileDescriptor) {
	PSID pSidOwner; // указатель на SID владельца объекта
	PSID pSidGroup; // указатель на SID первичной группы объекта
	PSECURITY_DESCRIPTOR pSecurityDescriptor; // указатель на SD
	LPTSTR lpStringSid; // указатель на строку SID
	DWORD dwRetCode; // код возврата

	// получаем дескриптор безопасности файла
	dwRetCode = GetSecurityInfo(
		fileDescriptor, // дескриптор файла
		SE_FILE_OBJECT, // объект файл
		GROUP_SECURITY_INFORMATION | OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION | SACL_SECURITY_INFORMATION | 
		BACKUP_SECURITY_INFORMATION | ATTRIBUTE_SECURITY_INFORMATION | LABEL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION |
		PROTECTED_SACL_SECURITY_INFORMATION | SCOPE_SECURITY_INFORMATION,
		&pSidOwner, // адрес указателя на SID владельца
		&pSidGroup, // адрес указателя на первичную группу
		NULL, // указатель на DACL не нужен
		NULL, // указатель на SACL не нужен
		&pSecurityDescriptor); // адрес указателя на SD
	if (dwRetCode != ERROR_SUCCESS) {
		printf("Get named security info failed.\n");
		printf("Error code: %u\n", dwRetCode);
		return dwRetCode;
	}
	// преобразуем SID владельца в строку
	if (!ConvertSidToStringSid(pSidOwner, &lpStringSid)) {
		printf("Convert SID to string SID failed.");
		dwRetCode = GetLastError();
		return dwRetCode;
	}
	// печатаем SID владельца
	wprintf(L"File owner SID: %s\n", lpStringSid);
	// освобождаем память для строки
	LocalFree(lpStringSid);
	// преобразуем SID первичной группы в строку
	if (!ConvertSidToStringSid(pSidGroup, &lpStringSid)) {
		printf("Convert SID to string SID failed.");
		dwRetCode = GetLastError();
		return dwRetCode;
	}
	// печатаем SID первичной группы
	wprintf(L"File group SID: %s\n", lpStringSid);
	// освобождаем память для строки
	LocalFree(lpStringSid);

	// Получаем структуру, содержащую юзернейм и домен овнера (владельца) файла
	Account fileOwner = getUserAccountFromSID(pSidOwner);
	// Печатаем юзернейм и имя домена
	wprintf(L"File owner name: %s\n", fileOwner.userName);
	wprintf(L"File owner domain: %s\n", fileOwner.domainName);
	printAllSecurityDescriptorInformation(pSecurityDescriptor);

	// освобождаем память для дескриптора
	LocalFree(pSecurityDescriptor);
}