#include "main.h"

Account getUserAccountFromSID(PSID lpSID) {
	LPTSTR lpDomainName = NULL, userName = NULL;

	DWORD dwErrCode;
	DWORD dwLengthOfUserName = 0, dwLengthOfDomainName = 0;
	SID_NAME_USE type_of_SID;
	if (!LookupAccountSid(
		NULL, // ���� �� ��������� ����������
		lpSID, // ��������� �� SID
		userName, // ��� ������������
		&dwLengthOfUserName, // ����� ����� ������������
		lpDomainName, // ���������� ��� ������
		&dwLengthOfDomainName, // ����� ����� ������
		&type_of_SID)) // ��� ������� ������
	{
		dwErrCode = GetLastError();
		if (dwErrCode == ERROR_INSUFFICIENT_BUFFER) {
			// ������������ ������ ��� ��� ������
			lpDomainName = (LPTSTR) new wchar_t[dwLengthOfDomainName];
			userName = (LPTSTR) new wchar_t[dwLengthOfUserName];
		}
		else {
			printf("Lookup account SID for length failed.\n");
			printf("Error code: %d\n", dwErrCode);
		}
	}
	// ���������� ��� ������� ������ �� SID
	if (!LookupAccountSid(
		NULL, // ���� �� ��������� ����������
		lpSID, // ��������� �� SID
		userName, // ��� ������������
		&dwLengthOfUserName, // ����� ����� ������������
		lpDomainName, // ���������� ��� ������ 
		&dwLengthOfDomainName, // ����� ����� ������
		&type_of_SID)) // ��� ������� ������
	{
		dwErrCode = GetLastError();
		printf("Lookup account SID failed.\n");
		printf("Error code: %d\n", dwErrCode);
	}

	Account currentSIDOwner = { userName, lpDomainName };
	return currentSIDOwner;
}

DWORD printAllSecurityDescriptorInformation(PSECURITY_DESCRIPTOR securityDescriptorPtr) {
	SECURITY_DESCRIPTOR_CONTROL wControl; // ����������� ����� �� SD 
	LPWSTR StringSecurityDescriptor; // ������ � SD
	DWORD StringSecurityDescriptorLen; // ����� ������ � SD 
	DWORD dwRevision; // ������ ����������� ������������ 
	DWORD dwRetCode; // ��� ��������

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
	// ���������� ���������� �� ������������ �����
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
	// ������� �� ������ ������ ����������� ������������
	printf("\nDescriptor revision: %u\n", dwRevision);
	if (!ConvertSecurityDescriptorToStringSecurityDescriptorW(
		securityDescriptorPtr, // ����� ����������� ������������
		SDDL_REVISION_1, // ������ ����� ��������
		OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION |
		DACL_SECURITY_INFORMATION | SACL_SECURITY_INFORMATION,
		&StringSecurityDescriptor, // ����� ��� ������
		&StringSecurityDescriptorLen)) // ����� ������
	{
		dwRetCode = GetLastError();
		wprintf(L"Convert security descriptor to string security descriptor failed.");
		printf("Error code: %u\n", dwRetCode);
		return dwRetCode;
	}
	wprintf(L"String security descriptor length: %u\n",
		StringSecurityDescriptorLen);
	wprintf(L"String security desriptor: %s\n", StringSecurityDescriptor);

	return ERROR_SUCCESS;
}

DWORD printFileOwnerInfo(PSECURITY_DESCRIPTOR securityDescriptorPtr) {
	BOOL bOwnerDefaulted = FALSE; // ���� ��������� �� ���������
	BOOL bGroupDefaulted = FALSE; // ���� ��������� ������ �� ���������
	PSID pSidOwner = NULL; // ��������� �� SID ��������� ������� 
	PSID pSidGroup = NULL; // ��������� �� SID ��������� ������ �������
	LPWSTR lpStringSid; // ��������� �� ������ SID
	DWORD dwRetCode; // ��� ��������

	// �������� ��������� ������� �� ����������� ������������
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
	// �������� SD ��������� ������ ��������� �������
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

	// ����������� SID ��������� � ������
	if (!ConvertSidToStringSidW(pSidOwner, &lpStringSid)) {
		printf("Convert SID to string SID failed.");
		dwRetCode = GetLastError();
		return dwRetCode;
	}
	// �������� SID ���������
	wprintf(L"File owner SID: %s\n", lpStringSid);
	// ����������� ������ ��� ������
	LocalFree(lpStringSid);

	// ����������� SID ��������� ������ � ������
	if (!ConvertSidToStringSidW(pSidGroup, &lpStringSid)) {
		printf("Convert SID to string SID failed.");
		dwRetCode = GetLastError();
		return dwRetCode;
	}
	// �������� SID ��������� ������
	wprintf(L"File group SID: %s\n", lpStringSid);
	// ����������� ������ ��� ������
	LocalFree(lpStringSid);

	// �������� ���������, ���������� �������� � ����� ������ (���������) �����
	Account fileOwner = getUserAccountFromSID(pSidOwner);
	// �������� �������� � ��� ������
	wprintf(L"File owner name: %s\n", fileOwner.userName);
	wprintf(L"File owner domain: %s\n", fileOwner.domainName);

	wprintf(L"File owner %s set by default\n", bOwnerDefaulted ? L"is" : L"isn`t");
	wprintf(L"File group-owner %s set by default\n", bGroupDefaulted ? L"is" : L"isn`t");

	return ERROR_SUCCESS;
}

DWORD printFileSecurityInfo(HANDLE fileDescriptor) {
	PISECURITY_DESCRIPTOR pSecurityDescriptor = getSecurityDescriptor(fileDescriptor); // ��������� �� SD
	DWORD dwRetCode = ERROR_SUCCESS; // ��� ��������, �� ��������� ��� ���������
	
	if (printFileOwnerInfo(pSecurityDescriptor) != ERROR_SUCCESS) {
		wprintf(L"Unable to print file owner info\n");
		dwRetCode |= 1;
	}
	if (printAllSecurityDescriptorInformation(pSecurityDescriptor) != ERROR_SUCCESS) {
		wprintf(L"Unable to print DACL and SACL of file\n");
		dwRetCode |= 2;
	}

	// ����������� ������ ��� �����������
	LocalFree(pSecurityDescriptor);

	return dwRetCode;
}