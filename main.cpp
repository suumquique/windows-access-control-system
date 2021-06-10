// Файл с заголовками всех функций и библиотек проекта
#include "main.hpp"

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
	changeACL(fileDescriptor);
	wprintf(L"\n\nNew file info after changes:\n\n");
	printFileSecurityInfo(fileDescriptor);
	system("pause");
}