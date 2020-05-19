// security_log_writer.cpp : Defines the entry point for the console application.
//
// 
/*
___!!!___ Add Authz.lib to Project -> Properties -> Linker -> Input -> Additional Dependencies ___!!!___
___!!!___ Go to Computer Configuration-> Policy-> Windows Settings-> Security Settings-> Local Policies ___!!!___ 
___!!!___ Then edit the audit policy as shown in the image, or at least change the access to the Audit object and check all three boxes: "Define these policy settings", "Success" and "Failure", click OK to close the dialog box;___!!!___ 
Below - Assign user rights. Click on it, and then click on the policy: generate a security audit.
Add your domain and username, in my case its UIDDEVAdministrator. This is the user my program will run under. Voila! You have access to change security logs.
*/

#include <stdio.h>
#include <iostream>
#include <string>
#include <strsafe.h>
#include <windows.h>
#include <authz.h>



int main()
{
	BOOL bResult = TRUE;
	//DWORD dwAuditId = 4624;
	DWORD dwAuditId = 5000;
	PWSTR pUserSid = NULL;
	PWSTR Source_Name = L"Test security audit";
	//Source_Name = L"Microsoft-Windows-Security-Auditing";
	DWORD dwFlags = 0x1;
	DWORD err = NULL;
	BOOL res = NULL;

	wchar_t pBuf[1024];
	GetModuleFileName(NULL, pBuf, 1024);
	DWORD id = GetCurrentProcessId();
	printf("Current Process ID = 0x%08x\n", id);

	AUTHZ_SOURCE_SCHEMA_REGISTRATION ar;
	memset(&ar, 0, sizeof(ar));
	ar.dwFlags = AUTHZ_ALLOW_MULTIPLE_SOURCE_INSTANCES;
	ar.szEventSourceName = Source_Name;
	ar.szEventMessageFile = pBuf;
	ar.szEventSourceXmlSchemaFile = NULL;
	ar.szEventAccessStringsFile = pBuf;
	ar.szExecutableImagePath = NULL;
	ar.dwObjectTypeNameCount = 1;
	//ar.ObjectTypeNames[0] = NULL;

	res = AuthzInstallSecurityEventSource(0, &ar);
	if (!res) {
		err = GetLastError();
		printf("AuthzInstallSecurityEventSource: %d\n", err);
	}

	AUTHZ_SECURITY_EVENT_PROVIDER_HANDLE hEventProvider;
	printf("0x%08x\n", &hEventProvider);

	//Source_Name = L"Microsoft-Windows-Security-Auditing";
	res = AuthzRegisterSecurityEventSource(0, Source_Name, &hEventProvider);
	if (!res) {
		err = GetLastError();
		printf("AuthzRegisterSecurityEventSource: %d\n", err);
	}
	printf("0x%08x\n", *hEventProvider);

	AUDIT_PARAMS ap;
	//memset(&ap, 0, sizeof(ap));
	ap.Count = 0;



	/*
	if (!AuthzReportSecurityEventFromParams(
	dwFlags,
	hEventProvider,
	dwAuditId,
	pUserSid, //PSID pUserSid
	&ap	 //PAUDIT_PARAMS pParams
	))
	{
	err = GetLastError();
	printf("AuthzReportSecurityEvent: %d\n", err);
	}
	*/



	if (!AuthzReportSecurityEvent(
		dwFlags,
		hEventProvider,
		dwAuditId,
		pUserSid, //PSID pUserSid
		2,	 //DWORD dwCount
		APT_String, L"Jay Hamlin",
		APT_String, L"March 21, 1960"))
	{
		err = GetLastError();
		printf("AuthzReportSecurityEvent: %d\n", err);
	}

	return 0;
}

