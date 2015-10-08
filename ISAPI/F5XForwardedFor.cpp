//===========================================================================
//
// File         : F5XForwardingFor.cpp
// Description  : ISAPI Filter for replacing ISAPI c-ip value with 
//                X-Forwarding-For HTTP header
//                   
//---------------------------------------------------------------------------
//
// The contents of this file are subject to the "END USER LICENSE AGREEMENT FOR F5
// Software Development Kit for iControl"; you may not use this file except in
// compliance with the License. The License is included in the iControl
// Software Development Kit.
//
// Software distributed under the License is distributed on an "AS IS"
// basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See
// the License for the specific language governing rights and limitations
// under the License.
//
// The Original Code is iControl Code and related documentation
// distributed by F5.
//
// The Initial Developer of the Original Code is F5 Networks, Inc.
// Seattle, WA, USA.
// Portions created by F5 are Copyright (C) 2004 F5 Networks, Inc.
// All Rights Reserved.
// iControl (TM) is a registered trademark of F5 Networks, Inc.
//
// Alternatively, the contents of this file may be used under the terms
// of the GNU General Public License (the "GPL"), in which case the
// provisions of GPL are applicable instead of those above.  If you wish
// to allow use of your version of this file only under the terms of the
// GPL and not to allow others to use your version of this file under the
// License, indicate your decision by deleting the provisions above and
// replace them with the notice and other provisions required by the GPL.
// If you do not delete the provisions above, a recipient may use your
// version of this file under either the License or the GPL.
//
//===========================================================================

//===========================================================================
//	Include Files
//===========================================================================
#include "stdafx.h"
#include "F5XForwardedFor.h"

#include <windows.h>
#include <httpfilt.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>

//===========================================================================
//	Forward References
//===========================================================================

//---------------------------------------------------------------------------
//	DebugMsg() is used for debugging.
//	Choose debugger output or log file.
//---------------------------------------------------------------------------
#ifdef _DEBUG
	#define TO_FILE		// uncomment out to use a log file
	#ifdef TO_FILE
		#define DEST ghFile
		#define DebugMsg(x)	WriteToFile x;
		HANDLE ghFile;
		#define LOGFILE TEXT("c:\\F5LogHeader.log")
		void WriteToFile (HANDLE hFile, char *szFormat, ...)
		{
			char szBuf[1024];
			DWORD dwWritten;
			va_list list;
			va_start (list, szFormat);
			vsprintf (szBuf, szFormat, list);
			hFile = CreateFile (LOGFILE, GENERIC_WRITE, 
								0, NULL, OPEN_ALWAYS, 
								FILE_ATTRIBUTE_NORMAL, NULL);
			if (hFile != INVALID_HANDLE_VALUE) {
				SetFilePointer (hFile, 0, NULL, FILE_END);
				WriteFile (hFile, szBuf, lstrlen (szBuf), &dwWritten, NULL);
				WriteFile(hFile, TEXT("\r\n"), 2, &dwWritten, NULL);
				CloseHandle (hFile);
			}
			va_end (list);
		}
	#else

		#define	DEST               buff
		#define	DebugMsg(x) {					\
					TCHAR buff[256];				\
					wsprintf x;					\
					OutputDebugString( buff );	\
					OutputDebugString(TEXT("\r\n")); \
				}
	#endif
#else
	#define DebugMsg(x)
#endif
void ReadConfiguration(HANDLE hModule);

//===========================================================================
//	Globals
//===========================================================================
CRITICAL_SECTION gCS;		// A critical section handle
							// is used to protect global
							// state properties
static const DWORD BUFFER_LEN = 256;
static TCHAR *DEFAULT_HEADER_NAME = _T("X-Forwarded-For:");

TCHAR gHEADER_NAME[BUFFER_LEN];

//---------------------------------------------------------------------------
//	This the the entry and exit point for the filter
//	it is called when the filter is loaded and unloaded
//	by IIS.  This is where state properties need to be 
//	retrieved and store on persistant storage.
//---------------------------------------------------------------------------
BOOL APIENTRY
DllMain
(
	HANDLE hModule, 
	DWORD ul_reason_for_call, 
	LPVOID lpReserved )
{
	switch( ul_reason_for_call )
	{
		case DLL_PROCESS_ATTACH: 
		{
			InitializeCriticalSection(&gCS);
			ReadConfiguration(hModule);
			break;
		}
		//    case DLL_THREAD_ATTACH:
		//    case DLL_THREAD_DETACH:
		case DLL_PROCESS_DETACH:
		{
			DeleteCriticalSection(&gCS);
			break;
		}
	}
	return TRUE;
}

//---------------------------------------------------------------------------
//	GetFilterVersion - An ISAPI/Win32 API method
//	This method is required by IIS.  It is called 
//	following the process load to ensure that the 
//	filter is compatable with the server.
//---------------------------------------------------------------------------
BOOL WINAPI
GetFilterVersion
(
	HTTP_FILTER_VERSION * pVer
)
{
	DebugMsg(( DEST,
		TEXT("[GetFilterVersion] Server filter version is %d.%d"),
		HIWORD( pVer->dwServerFilterVersion ),
		LOWORD( pVer->dwServerFilterVersion ) ));

	pVer->dwFilterVersion = HTTP_FILTER_REVISION;

	DebugMsg(( DEST,
		TEXT("[GetFilterVersion] Filter version is %d.%d"),
		HIWORD( pVer->dwFilterVersion ),
		LOWORD( pVer->dwFilterVersion ) ));


	//--------------------------------------------------------------------------
	//	Specify the security level of notifications
	//	(secured port, nonsecured port, or both), the
	//	types of events and order of notification for
	//	this filter (high, medium or low, default=low).
	//--------------------------------------------------------------------------
	pVer->dwFlags =
	(
		SF_NOTIFY_SECURE_PORT			|
		SF_NOTIFY_NONSECURE_PORT		|
//		SF_NOTIFY_READ_RAW_DATA			|
		SF_NOTIFY_PREPROC_HEADERS		|
//		SF_NOTIFY_URL_MAP				|
//		SF_NOTIFY_AUTHENTICATION		|
//		SF_NOTIFY_SEND_RAW_DATA			|
		SF_NOTIFY_LOG					|
		SF_NOTIFY_END_OF_NET_SESSION	|
		SF_NOTIFY_ORDER_DEFAULT
	);
	//--------------------------------------------------------------------------
	//	A brief one line description of the filter
	//--------------------------------------------------------------------------
	_tcscpy( pVer->lpszFilterDesc, TEXT("F5 Networks Proxy X-Forwarded-For ISAPI Log Filter, v1.0") );
	
	return TRUE;
}


//---------------------------------------------------------------------------
//	HttpFilterProc - ISAPI / Win32 API method
//	This method is a required by IIS.  It is called
//	for each notification event requested.  This is
//	where the filter accomplishes its purpose in life.
//---------------------------------------------------------------------------
DWORD WINAPI 
HttpFilterProc
(
	HTTP_FILTER_CONTEXT *pfc,
	DWORD NotificationType,
	VOID * pvData
)
{
	DWORD dwRet;

	DebugMsg(( DEST,
		TEXT("[HttpFilerProc] Notification Type: %d"),
		NotificationType));

	//--------------------------------------------------------------------------
	// Direct the notification to the appropriate
	// routine for processing.
	//--------------------------------------------------------------------------
	switch ( NotificationType )
	{
		case SF_NOTIFY_READ_RAW_DATA:
			dwRet = OnReadRawData(pfc, (PHTTP_FILTER_RAW_DATA) pvData );
			break;
		case SF_NOTIFY_PREPROC_HEADERS:
			dwRet = OnPreprocHeaders(pfc, (PHTTP_FILTER_PREPROC_HEADERS) pvData );
			break;
		case SF_NOTIFY_URL_MAP:
			dwRet = OnUrlMap(pfc, (PHTTP_FILTER_URL_MAP) pvData );
			break;
		case SF_NOTIFY_AUTHENTICATION:
			dwRet = OnAuthentication(pfc, (PHTTP_FILTER_AUTHENT) pvData );
			break;
		case SF_NOTIFY_SEND_RAW_DATA:
			dwRet = OnSendRawData(pfc, (PHTTP_FILTER_RAW_DATA) pvData );
			break;
		case SF_NOTIFY_LOG:
			dwRet = OnLog(pfc, (PHTTP_FILTER_LOG) pvData );
			break;
		case SF_NOTIFY_END_OF_NET_SESSION:
			dwRet = OnEndOfNetSession(pfc);
			break;
		default:
			DebugMsg(( DEST,
				TEXT("[HttpFilterProc] Unknown notification type, %d"), NotificationType ));
			dwRet = SF_STATUS_REQ_NEXT_NOTIFICATION;
			break;
	}
	return dwRet;
}

//===========================================================================
//	Internal Helper Routines
//===========================================================================

//===========================================================================
//	IIS Filter Event Routines
//===========================================================================

//---------------------------------------------------------------------------
//	OnReadRawData -
//	The data returned at pvData->pvInData includes the 
//	header, types of data accepted and the browsers type
//---------------------------------------------------------------------------
DWORD
OnReadRawData
(
	HTTP_FILTER_CONTEXT *pfc,
	HTTP_FILTER_RAW_DATA *pvData
)
{
	DebugMsg(( DEST, "[onReadRawData]"));
	return SF_STATUS_REQ_NEXT_NOTIFICATION;
}

//---------------------------------------------------------------------------
//	OnPreprocHeaders -
//	The data returned within pvData includes three
//	callback methods to get, set and/or add to the
//	header
//---------------------------------------------------------------------------
DWORD
OnPreprocHeaders
(
	HTTP_FILTER_CONTEXT *pfc,
	HTTP_FILTER_PREPROC_HEADERS *pvData
)
{
	DebugMsg(( DEST, TEXT("[onPreprocHeaders]")));

	EnterCriticalSection(&gCS);

	//--------------------------------------------------------------------------
	// See if context has been allocated for this connection
	//--------------------------------------------------------------------------
	if ( NULL == pfc->pFilterContext )
	{
		DebugMsg((DEST, _T("Allocating memory for pfc context!")));	
		//----------------------------------------------------------------------
		// Memory allocated from AllocMem does not need to be freed as IIS
		// will clean all allocations up at the close of the connection.
		//----------------------------------------------------------------------
		pfc->pFilterContext = pfc->AllocMem(pfc, 2048, 0);
	}

	//--------------------------------------------------------------------------
	// Look for the X-Forwarded-For header
	//--------------------------------------------------------------------------
	TCHAR  achHeaderValue[2048] = _T("");
	DWORD cb = 2048*sizeof(TCHAR);
	if (pvData->GetHeader(pfc, gHEADER_NAME, achHeaderValue, &cb))
	{
		TCHAR *p = _tcschr(achHeaderValue, ',');
		if ( NULL != p )
		{
			*p = _T('\0');
		}

		DebugMsg((DEST, _T("Found '%s' with value of '%s'\n"), gHEADER_NAME, achHeaderValue));

		TCHAR * sep = _tcschr(achHeaderValue, _T(','));
		if ( NULL != sep )
		{
			*sep = _T('\0');
			DebugMsg( (DEST, _T("Proxy detected in value, removing proxy info and using '%s'"), achHeaderValue));
		}

		sep = _tcschr(achHeaderValue, _T(';'));
		if ( NULL != sep )
		{
			*sep = _T('\0');
			DebugMsg( (DEST, _T("Proxy detected in value, removing proxy info and using '%s'"), achHeaderValue));
		}

		_tcsncpy((TCHAR *)pfc->pFilterContext, achHeaderValue, 2000);


	}
	else
	{
		DebugMsg((DEST, _T("Didn't find '%s' header!"), gHEADER_NAME));
		_tcscpy((TCHAR *)pfc->pFilterContext, _T(""));
	}

	LeaveCriticalSection(&gCS);

	return SF_STATUS_REQ_NEXT_NOTIFICATION;
}

//---------------------------------------------------------------------------
//	OnUrlMap -
//	The data returned within pvData includes the URL
//	requested (pvData->pszURL) and the full path to
//	the physical data (pvData->pszPhysicalPath.
//---------------------------------------------------------------------------

DWORD
OnUrlMap
(
	HTTP_FILTER_CONTEXT *pfc,
	HTTP_FILTER_URL_MAP *pvData
)
{
	DebugMsg(( DEST, TEXT("[onUrlMap]")));
	return SF_STATUS_REQ_NEXT_NOTIFICATION;
}

//---------------------------------------------------------------------------
//	OnAuthentication -
//	The data returned within pvData includes 
//	User identification (pvData->pszUser) and
//	the user's password (pvData->pszPassword).
//---------------------------------------------------------------------------
DWORD
OnAuthentication
(
	HTTP_FILTER_CONTEXT *pfc,
	HTTP_FILTER_AUTHENT *pvData
)
{
	DebugMsg(( DEST, TEXT("[onAuthentication]")));
	return SF_STATUS_REQ_NEXT_NOTIFICATION;
}

//---------------------------------------------------------------------------
//	OnSendRawData -
//	This routine is called twice for this event.
//	The first time it is called is when it sends
//	the browser a notification of the actual data
//	it is about to transmit(e.g. text/html, image/gif,
//	etc.)  The second time this routine is called
//	is when the actual data (e.g. text, gif, etc.)
//	is being transmitted to the browser.
//---------------------------------------------------------------------------
DWORD
OnSendRawData
(
	HTTP_FILTER_CONTEXT *pfc,
	HTTP_FILTER_RAW_DATA *pvData
)
{
	DebugMsg(( DEST, TEXT("[onSendRawData]")));
	return SF_STATUS_REQ_NEXT_NOTIFICATION;
}

//---------------------------------------------------------------------------
//	OnLog -
//	This routine is called following the data
//	being sent to the browser.  The data within
//	pvData includes the client host name, 
//	client user name, server name, operation 
//	requested (e.g. GET, POST, etc.), target
//	item (e.g. /default.htm), parameters passed
//	with the target and the status returned to
//	the browser.
//---------------------------------------------------------------------------
DWORD
OnLog
(
	HTTP_FILTER_CONTEXT *pfc,
	HTTP_FILTER_LOG *pvData
)
{
	DebugMsg(( DEST, TEXT("[onLog]")));

	//--------------------------------------------------------------------------
	// If pFilterContext was set with the X-Forwarded-For header
	// then replace the client hostname with that value.
	//--------------------------------------------------------------------------
	if ( (NULL != pfc->pFilterContext) && (_T('\0') != *(TCHAR *)(pfc->pFilterContext)) )
	{
		pvData->pszClientHostName = (TCHAR *)pfc->pFilterContext;
	}

	return SF_STATUS_REQ_NEXT_NOTIFICATION;
}

//---------------------------------------------------------------------------
//	OnEndOfNetSession -
//	This routine is called following the 
//	transmission of all the data requested
//	by the browser.
//---------------------------------------------------------------------------
DWORD
OnEndOfNetSession
(
	HTTP_FILTER_CONTEXT *pfc
)
{
	DebugMsg(( DEST, TEXT("[onEndOfNetSession]")));
	return SF_STATUS_REQ_NEXT_NOTIFICATION;
}

//---------------------------------------------------------------------------
// ReadConfiguration -
// Read configuration overrides from configuration file.
//---------------------------------------------------------------------------
void
ReadConfiguration
(
	HANDLE hModule
)
{
	TCHAR configPath[BUFFER_LEN];
	DWORD dwLen = 0;

	memset(gHEADER_NAME, '\0', BUFFER_LEN * sizeof(TCHAR));
	memset(configPath, '\0', BUFFER_LEN * sizeof(TCHAR));

	DebugMsg((DEST, "============================================"));

	dwLen = GetModuleFileName((HMODULE)hModule, configPath, 256);
	if (dwLen > 4)
	{
		// convert .dll to .ini
		configPath[dwLen-3] = 'i';
		configPath[dwLen-2] = 'n';
		configPath[dwLen-1] = 'i';

		DebugMsg((DEST, _T("Reading profile information from '%s'"), configPath));

		DWORD dwStat = GetPrivateProfileString(
			_T("SETTINGS"), _T("HEADER"), DEFAULT_HEADER_NAME,
			gHEADER_NAME, BUFFER_LEN,
			configPath);
		DebugMsg((DEST, _T("Using custom header value of '%s'"), gHEADER_NAME));
	}
	if ( _T('\0') == gHEADER_NAME[0] )
	{
		_tcscpy(gHEADER_NAME, DEFAULT_HEADER_NAME);
	}
	if ( _T(':') != gHEADER_NAME[_tcslen(gHEADER_NAME)-1] )
	{
		_tcscat(gHEADER_NAME, _T(":"));
	}
}

/* End Of File */
