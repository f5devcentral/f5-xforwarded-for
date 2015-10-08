//===========================================================================
//
// File         : F5XForwardingFor.h
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


// The following ifdef block is the standard way of creating macros which make exporting 
// from a DLL simpler. All files within this DLL are compiled with the F5LOGHEADER_EXPORTS
// symbol defined on the command line. this symbol should not be defined on any project
// that uses this DLL. This way any other project whose source files include this file see 
// F5LOGHEADER_API functions as being imported from a DLL, whereas this DLL sees symbols
// defined with this macro as being exported.
#ifdef F5LOGHEADER_EXPORTS
#define F5LOGHEADER_API __declspec(dllexport)
#else
#define F5LOGHEADER_API __declspec(dllimport)
#endif


/*
	Private prototypes
		These are the methods executed for each of
		the related filter events.
*/
DWORD
OnAuthentication
(
	HTTP_FILTER_CONTEXT *pfc,
	HTTP_FILTER_AUTHENT *pvData
);

DWORD
OnLog
(
	HTTP_FILTER_CONTEXT *pfc,
	HTTP_FILTER_LOG *pvData
);

DWORD
OnUrlMap
(
	HTTP_FILTER_CONTEXT *pfc,
	HTTP_FILTER_URL_MAP *pvData
);

DWORD
OnPreprocHeaders
(
	HTTP_FILTER_CONTEXT *pfc,
	HTTP_FILTER_PREPROC_HEADERS *pvData
);

DWORD
OnEndOfNetSession
(
	HTTP_FILTER_CONTEXT *pfc
);

DWORD
OnSendRawData
(
	HTTP_FILTER_CONTEXT *pfc,
	HTTP_FILTER_RAW_DATA *pvData
);

DWORD
OnReadRawData
(
	HTTP_FILTER_CONTEXT *pfc,
	HTTP_FILTER_RAW_DATA *pvData
);
