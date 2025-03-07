/*
 *	   Copyright (c) 2000-2013 Thomas Heller
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 * LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 * OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 * WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#include <windows.h>
#include <stdio.h>

void SystemError(int error, char *msg)
{
	char Buffer[1024];
	int n;

	if (error) {
		LPVOID lpMsgBuf;
		FormatMessageA(
			FORMAT_MESSAGE_ALLOCATE_BUFFER |
			FORMAT_MESSAGE_FROM_SYSTEM,
			NULL,
			error,
			MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
			(LPSTR)&lpMsgBuf,
			0,
			NULL
			);
		strncpy(Buffer, lpMsgBuf, sizeof(Buffer));
		LocalFree(lpMsgBuf);
	} else
		Buffer[0] = '\0';
	n = lstrlenA(Buffer);
	_snprintf(Buffer+n, sizeof(Buffer)-n, msg);
	MessageBoxA(GetFocus(), Buffer, NULL, MB_OK | MB_ICONSTOP);
}

extern int init(char *, int, wchar_t **);
extern int start();

/*
  The main function for our exe.
*/
int WINAPI
WinMain(HINSTANCE hInst, HINSTANCE hPrevInst,
	LPSTR lpCmdLine, int nCmdShow)
{
	int result = 0;
	int argc;
	LPWSTR *argv;
	LPWSTR cmdline = GetCommandLineW();
	argv = CommandLineToArgvW(cmdline, &argc);
	result = init("windows_exe", argc, argv);
	if (result)
		return result;
	return start();
}
