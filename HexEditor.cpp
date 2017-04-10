#include "HexEditor.h"

void HexEditor_Manual()
{
	const int select = 3;
	TCHAR sbuf[select][MAX_PATH] =
	{ _T("- Read VA/RVA/OFFSET Position Line"), _T("- Write VA/RVA/OFFSET Position Value"), _T("- exit") };

	gotoxy(0, 2);
	_tprintf_s(_T("Usages "));

	for (int i = 0; i < select; i++)
	{
		gotoxy(7, 2 + i);
		_tprintf_s(_T("%s"), sbuf[i]);
	}
}

void HexEditor()
{
	SetColor(WHITE);
	if (!LastOpen)
	{
		SetColor(RED);
		_tprintf_s(_T("ERROR : Not File Select\n"));
		_tprintf_s(_T("      -> Please 1.Select File and 3.HEX !\n\n"));
		SetColor(WHITE);

		system("pause");
		return;
	}

	int str_cnt = 0;
	const int max_input = 10;

	TCHAR buf[max_input][MAX_PATH] = { 0, };
	TCHAR input[MAX_PATH] = { 0, };

	BOOL IsEnd = TRUE;
	BOOL First = FALSE;

	system("cls");

	do {

		gotoxy(0, 0);
		_tprintf_s(_T("Hex > "));

		if (!First)
		{
			HexEditor_Manual();
			First = TRUE;
		}

		SetColor(YELLOW);
		gotoxy(7, 0);
		for (int i = 0; i < MAX_PATH; i++)
		{
			input[i] = getchar();
			if (input[i] == 10)
			{
				input[i] = '\0';
				break;
			}
		}
		SetColor(WHITE);

		str_cnt = input_split(input, buf);

		system("cls");

		if (!_tcscmp(input, _T("exit")))
			IsEnd = FALSE;
		else
		{
			if (!_tcscmp(buf[0], _T("Read")))
			{
				if (!_tcscmp(buf[1], _T("VA")))
					Read_HexEditor(VA, _tcstoi64(buf[2], NULL, 16), _tcstoi64(buf[3], NULL, 10));
				else if (!_tcscmp(buf[1], _T("RVA")))
					Read_HexEditor(RVA, _tcstoi64(buf[2], NULL, 16), _tcstoi64(buf[3], NULL, 10));
				else if (!_tcscmp(buf[1], _T("OFFSET")))
					Read_HexEditor(OFFSET, _tcstoi64(buf[2], NULL, 16), _tcstoi64(buf[3], NULL, 10));
				else
					First = FALSE;
			}

			else if (!_tcscmp(buf[0], _T("Write")))
			{
				if (!_tcscmp(buf[1], _T("VA")))
					Write_HexEditor(VA, _tcstoi64(buf[2], NULL, 16), _tcstoi64(buf[3], NULL, 16));
				else if (!_tcscmp(buf[1], _T("RVA")))
					Write_HexEditor(RVA, _tcstoi64(buf[2], NULL, 16), _tcstoi64(buf[3], NULL, 16));
				else if (!_tcscmp(buf[1], _T("OFFSET")))
					Write_HexEditor(OFFSET, _tcstoi64(buf[2], NULL, 16), _tcstoi64(buf[3], NULL, 16));
				else
					First = FALSE;
			}

			else
				First = FALSE;
		}

	} while (IsEnd);
}

void Read_HexEditor(int mode, DWORD dwPoint, DWORD dwLine)
{
	const DWORD DosStart = 0;
	const DWORD DosEnd = sizeof(IMAGE_DOS_HEADER) - 1;

	const DWORD FileStart = Dos.e_lfanew + sizeof(DWORD);
	const DWORD FileEnd = FileStart + sizeof(IMAGE_FILE_HEADER) - 1;

	const DWORD OptionStart = Dos.e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER);
	const DWORD Option32End = OptionStart + sizeof(IMAGE_OPTIONAL_HEADER32) - 1;
	const DWORD Option64End = OptionStart + sizeof(IMAGE_OPTIONAL_HEADER64) - 1;

	DWORD SecStart = 0x00;
	DWORD SecEnd = 0x00;

	if (bit == 0x10B)
	{
		SecStart = Dos.e_lfanew + sizeof(IMAGE_NT_HEADERS32);
		SecEnd = SecStart + sizeof(IMAGE_SECTION_HEADER)*NT32.FileHeader.NumberOfSections - 1;
	}
	else if (bit == 0x20B)
	{
		SecStart = Dos.e_lfanew + sizeof(IMAGE_NT_HEADERS64);
		SecEnd = SecStart + sizeof(IMAGE_SECTION_HEADER)*NT64.FileHeader.NumberOfSections - 1;
	}

	ULONGLONG ullRVA = 0;
	ULONGLONG offset = 0;
	int found_number = 0;
	int max_SecCnt = 0;
	BOOL bSuccess = FALSE;

	if (dwLine > 40)
		dwLine = 40;

	if ((mode == VA) || (mode == RVA))
	{
		if (mode == VA)
		{
			if (bit == 0x10B)
			{
				ullRVA = dwPoint - NT32.OptionalHeader.ImageBase;
				max_SecCnt = NT32.FileHeader.NumberOfSections;
			}
			else if (bit == 0x20B)
			{
				ullRVA = dwPoint - NT64.OptionalHeader.ImageBase;
				max_SecCnt = NT64.FileHeader.NumberOfSections;
			}
		}
		else if (mode == RVA)
		{
			ullRVA = dwPoint;
			max_SecCnt = (bit == 0x10B) ? NT32.FileHeader.NumberOfSections : NT64.FileHeader.NumberOfSections;
		}

		if (Sec[0].VirtualAddress > ullRVA)
		{
			offset = ullRVA;
			bSuccess = TRUE;
		}
		else
		{
			for (int i = 1; i < max_SecCnt; i++)
			{
				if ((ullRVA >= Sec[i - 1].VirtualAddress) && (ullRVA < Sec[i].VirtualAddress))
				{
					offset = ullRVA - Sec[i - 1].VirtualAddress + Sec[i - 1].PointerToRawData;
					bSuccess = TRUE;
					break;
				}
			}

			if (!bSuccess)
			{
				if (ullRVA >= Sec[max_SecCnt - 1].VirtualAddress)
				{
					offset = ullRVA - Sec[max_SecCnt - 1].VirtualAddress + Sec[max_SecCnt - 1].PointerToRawData;
					bSuccess = TRUE;
				}
			}
		}
	}
	else if (mode == OFFSET)
	{
		SetFilePointer(File, 0, NULL, FILE_END);
		DWORD max_fileSize = GetFileSize(File, NULL);

		if (max_fileSize >= dwPoint)
		{
			offset = dwPoint;
			bSuccess = TRUE;
		}
	}

	gotoxy(0, 2);
	if (bSuccess)
	{
		SetColor(YELLOW);
		SetFilePointer(File, offset, NULL, FILE_BEGIN);
		_tprintf_s(_T("%10s  00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F  Value"), _T("[ OFFSET ]"));
		SetColor(WHITE);

		for (int i = 1; i <= dwLine; i++)
		{
			gotoxy(0, 2 + i);
			_tprintf_s(_T("0x%08X"), offset + (i - 1) * 16);

			BYTE buf[16] = { 0, };

			gotoxy(12, 2 + i);
			for (int j = 0; j <= 0xF; j++)
			{
				BYTE byte = 0x00;
				DWORD cnt = 0x00;
				ReadFile(File, &byte, sizeof(BYTE), &cnt, NULL);
				buf[j] = byte;

				int PreOffset = offset + (i - 1) * 16 + j;
				if ((PreOffset >= DosStart) && (PreOffset <= DosEnd))
					SetColor(DARK_RED);
				else if ((PreOffset >= Dos.e_lfanew) && (PreOffset <= Dos.e_lfanew + sizeof(DWORD) - 1))
					SetColor(DARK_YELLOW);
				else if ((PreOffset >= FileStart) && (PreOffset <= FileEnd))
					SetColor(DARK_GREEN);
				else if ((PreOffset >= SecStart) && (PreOffset <= SecEnd))
					SetColor(DARK_SKY_BLUE);

				if (bit == 0x10B)
				{
					if ((PreOffset >= OptionStart) && (PreOffset <= Option32End))
						SetColor(DARK_BLUE);
				}
				else if (bit == 0x20B)
				{
					if ((PreOffset >= OptionStart) && (PreOffset <= Option64End))
						SetColor(DARK_BLUE);
				}

				_tprintf_s(_T("%02X "), byte);

				SetColor(WHITE);
			}

			for (int j = 0; j <= 0xF; j++)
			{
				if ((buf[j] >= 0x20) && (buf[j] <= 0x7A))
					_tprintf_s(_T("%c"), buf[j]);
				else
					_tprintf_s(_T("."));
			}
		}
	}
	else
	{
		SetColor(RED);
		_tprintf_s(_T("ERROR : Not Found 0x%X !!"), dwPoint);
		SetColor(WHITE);
	}
}

void Write_HexEditor(int mode, DWORD dwPoint, BYTE dwValue)
{
	ULONGLONG ullRVA = 0;
	ULONGLONG offset = 0;
	int found_number = 0;
	int max_SecCnt = 0;
	BOOL bSuccess = FALSE;

	DWORD dwLine = 10;

	if ((mode == VA) || (mode == RVA))
	{
		if (mode == VA)
		{
			if (bit == 0x10B)
			{
				ullRVA = dwPoint - NT32.OptionalHeader.ImageBase;
				max_SecCnt = NT32.FileHeader.NumberOfSections;
			}
			else if (bit == 0x20B)
			{
				ullRVA = dwPoint - NT64.OptionalHeader.ImageBase;
				max_SecCnt = NT64.FileHeader.NumberOfSections;
			}
		}
		else if (mode == RVA)
		{
			ullRVA = dwPoint;
			max_SecCnt = (bit == 0x10B) ? NT32.FileHeader.NumberOfSections : NT64.FileHeader.NumberOfSections;
		}

		if (Sec[0].VirtualAddress > ullRVA)
		{
			offset = ullRVA;
			bSuccess = TRUE;
		}
		else
		{
			for (int i = 1; i < max_SecCnt; i++)
			{
				if ((ullRVA >= Sec[i - 1].VirtualAddress) && (ullRVA < Sec[i].VirtualAddress))
				{
					offset = ullRVA - Sec[i - 1].VirtualAddress + Sec[i - 1].PointerToRawData;
					bSuccess = TRUE;
					break;
				}
			}

			if (!bSuccess)
			{
				if (ullRVA >= Sec[max_SecCnt - 1].VirtualAddress)
				{
					offset = ullRVA - Sec[max_SecCnt - 1].VirtualAddress + Sec[max_SecCnt - 1].PointerToRawData;
					bSuccess = TRUE;
				}
			}
		}
	}
	else if (mode == OFFSET)
	{
		SetFilePointer(File, 0, NULL, FILE_END);
		DWORD max_fileSize = GetFileSize(File, NULL);

		if (max_fileSize >= dwPoint)
		{
			offset = dwPoint;
			bSuccess = TRUE;
		}
	}

	gotoxy(0, 2);
	if (bSuccess)
	{
		SetColor(YELLOW);
		SetFilePointer(File, offset, NULL, FILE_BEGIN);
		_tprintf_s(_T("%10s  00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F  Value"), _T("[ OFFSET ]"));
		SetColor(WHITE);

		for (int i = 1; i <= dwLine; i++)
		{
			gotoxy(0, 2 + i);
			_tprintf_s(_T("0x%08X"), offset + (i - 1) * 16);

			BYTE buf[16] = { 0, };

			gotoxy(12, 2 + i);
			for (int j = 0; j <= 0xF; j++)
			{
				BYTE byte = 0x00;
				DWORD cnt = 0x00;
				ReadFile(File, &byte, sizeof(BYTE), &cnt, NULL);
				buf[j] = byte;
				_tprintf_s(_T("%02X "), byte);
			}

			for (int j = 0; j <= 0xF; j++)
			{
				if ((buf[j] >= 0x20) && (buf[j] <= 0x7A))
					_tprintf_s(_T("%c"), buf[j]);
				else
					_tprintf_s(_T("."));
			}
		}

		{//cnt 변수 제한두기
			DWORD cnt = 0x00;
			SetFilePointer(File, offset, NULL, FILE_BEGIN);
			WriteFile(File, &dwValue, sizeof(BYTE), &cnt, NULL);
		}

		SetFilePointer(File, offset, NULL, FILE_BEGIN);

		SetColor(YELLOW);
		gotoxy(0, dwLine + 12);
		_tprintf_s(_T("%10s  00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F  Value"), _T("[ OFFSET ]"));
		SetColor(WHITE);

		for (int i = 1; i <= dwLine; i++)
		{
			gotoxy(0, dwLine + 12 + i);
			_tprintf_s(_T("0x%08X"), offset + (i - 1) * 16);

			BYTE buf[16] = { 0, };

			gotoxy(12, dwLine + 12 + i);
			for (int j = 0; j <= 0xF; j++)
			{
				BYTE byte = 0x00;
				DWORD cnt = 0x00;
				ReadFile(File, &byte, sizeof(BYTE), &cnt, NULL);
				buf[j] = byte;
				_tprintf_s(_T("%02X "), byte);
			}

			for (int j = 0; j <= 0xF; j++)
			{
				if ((buf[j] >= 0x20) && (buf[j] <= 0x7A))
					_tprintf_s(_T("%c"), buf[j]);
				else
					_tprintf_s(_T(" "));
			}
		}
	}
	else
	{
		SetColor(RED);
		_tprintf_s(_T("ERROR : Not Found 0x%X !!"), dwPoint);
		SetColor(WHITE);
	}

}