#include "Protect.h"

void Protector_Manual()
{
	const int select = 2;
	TCHAR sbuf[select][MAX_PATH] =
	{ _T("- Protect"), _T("- exit") };

	gotoxy(0, 2);
	_tprintf_s(_T("Usages "));

	for (int i = 0; i < select; i++)
	{
		gotoxy(7, 2 + i);
		_tprintf_s(_T("%s"), sbuf[i]);
	}
}

void Protector()
{
	SetColor(WHITE);
	if (!LastOpen)
	{
		SetColor(RED);
		_tprintf_s(_T("ERROR : Not File Select\n"));
		_tprintf_s(_T("      -> Please 1.Select File and 4.Protector !\n\n"));
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
		_tprintf_s(_T("Protector > "));

		if (!First)
		{
			Protector_Manual();
			First = TRUE;
		}

		SetColor(YELLOW);
		gotoxy(12, 0);
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
			if (!_tcscmp(input, _T("Protect")))
			{
				PlusAntiDebugging();
			}
			else
				First = FALSE;
		}

	} while (IsEnd);
}

void PlusAntiDebugging()
{
	if (bit != 0x10B)
	{
		gotoxy(0, 2);
		SetColor(RED);
		_tprintf_s(_T("ERROR : Protect only 32bit PE"));
		SetColor(WHITE);
		return;
	}

	LONG offset = Dos.e_lfanew;
	offset += sizeof(IMAGE_NT_HEADERS32);
	offset += (sizeof(IMAGE_SECTION_HEADER)*NT32.FileHeader.NumberOfSections);

	BOOL Check = FALSE;

	{
		BYTE Name[8] = ".Anti";

		for (int i = 0; i < NumberSection; i++)
		{
			if (ByteCmp(Name, Sec[i].Name))
			{
				Check = TRUE;
				break;
			}
			else
				Check = FALSE;
		}

		if (Check)
		{
			gotoxy(0, 2);
			SetColor(RED);
			_tprintf_s(_T("ERROR : .Anti Section already make"));
			SetColor(WHITE);
			return;
		}
	}

	{
		BYTE Name[8] = ".reloc";

		for (int i = 0; i < NumberSection; i++)
		{
			if (ByteCmp(Name, Sec[i].Name))
			{
				Check = TRUE;
				break;
			}
			else
				Check = FALSE;
		}

		if (Check)
		{
			gotoxy(0, 2);
			SetColor(RED);
			_tprintf_s(_T("ERROR : First, .reloc Section delete // Second, Protect"));
			SetColor(WHITE);
			return;
		}
	}

	DWORD CodeSection = 0xFFFFFFFF;
	{
		DWORD option = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ;

		Check = TRUE;
		for (int i = 0; i < NumberSection; i++)
		{
			if ((Sec[i].Characteristics&option) == option)
			{
				Check = FALSE;
				CodeSection = (DWORD)i;
				break;
			}
		}

		if (Check)
		{
			gotoxy(0, 2);
			SetColor(RED);
			_tprintf_s(_T("ERROR : Not Found Code Section"));
			SetColor(WHITE);
			return;
		}
	}

	{
		Check = FALSE;
		DWORD size = 0x00;
		size = sizeof(IMAGE_NT_HEADERS32);

		SetFilePointer(File, Dos.e_lfanew + size, NULL, FILE_BEGIN);
		SetFilePointer(File, -(sizeof(DWORD) * 2 * 7), NULL, FILE_CURRENT);

		DWORD cnt;
		ULONGLONG TLSCheck = 0x00;
		ReadFile(File, &TLSCheck, sizeof(ULONGLONG), &cnt, NULL);

		if (TLSCheck != 0x00)
			Check = TRUE;

		if (Check)
		{
			gotoxy(0, 2);
			SetColor(RED);
			_tprintf_s(_T("ERROR : TLS CALLBACK is Not Protect"));
			SetColor(WHITE);
			return;
		}
	}

	BOOL Is0x00 = TRUE;

	SetFilePointer(File, offset, NULL, FILE_BEGIN);
	for (int i = 0; i < IMAGE_SIZEOF_SECTION_HEADER; i++)
	{
		BYTE buf;
		DWORD cnt;
		ReadFile(File, &buf, sizeof(BYTE), &cnt, NULL);
		if (buf != 0x00)
		{
			Is0x00 = FALSE;
			break;
		}
	}

	if (Is0x00)
	{
		SetFilePointer(File, offset, NULL, FILE_BEGIN);

		DWORD cnt;

		BYTE Name[8] = ".Anti";
		DWORD VirtualSize = 0x0;
		DWORD LastSection;
		DWORD VirtualAddress;
		DWORD SizeOfRawData;
		DWORD PointerToRawData;
		DWORD Reserved1 = 0x00000000;
		WORD Reserved2 = 0x0000;
		DWORD Characteristics = 0xE0000020;

		DWORD SizeOfImage;
		DWORD SizeOfCode;
		DWORD OEP;
		WORD NumberOfSections;

		LastSection = NT32.FileHeader.NumberOfSections - 1;

		VirtualSize = NT32.OptionalHeader.SectionAlignment;
		if ((Sec[LastSection].Misc.VirtualSize%NT32.OptionalHeader.SectionAlignment) == 0)
			VirtualAddress = Sec[LastSection].VirtualAddress + (Sec[LastSection].Misc.VirtualSize / NT32.OptionalHeader.SectionAlignment)*NT32.OptionalHeader.SectionAlignment;
		else
			VirtualAddress = Sec[LastSection].VirtualAddress + (Sec[LastSection].Misc.VirtualSize / NT32.OptionalHeader.SectionAlignment)*NT32.OptionalHeader.SectionAlignment + NT32.OptionalHeader.SectionAlignment;
		SizeOfRawData = NT32.OptionalHeader.FileAlignment;

		SizeOfImage = NT32.OptionalHeader.SizeOfImage + VirtualSize;
		SizeOfCode = NT32.OptionalHeader.SizeOfCode + SizeOfRawData;
		NumberOfSections = NT32.FileHeader.NumberOfSections + 1;

		PointerToRawData = Sec[LastSection].PointerToRawData + Sec[LastSection].SizeOfRawData;

		WriteFile(File, &Name, sizeof(Name), &cnt, NULL);
		WriteFile(File, &VirtualSize, sizeof(DWORD), &cnt, NULL);
		WriteFile(File, &VirtualAddress, sizeof(DWORD), &cnt, NULL);
		WriteFile(File, &SizeOfRawData, sizeof(DWORD), &cnt, NULL);
		WriteFile(File, &PointerToRawData, sizeof(DWORD), &cnt, NULL);
		WriteFile(File, &Reserved1, sizeof(DWORD), &cnt, NULL);
		WriteFile(File, &Reserved1, sizeof(DWORD), &cnt, NULL);
		WriteFile(File, &Reserved2, sizeof(WORD), &cnt, NULL);
		WriteFile(File, &Reserved2, sizeof(WORD), &cnt, NULL);
		WriteFile(File, &Characteristics, sizeof(DWORD), &cnt, NULL);

		SetColor(WHITE);

		gotoxy(0, 2);
		_tprintf_s(_T("New Section Header !!"));

		SetFilePointer(File, Dos.e_lfanew + sizeof(DWORD) + sizeof(WORD), NULL, FILE_BEGIN);
		WriteFile(File, &NumberOfSections, sizeof(WORD), &cnt, NULL);

		gotoxy(0, 3);
		_tprintf_s(_T("File->NumberOfSections : 0x%X"), NumberOfSections);

		SetFilePointer(File, Dos.e_lfanew + sizeof(DWORD) * 2 + sizeof(IMAGE_FILE_HEADER), NULL, FILE_BEGIN);
		WriteFile(File, &SizeOfCode, sizeof(DWORD), &cnt, NULL);

		gotoxy(0, 4);
		_tprintf_s(_T("Option->SizeOfCode : 0x%X"), SizeOfCode);

		SetFilePointer(File, Dos.e_lfanew + sizeof(IMAGE_FILE_HEADER) + sizeof(DWORD) * 15, NULL, FILE_BEGIN);
		WriteFile(File, &SizeOfImage, sizeof(DWORD), &cnt, NULL);

		gotoxy(0, 5);
		_tprintf_s(_T("Option->SizeOfImage : 0x%X"), SizeOfImage);

		SetFilePointer(File, Sec[LastSection].PointerToRawData + Sec[LastSection].SizeOfRawData, NULL, FILE_BEGIN);
		for (int i = 0; i < (int)SizeOfRawData; i++)
		{
			BYTE num = 0x00;
			WriteFile(File, &num, sizeof(BYTE), &cnt, NULL);
		}

		gotoxy(0, 6);
		_tprintf_s(_T("New Section Body !!"));

		OEP = VirtualAddress + 0x10;	//OEP

		DWORD O_OEP;
		SetFilePointer(File, Dos.e_lfanew + sizeof(IMAGE_FILE_HEADER) + sizeof(DWORD) * 5, NULL, FILE_BEGIN);
		ReadFile(File, &O_OEP, sizeof(DWORD), &cnt, NULL);

		SetFilePointer(File, Dos.e_lfanew + sizeof(IMAGE_FILE_HEADER) + sizeof(DWORD) * 5, NULL, FILE_BEGIN);
		WriteFile(File, &OEP, sizeof(DWORD), &cnt, NULL);

		gotoxy(0, 7);
		_tprintf_s(_T("Orignal OEP -> New OEP : 0x%X"), OEP);

		//TimeStamp 마지막 1 BYTE key로 사용 
		BYTE Encryption_Key;
		if (bit == 0x10B)
			Encryption_Key = (BYTE)NT32.FileHeader.TimeDateStamp;
		else if (bit == 0x20B)
			Encryption_Key = (BYTE)NT64.FileHeader.TimeDateStamp;

		DWORD Start = Sec[CodeSection].PointerToRawData;
		DWORD End = Sec[CodeSection].SizeOfRawData - 1;
		SetFilePointer(File, Start, NULL, FILE_BEGIN);
		for (int i = 1; i <= (int)End; i++)
		{
			BYTE Encryption_BYTE;
			ReadFile(File, &Encryption_BYTE, sizeof(BYTE), &cnt, NULL);

			Encryption_BYTE ^= Encryption_Key;
			SetFilePointer(File, -1, NULL, FILE_CURRENT);
			WriteFile(File, &Encryption_BYTE, sizeof(BYTE), &cnt, NULL);
		}

		gotoxy(0, 8);
		_tprintf_s(_T("Code Section Encryption Success!!"));

		DWORD size = sizeof(IMAGE_NT_HEADERS32);
		SetFilePointer(File, Dos.e_lfanew + size + sizeof(IMAGE_SECTION_HEADER)*CodeSection + 8 + sizeof(DWORD) * 7, NULL, FILE_BEGIN);
		WriteFile(File, &Characteristics, sizeof(DWORD), &cnt, NULL);	//옵션 추가

		gotoxy(0, 9);
		_tprintf_s(_T("Code Section Option renew"));

		BYTE opcode[] = { 0x60, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x5F, 0x83, 0xEF, 0x16, 0x0F, 0xB6, 0x37, 0x8B, 0x5F, 0x05,
			0x33, 0xC9, 0x3B, 0x4F, 0x09, 0x74, 0x10, 0x90, 0x90, 0x90, 0x90, 0x0F, 0xB6, 0x04, 0x19, 0x33,
			0xC6, 0x88, 0x04, 0x19, 0x41, 0xEB, 0xEB, 0x90, 0x64, 0xA1, 0x18, 0x00, 0x00, 0x00, 0x8B, 0x40,
			0x30, 0x0F, 0xB6, 0x40, 0x02, 0x85, 0xC0, 0x74, 0x05, 0xE9, 0xB3, 0x2F, 0xBF, 0xFF, 0x61, 0xE9 };	//0xE9 다음 점프값 추가

		SetFilePointer(File, PointerToRawData, NULL, FILE_BEGIN);
		WriteFile(File, &Encryption_Key, sizeof(BYTE), &cnt, NULL);

		DWORD CodeSection_VA = 0x00;
		DWORD CodeSection_Size = Sec[CodeSection].SizeOfRawData - 1;
		O_OEP += NT32.OptionalHeader.ImageBase;
		CodeSection_VA = NT32.OptionalHeader.ImageBase + Sec[CodeSection].VirtualAddress;

		WriteFile(File, &O_OEP, sizeof(DWORD), &cnt, NULL);

		WriteFile(File, &CodeSection_VA, sizeof(DWORD), &cnt, NULL);
		WriteFile(File, &CodeSection_Size, sizeof(DWORD), &cnt, NULL);

		SetFilePointer(File, PointerToRawData + 0x10, NULL, FILE_BEGIN);
		WriteFile(File, &opcode, sizeof(opcode), &cnt, NULL);

		DWORD EIP = NT32.OptionalHeader.ImageBase + VirtualAddress + sizeof(opcode) - 1 + 5 + 0x10;
		DWORD JMP_Opcode = (DWORD)~(EIP - O_OEP) + 1;
		WriteFile(File, &JMP_Opcode, sizeof(DWORD), &cnt, NULL);

		gotoxy(0, 10);
		_tprintf_s(_T("OPCODE Plus !!"));
	}
	else
	{
		gotoxy(0, 2);

		SetColor(RED);
		_tprintf_s(_T("ERROR : SECTION Not empty"));
		SetColor(WHITE);
	}
}