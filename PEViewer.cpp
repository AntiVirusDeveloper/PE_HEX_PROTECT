#include "PEViewer.h"

void PEView_Init()
{
	if (LastOpen)
	{
		delete[] Sec;

		bit = 0;
		NumberSection = 0;

		LastOpen = FALSE;
	}
}

BOOL SetDosHeader(BOOL First = TRUE)
{
	SetFilePointer(File, 0, NULL, FILE_BEGIN);

	if (First)
		_tprintf_s(_T("\n[ DosHeader ]\n"));

	DWORD Success = 0x00;
	ReadFile(File, &Dos, sizeof(IMAGE_DOS_HEADER), &Success, NULL);
	if (Success != sizeof(IMAGE_DOS_HEADER))
		return FALSE;

	return TRUE;
}

BOOL SetNT32Header(BOOL First = TRUE)
{
	SetFilePointer(File, Dos.e_lfanew, NULL, FILE_BEGIN);

	if (First)
		_tprintf_s(_T("\n[ NT32 Header ]\n"));

	DWORD Success = 0x00;
	ReadFile(File, &NT32, sizeof(IMAGE_NT_HEADERS32), &Success, NULL);
	if (Success != sizeof(IMAGE_NT_HEADERS32))
		return FALSE;

	return TRUE;
}

BOOL SetNT64Header(BOOL First = TRUE)
{
	SetFilePointer(File, Dos.e_lfanew, NULL, FILE_BEGIN);

	if (First)
		_tprintf_s(_T("\n[ NT64 Header ]\n"));

	DWORD Success = 0x00;
	ReadFile(File, &NT64, sizeof(IMAGE_NT_HEADERS64), &Success, NULL);
	if (Success != sizeof(IMAGE_NT_HEADERS64))
		return FALSE;

	return TRUE;
}

BOOL SetSectionHeader(BOOL First = TRUE)
{
	DWORD offset = Dos.e_lfanew + ((bit == 0x10B) ? sizeof(IMAGE_NT_HEADERS32) : sizeof(IMAGE_NT_HEADERS64));

	if (First)
		_tprintf_s(_T("\n[ Section Header ]\n"));

	for (int i = 0; i < NumberSection; i++)
	{
		DWORD Success = 0x00;
		ReadFile(File, &Sec[i], IMAGE_SIZEOF_SECTION_HEADER, &Success, NULL);
		if (Success != IMAGE_SIZEOF_SECTION_HEADER)
			return FALSE;

		if (First)
			_tprintf_s(_T("Section[%d] Success!!\n"), i);
	}

	return TRUE;
}

void PE_Manual()
{
	const int select = 8;
	TCHAR sbuf[select][MAX_PATH] =
	{ _T("- Dos"), _T("- Nt"), _T("- File"), _T("- Option"), _T("- Section ?"), _T("- Graph ALL/Header"), _T("- Graph VA/RVA/OFFSET 값"), _T("- exit") };

	gotoxy(0, 2);
	_tprintf_s(_T("Usages "));

	for (int i = 0; i < select; i++)
	{
		gotoxy(7, 2 + i);
		_tprintf_s(_T("%s"), sbuf[i]);
	}
}

void PEViewer()
{
	SetColor(WHITE);
	if (!LastOpen)
	{
		SetColor(RED);
		_tprintf_s(_T("ERROR : Not File Select\n"));
		_tprintf_s(_T("      -> Please 1.Select File and 2.PE !\n\n"));
		SetColor(WHITE);

		system("pause");
		return;
	}

	int str_cnt = 0;

	TCHAR input[MAX_PATH] = { 0, };

	const int max_input = 10;
	TCHAR buf[max_input][MAX_PATH] = { 0, };

	BOOL First = FALSE;

	SetDosHeader(FALSE);
	if (bit == 0x10B)
	{
		SetNT32Header(FALSE);
		NumberSection = NT32.FileHeader.NumberOfSections;
	}
	else if (bit == 0x20B)
	{
		SetNT64Header(FALSE);
		NumberSection = NT32.FileHeader.NumberOfSections;
	}

	delete[] Sec;
	Sec = new IMAGE_SECTION_HEADER[NumberSection];
	SetSectionHeader(FALSE);

	system("cls");

	do {
		gotoxy(0, 0);
		_tprintf_s(_T("PE > "));

		if (!First)
		{
			PE_Manual();
			First = TRUE;
		}

		//gotoxy(0, 40);
		//_tprintf_s(_T("==================ERROR List=================="));

		SetColor(YELLOW);
		gotoxy(5, 0);
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
			break;
		else
		{
			if (str_cnt == 1)
			{
				if (!_tcscmp(input, _T("Dos")))
					PE_DosHeader_View();
				else if (!_tcscmp(input, _T("Nt")))
					PE_NTHeader_View();
				else if (!_tcscmp(input, _T("File")))
					PE_FileHeader_View();
				else if (!_tcscmp(input, _T("Option")))
					PE_OptionHeader_View();
				else
					First = FALSE;
			}
			else if (str_cnt == 2)
			{
				if (!_tcscmp(buf[0], _T("Section")))
				{
					int SecIndex = _tstoi(buf[1]);
					if (SecIndex < NumberSection)
						PE_Section_View(SecIndex);
					else
						First = FALSE;
				}
				else if (!_tcscmp(buf[0], _T("Graph")))
				{
					if (!_tcscmp(buf[1], _T("Header")))
						PE_Graph(buf[1], FALSE);
					else if (!_tcscmp(buf[1], _T("ALL")))
						PE_Graph(buf[1], TRUE);
					else
						First = FALSE;
				}
				else
					First = FALSE;
			}
			else if (str_cnt == 3)
			{
				if (!_tcscmp(buf[0], _T("Graph")))
				{
					ULONGLONG iNum = _tcstol(buf[2], NULL, 16);
					if (iNum == 0)
						First = FALSE;
					else
					{
						if (!_tcscmp(buf[1], _T("VA")))
							PE_Graph_Found(VA, iNum);
						else if (!_tcscmp(buf[1], _T("RVA")))
							PE_Graph_Found(RVA, iNum);
						else if (!_tcscmp(buf[1], _T("OFFSET")))
							PE_Graph_Found(OFFSET, iNum);
						else
							First = FALSE;
					}
				}
				else
					First = FALSE;
			}
			else
				First = FALSE;
		}
	} while (TRUE);
}

void PE_DosHeader_View()
{
	SetColor(YELLOW);
	gotoxy(0, 2);
	_tprintf_s(_T("%-20s %-10s %-10s    %-20s"), _T("Name"), _T("Size"), _T("Value"), _T("Description"));

	SetColor(WHITE);
	gotoxy(0, 3);
	_tprintf_s(_T("%-20s %-10s 0x%08X   %-20s"), _T("e_magic"), size_Name(sizeof(Dos.e_magic)), Dos.e_magic, _T("MZ != not PE"));

	gotoxy(0, 4);
	_tprintf_s(_T("%-20s %-10s 0x%08X   %-20s"), _T("e_cblp"), size_Name(sizeof(Dos.e_cblp)), Dos.e_cblp, "");

	gotoxy(0, 5);
	_tprintf_s(_T("%-20s %-10s 0x%08X   %-20s"), _T("e_cp"), size_Name(sizeof(Dos.e_cp)), Dos.e_cp, "");

	gotoxy(0, 6);
	_tprintf_s(_T("%-20s %-10s 0x%08X   %-20s"), _T("e_crlc"), size_Name(sizeof(Dos.e_crlc)), Dos.e_crlc, "");

	gotoxy(0, 7);
	_tprintf_s(_T("%-20s %-10s 0x%08X   %-20s"), _T("e_cparhdr"), size_Name(sizeof(Dos.e_cparhdr)), Dos.e_cparhdr, "");

	gotoxy(0, 8);
	_tprintf_s(_T("%-20s %-10s 0x%08X   %-20s"), _T("e_minalloc"), size_Name(sizeof(Dos.e_minalloc)), Dos.e_minalloc, "");

	gotoxy(0, 9);
	_tprintf_s(_T("%-20s %-10s 0x%08X   %-20s"), _T("e_maxalloc"), size_Name(sizeof(Dos.e_maxalloc)), Dos.e_maxalloc, "");

	gotoxy(0, 10);
	_tprintf_s(_T("%-20s %-10s 0x%08X   %-20s"), _T("e_ss"), size_Name(sizeof(Dos.e_ss)), Dos.e_ss, "");

	gotoxy(0, 11);
	_tprintf_s(_T("%-20s %-10s 0x%08X   %-20s"), _T("e_sp"), size_Name(sizeof(Dos.e_sp)), Dos.e_sp, "");

	gotoxy(0, 12);
	_tprintf_s(_T("%-20s %-10s 0x%08X   %-20s"), _T("e_csum"), size_Name(sizeof(Dos.e_csum)), Dos.e_csum, "");

	gotoxy(0, 13);
	_tprintf_s(_T("%-20s %-10s 0x%08X   %-20s"), _T("e_ip"), size_Name(sizeof(Dos.e_ip)), Dos.e_ip, "");

	gotoxy(0, 14);
	_tprintf_s(_T("%-20s %-10s 0x%08X   %-20s"), _T("e_cs"), size_Name(sizeof(Dos.e_cs)), Dos.e_cs, "");

	gotoxy(0, 15);
	_tprintf_s(_T("%-20s %-10s 0x%08X   %-20s"), _T("e_lfarlc"), size_Name(sizeof(Dos.e_lfarlc)), Dos.e_lfarlc, "");

	gotoxy(0, 16);
	_tprintf_s(_T("%-20s %-10s 0x%08X   %-20s"), _T("e_ovno"), size_Name(sizeof(Dos.e_ovno)), Dos.e_ovno, "");

	gotoxy(0, 17);
	_tprintf_s(_T("%-20s %-10s 0x%08X   %-20s"), _T("e_res"), size_Name(sizeof(Dos.e_res)), Dos.e_res, "");

	gotoxy(0, 18);
	_tprintf_s(_T("%-20s %-10s 0x%08X   %-20s"), _T("e_oemid"), size_Name(sizeof(Dos.e_oemid)), Dos.e_oemid, "");

	gotoxy(0, 19);
	_tprintf_s(_T("%-20s %-10s 0x%08X   %-20s"), _T("e_oeminfo"), size_Name(sizeof(Dos.e_oeminfo)), Dos.e_oeminfo, "");

	gotoxy(0, 20);
	_tprintf_s(_T("%-20s %-10s 0x%08X   %-20s"), _T("e_res2"), size_Name(sizeof(Dos.e_res2)), Dos.e_res2, "");

	gotoxy(0, 21);
	_tprintf_s(_T("%-20s %-10s 0x%08X   %-20s"), _T("e_lfanew"), size_Name(sizeof(Dos.e_lfanew)), Dos.e_lfanew, "");

	COORD pos;

	SetColor(YELLOW);
	pos = make_box(23, TRUE);
	SetColor(WHITE);

	gotoxy(pos.X, pos.Y);
	_tprintf_s(_T("%s"), _T("Dos_Header"));

	SetColor(YELLOW);
	pos = make_box(23, TRUE, 30);
	SetColor(WHITE);

	gotoxy(pos.X, pos.Y);
	_tprintf_s(_T("RVA == OFFSET"));

	gotoxy(pos.X, pos.Y + 1);	//RVA of FileOffset 출력
	_tprintf_s(_T("0x%X - 0x%X"), 0, sizeof(IMAGE_DOS_HEADER));
}

void PE_NTHeader_View()
{
	SetColor(YELLOW);
	gotoxy(0, 2);
	_tprintf_s(_T("%-20s %-10s %-10s    %-20s"), _T("Name"), _T("Size"), _T("Value"), _T("Description"));

	SetColor(WHITE);
	if (bit == 0x10B)
	{
		gotoxy(0, 3);
		_tprintf_s(_T("%-20s %-10s 0x%08X    %-20s"), _T("Signature"), size_Name(sizeof(NT32.Signature)), NT32.Signature, _T("PE\\0\\0 != not PE"));

		gotoxy(0, 4);
		_tprintf_s(_T("%-20s %-10s 0x%08X    %-20s"), _T("FileHeader"), size_Name(sizeof(NT32.FileHeader)), &NT32.FileHeader, _T(""));

		gotoxy(0, 5);
		_tprintf_s(_T("%-20s %-10s 0x%08X    %-20s"), _T("OptionalHeader"), size_Name(sizeof(NT32.OptionalHeader)), &NT32.OptionalHeader, _T(""));
	}
	else if (bit == 0x20B)
	{
		gotoxy(0, 3);
		_tprintf_s(_T("%-20s %-10s 0x%08X    %-20s"), _T("Signature"), size_Name(sizeof(NT64.Signature)), NT64.Signature, _T("PE\0\0 != not PE"));

		gotoxy(0, 4);
		_tprintf_s(_T("%-20s %-10s 0x%08X    %-20s"), _T("FileHeader"), size_Name(sizeof(NT64.FileHeader)), NT64.FileHeader, _T(""));

		gotoxy(0, 5);
		_tprintf_s(_T("%-20s %-10s 0x%08X    %-20s"), _T("OptionalHeader"), size_Name(sizeof(NT64.OptionalHeader)), NT64.OptionalHeader, _T(""));
	}

	COORD pos;

	SetColor(YELLOW);
	pos = make_box(7, TRUE);
	SetColor(WHITE);

	gotoxy(pos.X, pos.Y);
	if (bit == 0x10B)
		_tprintf_s(_T("%s"), _T("NT32_Header"));
	else if (bit == 0x20B)
		_tprintf_s(_T("%s"), _T("NT64_Header"));

	SetColor(YELLOW);
	pos = make_box(7, TRUE, 30);
	SetColor(WHITE);

	gotoxy(pos.X, pos.Y);
	_tprintf_s(_T("RVA == OFFSET"));

	gotoxy(pos.X, pos.Y + 1);	//RVA of FileOffset 출력
	if (bit == 0x10B)
		_tprintf_s(_T("0x%X - 0x%X"), Dos.e_lfanew, Dos.e_lfanew + sizeof(IMAGE_NT_HEADERS32));
	else if (bit == 0x20B)
		_tprintf_s(_T("0x%X - 0x%X"), Dos.e_lfanew, Dos.e_lfanew + sizeof(IMAGE_NT_HEADERS64));
}

void PE_FileHeader_View()
{
	SetColor(YELLOW);
	gotoxy(0, 2);
	_tprintf_s(_T("%-20s %-10s %-10s    %-20s"), _T("Name"), _T("Size"), _T("Value"), _T("Description"));

	SetColor(WHITE);
	if (bit == 0x10B)
	{
		gotoxy(0, 3);
		_tprintf_s(_T("%-20s %-10s 0x%08X    %-20s"), _T("Machine"), size_Name(sizeof(NT32.FileHeader.Machine)), NT32.FileHeader.Machine, _T(""));

		gotoxy(0, 4);
		_tprintf_s(_T("%-20s %-10s 0x%08X    %-20s"), _T("NumberOfSections"), size_Name(sizeof(NT32.FileHeader.NumberOfSections)), NT32.FileHeader.NumberOfSections, _T(""));

		gotoxy(0, 5);
		_tprintf_s(_T("%-20s %-10s 0x%08X    %-20s"), _T("TimeDateStamp"), size_Name(sizeof(NT32.FileHeader.TimeDateStamp)), NT32.FileHeader.TimeDateStamp, _T(""));

		gotoxy(0, 6);
		_tprintf_s(_T("%-20s %-10s 0x%08X    %-20s"), _T("PointerToSymbolTable"), size_Name(sizeof(NT32.FileHeader.PointerToSymbolTable)), NT32.FileHeader.PointerToSymbolTable, _T(""));

		gotoxy(0, 7);
		_tprintf_s(_T("%-20s %-10s 0x%08X    %-20s"), _T("NumberOfSymbols"), size_Name(sizeof(NT32.FileHeader.NumberOfSymbols)), NT32.FileHeader.NumberOfSymbols, _T(""));

		gotoxy(0, 8);
		_tprintf_s(_T("%-20s %-10s 0x%08X    %-20s"), _T("SizeOfOptionalHeader"), size_Name(sizeof(NT32.FileHeader.SizeOfOptionalHeader)), NT32.FileHeader.SizeOfOptionalHeader, _T(""));

		gotoxy(0, 8);
		_tprintf_s(_T("%-20s %-10s 0x%08X    %-20s"), _T("Characteristics"), size_Name(sizeof(NT32.FileHeader.Characteristics)), NT32.FileHeader.Characteristics, _T(""));
	}
	else if (bit == 0x20B)
	{
		gotoxy(0, 3);
		_tprintf_s(_T("%-20s %-10s 0x%08X    %-20s"), _T("Machine"), size_Name(sizeof(NT64.FileHeader.Machine)), NT64.FileHeader.Machine, _T(""));

		gotoxy(0, 4);
		_tprintf_s(_T("%-20s %-10s 0x%08X    %-20s"), _T("NumberOfSections"), size_Name(sizeof(NT64.FileHeader.NumberOfSections)), NT64.FileHeader.NumberOfSections, _T(""));

		gotoxy(0, 5);
		_tprintf_s(_T("%-20s %-10s 0x%08X    %-20s"), _T("TimeDateStamp"), size_Name(sizeof(NT64.FileHeader.TimeDateStamp)), NT64.FileHeader.TimeDateStamp, _T(""));

		gotoxy(0, 6);
		_tprintf_s(_T("%-20s %-10s 0x%08X    %-20s"), _T("PointerToSymbolTable"), size_Name(sizeof(NT64.FileHeader.PointerToSymbolTable)), NT64.FileHeader.PointerToSymbolTable, _T(""));

		gotoxy(0, 7);
		_tprintf_s(_T("%-20s %-10s 0x%08X    %-20s"), _T("NumberOfSymbols"), size_Name(sizeof(NT64.FileHeader.NumberOfSymbols)), NT64.FileHeader.NumberOfSymbols, _T(""));

		gotoxy(0, 8);
		_tprintf_s(_T("%-20s %-10s 0x%08X    %-20s"), _T("SizeOfOptionalHeader"), size_Name(sizeof(NT64.FileHeader.SizeOfOptionalHeader)), NT64.FileHeader.SizeOfOptionalHeader, _T(""));

		gotoxy(0, 8);
		_tprintf_s(_T("%-20s %-10s 0x%08X    %-20s"), _T("Characteristics"), size_Name(sizeof(NT64.FileHeader.Characteristics)), NT64.FileHeader.Characteristics, _T(""));
	}

	COORD pos;

	SetColor(YELLOW);
	pos = make_box(10, TRUE);
	SetColor(WHITE);

	gotoxy(pos.X, pos.Y);
	if (bit == 0x10B)
		_tprintf_s(_T("%s"), _T("File_Header"));
	else if (bit == 0x20B)
		_tprintf_s(_T("%s"), _T("File_Header"));

	SetColor(YELLOW);
	pos = make_box(10, TRUE, 30);
	SetColor(WHITE);

	gotoxy(pos.X, pos.Y);
	_tprintf_s(_T("RVA == OFFSET"));

	gotoxy(pos.X, pos.Y + 1);	//RVA of FileOffset 출력
	_tprintf_s(_T("0x%X - 0x%X"), Dos.e_lfanew + sizeof(DWORD), Dos.e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER));
}

void PE_OptionHeader_View()
{
	SetColor(YELLOW);
	if (bit == 0x10B)
	{
		gotoxy(0, 2);
		_tprintf_s(_T("%-30s %-10s %-10s    %-20s"), _T("Name"), _T("Size"), _T("Value"), _T("Description"));

		SetColor(WHITE);
		gotoxy(0, 3);
		_tprintf_s(_T("%-30s %-10s 0x%08X    %-20s"), _T("Magic"), size_Name(sizeof(NT32.OptionalHeader.Magic)), NT32.OptionalHeader.Magic, _T(""));

		gotoxy(0, 4);
		_tprintf_s(_T("%-30s %-10s 0x%08X    %-20s"), _T("MajorLinkerVersion"), size_Name(sizeof(NT32.OptionalHeader.MajorLinkerVersion)), NT32.OptionalHeader.MajorLinkerVersion, _T(""));

		gotoxy(0, 5);
		_tprintf_s(_T("%-30s %-10s 0x%08X    %-20s"), _T("MinorLinkerVersion"), size_Name(sizeof(NT32.OptionalHeader.MinorLinkerVersion)), NT32.OptionalHeader.MinorLinkerVersion, _T(""));

		gotoxy(0, 6);
		_tprintf_s(_T("%-30s %-10s 0x%08X    %-20s"), _T("SizeOfCode"), size_Name(sizeof(NT32.OptionalHeader.SizeOfCode)), NT32.OptionalHeader.SizeOfCode, _T(""));

		gotoxy(0, 7);
		_tprintf_s(_T("%-30s %-10s 0x%08X    %-20s"), _T("SizeOfInitializedData"), size_Name(sizeof(NT32.OptionalHeader.SizeOfInitializedData)), NT32.OptionalHeader.SizeOfInitializedData, _T(""));

		gotoxy(0, 8);
		_tprintf_s(_T("%-30s %-10s 0x%08X    %-20s"), _T("SizeOfUninitializedData"), size_Name(sizeof(NT32.OptionalHeader.SizeOfUninitializedData)), NT32.OptionalHeader.SizeOfUninitializedData, _T(""));

		gotoxy(0, 9);
		_tprintf_s(_T("%-30s %-10s 0x%08X    %-20s"), _T("AddressOfEntryPoint"), size_Name(sizeof(NT32.OptionalHeader.AddressOfEntryPoint)), NT32.OptionalHeader.AddressOfEntryPoint, _T(""));

		gotoxy(0, 10);
		_tprintf_s(_T("%-30s %-10s 0x%08X    %-20s"), _T("BaseOfCode"), size_Name(sizeof(NT32.OptionalHeader.BaseOfCode)), NT32.OptionalHeader.BaseOfCode, _T(""));

		gotoxy(0, 11);
		_tprintf_s(_T("%-30s %-10s 0x%08X    %-20s"), _T("ImageBase"), size_Name(sizeof(NT32.OptionalHeader.ImageBase)), NT32.OptionalHeader.ImageBase, _T(""));

		gotoxy(0, 12);
		_tprintf_s(_T("%-30s %-10s 0x%08X    %-20s"), _T("SectionAlignment"), size_Name(sizeof(NT32.OptionalHeader.SectionAlignment)), NT32.OptionalHeader.SectionAlignment, _T(""));

		gotoxy(0, 13);
		_tprintf_s(_T("%-30s %-10s 0x%08X    %-20s"), _T("FileAlignment"), size_Name(sizeof(NT32.OptionalHeader.FileAlignment)), NT32.OptionalHeader.FileAlignment, _T(""));

		gotoxy(0, 14);
		_tprintf_s(_T("%-30s %-10s 0x%08X    %-20s"), _T("MajorOperatingSystemVersion"), size_Name(sizeof(NT32.OptionalHeader.MajorOperatingSystemVersion)), NT32.OptionalHeader.MajorOperatingSystemVersion, _T(""));

		gotoxy(0, 15);
		_tprintf_s(_T("%-30s %-10s 0x%08X    %-20s"), _T("MinorOperatingSystemVersion"), size_Name(sizeof(NT32.OptionalHeader.MinorOperatingSystemVersion)), NT32.OptionalHeader.MinorOperatingSystemVersion, _T(""));

		gotoxy(0, 16);
		_tprintf_s(_T("%-30s %-10s 0x%08X    %-20s"), _T("MajorImageVersion"), size_Name(sizeof(NT32.OptionalHeader.MajorImageVersion)), NT32.OptionalHeader.MajorImageVersion, _T(""));

		gotoxy(0, 17);
		_tprintf_s(_T("%-30s %-10s 0x%08X    %-20s"), _T("MinorImageVersion"), size_Name(sizeof(NT32.OptionalHeader.MinorImageVersion)), NT32.OptionalHeader.MinorImageVersion, _T(""));

		gotoxy(0, 18);
		_tprintf_s(_T("%-30s %-10s 0x%08X    %-20s"), _T("MajorSubsystemVersion"), size_Name(sizeof(NT32.OptionalHeader.MajorSubsystemVersion)), NT32.OptionalHeader.MajorSubsystemVersion, _T(""));

		gotoxy(0, 19);
		_tprintf_s(_T("%-30s %-10s 0x%08X    %-20s"), _T("MinorSubsystemVersion"), size_Name(sizeof(NT32.OptionalHeader.MinorSubsystemVersion)), NT32.OptionalHeader.MinorSubsystemVersion, _T(""));

		gotoxy(0, 20);
		_tprintf_s(_T("%-30s %-10s 0x%08X    %-20s"), _T("Win32VersionValue"), size_Name(sizeof(NT32.OptionalHeader.Win32VersionValue)), NT32.OptionalHeader.Win32VersionValue, _T(""));

		gotoxy(0, 21);
		_tprintf_s(_T("%-30s %-10s 0x%08X    %-20s"), _T("SizeOfImage"), size_Name(sizeof(NT32.OptionalHeader.SizeOfImage)), NT32.OptionalHeader.SizeOfImage, _T(""));

		gotoxy(0, 22);
		_tprintf_s(_T("%-30s %-10s 0x%08X    %-20s"), _T("SizeOfHeaders"), size_Name(sizeof(NT32.OptionalHeader.SizeOfHeaders)), NT32.OptionalHeader.SizeOfHeaders, _T(""));

		gotoxy(0, 23);
		_tprintf_s(_T("%-30s %-10s 0x%08X    %-20s"), _T("CheckSum"), size_Name(sizeof(NT32.OptionalHeader.CheckSum)), NT32.OptionalHeader.CheckSum, _T(""));

		gotoxy(0, 24);
		_tprintf_s(_T("%-30s %-10s 0x%08X    %-20s"), _T("Subsystem"), size_Name(sizeof(NT32.OptionalHeader.Subsystem)), NT32.OptionalHeader.Subsystem, _T(""));

		gotoxy(0, 25);
		_tprintf_s(_T("%-30s %-10s 0x%08X    %-20s"), _T("DllCharacteristics"), size_Name(sizeof(NT32.OptionalHeader.DllCharacteristics)), NT32.OptionalHeader.DllCharacteristics, _T(""));

		gotoxy(0, 26);
		_tprintf_s(_T("%-30s %-10s 0x%08X    %-20s"), _T("SizeOfStackReserve"), size_Name(sizeof(NT32.OptionalHeader.SizeOfStackReserve)), NT32.OptionalHeader.SizeOfStackReserve, _T(""));

		gotoxy(0, 27);
		_tprintf_s(_T("%-30s %-10s 0x%08X    %-20s"), _T("SizeOfStackCommit"), size_Name(sizeof(NT32.OptionalHeader.SizeOfStackCommit)), NT32.OptionalHeader.SizeOfStackCommit, _T(""));

		gotoxy(0, 28);
		_tprintf_s(_T("%-30s %-10s 0x%08X    %-20s"), _T("SizeOfHeapReserve"), size_Name(sizeof(NT32.OptionalHeader.SizeOfHeapReserve)), NT32.OptionalHeader.SizeOfHeapReserve, _T(""));

		gotoxy(0, 29);
		_tprintf_s(_T("%-30s %-10s 0x%08X    %-20s"), _T("SizeOfHeapCommit"), size_Name(sizeof(NT32.OptionalHeader.SizeOfHeapCommit)), NT32.OptionalHeader.SizeOfHeapCommit, _T(""));

		gotoxy(0, 30);
		_tprintf_s(_T("%-30s %-10s 0x%08X    %-20s"), _T("LoaderFlags"), size_Name(sizeof(NT32.OptionalHeader.LoaderFlags)), NT32.OptionalHeader.LoaderFlags, _T(""));

		gotoxy(0, 31);
		_tprintf_s(_T("%-30s %-10s 0x%08X    %-20s"), _T("NumberOfRvaAndSizes"), size_Name(sizeof(NT32.OptionalHeader.NumberOfRvaAndSizes)), NT32.OptionalHeader.NumberOfRvaAndSizes, _T(""));

		gotoxy(0, 32);
		_tprintf_s(_T("%-30s %-10s 0x%08X    %-20s"), _T("DataDirectory"), size_Name(sizeof(NT32.OptionalHeader.DataDirectory)), &NT64.OptionalHeader.DataDirectory, _T(""));
	}
	else if (bit == 0x20B)
	{
		gotoxy(0, 2);
		_tprintf_s(_T("%-30s %-10s %-18s    %-20s"), _T("Name"), _T("Size"), _T("Value"), _T("Description"));

		SetColor(WHITE);
		gotoxy(0, 3);
		_tprintf_s(_T("%-30s %-10s 0x%016X    %-20s"), _T("Magic"), size_Name(sizeof(NT64.OptionalHeader.Magic)), NT64.OptionalHeader.Magic, _T(""));

		gotoxy(0, 4);
		_tprintf_s(_T("%-30s %-10s 0x%016X    %-20s"), _T("MajorLinkerVersion"), size_Name(sizeof(NT64.OptionalHeader.MajorLinkerVersion)), NT64.OptionalHeader.MajorLinkerVersion, _T(""));

		gotoxy(0, 3);
		_tprintf_s(_T("%-30s %-10s 0x%016X    %-20s"), _T("MinorLinkerVersion"), size_Name(sizeof(NT64.OptionalHeader.MinorLinkerVersion)), NT64.OptionalHeader.MinorLinkerVersion, _T(""));

		gotoxy(0, 4);
		_tprintf_s(_T("%-30s %-10s 0x%016X    %-20s"), _T("SizeOfCode"), size_Name(sizeof(NT64.OptionalHeader.SizeOfCode)), NT64.OptionalHeader.SizeOfCode, _T(""));

		gotoxy(0, 5);
		_tprintf_s(_T("%-30s %-10s 0x%016X    %-20s"), _T("SizeOfInitializedData"), size_Name(sizeof(NT64.OptionalHeader.SizeOfInitializedData)), NT64.OptionalHeader.SizeOfInitializedData, _T(""));

		gotoxy(0, 6);
		_tprintf_s(_T("%-30s %-10s 0x%016X    %-20s"), _T("SizeOfUninitializedData"), size_Name(sizeof(NT64.OptionalHeader.SizeOfUninitializedData)), NT64.OptionalHeader.SizeOfUninitializedData, _T(""));

		gotoxy(0, 7);
		_tprintf_s(_T("%-30s %-10s 0x%016X    %-20s"), _T("AddressOfEntryPoint"), size_Name(sizeof(NT64.OptionalHeader.AddressOfEntryPoint)), NT64.OptionalHeader.AddressOfEntryPoint, _T(""));

		gotoxy(0, 8);
		_tprintf_s(_T("%-30s %-10s 0x%016X    %-20s"), _T("BaseOfCode"), size_Name(sizeof(NT64.OptionalHeader.BaseOfCode)), NT64.OptionalHeader.BaseOfCode, _T(""));

		gotoxy(0, 9);
		_tprintf_s(_T("%-30s %-10s 0x%016X    %-20s"), _T("ImageBase"), size_Name(sizeof(NT64.OptionalHeader.ImageBase)), NT64.OptionalHeader.ImageBase, _T(""));

		gotoxy(0, 10);
		_tprintf_s(_T("%-30s %-10s 0x%016X    %-20s"), _T("SectionAlignment"), size_Name(sizeof(NT64.OptionalHeader.SectionAlignment)), NT64.OptionalHeader.SectionAlignment, _T(""));

		gotoxy(0, 11);
		_tprintf_s(_T("%-30s %-10s 0x%016X    %-20s"), _T("FileAlignment"), size_Name(sizeof(NT64.OptionalHeader.FileAlignment)), NT64.OptionalHeader.FileAlignment, _T(""));

		gotoxy(0, 12);
		_tprintf_s(_T("%-30s %-10s 0x%016X    %-20s"), _T("MajorOperatingSystemVersion"), size_Name(sizeof(NT64.OptionalHeader.MajorOperatingSystemVersion)), NT64.OptionalHeader.MajorOperatingSystemVersion, _T(""));

		gotoxy(0, 13);
		_tprintf_s(_T("%-30s %-10s 0x%016X    %-20s"), _T("MinorOperatingSystemVersion"), size_Name(sizeof(NT64.OptionalHeader.MinorOperatingSystemVersion)), NT64.OptionalHeader.MinorOperatingSystemVersion, _T(""));

		gotoxy(0, 14);
		_tprintf_s(_T("%-30s %-10s 0x%016X    %-20s"), _T("MajorImageVersion"), size_Name(sizeof(NT64.OptionalHeader.MajorImageVersion)), NT64.OptionalHeader.MajorImageVersion, _T(""));

		gotoxy(0, 15);
		_tprintf_s(_T("%-30s %-10s 0x%016X    %-20s"), _T("MinorImageVersion"), size_Name(sizeof(NT64.OptionalHeader.MinorImageVersion)), NT64.OptionalHeader.MinorImageVersion, _T(""));

		gotoxy(0, 16);
		_tprintf_s(_T("%-30s %-10s 0x%016X    %-20s"), _T("MajorSubsystemVersion"), size_Name(sizeof(NT64.OptionalHeader.MajorSubsystemVersion)), NT64.OptionalHeader.MajorSubsystemVersion, _T(""));

		gotoxy(0, 17);
		_tprintf_s(_T("%-30s %-10s 0x%016X    %-20s"), _T("MinorSubsystemVersion"), size_Name(sizeof(NT64.OptionalHeader.MinorSubsystemVersion)), NT64.OptionalHeader.MinorSubsystemVersion, _T(""));

		gotoxy(0, 18);
		_tprintf_s(_T("%-30s %-10s 0x%016X    %-20s"), _T("Win32VersionValue"), size_Name(sizeof(NT64.OptionalHeader.Win32VersionValue)), NT64.OptionalHeader.Win32VersionValue, _T(""));

		gotoxy(0, 19);
		_tprintf_s(_T("%-30s %-10s 0x%016X    %-20s"), _T("SizeOfImage"), size_Name(sizeof(NT64.OptionalHeader.SizeOfImage)), NT64.OptionalHeader.SizeOfImage, _T(""));

		gotoxy(0, 20);
		_tprintf_s(_T("%-30s %-10s 0x%016X    %-20s"), _T("SizeOfHeaders"), size_Name(sizeof(NT64.OptionalHeader.SizeOfHeaders)), NT64.OptionalHeader.SizeOfHeaders, _T(""));

		gotoxy(0, 21);
		_tprintf_s(_T("%-30s %-10s 0x%016X    %-20s"), _T("CheckSum"), size_Name(sizeof(NT64.OptionalHeader.CheckSum)), NT64.OptionalHeader.CheckSum, _T(""));

		gotoxy(0, 22);
		_tprintf_s(_T("%-30s %-10s 0x%016X    %-20s"), _T("Subsystem"), size_Name(sizeof(NT64.OptionalHeader.Subsystem)), NT64.OptionalHeader.Subsystem, _T(""));

		gotoxy(0, 23);
		_tprintf_s(_T("%-30s %-10s 0x%016X    %-20s"), _T("DllCharacteristics"), size_Name(sizeof(NT64.OptionalHeader.DllCharacteristics)), NT64.OptionalHeader.DllCharacteristics, _T(""));

		gotoxy(0, 24);
		_tprintf_s(_T("%-30s %-10s 0x%016X    %-20s"), _T("SizeOfStackReserve"), size_Name(sizeof(NT64.OptionalHeader.SizeOfStackReserve)), NT64.OptionalHeader.SizeOfStackReserve, _T(""));

		gotoxy(0, 25);
		_tprintf_s(_T("%-30s %-10s 0x%016X    %-20s"), _T("SizeOfStackCommit"), size_Name(sizeof(NT64.OptionalHeader.SizeOfStackCommit)), NT64.OptionalHeader.SizeOfStackCommit, _T(""));

		gotoxy(0, 26);
		_tprintf_s(_T("%-30s %-10s 0x%016X    %-20s"), _T("SizeOfHeapReserve"), size_Name(sizeof(NT64.OptionalHeader.SizeOfHeapReserve)), NT64.OptionalHeader.SizeOfHeapReserve, _T(""));

		gotoxy(0, 27);
		_tprintf_s(_T("%-30s %-10s 0x%016X    %-20s"), _T("SizeOfHeapCommit"), size_Name(sizeof(NT64.OptionalHeader.SizeOfHeapCommit)), NT64.OptionalHeader.SizeOfHeapCommit, _T(""));

		gotoxy(0, 28);
		_tprintf_s(_T("%-30s %-10s 0x%016X    %-20s"), _T("LoaderFlags"), size_Name(sizeof(NT64.OptionalHeader.LoaderFlags)), NT64.OptionalHeader.LoaderFlags, _T(""));

		gotoxy(0, 29);
		_tprintf_s(_T("%-30s %-10s 0x%016X    %-20s"), _T("NumberOfRvaAndSizes"), size_Name(sizeof(NT64.OptionalHeader.NumberOfRvaAndSizes)), NT64.OptionalHeader.NumberOfRvaAndSizes, _T(""));

		gotoxy(0, 30);
		_tprintf_s(_T("%-30s %-10s 0x%016X    %-20s"), _T("DataDirectory"), size_Name(sizeof(NT64.OptionalHeader.DataDirectory)), &NT64.OptionalHeader.DataDirectory, _T(""));
	}

	COORD pos;

	SetColor(YELLOW);
	pos = make_box(32, TRUE);
	SetColor(WHITE);

	gotoxy(pos.X, pos.Y);
	_tprintf_s(_T("%s"), _T("Optional_Header"));

	SetColor(YELLOW);
	pos = make_box(32, TRUE, 30);
	SetColor(WHITE);

	gotoxy(pos.X, pos.Y);
	_tprintf_s(_T("RVA == OFFSET"));

	gotoxy(pos.X, pos.Y + 1);	//RVA of FileOffset 출력
	_tprintf_s(_T("0x%X - 0x%X"), Dos.e_lfanew + sizeof(DWORD), Dos.e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER));
}

void PE_Section_View(int SecIndex)
{
	int i = SecIndex;

	TCHAR sbuf[MAX_PATH] = { 0, };
	for (int j = 0; j < 8; j++)
		sbuf[j] = Sec[i].Name[j];

	gotoxy(0, 2);
	_tprintf_s(_T("[ Section[%d] - %s ]"), i, sbuf);

	SetColor(YELLOW);
	gotoxy(0, 3);
	_tprintf_s(_T("%-22s %-10s %-10s    %-20s"), _T("Name"), _T("Size"), _T("Value"), _T("Description"));
	SetColor(WHITE);

	gotoxy(0, 4);
	_tprintf_s(_T("%-22s %-10s 0x%08X    %-20s"), _T("Name[8]"), _T("BYTE[8]"), Sec[i].Name, sbuf);

	gotoxy(0, 5);
	_tprintf_s(_T("%-22s %-10s 0x%08X    %-20s"), _T("VirtualSize"), size_Name(sizeof(Sec[i].Misc.VirtualSize)), Sec[i].Misc.VirtualSize, _T(""));

	gotoxy(0, 6);
	_tprintf_s(_T("%-22s %-10s 0x%08X    %-20s"), _T("VirtualAddress"), size_Name(sizeof(Sec[i].VirtualAddress)), Sec[i].VirtualAddress, _T(""));

	gotoxy(0, 7);
	_tprintf_s(_T("%-22s %-10s 0x%08X    %-20s"), _T("SizeOfRawData"), size_Name(sizeof(Sec[i].SizeOfRawData)), Sec[i].SizeOfRawData, _T(""));

	gotoxy(0, 8);
	_tprintf_s(_T("%-22s %-10s 0x%08X    %-20s"), _T("PointerToRawData"), size_Name(sizeof(Sec[i].PointerToRawData)), Sec[i].PointerToRawData, _T(""));

	gotoxy(0, 9);
	_tprintf_s(_T("%-22s %-10s 0x%08X    %-20s"), _T("PointerToRelocations"), size_Name(sizeof(Sec[i].PointerToRelocations)), Sec[i].PointerToRelocations, _T(""));

	gotoxy(0, 10);
	_tprintf_s(_T("%-22s %-10s 0x%08X    %-20s"), _T("PointerToLinenumbers"), size_Name(sizeof(Sec[i].PointerToLinenumbers)), Sec[i].PointerToLinenumbers, _T(""));

	gotoxy(0, 11);
	_tprintf_s(_T("%-22s %-10s 0x%08X    %-20s"), _T("NumberOfRelocations"), size_Name(sizeof(Sec[i].NumberOfRelocations)), Sec[i].NumberOfRelocations, _T(""));

	gotoxy(0, 12);
	_tprintf_s(_T("%-22s %-10s 0x%08X    %-20s"), _T("NumberOfLinenumbers"), size_Name(sizeof(Sec[i].NumberOfLinenumbers)), Sec[i].NumberOfLinenumbers, _T(""));

	TCHAR option[MAX_PATH];
	SectionOptionPrint(Sec[i].Characteristics, option);

	gotoxy(0, 13);
	_tprintf_s(_T("%-22s %-10s 0x%08X    %-20s"), _T("Characteristics"), size_Name(sizeof(Sec[i].Characteristics)), Sec[i].Characteristics, option);

	COORD pos;

	SetColor(YELLOW);
	pos = make_box(15, TRUE);
	SetColor(WHITE);

	gotoxy(pos.X, pos.Y);
	_tprintf_s(_T("%s"), sbuf);

	SetColor(YELLOW);
	pos = make_box(15, TRUE, 30);
	SetColor(WHITE);

	gotoxy(pos.X, pos.Y);
	_tprintf_s(_T("RVA == OFFSET"));

	gotoxy(pos.X, pos.Y + 1);
	if (bit == 0x10B)
		_tprintf_s(_T("0x%X - 0x%X"), Dos.e_lfanew + sizeof(IMAGE_NT_HEADERS32) + (i*sizeof(IMAGE_SECTION_HEADER)), Dos.e_lfanew + sizeof(IMAGE_NT_HEADERS32) + ((i + 1)*sizeof(IMAGE_SECTION_HEADER)));
	else if (bit == 0x20B)
		_tprintf_s(_T("0x%X - 0x%X"), Dos.e_lfanew + sizeof(IMAGE_NT_HEADERS64) + (i*sizeof(IMAGE_SECTION_HEADER)), Dos.e_lfanew + sizeof(IMAGE_NT_HEADERS64) + ((i + 1)*sizeof(IMAGE_SECTION_HEADER)));
}

void SectionOptionPrint(DWORD option, TCHAR *str)
{
	TCHAR buf[MAX_PATH];

	if ((option & 0x00000020))
		_tcscat(buf, _T("_CODE"));

	if ((option & 0x00000040))
		_tcscat(buf, _T("_InitData"));

	if ((option & 0x00000040))
		_tcscat(buf, _T("_UnInitData"));

	if ((option & 0x10000000))
		_tcscat(buf, _T("_SHARED"));

	if ((option & 0x20000000))
		_tcscat(buf, _T("_EXECUTE"));

	if ((option & 0x40000000))
		_tcscat(buf, _T("_READ"));

	if ((option & 0x80000000))
		_tcscat(buf, _T("_WRITE"));

	_tcscpy(str, buf);
}

void PE_Graph(TCHAR buf[], BOOL bBody = FALSE)
{
	COORD StrPos = { 0, 0 };

	int start = 3;

	SetColor(GREEN);
	gotoxy(0, start - 1);
	_tprintf_s(_T("[ Header ]"));

	gotoxy(3 + 25, start - 1);
	_tprintf_s(_T("[ OFFSET ]"));

	if (bBody)
	{
		gotoxy(50, start - 1);
		_tprintf_s(_T("[ Body ]"));

		gotoxy(50 + 3 + 25, start - 1);
		_tprintf_s(_T("[ OFFSET ]"));

		gotoxy(50 + 3 + 25 + 25, start - 1);
		_tprintf_s(_T("[ RVA ]"));
	}

	SetColor(YELLOW);
	StrPos = make_box(start, TRUE);
	SetColor(WHITE);

	gotoxy(StrPos.X, StrPos.Y);
	_tprintf_s(_T("%s"), _T("Dos_Header"));

	gotoxy(StrPos.X + 25, StrPos.Y);
	_tprintf_s(_T("0x%X - 0x%X"), 0x0, sizeof(IMAGE_DOS_HEADER));

	start += 4;

	SetColor(YELLOW);
	StrPos = make_box(start);
	SetColor(WHITE);

	if (bit == 0x10B)
	{
		gotoxy(StrPos.X, StrPos.Y);
		_tprintf_s(_T("%s"), _T("NT32_Header"));

		gotoxy(StrPos.X + 25, StrPos.Y);
		_tprintf_s(_T("0x%X - 0x%X"), Dos.e_lfanew, (DWORD)Dos.e_lfanew + sizeof(IMAGE_NT_HEADERS32));
	}
	else if (bit == 0x20B)
	{
		gotoxy(StrPos.X, StrPos.Y);
		_tprintf_s(_T("%s"), _T("NT64_Header"));

		gotoxy(StrPos.X + 25, StrPos.Y);
		_tprintf_s(_T("0x%X - 0x%X"), Dos.e_lfanew, (DWORD)Dos.e_lfanew + sizeof(IMAGE_NT_HEADERS64));
	}

	start += 4;
	int max_cnt = 0;

	if (bit == 0x10B)
		max_cnt = NT32.FileHeader.NumberOfSections;
	else if (bit == 0x20B)
		max_cnt = NT64.FileHeader.NumberOfSections;

	if (max_cnt <= 7)
	{
		for (int i = 0; i < max_cnt; i++)
		{
			SetColor(YELLOW);
			StrPos = make_box(start);
			SetColor(WHITE);

			gotoxy(StrPos.X, StrPos.Y);

			TCHAR sbuf[MAX_PATH];
			for (int j = 0; j < 8; j++)
				sbuf[j] = Sec[i].Name[j];
			sbuf[8] = '\0';
			_tprintf_s(_T("%s"), sbuf);

			gotoxy(StrPos.X + 25, StrPos.Y);
			if (bit == 0x10B)
				_tprintf_s(_T("0x%X - 0x%X"), (DWORD)Dos.e_lfanew + sizeof(IMAGE_NT_HEADERS32) + sizeof(IMAGE_SECTION_HEADER)*i, (DWORD)Dos.e_lfanew + sizeof(IMAGE_NT_HEADERS32) + sizeof(IMAGE_SECTION_HEADER)*(i + 1));
			else if (bit == 0x20B)
				_tprintf_s(_T("0x%X - 0x%X"), (DWORD)Dos.e_lfanew + sizeof(IMAGE_NT_HEADERS64) + sizeof(IMAGE_SECTION_HEADER)*i, (DWORD)Dos.e_lfanew + sizeof(IMAGE_NT_HEADERS64) + sizeof(IMAGE_SECTION_HEADER)*(i + 1));

			start += 4;
		}

		if (bBody)
		{
			start = 3;

			for (int i = 0; i < max_cnt; i++)
			{
				SetColor(YELLOW);
				if (i == 0)
					StrPos = make_box(start, TRUE, 50);
				else
					StrPos = make_box(start, FALSE, 50);
				SetColor(WHITE);

				gotoxy(StrPos.X, StrPos.Y);

				TCHAR sbuf[MAX_PATH];
				for (int j = 0; j < 8; j++)
					sbuf[j] = Sec[i].Name[j];
				sbuf[8] = '\0';
				_tprintf_s(_T("%s"), sbuf);

				gotoxy(StrPos.X + 25, StrPos.Y);
				_tprintf_s(_T("0x%X - 0x%X"), Sec[i].PointerToRawData, Sec[i].PointerToRawData + Sec[i].SizeOfRawData - 1);

				gotoxy(StrPos.X + 50, StrPos.Y);
				_tprintf_s(_T("0x%X - 0x%X"), Sec[i].VirtualAddress, Sec[i].VirtualAddress + Sec[i].Misc.VirtualSize);

				start += 4;
			}
		}
	}
	else
	{
		for (int i = 0; i < 4; i++)
		{
			SetColor(YELLOW);
			StrPos = make_box(start);
			SetColor(WHITE);

			gotoxy(StrPos.X, StrPos.Y);

			TCHAR sbuf[MAX_PATH];
			for (int j = 0; j < 8; j++)
				sbuf[j] = Sec[i].Name[j];
			sbuf[8] = '\0';
			_tprintf_s(_T("%s"), sbuf);

			gotoxy(StrPos.X + 25, StrPos.Y);
			if (bit == 0x10B)
				_tprintf_s(_T("0x%X - 0x%X"), (DWORD)Dos.e_lfanew + sizeof(IMAGE_NT_HEADERS32) + sizeof(IMAGE_SECTION_HEADER)*i, (DWORD)Dos.e_lfanew + sizeof(IMAGE_NT_HEADERS32) + sizeof(IMAGE_SECTION_HEADER)*(i + 1));
			else if (bit == 0x20B)
				_tprintf_s(_T("0x%X - 0x%X"), (DWORD)Dos.e_lfanew + sizeof(IMAGE_NT_HEADERS64) + sizeof(IMAGE_SECTION_HEADER)*i, (DWORD)Dos.e_lfanew + sizeof(IMAGE_NT_HEADERS64) + sizeof(IMAGE_SECTION_HEADER)*(i + 1));

			start += 4;
		}

		for (int i = 1; i <= 3 * 2; i += 2)
		{
			gotoxy(StrPos.X, StrPos.Y + 3 + i);
			_tprintf_s(_T("."));

			start += i;
		}

		SetColor(YELLOW);
		StrPos = make_box(start, TRUE);
		SetColor(WHITE);

		gotoxy(StrPos.X, StrPos.Y);

		TCHAR sbuf[MAX_PATH];
		for (int i = 0; i < 8; i++)
			sbuf[i] = Sec[max_cnt - 1].Name[i];
		sbuf[8] = '\0';
		_tprintf_s(_T("%s"), sbuf);

		gotoxy(StrPos.X + 25, StrPos.Y);
		if (bit == 0x10B)
			_tprintf_s(_T("0x%X - 0x%X"), (DWORD)Dos.e_lfanew + sizeof(IMAGE_NT_HEADERS32) + sizeof(IMAGE_SECTION_HEADER)*(max_cnt - 1), (DWORD)Dos.e_lfanew + sizeof(IMAGE_NT_HEADERS32) + sizeof(IMAGE_SECTION_HEADER)*max_cnt);
		else if (bit == 0x20B)
			_tprintf_s(_T("0x%X - 0x%X"), (DWORD)Dos.e_lfanew + sizeof(IMAGE_NT_HEADERS64) + sizeof(IMAGE_SECTION_HEADER)*(max_cnt - 1), (DWORD)Dos.e_lfanew + sizeof(IMAGE_NT_HEADERS64) + sizeof(IMAGE_SECTION_HEADER)*max_cnt);

		if (bBody)
		{
			start = 3;
			for (int i = 0; i < 5; i++)
			{
				SetColor(YELLOW);
				if (i == 0)
					StrPos = make_box(start, TRUE, 50);
				else
					StrPos = make_box(start, FALSE, 50);
				SetColor(WHITE);

				gotoxy(StrPos.X, StrPos.Y);

				TCHAR sbuf[MAX_PATH];
				for (int j = 0; j < 8; j++)
					sbuf[j] = Sec[i].Name[j];
				sbuf[8] = '\0';
				_tprintf_s(_T("%s"), sbuf);

				gotoxy(StrPos.X + 25, StrPos.Y);
				if (Sec[i].PointerToRawData != 0x0)
					_tprintf_s(_T("0x%X - 0x%X"), Sec[i].PointerToRawData, Sec[i].PointerToRawData + Sec[i].SizeOfRawData - 1);
				else
					_tprintf_s(_T("0x%X - 0x%X"), Sec[i].PointerToRawData, Sec[i].SizeOfRawData);

				gotoxy(StrPos.X + 50, StrPos.Y);
				_tprintf_s(_T("0x%X - 0x%X"), Sec[i].VirtualAddress, Sec[i].VirtualAddress + Sec[i].Misc.VirtualSize);

				start += 4;
			}

			for (int i = 1; i <= 3 * 2; i += 2)
			{
				gotoxy(StrPos.X, StrPos.Y + 3 + i);
				_tprintf_s(_T("."));

				start += i;
			}

			SetColor(YELLOW);
			StrPos = make_box(start, TRUE, 50);
			SetColor(WHITE);

			gotoxy(StrPos.X, StrPos.Y);

			TCHAR sbuf[MAX_PATH];
			for (int i = 0; i < 8; i++)
				sbuf[i] = Sec[max_cnt - 1].Name[i];
			sbuf[8] = '\0';
			_tprintf_s(_T("%s"), sbuf);

			gotoxy(StrPos.X + 25, StrPos.Y);
			if (Sec[max_cnt - 1].PointerToRawData != 0x0)
				_tprintf_s(_T("0x%X - 0x%X"), Sec[max_cnt - 1].PointerToRawData, Sec[max_cnt - 1].PointerToRawData + Sec[max_cnt - 1].SizeOfRawData - 1);
			else
				_tprintf_s(_T("0x%X - 0x%X"), Sec[max_cnt - 1].PointerToRawData, Sec[max_cnt - 1].SizeOfRawData);

			gotoxy(StrPos.X + 50, StrPos.Y);
			_tprintf_s(_T("0x%X - 0x%X"), Sec[max_cnt - 1].VirtualAddress, Sec[max_cnt - 1].VirtualAddress + Sec[max_cnt - 1].Misc.VirtualSize);
		}
	}
}

void PE_Graph_Found(int mode, ULONGLONG uNum)
{
	int start = 4;
	int max_SecCnt = 0;
	int found_number = 0;

	TCHAR sbuf[MAX_PATH];
	BOOL bSuccess = FALSE;

	ULONGLONG Number = uNum;
	ULONGLONG ImageBase = 0;

	if (bit == 0x10B)
	{
		max_SecCnt = NT32.FileHeader.NumberOfSections;
		ImageBase = NT32.OptionalHeader.ImageBase;
	}
	else if (bit == 0x20B)
	{
		max_SecCnt = NT64.FileHeader.NumberOfSections;
		ImageBase = NT64.OptionalHeader.ImageBase;
	}

	if (mode == VA)
		Number = uNum - ImageBase;

	TCHAR buf[MAX_PATH] = { 0, };
	if (mode == VA)
		_tcscpy(buf, _T("VA"));
	else if (mode == RVA)
		_tcscpy(buf, _T("RVA"));
	else if (mode == OFFSET)
		_tcscpy(buf, _T("OFFSET"));

	SetColor(VIOLET);
	gotoxy(0, start - 2);
	_tprintf_s(_T("Found [ %s ] : 0x%X"), buf, uNum);

	for (int i = 1; i < max_SecCnt; i++)
	{
		if ((mode == VA) || (mode == RVA))
		{
			if ((Number >= Sec[i - 1].VirtualAddress) && (Number < (Sec[i].VirtualAddress)))
			{
				SetColor(YELLOW);
				COORD StrPos = make_box(start, TRUE);
				SetColor(WHITE);

				gotoxy(StrPos.X, StrPos.Y);

				for (int j = 0; j < 8; j++)
					sbuf[j] = Sec[i - 1].Name[j];
				sbuf[8] = '\0';
				_tprintf_s(_T("%s"), sbuf);

				bSuccess = TRUE;
				found_number = i - 1;
				break;
			}
		}
		else if (mode == OFFSET)
		{
			if ((Number >= Sec[i - 1].PointerToRawData) && (Number < (Sec[i].PointerToRawData)))
			{
				SetColor(YELLOW);
				COORD StrPos = make_box(start, TRUE);
				SetColor(WHITE);

				gotoxy(StrPos.X, StrPos.Y);

				for (int j = 0; j < 8; j++)
					sbuf[j] = Sec[i - 1].Name[j];
				sbuf[8] = '\0';
				_tprintf_s(_T("%s"), sbuf);

				bSuccess = TRUE;
				found_number = i - 1;
				break;
			}
		}
	}

	if (!bSuccess)
	{
		if ((mode == VA) || (mode == RVA))
		{
			if (Number >= Sec[max_SecCnt - 1].VirtualAddress)
			{
				SetColor(YELLOW);
				COORD StrPos = make_box(start, TRUE);
				SetColor(WHITE);

				gotoxy(StrPos.X, StrPos.Y);

				for (int j = 0; j < 8; j++)
					sbuf[j] = Sec[max_SecCnt - 1].Name[j];
				sbuf[8] = '\0';
				_tprintf_s(_T("%s"), sbuf);

				bSuccess = TRUE;
				found_number = max_SecCnt - 1;
			}
		}
		else if (mode == OFFSET)
		{
			if (Number >= Sec[max_SecCnt - 1].PointerToRawData)
			{
				SetColor(YELLOW);
				COORD StrPos = make_box(start, TRUE);
				SetColor(WHITE);

				gotoxy(StrPos.X, StrPos.Y);

				for (int j = 0; j < 8; j++)
					sbuf[j] = Sec[max_SecCnt - 1].Name[j];
				sbuf[8] = '\0';
				_tprintf_s(_T("%s"), sbuf);

				bSuccess = TRUE;
				found_number = max_SecCnt - 1;
			}
		}
	}

	gotoxy(0, start - 1);

	if (bSuccess)
	{
		SetColor(GREEN);
		if ((mode == VA) || (mode == RVA))
		{
			ULONGLONG offset = Number - Sec[found_number].VirtualAddress + Sec[found_number].PointerToRawData;
			_tprintf(_T("Select Section [ %s ] => RVA : 0x%llX, OFFSET : 0x%llX"), sbuf, Number, offset);
		}
		else if (mode == OFFSET)
			_tprintf_s(_T("Select Section [ %s ] => OFFSET : 0x%llX, RVA : 0x%llX"), sbuf, Number, Number - Sec[found_number].PointerToRawData + Sec[found_number].VirtualAddress);
	}
	else
	{
		SetColor(RED);
		_tprintf_s(_T("ERROR : Not Found Section !!"));
	}
	SetColor(WHITE);
}