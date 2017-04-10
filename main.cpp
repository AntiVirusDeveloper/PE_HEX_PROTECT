#include "Utils.h"
#include "PEViewer.h"
#include "HexEditor.h"
#include "Protect.h"

HANDLE File;
TCHAR FilePath[MAX_PATH];

BOOL LastOpen = FALSE;

WORD bit = 0;
int NumberSection = 0;

IMAGE_DOS_HEADER Dos;
IMAGE_NT_HEADERS32 NT32;
IMAGE_NT_HEADERS64 NT64;
IMAGE_SECTION_HEADER *Sec;

//시작화면 구성
void Start();

//파일을 선택해서 핸들 값 및 PE 구조 중 Dos,NT,Section 구조체의 정보를 저장함
void SelectFile();

//main 함수
int _tmain()
{
	Start();

	return 0;
}

void Start()
{
	BOOL IsEnd = TRUE;

	TCHAR input[MAX_PATH];
	memset(input, NULL, MAX_PATH);

	setting_console();

	do {
		SetColor(YELLOW);
		_tprintf_s(_T("[ PE_HEX ]\n"));
		SetColor(WHITE);

		_tprintf_s(_T("1. Select File (%s)\n"), FilePath);
		_tprintf_s(_T("2. PE Viewer\n"));
		_tprintf_s(_T("3. Hex Editor\n"));
		_tprintf_s(_T("4. Protector\n\n"));

		_tprintf_s(_T(">> "));

		SetColor(YELLOW);
		for (int i = 0; i < MAX_PATH; i++)
		{
			input[i] = getchar();
			if (input[i] == 10)
			{
				input[i] = '\0';
				break;
			}
		}

		_tprintf_s(_T("\n\n"));

		if (!_tcscmp(input, _T("exit")))
			IsEnd = FALSE;

		DWORD select = (DWORD)_tstoi(input);

		if (select == 1)
			SelectFile();
		
		else if (select == 2)
			PEViewer();
		
		else if (select == 3)
			HexEditor();

		else if (select == 4)
			Protector();

		system("cls");

	} while (IsEnd);

	if (File != NULL)
		CloseHandle(File);

	if (Sec != NULL)
		delete[] Sec;
}

void SelectFile()
{
	memset(FilePath, NULL, MAX_PATH);

	SetColor(WHITE);
	_tprintf_s(_T("File Path : "));

	SetColor(YELLOW);
	for (int i = 0; i < MAX_PATH; i++)
	{
		FilePath[i] = getchar();
		if (FilePath[i] == 10)
		{
			FilePath[i] = '\0';
			break;
		}
	}

	SetColor(WHITE);

	if ((File == NULL) || (File == INVALID_HANDLE_VALUE))
		CloseHandle(File);

	File = CreateFile(FilePath, GENERIC_READ | GENERIC_WRITE, NULL, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (_tcscmp(UserStrrchr(FilePath,'.'), _T(".exe")))	//tcschr 문자열 버그 ; '.' 이 포함이 안될경우 예외발생
	{
		CloseHandle(File);
		File = NULL;
	}

	if ((File == INVALID_HANDLE_VALUE) || (File == NULL))
	{
		SetColor(RED);
		_tprintf_s(_T("ERROR : CreateFile(%s) Failed.. [0x%X]\n"), FilePath, GetLastError());
		memset(FilePath, NULL, MAX_PATH);

		SetColor(WHITE);

		LastOpen = FALSE;
	}
	else
	{
		SetColor(GREEN);
		_tprintf_s(_T("\nCreateFile(%s) Success!!\n"), FilePath);
		SetColor(WHITE);

		PEView_Init();

		if (SetDosHeader(TRUE))
		{
			SetColor(SKY_BLUE);
			_tprintf_s(_T("Set Dos Header Success!!\n"));
		}
		else
		{
			SetColor(RED);
			_tprintf_s(_T("Error : Dos Header Failed.. [0x%X]\n"), GetLastError());
		}
		SetColor(WHITE);


		{
			DWORD t = 0x00;
			SetFilePointer(File, Dos.e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER), NULL, FILE_BEGIN);
			ReadFile(File, &bit, sizeof(WORD), &t, NULL);
		}

		if (bit == 0x10B)
		{
			if (SetNT32Header(TRUE))
			{
				SetColor(SKY_BLUE);
				_tprintf_s(_T("Set NT32 Header Success!!\n"));
			}
			else
			{
				SetColor(RED);
				_tprintf_s(_T("Error : NT32 Header Failed.. [0x%X]\n"), GetLastError());
			}

			NumberSection = NT32.FileHeader.NumberOfSections;
		}
		else if (bit == 0x20B)
		{
			if (SetNT64Header(TRUE))
			{
				SetColor(SKY_BLUE);
				_tprintf_s(_T("Set NT64 Header Success!!\n"));
			}
			else
			{
				SetColor(RED);
				_tprintf_s(_T("Error : NT64 Header Failed.. [0x%X]\n"), GetLastError());
			}

			NumberSection = NT64.FileHeader.NumberOfSections;
		}
		SetColor(WHITE);

		Sec = new IMAGE_SECTION_HEADER[NumberSection];

		if (SetSectionHeader(TRUE))
		{
			SetColor(SKY_BLUE);
			_tprintf_s(_T("Set Section Header Success!!\n\n"));
		}
		else
		{
			SetColor(RED);
			_tprintf_s(_T("Error : Section Header Failed.. [0x%X]\n"), GetLastError());
		}
		SetColor(WHITE);

		LastOpen = TRUE;
	}

	system("pause");
}