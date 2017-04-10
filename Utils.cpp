#include "Utils.h"

void setting_console()
{
	SetConsoleTitle(_T("PE_HEX"));
	system("mode con:cols=150 lines=50");
	system("cls");
}

void SetColor(int color)
{
	SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), color);
}

void gotoxy(int x, int y)
{
	COORD Pos = { x, y };
	SetConsoleCursorPosition(GetStdHandle(STD_OUTPUT_HANDLE), Pos);
}

int input_split(TCHAR input[], TCHAR buf[][MAX_PATH])
{
	int cnt = 0;
	int len = _tcslen(input);

	int sbuf_cnt = 0;
	TCHAR sbuf[MAX_PATH] = { 0, };

	int buf_cnt = 0;

	for (int i = 0; i<len + 1; i++)
	{
		if ((input[i] == 32) || (input[i] == '\0'))
		{
			sbuf[sbuf_cnt++] = '\0';
			_tcscpy(buf[buf_cnt++], sbuf);

			memset(sbuf, NULL, MAX_PATH);
			sbuf_cnt = 0;

			cnt++;
		}
		else
		{
			sbuf[sbuf_cnt++] = input[i];
		}
	}

	return cnt;
}

TCHAR* size_Name(int size)
{
	switch (size)
	{
	case 1: return _T("BYTE");
	case 2: return _T("WORD");
	case 4: return _T("DWORD");
	case 8: return _T("ULONGLONG");
	default: return NULL;
	}
}

TCHAR* UserStrrchr(TCHAR FilePath[], char key)
{
	int endPoint = _tcslen(FilePath);
	int start = endPoint - 1;
	for (int i = 0; i <= endPoint; i++)
	{
		if (FilePath[start] == key)
		{
			if (endPoint == start)
				return _T("");

			TCHAR sbuf[MAX_PATH] = { 0, };

			for (int j = 0; start != endPoint; j++)
				sbuf[j] = FilePath[start++];

			return sbuf;
		}
		else
			start--;
	}

	return _T("");
}

COORD make_box(int box_start, BOOL first, int box_position)
{
	char x_buf[MAX_PATH];
	x_buf[0] = '+';
	for (int i = 1; i < 21; i++)
		x_buf[i] = '-';
	x_buf[21] = '+';
	x_buf[22] = '\0';

	char y_buf = '|';

	const int box_first_position = box_position;	//박스 시작지점

	if (first == TRUE)
	{
		gotoxy(box_first_position, box_start);
		printf("%s", x_buf);
	}

	for (int i = box_start + 1; i < box_start + 4; i++) //0~3
	{
		gotoxy(box_first_position, i);
		printf("%c", y_buf);

		gotoxy(box_first_position + strlen(x_buf) - 1, i);
		printf("%c", y_buf);
	}

	gotoxy(box_first_position, box_start + 4);
	printf("%s", x_buf);

	COORD pos = { box_first_position + 3, box_start + 2 };
	return pos;
}

BOOL ByteCmp(BYTE first[], BYTE second[])
{
	if (sizeof(first) != sizeof(second))
		return FALSE;

	int max = sizeof(first);
	for (int i = 0; i < max; i++)
	{
		if (first[i] != second[i])
			return FALSE;
	}

	return TRUE;
}