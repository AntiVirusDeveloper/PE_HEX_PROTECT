#ifndef __UTILS
#define __UTILS

#include <stdio.h>
#include <tchar.h>
#include <Windows.h>

enum{ VA = 1000, RVA, OFFSET };

enum {
	BLACK,      /*  0 : ��� */
	DARK_BLUE,    /*  1 : ��ο� �Ķ� */
	DARK_GREEN,    /*  2 : ��ο� �ʷ� */
	DARK_SKY_BLUE,  /*  3 : ��ο� �ϴ� */
	DARK_RED,    /*  4 : ��ο� ���� */
	DARK_VOILET,  /*  5 : ��ο� ���� */
	DARK_YELLOW,  /*  6 : ��ο� ��� */
	GRAY,      /*  7 : ȸ�� */
	DARK_GRAY,    /*  8 : ��ο� ȸ�� */
	BLUE,      /*  9 : �Ķ� */
	GREEN,      /* 10 : �ʷ� */
	SKY_BLUE,    /* 11 : �ϴ� */
	RED,      /* 12 : ���� */
	VIOLET,      /* 13 : ���� */
	YELLOW,      /* 14 : ��� */
	WHITE,      /* 15 : �Ͼ� */
};

//�ܼ�â Title, ũ��
void setting_console();

//�ܼ�â �Է� ���� ����
void SetColor(int color);

//����� ������ ��ǥ ����
void gotoxy(int x, int y);

//input �� �Էµ� ���ڿ��� ������ �������� ������ buf �� ����
int input_split(TCHAR input[], TCHAR buf[][MAX_PATH]);

//size �� �Էµ� ���� ���� BYTE, WORD, DWORD ���ڿ� ���
TCHAR* size_Name(int size);

//key ���� �������� FilePath �� �κ��� ���ڿ��� ������
TCHAR* UserStrrchr(TCHAR FilePath[], char key);

//gotoxy(box_position,box_start) ��ġ�� ���ڸ� �׸���
COORD make_box(int box_start, BOOL first = FALSE, int box_position = 0);

//�ΰ��� BYTE �� ������ ��
BOOL ByteCmp(BYTE first[], BYTE second[]);

#endif