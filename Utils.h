#ifndef __UTILS
#define __UTILS

#include <stdio.h>
#include <tchar.h>
#include <Windows.h>

enum{ VA = 1000, RVA, OFFSET };

enum {
	BLACK,      /*  0 : 까망 */
	DARK_BLUE,    /*  1 : 어두운 파랑 */
	DARK_GREEN,    /*  2 : 어두운 초록 */
	DARK_SKY_BLUE,  /*  3 : 어두운 하늘 */
	DARK_RED,    /*  4 : 어두운 빨강 */
	DARK_VOILET,  /*  5 : 어두운 보라 */
	DARK_YELLOW,  /*  6 : 어두운 노랑 */
	GRAY,      /*  7 : 회색 */
	DARK_GRAY,    /*  8 : 어두운 회색 */
	BLUE,      /*  9 : 파랑 */
	GREEN,      /* 10 : 초록 */
	SKY_BLUE,    /* 11 : 하늘 */
	RED,      /* 12 : 빨강 */
	VIOLET,      /* 13 : 보라 */
	YELLOW,      /* 14 : 노랑 */
	WHITE,      /* 15 : 하양 */
};

//콘솔창 Title, 크기
void setting_console();

//콘솔창 입력 색깔 변경
void SetColor(int color);

//출력을 시작할 좌표 설정
void gotoxy(int x, int y);

//input 에 입력된 문자열을 공백을 기준으로 분할해 buf 에 저장
int input_split(TCHAR input[], TCHAR buf[][MAX_PATH]);

//size 로 입력된 값에 따라 BYTE, WORD, DWORD 문자열 출력
TCHAR* size_Name(int size);

//key 값을 기준으로 FilePath 뒷 부분의 문자열을 리턴함
TCHAR* UserStrrchr(TCHAR FilePath[], char key);

//gotoxy(box_position,box_start) 위치에 상자를 그린다
COORD make_box(int box_start, BOOL first = FALSE, int box_position = 0);

//두개의 BYTE 가 같은지 비교
BOOL ByteCmp(BYTE first[], BYTE second[]);

#endif