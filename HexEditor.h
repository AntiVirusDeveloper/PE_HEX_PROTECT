#ifndef __HEX
#define __HEX

#include <stdio.h>
#include <tchar.h>
#include <Windows.h>

#include "Utils.h"

extern HANDLE File;
extern BOOL LastOpen;

extern WORD bit;
extern int NumberSection;

extern IMAGE_DOS_HEADER Dos;
extern IMAGE_NT_HEADERS32 NT32;
extern IMAGE_NT_HEADERS64 NT64;
extern IMAGE_SECTION_HEADER *Sec;

//Hex 기본 화면
void HexEditor();

//HexEditor 사용 방법
void HexEditor_Manual();

//dwPoint로 파일 포인터를 이동한 후 dwLine 값 만큼 출력
void Read_HexEditor(int mode, DWORD dwPoint, DWORD dwLine);

//dwPoint로 파일 포인터를 이동한 후 dwValue 값으로 바꿈
void Write_HexEditor(int mode, DWORD dwPoint, BYTE dwValue);

#endif