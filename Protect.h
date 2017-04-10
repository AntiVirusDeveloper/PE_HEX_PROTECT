#ifndef __PROTECT
#define __PROTECT

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

//사용법을 출력함
void Protector_Manual();

//프로텍터 기본 화면 출력
void Protector();

//안티디버깅 기법, 코드 섹션 디코딩 루프를 새로운 섹션에 인젝션함
void PlusAntiDebugging();

#endif