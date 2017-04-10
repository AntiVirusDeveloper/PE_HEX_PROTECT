#ifndef __PE
#define __PE

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

void PEView_Init();

BOOL SetDosHeader(BOOL First);
BOOL SetNT32Header(BOOL First);
BOOL SetNT64Header(BOOL First);
BOOL SetSectionHeader(BOOL First);

//PE 기본 화면 
void PEViewer();

//PE Viewer 사용 방법 출력
void PE_Manual();

//File 포인터로 얻어온 파일의 구조를 그래프로 보여줌
void PE_Graph(TCHAR buf[], BOOL bBody);

//num 에 입력 된 값을 통해 해당되는 섹션을 출력함
void PE_Graph_Found(int mode, ULONGLONG num);

//Dos 헤더 구조를 보여줌
void PE_DosHeader_View();

//NT 시그니처와 FilePointer, OptionPointer 출력함
void PE_NTHeader_View();

//File 헤더 구조를 보여줌
void PE_FileHeader_View();

//Option 헤더 구조를 보여줌
void PE_OptionHeader_View();

//SetIndex 값에 따른 섹션을 출력함
void PE_Section_View(int SecIndex);

//option 에 입력된 값에 따라 str 문자열 설정, 섹션의 옵션을 보여줌
void SectionOptionPrint(DWORD option, TCHAR *str);

#endif