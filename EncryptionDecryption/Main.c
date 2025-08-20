#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#define MAX_BUFF_SIZE	1024	// 버퍼 사이즈
typedef void (*CryptFunc)(char* data, size_t len, const char* key);

typedef struct
{
	char filename[256];
	char* key;
	CryptFunc cryptFunc;
} Context;

/* --- Inline XOR 암호화 1 --- */
__inline void xorEncryptSimple(char* data, size_t len, const char* key) {
	size_t keyLen = strlen(key);
	for (size_t i = 0; i < len; i++)
		data[i] ^= key[i % keyLen];
}
/* --- 파일 읽기 ---*/
int readFile(const char* filename, char* buffer, size_t maxLen, size_t* outLen)
{
	FILE* fp = fopen(filename, "rb");
	if (!fp) return 0;

	size_t len = fread(buffer, 1, maxLen, fp);
	fclose(fp);
	*outLen = len;
	return 1;
}
/* --- 콘솔 메뉴 출력 --- */
void printMenu(void)
{
	printf("=== 파일 암호화 & 전자서명 도구 ===\n");
	printf("1. 평문 파일 읽기\n");
	printf("6. 종료\n");
	printf("원하는 메뉴 번호 입력: ");
}

int main(void)
{
	Context ctx = { "", "secretkey", xorEncryptSimple };
	char buffer[MAX_BUFF_SIZE]; // 입출력에 사용될 버퍼
	size_t dataLen = 0; // 파일 크기
	unsigned char signature = 0;
	int runnging = 1;

	while (runnging) {
		printMenu(); // 메뉴 출력
		int choice; // 메뉴 번호 입력받을 변수
		scanf_s("%d%*c", &choice); // 입력 받기, 변수의 메모리 주소를 인자로, %*c 줄바꿈 버림

		switch (choice)
		{
		case 1: // read plain text
			printf("읽을 파일명 입력: ");
			fgets(ctx.filename, sizeof(ctx.filename), stdin);	// 구조체의 filename에 입력값 저장
			ctx.filename[strcspn(ctx.filename, "\n")] = '\0';	// 구조체에 저장된 filename 입력시 저장된 개행 문자 제거
			if (readFile(ctx.filename, buffer, MAX_BUFF_SIZE, &dataLen))	// filename, 입출력 버퍼, 버퍼크기, 파일크기 변수의 주소
			{
				printf("파일 내용 (%zu 바이트):\n", dataLen);	// 파일 크기 확인
				fwrite(buffer, 1, dataLen, stdout);				// 파일 내용 출력, 버퍼 사이즈 만큼씩, stdout을 파일이름으로 변경시 파일에 작성
				printf("\n");
			}
			else
				printf("파일을 읽을 수 없습니다.\n");
			break;


		case 6:
			runnging = 0;
			break;

		default:
			printf("잘못된 선택입니다.\n");

		}
		printf("\n");
	}

	return 0;
}