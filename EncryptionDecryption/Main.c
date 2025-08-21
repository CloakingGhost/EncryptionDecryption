#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#define MAX_BUFF_SIZE	1024	// 버퍼 사이즈
#define MAX_FILE_NAME_SIZE	256
typedef void (*CryptFunc)(char* data, size_t len, const char* key);

typedef struct
{
	char filename[MAX_FILE_NAME_SIZE];
	char* key;
	CryptFunc cryptFunc;
} Context;

/* --- Inline XOR 암호화 1 --- */
void XorEncryptSimple(char* data, size_t len, const char* key)
{
	size_t keyLen = strlen(key);		// 시크릿 키
	for (size_t i = 0; i < len; i++)
	{
		data[i] ^= key[i % keyLen];		// 시크릿 키를 사용하여 나머지 연산의 값으로 바꿈
	}
}
/* --- 파일 읽기 ---*/
int ReadFile(const char* filename, char* buffer, size_t maxLen, size_t* outLen)
{
	FILE* fp = fopen(filename, "rb");			// 파일 포인터
	if (!fp) return 0;							// 없으면 종료

	size_t len = fread(buffer, 1, maxLen, fp);	// 버퍼에 저장
	fclose(fp);									// 파일 닫기
	*outLen = len;								// 파일 크기
	return 1;
}
int WriteFile(const char* filename, const char* buffer, size_t len)
{
	FILE* fp = fopen(filename, "wb");	// 파일 포인터, 모드
	if (!fp) return 0;					// 없으면 종료
	fwrite(buffer, 1, len, fp);			// 버퍼에 있는 내용 포인터 위치에 작성
	fclose(fp);							// 파일 닫기
	return 1;
}
int WriteSignatureFile(const char* filename, const unsigned char* sigature, size_t len)
{
	FILE* fp = fopen(filename, "wb");
	if (!fp) return 0;
	fwrite(sigature, 1, len, fp);
	fclose(fp);
	return 1;
}
int IsEncfile(const char* filename, const char* extension) {
	return strstr(filename, extension) != NULL;
}
unsigned char SimpleChecksum(const char* data, size_t len)
{
	unsigned char sum = 0;
	for (size_t i = 0; i < len; i++) {
		sum += data[i];
	}
	return sum;
}
unsigned char CreateSignature(const char* data, size_t len, const char* privKey)
{
	unsigned char hash = SimpleChecksum(data, len);
	unsigned char signature = hash;
	size_t keyLen = strlen(privKey);
	for (size_t i = 0; i < len; ++i)
	{
		signature ^= data[i];
	}
	return signature;
}
int VerifySignature(const char* data, size_t len, const char* privKey, unsigned char signature)
{
	unsigned char experted = CreateSignature(data, len, privKey);
	return (experted == signature);
}
/* --- 콘솔 메뉴 출력 --- */
void PrintMenu(void)
{
	printf("=== 파일 암호화 & 전자서명 도구 ===\n");
	printf("1. 평문 파일 읽기\n");
	printf("2. 파일 암호화\n");
	printf("3. 파일	복호화\n");
	printf("4. 전자서명 생성\n");
	printf("5. 전자서명 검증\n");
	printf("6. 종료\n");
	printf("원하는 메뉴 번호 입력: ");
}

int main(void)
{
	Context ctx = { "", "secretkey", XorEncryptSimple };
	char buffer[MAX_BUFF_SIZE]; // 입출력에 사용될 버퍼
	size_t dataLen = 0; // 파일 크기
	char encExtension[12] = { ".enc" };
	unsigned char signature = 0;
	int runnging = 1;

	while (runnging) {
		PrintMenu(); // 메뉴 출력
		int choice; // 메뉴 번호 입력받을 변수
		scanf_s("%d%*c", &choice); // 입력 받기, 변수의 메모리 주소를 인자로, %*c 줄바꿈 버림

		switch (choice)
		{
		case 1: // 파일읽기
			printf("읽을 파일명 입력: ");
			fgets(ctx.filename, sizeof(ctx.filename), stdin);	// 구조체의 filename에 입력값 저장
			ctx.filename[strcspn(ctx.filename, "\n")] = '\0';	// 구조체에 저장된 filename 입력시 저장된 개행 문자 제거
			if (ReadFile(ctx.filename, buffer, MAX_BUFF_SIZE, &dataLen))	// filename, 입출력 버퍼, 버퍼크기, 파일크기 변수의 주소
			{
				printf("파일 내용 (%zu 바이트):\n", dataLen);	// 파일 크기 확인
				fwrite(buffer, 1, dataLen, stdout);				// 파일 내용 출력, 버퍼 사이즈 만큼씩, stdout을 파일이름으로 변경시 파일에 작성
				printf("\n");
			}
			else
				printf("파일을 읽을 수 없습니다.\n");
			break;

		case 2: // 암호화 + 파일 쓰기
			printf("암호화할 파일명 입력: ");
			fgets(ctx.filename, sizeof(ctx.filename), stdin);				// 파일명 저장
			ctx.filename[strcspn(ctx.filename, "\n")] = '\0';				// 입력값의 개행문자 제거

			if (ReadFile(ctx.filename, buffer, MAX_BUFF_SIZE, &dataLen))	// 파일 읽어오기 -> buffer
			{
				ctx.cryptFunc(buffer, dataLen, ctx.key);					// 암호화 -> buffer에 담기

				char outFile[MAX_FILE_NAME_SIZE];											// 암호화된 파일 이름전용 버퍼
				snprintf(outFile, sizeof(outFile), "%s.enc", ctx.filename);	// 버퍼 크기에 맞는 파일 이름작성

				if (WriteFile(outFile, buffer, dataLen))					// 파일 생성
				{
					printf("파일 저장 완료\n");
				}
				else
				{
					printf("파일 저장 실패\n");
				}
			}
			else
			{
				printf("파일 읽기 실패\n");
			}
			break;

		case 3: // 복호화 + 파일 쓰기
			printf("복호화할 파일명 입력 (*%s)", encExtension);
			fgets(ctx.filename, sizeof(ctx.filename), stdin);
			ctx.filename[strcspn(ctx.filename, "\n")] = '\0';
			if (!IsEncfile(ctx.filename, encExtension))
			{
				printf("암호화 파일이 아님(*%s).\n", encExtension);
				break;
			}
			if (ReadFile(ctx.filename, buffer, MAX_BUFF_SIZE, &dataLen))
			{
				ctx.cryptFunc(buffer, dataLen, ctx.key);
				char outFile[MAX_FILE_NAME_SIZE];
				snprintf(outFile, sizeof(outFile), "dec_%s", ctx.filename);
				if (WriteFile(outFile, buffer, dataLen))
				{
					printf("복호화된 파일 저장: %s\n", outFile);
				}
				else
				{
					printf("파일 저장 실패\n");
				}
			}
			else
			{
				printf("파일 읽기 실패\n");
			}

			break;
		case 4: // 전자서명 생성
			printf("서명할 원본 파일명 입력: ");
			fgets(ctx.filename, sizeof(ctx.filename), stdin);
			ctx.filename[strcspn(ctx.filename, "\n")] = '\0';
			if (ReadFile(ctx.filename, buffer, MAX_BUFF_SIZE, &dataLen))
			{
				signature = CreateSignature(buffer, dataLen, ctx.key);
				char sigFile[MAX_FILE_NAME_SIZE];
				snprintf(sigFile, sizeof(sigFile), "sig_%s", ctx.filename);
				if (WriteSignatureFile(sigFile, &signature, sizeof(signature)))
				{
					printf("시그니처 파일 저장: %s\n", sigFile);
				}
				else
				{
					printf("시그니처 파일 생성 실패");
				}
			}
			else
			{
				printf("파일 읽기 실패\n");
			}
			break;
		case 5:	// 전자서명 검증
			printf("검증할 파일 입력: ");
			// 파일이름 가져와
			fgets(ctx.filename, sizeof(ctx.filename), stdin);
			ctx.filename[strcspn(ctx.filename, "\n")] = '\0';
			// 원본파일이름 읽어
			FILE* file = fopen(ctx.filename, "rb");
			if (!file)
			{
				printf("파일없음\n");
				break;
			}
			size_t len = fread(buffer, 1, MAX_BUFF_SIZE-1, file);
			fclose(file);
			buffer[len] = '\0';
			// 깊은 복사(내용복사)
			char fileBuff[MAX_BUFF_SIZE];
			memcpy_s(fileBuff, MAX_BUFF_SIZE, buffer, MAX_BUFF_SIZE);
			// sig_파일이름 읽어
			char sigFilename[MAX_FILE_NAME_SIZE] = "sig_";
			strcat_s(sigFilename, MAX_FILE_NAME_SIZE, ctx.filename);
			FILE* sigFile = fopen(sigFilename, "rb");
			fread(buffer, 1, MAX_BUFF_SIZE, sigFile);
			fclose(sigFile);
			unsigned char signature = *buffer;
			printf("%s\n", fileBuff);
			// 검증함수에 넣어(원본파일데이터, 크기, 키, 시그니처)
			if (VerifySignature(fileBuff, len, ctx.key, signature))
			{
				printf("검증 완료");
			}
			else
			{
				printf("검증 실패");
			}
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