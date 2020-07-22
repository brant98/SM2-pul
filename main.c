#include <stdio.h>
#include<time.h>
#include<string.h>
#include "miracl.h"
#include"SM2.h"
int main(void)
{

	unsigned char* message = "Be there or be square!";
	unsigned char message_jiem [22];//���ܺ�����Ĵ�����������
	//int Cipher_len = strlen(message)+96;  �������ĳ��Ȳ��Ƕ�̬�ģ����������ԸĽ�һ��
	unsigned char Cipher[118] = { 0 };
	//memset(Cipher, 0, sizeof(char) * 4);
	big d, pubx, puby;  //˽Կ
	epoint* pub;//��Կ

	clock_t start, finish;//��������ʱ����
	start = clock();
	SM2_init();//����ʼ����Բ���߲���
	SM2_creat_key(&d, &pub);//��Կ����

	SM2_encrypt(pub, message, strlen(message), Cipher);
	SM2_decrypt(d, Cipher, sizeof(Cipher), message_jiem);
	printf("After decrypting.The message is : ");
	for (int i = 0; i < 22; i++)
	{
		printf("%c", message_jiem[i]);
	}
	//printf("\n over \n");
	

	return 0;
}
