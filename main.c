#include <stdio.h>
#include<time.h>
#include<string.h>
#include "miracl.h"
#include"SM2.h"
int main(void)
{

	unsigned char* message = "Be there or be square!";
	unsigned char message_jm [22];
	//int Cipher_len = strlen(message)+96;  �������ĳ��Ȳ��Ƕ�̬�ģ����������ԸĽ�һ��
	unsigned char Cipher[118] = { 0 };

	big d, pubx, puby;  //˽Կ
	epoint* pub;//��Կ

	clock_t start, finish;//��������ʱ����
	start = clock();
	SM2_init();//����ʼ����Բ���߲���
	SM2_creat_key(&d, &pub);//��Կ����

	SM2_encrypt(pub, message, strlen(message), Cipher);
	SM2_decrypt(d, Cipher, 118, message_jm);
	
	for (int i = 0; i < 22; i++)
	{
		printf("%c", message_jm[i]);
	}

	return 0;
}
