#include <stdio.h>
#include<time.h>
#include "miracl.h"
#include"SM2.h"
int main(void)
{

	unsigned char* message = "Be there or be square!";
	//int Cipher_len = strlen(message)+96;  �������ĳ��Ȳ��Ƕ�̬�ģ����������ԸĽ�һ��
	unsigned char Cipher[118] = { 0 };

	big d, pubx, puby;  //˽Կ
	epoint* pub;//��Կ

	clock_t start, finish;
	start = clock();
	SM2_init();//����ʼ����Բ���߲���
	SM2_creat_key(&d, &pub);//��Կ����

	SM2_encrypt(pub, message, strlen(message), Cipher);



	
	return 0;
}
