#include <stdio.h>
#include<time.h>
#include "miracl.h"
#include"SM2.h"
int main(void)
{
	unsigned char pubx_char[32], puby_char[32], ZA[32];
	unsigned char r[32], s[32];//ǩ��
	const unsigned char* message = "be there or be square!";
	big d, pubx, puby;  //˽Կ
	epoint* pub;//��Կ

	clock_t start, finish;
	start = clock();

	SM2_init();//����ʼ����Բ���߲���
	SM2_creat_key(&d, &pub);//��Կ����

	
	return 0;
}
