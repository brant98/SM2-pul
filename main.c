#include <stdio.h>
#include<time.h>
#include<string.h>
#include "miracl.h"
#include"SM2.h"
int main(void)
{

	unsigned char* message = "Be there or be square!";
	unsigned char message_jm [22];
	//int Cipher_len = strlen(message)+96;  这里密文长度不是动态的，后续还可以改进一下
	unsigned char Cipher[118] = { 0 };

	big d, pubx, puby;  //私钥
	epoint* pub;//公钥

	clock_t start, finish;//计算运行时间用
	start = clock();
	SM2_init();//初初始化椭圆曲线参数
	SM2_creat_key(&d, &pub);//密钥生成

	SM2_encrypt(pub, message, strlen(message), Cipher);
	SM2_decrypt(d, Cipher, 118, message_jm);
	
	for (int i = 0; i < 22; i++)
	{
		printf("%c", message_jm[i]);
	}

	return 0;
}
