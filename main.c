#include <stdio.h>
#include<time.h>
#include "miracl.h"
#include"SM2.h"
int main(void)
{

	unsigned char* message = "Be there or be square!";
	//int Cipher_len = strlen(message)+96;  这里密文长度不是动态的，后续还可以改进一下
	unsigned char Cipher[118] = { 0 };

	big d, pubx, puby;  //私钥
	epoint* pub;//公钥

	clock_t start, finish;
	start = clock();
	SM2_init();//初初始化椭圆曲线参数
	SM2_creat_key(&d, &pub);//密钥生成

	SM2_encrypt(pub, message, strlen(message), Cipher);



	
	return 0;
}
