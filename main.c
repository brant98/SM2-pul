#include <stdio.h>
#include<time.h>
#include<string.h>
#include "miracl.h"
#include"SM2.h"
int main(void)
{

	unsigned char* message = "Be there or be square!";
	unsigned char message_jiem[22];//解密后的明文存放在这个里面
	//int Cipher_len = strlen(message)+96;  这里密文长度不是动态的，后续还可以改进一下
	unsigned char Cipher[118] = { 0 };
	big d, pubx, puby;  //私钥
	epoint* pub;//公钥

	clock_t start, finish;//计算运行时间用
	start = clock();
	int i = 0;
	SM2_init();//初初始化椭圆曲线参数
	SM2_creat_key(&d, &pub);//密钥生成

	for (i = 0; i < 1000; i++)
	{

	}
	SM2_encrypt(pub, message, strlen(message), Cipher);
	SM2_decrypt(d, Cipher, sizeof(Cipher), message_jiem);
	printf("After decrypting.The message is : ");
	for(i=0;i<sizeof(message_jiem);i++)
	printf("%c", message_jiem[i]);


	finish = clock();
	printf("Test of this algorithm finished\n");
	printf("Start at  %f s\n", (double)start / CLOCKS_PER_SEC);
	printf("End at %f s\n", (double)finish / CLOCKS_PER_SEC);
	printf("1000 times tests  used %f seconds in total.\n", (double)difftime(finish, start) / CLOCKS_PER_SEC);
	printf("The algorithm runs once used %f seconds on average.\n", (double)difftime(finish, start) / CLOCKS_PER_SEC / 1000);
	return 0;
}
