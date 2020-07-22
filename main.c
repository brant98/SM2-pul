#include <stdio.h>
#include<time.h>
#include<string.h>
#include "miracl.h"
#include"SM2.h"
int main(void)
{

	unsigned char* message = "Be there or be square!";
	unsigned char message_jiem [22];//解密后的明文存放在这个里面
	//int Cipher_len = strlen(message)+96;  这里密文长度不是动态的，后续还可以改进一下
	unsigned char Cipher[118] = { 0 };
	//memset(Cipher, 0, sizeof(char) * 4);
	big d, pubx, puby;  //私钥
	epoint* pub;//公钥

	clock_t start, finish;//计算运行时间用
	start = clock();
	SM2_init();//初初始化椭圆曲线参数
	SM2_creat_key(&d, &pub);//密钥生成

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
