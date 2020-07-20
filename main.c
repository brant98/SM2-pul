#include <stdio.h>
#include<time.h>
#include "miracl.h"
#include"SM2.h"
int main(void)
{
	unsigned char pubx_char[32], puby_char[32], ZA[32];
	unsigned char r[32], s[32];//签名
	const unsigned char* message = "be there or be square!";
	big d, pubx, puby;  //私钥
	epoint* pub;//公钥

	clock_t start, finish;
	start = clock();

	SM2_init();//初初始化椭圆曲线参数
	SM2_creat_key(&d, &pub);//密钥生成

	
	return 0;
}
