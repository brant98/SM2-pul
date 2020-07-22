#include <stdio.h>
#include <time.h>
#include<string.h>
#include "miracl.h"
#include"mirdef.h"
#include "SM2.h"
// ECC椭圆曲线参数（SM2标准推荐参数）
static unsigned char SM2_p[32] = {
	0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
static unsigned char SM2_a[32] = {
	0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFC };
static unsigned char SM2_b[32] = {
	0x28, 0xE9, 0xFA, 0x9E, 0x9D, 0x9F, 0x5E, 0x34, 0x4D, 0x5A, 0x9E, 0x4B, 0xCF, 0x65, 0x09, 0xA7,
	0xF3, 0x97, 0x89, 0xF5, 0x15, 0xAB, 0x8F, 0x92, 0xDD, 0xBC, 0xBD, 0x41, 0x4D, 0x94, 0x0E, 0x93 };
static unsigned char SM2_n[32] = {
	0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0x72, 0x03, 0xDF, 0x6B, 0x21, 0xC6, 0x05, 0x2B, 0x53, 0xBB, 0xF4, 0x09, 0x39, 0xD5, 0x41, 0x23 };
static unsigned char SM2_Gx[32] = {
	0x32, 0xC4, 0xAE, 0x2C, 0x1F, 0x19, 0x81, 0x19, 0x5F, 0x99, 0x04, 0x46, 0x6A, 0x39, 0xC9, 0x94,
	0x8F, 0xE3, 0x0B, 0xBF, 0xF2, 0x66, 0x0B, 0xE1, 0x71, 0x5A, 0x45, 0x89, 0x33, 0x4C, 0x74, 0xC7 };
static unsigned char SM2_Gy[32] = {
	0xBC, 0x37, 0x36, 0xA2, 0xF4, 0xF6, 0x77, 0x9C, 0x59, 0xBD, 0xCE, 0xE3, 0x6B, 0x69, 0x21, 0x53,
	0xD0, 0xA9, 0x87, 0x7C, 0xC6, 0x2A, 0x47, 0x40, 0x02, 0xDF, 0x32, 0xE5, 0x21, 0x39, 0xF0, 0xA0 };
static unsigned char SM2_h[32] = {
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 };

big para_p, para_a, para_b, para_n, para_Gx, para_Gy, para_h;
epoint* G;
miracl* mip;
/*
功能：SM2签名算法椭圆曲线参数初始化
输入：无
输出：无
返回：0失败  1成功
*/
int SM2_init(void)
{
	epoint* nG;
	mip = mirsys(10000, 16);
	mip->IOBASE = 16;
	para_p = mirvar(0);
	para_a = mirvar(0);
	para_b = mirvar(0);
	para_n = mirvar(0);
	para_Gx = mirvar(0);
	para_Gy = mirvar(0);
	para_h = mirvar(0);

	G = epoint_init();
	nG = epoint_init();

	bytes_to_big(32, SM2_p, para_p);  // 32=256/8
	bytes_to_big(32, SM2_a, para_a);
	bytes_to_big(32, SM2_b, para_b);
	bytes_to_big(32, SM2_n, para_n);
	bytes_to_big(32, SM2_Gx, para_Gx);
	bytes_to_big(32, SM2_Gy, para_Gy);
	//bytes_to_big(256, SM2_h, para_h);

	/*Initialises GF(p) elliptic curve.(MR_PROJECTIVE specifying projective coordinates)*/
	ecurve_init(para_a, para_b, para_p, MR_PROJECTIVE);

	/*initialise point G*/
	if (!epoint_set(para_Gx, para_Gy, 0, G))
		return 0;

	ecurve_mult(para_n, G, nG);

	/*test if the order of the point is n*/
	if (!point_at_infinity(nG))
		return 0;
	printf("Init successed!\n");
	return 1;             //成功运行到最后则返回1.若返回的是0则表示初始化不正确
}
int isInRange(big num) //判断d是否在规定范围内  1至n-1的闭区间
{
	big one, decr_n;
	one = mirvar(0);
	decr_n = mirvar(0);

	convert(1, one);
	decr(para_n, 1, decr_n);

	if ((mr_compare(num, one) > 0) && (mr_compare(num, decr_n) < 0))//compare(x,y)  x>y +1   x=y 0  x<y -1
		return 1;//返回1表示在适合范围
	return 0;//返回0表示不在适合的范围
}
int SM2_creat_key(big* d, epoint** pub)
{

	*d = mirvar(0);
	*pub = epoint_init();
	irand(time(NULL));
	bigrand(para_n, *d);  // d私钥 d应在1至n-2之间，包括两端
	while (isInRange(*d) != 1)
	{
		bigrand(para_n, *d);
	}
	ecurve_mult(*d, G, *pub);//pub中存放公钥
	printf("creat key done!\n");
	return 1; //成功返回1
}
/*
KDF密钥派生函数
 key derivation function
*Z是比特串，klen表示要获得的密钥数据的比特长度
*k是存放输出的，z是输入
*/
int KDF(unsigned char Z[], int zlen, unsigned char K[],int klen)
{
	int  i, j=0, t;
	int bit_klen;
	unsigned char Ha[32] = {0}; //摘要 及其长度为32
	unsigned char ct[4] = { 0,0,0,1 };

	bit_klen = klen * 8;//有多少位  也可以用字节。
	sha256 sha_256;

	if (bit_klen % 256)
		t = bit_klen / 256 + 1;
	else
		t = bit_klen / 256;
	//K= Ha1 || Ha2 || ...
	for (i = 1; i < t; i++)//因为后面有i-1  且最后一个Ha要单独求
	{
		//Ha1=Hv(Z|| ct )
		shs256_init(&sha_256);
		for (j = 0; j<zlen; j++)
			shs256_process(&sha_256, Z[j]);
		for (j = 0; j<4; j++)
			shs256_process(&sha_256, ct[j]);
		shs256_hash(&sha_256, Ha);

		memcpy((K + 32 * (i - 1)), Ha, 32);

		//ct++  注意进位,大小端
		if (ct[3] == 0xff)
		{
			ct[3] = 0;
			if (ct[2] == 0xff)
			{
				ct[2] = 0;
				if (ct[1] == 0xff)
				{
					ct[1] = 0;
					ct[0]++;
				}
				else
					ct[1]++;
			}
			else
				ct[2]++;
		}
		else
			ct[3]++;
	}

	
	shs256_init(&sha_256);
	for (j = 0; j < zlen; j++)
		shs256_process(&sha_256, Z[j]);
	for (j = 0; j < 4; j++)
		shs256_process(&sha_256, ct[j]);
	shs256_hash(&sha_256, Ha);

	//若klen/v是整数
	if (bit_klen % 256) //或者字节能否被32整除
	{
		j = klen - 32 * (klen / 32);
		memcpy((K + 32 * (t - 1)), Ha, j);
	}
	else
	{
		memcpy((K + 32 * (t - 1)), Ha, 32);
	}

	return 1;//返回1成功
}

/*
	功能：用公钥点G(x,y)对消息进行加密
	输入：pubKey公钥点、message明文、message_len消息长度
	输出：C密文
	返回：0成功 !0失败
*/
int SM2_encrypt(epoint* pubKey, unsigned char* message, int message_len, unsigned char C[])
{
	big k, C1x, C1y, x2, y2;  //k为随机数
	epoint* C1, * kP, * S;
	unsigned char x2y2_char[32 * 2] = { 0 };
	int i = 0, j = 0;
	sha256 sha_256;
	k = mirvar(0);
	C1x = mirvar(0);
	C1y = mirvar(0);
	x2 = mirvar(0);
	y2 = mirvar(0);
	C1 = epoint_init();
	kP = epoint_init();
	S = epoint_init();

	//step 1:产生随机数k   在1至n-1的双侧闭区间
	while (isInRange(k) == 0)
	{
		bigrand(para_n, k);
	}

	//step 2:计算椭圆曲线点C1 
	ecurve_mult(k, G, C1);  //C1 = [k]G
	epoint_get(C1, C1x, C1y);

	big_to_bytes(32, C1x, C, 1);
	big_to_bytes(32, C1y, C + 32, 1);

	//step 3：计算曲线点S  并判断是否为无穷远点，若是报错退出。
	bytes_to_big(32, SM2_h, para_h);
	ecurve_mult(para_h, pubKey, S);
	if (point_at_infinity(S))
	{
		printf("S is at infinity!\n");
		return 0;
	}
	//step 4: 计算[k]PB = (x2, y2)，并将x2,y2转换成比特串
	ecurve_mult(k, pubKey, kP);  //kP=[k]PB
	epoint_get(kP, x2, y2);

	big_to_bytes(32, x2, x2y2_char, 1);
	big_to_bytes(32, y2, x2y2_char + 32, 1);

	//step 5: KDF 并判断是否全为0   
	KDF(x2y2_char, 32 * 2,  C + 32 * 3, message_len);
	j = 32 * 3;

	int flag = 0;       //如果有不为0的 那么就不会全为0  标志位
	for (i = 0; i < message_len; i++, j++)
	{

		if (C[j] != 0x00)
		{
			flag = 1;
			break;
		}
	}

	if (flag == 0)
	{
		printf("The C is  all zero\n");
		return 0;
	}

	//step 6:C2=M异或t
	for (i = 0; i < message_len; i++)
	{
		C[32 * 3 + i] = message[i] ^ C[32 * 3 + i];
	}


	//step 7:计算C3
	shs256_init(&sha_256);
	
	for (j = 0; j<32; j++)
		shs256_process(&sha_256, x2y2_char[j]);
	for (j = 0; message[j] != 0; j++)
		shs256_process(&sha_256, message[j]);

	for (j = 32; j<64; j++)
		shs256_process(&sha_256, x2y2_char[j]);

	shs256_hash(&sha_256, C + 32 * 2);

	printf("SM2 encrypt done!\n");
	return 1;	//成功返回1
}

/*
	功能：用私钥d对消息进行解密
	输入：d私钥、C密文、Clen密文长度
	输出：message明文
	返回：1成功 0失败
*/
int SM2_decrypt(big d, unsigned char C[], int Clen, unsigned char message_jiem[])
{
	unsigned char x2y2[32 * 2] = { 0 };
	unsigned char hash[32] ;
	memset(hash, 0, sizeof(char) * 4);
//	memset(hash, 0, 32);
	big C1x, C1y, x2, y2, xx, temp;//xx  temp 用于判断是否在椭圆曲线上
	epoint* C1, * S, * dC1;
	sha256 sha_256;
	int i = 0, j = 0;
	C1x = mirvar(0);
	C1y = mirvar(0);
	x2 = mirvar(0);
	y2 = mirvar(0);
	xx = mirvar(0);
	temp = mirvar(0);
	C1 = epoint_init();
	S = epoint_init();
	dC1 = epoint_init();

	//step 1: 提取密文中的x1, y1,并判断是否有效
	bytes_to_big(32, C, C1x);
	bytes_to_big(32, C + 32, C1y);
	epoint_set(C1x, C1y, 0, C1);

	power(C1x, 3, para_p, xx);	//x_3 = x^3 mod p
	multiply(C1x, para_a, C1x); 	//x = a * x
	divide(C1x, para_p, temp); 	//x = a * x mod p, tmp = a * x / p
	add(xx, C1x, C1x);				//x = x^3 + ax
	add(C1x, para_b, C1x);			//x = x^3 + ax + b
	divide(C1x, para_p, temp);		//x = x^3 + ax + b mod p
	power(C1y, 2, para_p, C1y);		//y = y^2 mod p

	if (mr_compare(C1x, C1y) != 0)
	{
		printf("The C1 is not valid!\n");
		return 0;
	}

	//step 2:计算S=[h]C1并判断是否为无穷远点
	ecurve_mult(para_h, C1, S);
	if (point_at_infinity(S))
	{
		printf("S is at infinity!\n");
		return 0;
	}

	//step 3: [dB]C1 = (x2, y2)
	ecurve_mult(d, C1, dC1);
	epoint_get(dC1, x2, y2);
	big_to_bytes(32, x2, x2y2, 1);
	big_to_bytes(32, y2, x2y2 + 32, 1);

	//step 4:KDF  得到t  在message中
	KDF(x2y2, 32 * 2,  message_jiem, Clen-32 * 3);

	int flag = 0;//如果有一个不为0的 那么就不会全为0。  标志位
	for (i = 0; i < Clen - 32 * 3; i++)
	{

		if (message_jiem[j] != 0x00)
		{
			flag = 1;
			break;
		}
	}
	if (flag == 0)
	{
		printf("The t is  all zero\n");
		return 0;
	}

	//step 5: 计算M‘
	for (i = 0; i < Clen - 32 * 3; i++)
	{
		message_jiem[i] = message_jiem[i] ^ C[32 * 3 + i];
	}

	//step 6:
	shs256_init(&sha_256);
	for (j = 0; j <32; j++)
		shs256_process(&sha_256, x2y2[j]);
	for (j = 0; j < Clen - 32 * 3; j++)
	{
		shs256_process(&sha_256, message_jiem[j]);
	}
	for (j = 32; j<64; j++)
	{
		shs256_process(&sha_256, x2y2[j]);
	}
	shs256_hash(&sha_256, hash);

	if (memcmp(hash, C+32*2, 32) != 0) //这里花费了很长时间,还是不对。明明值是一样的哒 效果始终不对就换了一种方式。
	{
		printf("!!!!!!!!!Decrypt failed!\n");
	    return 0;
	}
	else
	{
	printf("Successed!  SM2 decrypt done! \n");

	}
	return 1;
}

