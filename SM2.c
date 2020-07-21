#include <stdio.h>
#include <time.h>
#include "miracl.h"

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
*/
int KDF(unsigned Z[], int zlen, int klen, unsigned char K[])
{



	return 1;//返回1成功
}

/*
	功能：用公钥点G(x,y)对消息进行加密
	输入：pubKey公钥点、message明文、message_len消息长度
	输出：C密文
	返回：0成功 !0失败
*/
int SM2_encrypt(epoint* pubKey, unsigned char message[], int message_len, unsigned char C[])
{
	big k,C1x,C1y,x2,y2;  //k为随机数
	epoint* C1, * kP, * S;
	unsigned char x2y2_char[32 * 2] = { 0 };
	k = mirvar(0);
	C1x = mirvar(0);
	C1y = mirvar(0);
	x2 = mirvar(0);
	y2 = mirvar(0);
	C1 = epoint2_init();
	kP = epoint2_init();
	S = epoint2_init();
	
	//step 1:产生随机数k   在1至n-1的双侧闭区间
	while (isInRange(k))
	{
		bigrand(para_n, k); 
	}
	//step 2:计算椭圆曲线点C1 
	ecurve_mult(k, G, C1);  //C1 = [k]G
	epoint_get(C1, C1x,C1y);
	
	big_to_bytes(32, C1x, C, 1);
	big_to_bytes(32, C1y, C + 32, 1);

	//step 3：计算曲线点S  并判断是否为无穷远点，若是报错退出。
	ecurve_mult(para_h, pubKey, S);
	if (point_at_infinity)
	{
		printf("S is not at infinity!\n");
		return 0;
	}

	//step 4: 计算[k]PB = (x2, y2)，并将x2,y2转换成比特串
	ecurve_mult(k, pubKey, kP);  //kP=[k]PB
	ecurve_get(kP, x2, y2);
	
	big_to_bytes(32, x2, x2y2_char, 1);
	big_to_bytes(32, y2, x2y2_char+32, 1);

	//step 5:

	/* test if the given array is all zero */
	/*int Test_Null(unsigned char array[], int len)
	{
		int i;

		for (i = 0; i < len; i++)
			if (array[i] != 0x00) return 0;

		return 1;
	}*/






}