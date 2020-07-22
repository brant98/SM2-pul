#include"miracl.h"
int SM2_init(void);
int isInRange(big num);//判断d是否在规定范围内  1至n-1的闭区间
int SM2_creat_key(big* d, epoint** pub);//生成公、私钥

int KDF(unsigned char Z[], int zlen, int klen, unsigned char K[]);//密钥派生函数
int SM2_encrypt(epoint* pubKey, unsigned char *message, int message_len, unsigned char C[]);
int SM2_decrypt(big d, unsigned char C[], int Clen, unsigned char  message[]);//解密函数
