#include"miracl.h"
int SM2_init(void);
int isInRange(big num);//�ж�d�Ƿ��ڹ涨��Χ��  1��n-1�ı�����
int SM2_creat_key(big* d, epoint** pub);//���ɹ���˽Կ

int KDF(unsigned char Z[], int zlen, int klen, unsigned char K[]);//��Կ��������
int SM2_encrypt(epoint* pubKey, unsigned char *message, int message_len, unsigned char C[]);
int SM2_decrypt(big d, unsigned char C[], int Clen, unsigned char  message[]);//���ܺ���
