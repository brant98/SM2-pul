#include"miracl.h"
int SM2_init(void);
int isInRange(big num);//判断d是否在规定范围内  1至n-1的闭区间
int SM2_creat_key(big* d, epoint** pub);//生成公、私钥

