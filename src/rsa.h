#ifndef _RSA_H
#define _RSA_H
#include <stdio.h>
#include <gmp.h>
#include <time.h>
#include <string.h>
#define max_m 255 //单可加密字节数
#define key_set_yunfei	mpz_set_str
#define key_set_yunfei	mpz_set_str
typedef struct w
{
	//
	mpz_t key_p, key_q, key_n, key_r, key_e, key_d, m, c;//你应该猜的到干嘛的
	char buf[max_m * 2 + 2] = { 0 };//单次可加密缓冲区
	char jiami_jiemi_buf[max_m] = { 0 };//加密解密完后用于缓存的
}KEY;

extern void key_s_zhuan_b(KEY *b);// 数转二进制
extern void key_init(KEY *b);//初始化一切大整数
extern void key_Generate_encryption_and_decryption_keys(KEY* b);//生成秘钥

extern void key_Generate_large_prime_Numbers(KEY *b);//素数生成
//数字密文的加密
extern void key_set_str_p_10(KEY *b, const char *s);//用来设置素数（10进制）
extern void key_set_str_q_10(KEY *b, const char *s);//用来设置素数（10进制）
extern void key_compute_n_r_yunfei(KEY *b);//计算欧拉函数和求模
extern void key_set_str_e_yunfei(KEY *b, const char *s);//公钥设置 并计算秘钥
extern void key_set_unbianma_m_10(KEY *b, const char *s);//设置非编码的明文
//extern void key_encryption(KEY* b);//加密


extern void key_set_str_e(KEY *b, const char *s);//公钥设置16进制


//数字密文的解密
extern void key_set_str_n_10(KEY *b, const char *s);//设置10 进制模
extern void key_set_str_d_10(KEY *b, const char *s);//设置10进制私钥
extern void key_set_str_c_10(KEY *b, char *s);//设置普通10进制密文
//extern void key_edecryption(KEY* b);//解密



//一切已编码解密都可以实现，只是是16进制
//解密的实现（16进制） 通过把密文转明文 在把明文转化为二进制就是真正的明文
//已编码解密
extern void key_set_str_c(KEY *b,  char *s);//设置普通密文
extern void key_set_str_n(KEY *b, const char *s);//设置16 进制模
extern void key_set_str_d(KEY *b, const char *s);//设置16进制私钥
//extern void key_edecryption(KEY* b);//解密
//extern void key_s_zhuan_b(KEY *b);// 数转二进制



//用于键盘输入加密
//通过初始化和秘钥的生成再设置明文（16进制输入） 
//普通明文是指键盘输入的明文，也可以作为文件最后不足255字节部分使用
//extern void key_init(KEY *b);//初始化
//extern void key_Generate_encryption_and_decryption_keys(KEY* b);//生成秘钥
extern void key_set_str_m_pt(KEY *b, char *s);//设置普通的明文，该函数包括把二进制编码成数字的过程
//extern void key_encryption(KEY* b);//加密就可以生成数字密文


//主要用于文件加密的过程中 满255字节的 其他过程与上面一样,功能没写完，请忽略
extern void key_set_str_m(KEY *b, unsigned char *s);//设置二进制明文




extern void key_encryption(KEY* b);//加密
extern void key_edecryption(KEY* b);//解密

extern void key_printf_m_10(KEY* b);//打印非转码的明文（10进制)
extern void key_printf_m(KEY* b);//打印非转码的明文（16进制）
extern void key_printf_m_str(KEY* b);//打印转码后的明文 是字符串
extern void key_printf_c(KEY* b);	//打印密文（16进制）
extern void key_printf_c_10_yunfei(KEY* b);//打印密文（10进制）
extern void key_printf_n_10(KEY* b);//打印乘积 n（10进制）
extern void key_printf_n(KEY* b); //打印乘积 n （16进制）
extern void key_printf_r(KEY* b);//打印Φn r (10进制)


extern void key_printf_p_q(KEY* b); //打印16进制的两个素数
extern void key_printf_n_e(KEY* b); //打印乘积 n 和 公钥e (16进制)
extern void key_printf_n_d(KEY* b); //打印乘积 n 和 私钥d (16进制)
extern void key_printf_d_10_yunfei(KEY* b);//打印私钥（10进制）
extern void key_clear(KEY* b);//收尾函数 回收堆资源
extern void binary_string(char*, unsigned const char*, int);//从二进制转化为可以计算的数字 //编码
extern void string_binary(char*, unsigned char*, int);//从可计算的数字转化为二进制 //解码

#endif