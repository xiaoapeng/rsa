// rsa算法.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//
#include "pch.h"
#include "rsa.h"
#include <time.h>
#include <stdio.h>
#include<string.h>

char yemian();

int main()
{
	
	unsigned char m_buf[max_m] = { 0 };//明文缓冲区
	char buf[max_m * 2 + 2] = { 0 };//用于密文秘钥输入暂存
	KEY key;
	key_init(&key);

	while (1)
	{
		switch (yemian())
		{
		case '1':
			key_Generate_encryption_and_decryption_keys(&key);
			printf("请输入要加密的字符（汉字、数字、字母都可以）\n");
			printf("请小于或者等于255个字符，若不满足要求请使用文件加密\n");
			fflush(stdin);
			getchar();
			fgets((char*)m_buf, 225, stdin);
			key_set_str_m_pt(&key, (char*)m_buf);
			key_encryption(&key);
			key_printf_c(&key);
			key_printf_n_d(&key);
			break;
		case '2':
			printf("请输入模：");
			scanf("%s", buf);
			key_set_str_n(&key, buf);
			printf("私钥：");
			scanf("%s", buf);
			key_set_str_d(&key, buf);
			printf("密文：");
			scanf("%s", buf);
			key_set_str_c(&key, buf);

			key_edecryption(&key);
			key_s_zhuan_b(&key);
			key_printf_m_str(&key);
			break;
		case '3':
			//16进制
			fflush(stdin);
			getchar();
			key_Generate_large_prime_Numbers(&key);//生成大素数
			key_compute_n_r_yunfei(&key);//n计算模和r
			printf("(16进制)公钥e：");
			fgets((char*)buf, 225, stdin);
			key_set_str_e(&key, buf);//设置公钥设置公钥且计算秘钥
			printf("        (n,e)\n");
			key_printf_n_e(&key);
			printf("\n\n");
			printf("        (n,d)\n");
			key_printf_n_d(&key);
			break;
		case '4':
			fflush(stdin);
			getchar();
			printf("(10进制)p：");
			fgets((char*)buf, 225, stdin);//"11"
			//key_set_yunfei(key.key_p, buf, 10);//88888888888888
			key_set_str_p_10(&key, buf);
			
			printf("(10进制)q：");
			fflush(stdin);
			fgets((char*)buf, 225, stdin);
			//key_set_yunfei(key.key_q, buf, 10);//88888888888888
			key_set_str_q_10(&key, buf);

			key_compute_n_r_yunfei(&key);//n计算模和r
			
			key_printf_n_10(&key);//打印模
			key_printf_r(&key);//打印r

			printf("(10进制)公钥e：");
			fgets((char*)buf, 225, stdin);
			key_set_str_e_yunfei(&key, buf);//设置公钥且计算秘钥
			key_printf_d_10_yunfei(&key);//打印秘钥
			printf("(10进制)m：");
			fgets((char*)buf, 225, stdin);
			key_set_unbianma_m_10(&key,buf);

			key_encryption(&key);
			//gmp_printf("密文:%ZX哈哈\n", key.c);
			key_printf_c_10_yunfei(&key);

			break;
		case '5' :
			//进制重写

			
			printf("请输入模：");
			scanf("%s", buf);
			key_set_str_n_10(&key, buf);
			key_printf_n_10(&key);//打印模
			printf("私钥：");
			scanf("%s", buf);
			key_set_str_d_10(&key, buf);
			key_printf_d_10_yunfei(&key);//打印秘钥
			printf("密文：");
			scanf("%s", buf);
			key_set_str_c_10(&key, buf);
			key_printf_c_10_yunfei(&key);
			key_edecryption(&key);
			key_printf_m_10(&key);

			break;
		case '6':
			goto exit;

			break;

		default:
			break;
		}
		system("pause");
		system("cls");
	}
	exit:
	key_clear(&key);
	getchar();
	getchar();
	return 0;
}
char yemian()
{
	printf("             ***********加密小程序************\n");
	printf("             *********************************\n");
	printf("             *********************************\n");
	printf("                  1.加密数字汉字字母组合\n");
	printf("             *********************************\n");
	printf("                  2.解密数字汉字字母组合\n");
	printf("             *********************************\n");
	printf("                  3.生成秘钥公钥对\n");
	printf("             *********************************\n");
	printf("                  4.数字加密\n");
	printf("             *********************************\n");
	printf("                  5.数字解密\n");
	printf("             *********************************\n");
	printf("                  6.退出\n");
	char ch='p';
	ch = getchar();
	return ch;
}