#ifndef _RSA_H
#define _RSA_H
#include <stdio.h>
#include <gmp.h>
#include <time.h>
#include <string.h>
#define max_m 255 //���ɼ����ֽ���
#define key_set_yunfei	mpz_set_str
#define key_set_yunfei	mpz_set_str
typedef struct w
{
	//
	mpz_t key_p, key_q, key_n, key_r, key_e, key_d, m, c;//��Ӧ�òµĵ������
	char buf[max_m * 2 + 2] = { 0 };//���οɼ��ܻ�����
	char jiami_jiemi_buf[max_m] = { 0 };//���ܽ���������ڻ����
}KEY;

extern void key_s_zhuan_b(KEY *b);// ��ת������
extern void key_init(KEY *b);//��ʼ��һ�д�����
extern void key_Generate_encryption_and_decryption_keys(KEY* b);//������Կ

extern void key_Generate_large_prime_Numbers(KEY *b);//��������
//�������ĵļ���
extern void key_set_str_p_10(KEY *b, const char *s);//��������������10���ƣ�
extern void key_set_str_q_10(KEY *b, const char *s);//��������������10���ƣ�
extern void key_compute_n_r_yunfei(KEY *b);//����ŷ����������ģ
extern void key_set_str_e_yunfei(KEY *b, const char *s);//��Կ���� ��������Կ
extern void key_set_unbianma_m_10(KEY *b, const char *s);//���÷Ǳ��������
//extern void key_encryption(KEY* b);//����


extern void key_set_str_e(KEY *b, const char *s);//��Կ����16����


//�������ĵĽ���
extern void key_set_str_n_10(KEY *b, const char *s);//����10 ����ģ
extern void key_set_str_d_10(KEY *b, const char *s);//����10����˽Կ
extern void key_set_str_c_10(KEY *b, char *s);//������ͨ10��������
//extern void key_edecryption(KEY* b);//����



//һ���ѱ�����ܶ�����ʵ�֣�ֻ����16����
//���ܵ�ʵ�֣�16���ƣ� ͨ��������ת���� �ڰ�����ת��Ϊ�����ƾ�������������
//�ѱ������
extern void key_set_str_c(KEY *b,  char *s);//������ͨ����
extern void key_set_str_n(KEY *b, const char *s);//����16 ����ģ
extern void key_set_str_d(KEY *b, const char *s);//����16����˽Կ
//extern void key_edecryption(KEY* b);//����
//extern void key_s_zhuan_b(KEY *b);// ��ת������



//���ڼ����������
//ͨ����ʼ������Կ���������������ģ�16�������룩 
//��ͨ������ָ������������ģ�Ҳ������Ϊ�ļ������255�ֽڲ���ʹ��
//extern void key_init(KEY *b);//��ʼ��
//extern void key_Generate_encryption_and_decryption_keys(KEY* b);//������Կ
extern void key_set_str_m_pt(KEY *b, char *s);//������ͨ�����ģ��ú��������Ѷ����Ʊ�������ֵĹ���
//extern void key_encryption(KEY* b);//���ܾͿ���������������


//��Ҫ�����ļ����ܵĹ����� ��255�ֽڵ� ��������������һ��,����ûд�꣬�����
extern void key_set_str_m(KEY *b, unsigned char *s);//���ö���������




extern void key_encryption(KEY* b);//����
extern void key_edecryption(KEY* b);//����

extern void key_printf_m_10(KEY* b);//��ӡ��ת������ģ�10����)
extern void key_printf_m(KEY* b);//��ӡ��ת������ģ�16���ƣ�
extern void key_printf_m_str(KEY* b);//��ӡת�������� ���ַ���
extern void key_printf_c(KEY* b);	//��ӡ���ģ�16���ƣ�
extern void key_printf_c_10_yunfei(KEY* b);//��ӡ���ģ�10���ƣ�
extern void key_printf_n_10(KEY* b);//��ӡ�˻� n��10���ƣ�
extern void key_printf_n(KEY* b); //��ӡ�˻� n ��16���ƣ�
extern void key_printf_r(KEY* b);//��ӡ��n r (10����)


extern void key_printf_p_q(KEY* b); //��ӡ16���Ƶ���������
extern void key_printf_n_e(KEY* b); //��ӡ�˻� n �� ��Կe (16����)
extern void key_printf_n_d(KEY* b); //��ӡ�˻� n �� ˽Կd (16����)
extern void key_printf_d_10_yunfei(KEY* b);//��ӡ˽Կ��10���ƣ�
extern void key_clear(KEY* b);//��β���� ���ն���Դ
extern void binary_string(char*, unsigned const char*, int);//�Ӷ�����ת��Ϊ���Լ�������� //����
extern void string_binary(char*, unsigned char*, int);//�ӿɼ��������ת��Ϊ������ //����

#endif