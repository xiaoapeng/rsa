#include "pch.h"
#include "rsa.h"

static void key_set_m(KEY* b, const char *s, int jingzhi);//设置计算明文<=255字节
static void key_set_c(KEY* b, const char *s, int jingzhi);//设置计算密文<=255字节
static void Generate_large_prime_Numbers(mpz_t *p, mpz_t *q);//素数生成


static void mod_inv(mpz_t d, mpz_t e, mpz_t r);//算出秘钥 
static void extgcd(mpz_t, mpz_t, mpz_t, mpz_t, mpz_t);//递归求逆元 扩展欧几里得算法
static void mod_exp(mpz_t result, mpz_t exponent, mpz_t base, mpz_t n); //加解密子函数

void key_s_zhuan_b(KEY * b)
{
	char*s = mpz_get_str(NULL, 16, b->m);
	string_binary(s,(unsigned char*) b->buf,(strlen(s)-1)/2);
	//free(s);
}

void key_init(KEY *b)//初始化 
{
	mpz_init(b->key_p);	
	mpz_init(b->key_q);
	mpz_init(b->key_n);
	mpz_init(b->key_r);
	mpz_init(b->key_d);
	mpz_init(b->m);
	mpz_init(b->c);
	mpz_init(b->key_e);
}

void key_Generate_encryption_and_decryption_keys(KEY *b)
{
	mpz_set_str(b->key_e,"65537",10);//公钥 考虑到运算速度 和相对安全性
	Generate_large_prime_Numbers(&b->key_p, &b->key_q);
	mpz_mul(b->key_n, b->key_p, b->key_q); //求模

	mpz_sub_ui(b->key_p, b->key_p, 1);//欧拉函数计算
	mpz_sub_ui(b->key_q, b->key_q, 1);
	mpz_mul(b->key_r, b->key_p, b->key_q);
	mpz_add_ui(b->key_p, b->key_p, 1);
	mpz_add_ui(b->key_q, b->key_q, 1);
	mod_inv(b->key_d, b->key_e, b->key_r);//生成私钥
}
void key_Generate_large_prime_Numbers(KEY * b)
{
	Generate_large_prime_Numbers(&b->key_p, &b->key_q);
}
void key_compute_n_r_yunfei(KEY * b)
{
	

	mpz_mul(b->key_n, b->key_p, b->key_q); //求模

	mpz_sub_ui(b->key_p, b->key_p, 1); //b->key_p--
	mpz_sub_ui(b->key_q, b->key_q, 1);//b->key_q--

	mpz_mul(b->key_r, b->key_p, b->key_q);//欧拉函数计算
	mpz_add_ui(b->key_p, b->key_p, 1);
	mpz_add_ui(b->key_q, b->key_q, 1);
}

void key_set_str_p_10(KEY * b, const char * s)
{


	mpz_set_str(b->key_p,(const char *)s  , 10);
	//gmp_printf("p=%Zd\n", b->key_p);
	//gmp_printf("q=%d\n", b->key_q);
}

void key_set_str_q_10(KEY * b, const char * s)
{
	mpz_set_str(b->key_q, (const char *)s, 10);
}

void key_set_str_m(KEY *b,unsigned char *s)//设置计算明文
{
	binary_string(b->buf, (const unsigned char *)s, max_m);
	key_set_m(b, b->buf,16);
}

void key_set_str_c(KEY * b,   char * s)//设置计算密文
{
	key_set_c(b, s,16);
}

void key_set_str_e_yunfei(KEY * b, const char * s)
{
	mpz_set_str(b->key_e, s, 10);
	mod_inv(b->key_d, b->key_e, b->key_r);//生成私钥
}

void key_set_unbianma_m_10(KEY * b, const char * s)
{
	mpz_set_str(b->m, s, 10);
}

void key_set_str_e(KEY * b, const char * s)
{
	mpz_set_str(b->key_e, s, 16);
	mod_inv(b->key_d, b->key_e, b->key_r);//生成私钥
}

void key_set_str_n_10(KEY * b, const char * s)
{
	mpz_set_str(b->key_n, s, 10);
}

void key_set_str_d_10(KEY * b, const char * s)
{
	mpz_set_str(b->key_d, s, 10);
}

void key_set_str_c_10(KEY * b, char * s)
{
	mpz_set_str(b->c, s, 10);
}

void key_set_str_m_pt(KEY * b, char * s)
{
	
	binary_string(b->buf, (const unsigned char *)s, strlen(s));
	key_set_m(b, b->buf, 16);
}



void key_set_m(KEY *b,const char *s,int jingzhi)
{
	mpz_set_str(b->m, s, jingzhi);
}

void key_set_c(KEY *b, const char *s, int jingzhi)
{
	mpz_set_str(b->c, s, jingzhi);
}

void key_encryption(KEY *b)//加密
{     
	mod_exp(b->c, b->key_e, b->m, b->key_n);//加解密子函数
	//输入 公钥 b->key_e
	//输入 乘积 b->key_n
	//输入 明文 b->m
	//输出 密文 b->c
}

void key_edecryption(KEY *b)//解密
{
	mod_exp(b->m, b->key_d, b->c, b->key_n);
	//输入 私钥 b->key_d
	//输入 乘积 b->key_n
	//输入 密文 b->c
	//输出 明文 b->m
}

void key_printf_m_10(KEY * b)
{
	gmp_printf("明文:%Zd\n\n", b->m);
}

void key_printf_m(KEY *b)
{
	gmp_printf("明文:%ZX\n\n",b->m);
}

void key_printf_m_str(KEY * b)
{
	printf("明文：%s\n", b->buf);
}

void key_printf_c(KEY *b)
{
	gmp_printf("密文:%ZX\n\n",b->c);
}

void key_printf_c_10_yunfei(KEY * b)
{
	gmp_printf("密文:%Zd\n", b->c);
}

void key_printf_n_10(KEY * b)
{
	gmp_printf("n=p*q=%Zd \n\n", b->key_n);
}

void key_printf_n(KEY * b)
{
	gmp_printf("n=p*q=%ZX \n\n", b->key_n);
}

void key_printf_r(KEY * b)
{
	gmp_printf("r=%Zd\n\n", b->key_r);
}

void key_set_str_n(KEY * b, const char *s)
{
	mpz_set_str(b->key_n,s,16);
}

void key_set_str_d(KEY * b, const char * s)
{
	mpz_set_str(b->key_d, s, 16);
}

void key_printf_p_q(KEY *b)
{
	gmp_printf("素数1:%ZX\n\n", b->key_p);   //以十六进制的形式输出生成的素数
	gmp_printf("素数2:%ZX\n\n", b->key_q);
}

void key_printf_n_e(KEY *b)
{
	gmp_printf("乘积n:%ZX:\n\n", b->key_n);
	gmp_printf("公钥:%ZX\n\n", b->key_e);
}

void key_printf_n_d(KEY *b)
{
	gmp_printf("乘积n:%ZX\n\n", b->key_n);
	gmp_printf("私钥:%ZX\n\n", b->key_d);
}
void key_printf_d_10_yunfei(KEY * b)
{
	gmp_printf("私钥:%Zd\n\n", b->key_d);
}
void key_clear(KEY *b)
{
	mpz_clear(b->c);
	mpz_clear(b->m);
	mpz_clear(b->key_d);
	mpz_clear(b->key_r);
	mpz_clear(b->key_e);
	mpz_clear(b->key_n);
	mpz_clear(b->key_p);
	mpz_clear(b->key_q);
}
void Generate_large_prime_Numbers(mpz_t *p, mpz_t *q)
{
	gmp_randstate_t grt;
	gmp_randinit_default(grt); //设置随机数生成算法为默认
	gmp_randseed_ui(grt, time(NULL));	//设置随机化种子为当前时间，这几条语句的作用相当于标准C中的srand(time(NULL));

	mpz_t key_p, key_q; //素数存放位置
	mpz_init(key_p);	//初始化 素数
	mpz_init(key_q);	//一个mpz_t类型的变量必须在初始化后才能被使用

	mpz_urandomb(key_p, grt, 1024);
	mpz_urandomb(key_q, grt, 1024);	//生成随机数

	if (mpz_even_p(key_p))
		mpz_add_ui(key_p, key_p, 1);//k
	if (mpz_even_p(key_q))
		mpz_add_ui(key_q, key_q, 1);	//如果生成的随机数为偶数，则加一



	//判断 n 是否为素数,若 n 确定是素数则返回 2,如果 n 是概率素数 (不能完全
//确定) 那么返回 1,或者如果 n 确定是合数那么返回 0。reps 控制这
//样的判别做多少次,5 到 10 是较合理的数值,更多次的判别可以减小合数被返
//回为概率素数的可能
	while (!mpz_probab_prime_p(key_p, 25) > 0)  //逐个检查比p大的奇数是否为素数
		mpz_add_ui(key_p, key_p, 2);
	while (!mpz_probab_prime_p(key_q, 25) > 0)
		mpz_add_ui(key_q, key_q, 2);
	mpz_set(*p, key_p);
	mpz_set(*q, key_q);
	mpz_clear(key_p);
	mpz_clear(key_q);
}
//扩展欧几里得算法
void mod_inv(mpz_t  d, mpz_t  e, mpz_t  r)//输入：e公钥      r Φ(n)
										 //输出： d私钥
{
	mpz_t d_, x, y;
	mpz_t _e, _r;
	mpz_init_set(_e, e);//_e=e
	mpz_init_set(_r, r);//_r=r

	mpz_init(d_);//初始化
	mpz_init(x);//初始化
	mpz_init(y);//初始化
	extgcd(_e, _r, d_, x, y);//调用递归
	

	//求e在r下的逆元
	//不存在 就返回-1
	//return 
	if (!mpz_cmp_ui(d_, 1)) //   if(d_==1)
							//   {
	{						//       d=x+r
		mpz_add(d, x, r);	//       d=d/r
		mpz_tdiv_r(d, d, r);//   }
	}						//   else
	else                    //   {
	{                       //		d=-1
		mpz_set_ui(d, -1);  //   }
	}
	
	mpz_clear(d_);
	mpz_clear(x);
	mpz_clear(y);
	mpz_clear(_e);
	mpz_clear(_r);
}

void extgcd(mpz_t e, mpz_t r, mpz_t d_, mpz_t x, mpz_t y)
{
	mpz_t _e, _r,k;
	mpz_init_set(_e, e);//_e=e
	mpz_init_set(_r, r);//_r=r
	mpz_init(k);//初始化
	if (!mpz_cmp_ui(r, 0))//if(r==0)
	{
		mpz_set(d_, e);//d=_e
		mpz_set_ui(x, 1);//x=1
		mpz_set_ui(y, 0);//y=0

	}
	else
	{
		mpz_tdiv_r(k, _e, _r);//k=_e%_r 向下取余
		extgcd(_r, k , d_, y, x);//递归

		//y-=x*(_e%_r);
		//下面的语句相当于上面的伪代码
//******************************
		mpz_tdiv_q(k, _e, _r); //k=_e%_r
		mpz_mul(k, x, k);//k=x*k
		mpz_sub(y, y, k);//y=y-k
//******************************
	}
	mpz_clear(_e);
	mpz_clear(_r);
	mpz_clear(k);
}
//                 密文                 密钥                  明文            模
void mod_exp(mpz_t result,  mpz_t exponent,  mpz_t base,  mpz_t n)
{
	char exp[2048 + 10];
	mpz_get_str(exp, 2, exponent); //把密钥e转化为二进制并储存到字符数组exp中

	mpz_t x, power;//定义两个大整数
	mpz_init(power);//初始化
	mpz_init_set_ui(x, 1);  // x = 1
	if (mpz_cmp_ui(n, 0)== 0)
	{
		printf("除数为零\n");
		printf("请忽略计算结果\n");
	}
	else
		mpz_mod(power, base, n); //power = base mod n    power=base%n //取模运算

	for (int i = strlen(exp) - 1; i >= 0; i--)
	{
		if (exp[i] == '1')
		{
			mpz_mul(x, x, power); //x=x*power
			mpz_mod(x, x, n);   //x = x * power mod n
		}
		mpz_mul(power, power, power);//power=power* power
		mpz_mod(power, power, n);  //power = power^2 mod n
	}
	mpz_set(result, x); //返回结果 result=x
}
void binary_string(char *buf, unsigned const char *s,int n)
{
	*(buf++) = '1';
	for (int i = 0; i < n; i++)
	{
		sprintf(buf+2*i, "%02x", *(s+i));//打印到buf缓冲区
	}
	buf[2*n] = 0;
	//printf("%s\n", buf);
}
void string_binary( char *s, unsigned char *m_buf, int n)
{
	s++;
	for (int i = 0; i < n; i++)
	{
		sscanf(s+2*i, "%2x", m_buf+i);
	}
}