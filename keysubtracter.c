/*
Developed by Luis Alberto
email: alberto.bsd@gmail.com
*/


#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <gmp.h>
#include <string.h>
#include <unistd.h>
#include <math.h>
#include <time.h>
#include "util.h"

#include "gmpecc.h"
#include "base58/libbase58.h"
#include "rmd160/rmd160.h"
#include "sha256/sha256.h"


const char *version = "0.1.20210918";
const char *EC_constant_N = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141";
const char *EC_constant_P = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f";
const char *EC_constant_Gx = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
const char *EC_constant_Gy = "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8";


const char *formats[3] = {"publickey","rmd160","address"};
const char *looks[2] = {"compress","uncompress"};

void showhelp();
void set_format(char *param);
void set_look(char *param);
void set_bit(char *param);
void set_publickey(char *param);
void set_range(char *param);
void generate_straddress(struct Point *publickey,bool compress,char *dst);
void generate_strrmd160(struct Point *publickey,bool compress,char *dst);
void generate_strpublickey(struct Point *publickey,bool compress,char *dst);

char *str_output = NULL;

char str_publickey[131];
char str_rmd160[41];
char str_address[41];

struct Point target_publickey,base_publickey,sum_publickey,negated_publickey,dst_publickey;

int FLAG_RANGE = 0;
int FLAG_BIT = 0;
int FLAG_RANDOM = 0;
int FLAG_PUBLIC = 0;
int FLAG_FORMAT = 0;
int FLAG_HIDECOMMENT = 0;
int FLAG_LOOK = 0;
int FLAG_MODE = 0;
int FLAG_N;
uint64_t N = 0,M;

mpz_t min_range,max_range,diff,TWO,base_key,sum_key,dst_key;
gmp_randstate_t state;

// Define the start and end y-coordinate values for the allowed range
mpz_t start_y, end_y;

int main(int argc, char **argv)  {
    FILE *OUTPUT;
    char c;
    uint64_t i = 0;
    mpz_init_set_str(start_y, "1ae168fea63dc339a3c58419466ceaeef7f632653266d0e1236431a950cfe52a", 16);
    mpz_init_set_str(end_y, "cc338921b0a7d9fd64380971763b61e9add888a4375f8e0f05cc262ac64f9c37", 16);
    
    mpz_init_set_str(EC.p, EC_constant_P, 16);
    mpz_init_set_str(EC.n, EC_constant_N, 16);
    mpz_init_set_str(G.x , EC_constant_Gx, 16);
    mpz_init_set_str(G.y , EC_constant_Gy, 16);
    init_doublingG(&G);

    mpz_init(min_range);
    mpz_init(max_range);
    mpz_init(diff);
    mpz_init_set_ui(TWO,2);
    mpz_init(target_publickey.x);
    mpz_init_set_ui(target_publickey.y,0);
    while ((c = getopt(argc, argv, "hvxRb:n:o:p:r:f:l:")) != -1) {
        switch(c) {
            case 'x':
                FLAG_HIDECOMMENT = 1;
            break;
            case 'h':
                showhelp();
                exit(0);
            break;
            case 'b':
                set_bit((char *)optarg);
                FLAG_BIT = 1;
            break;
            case 'n':
                N = strtol((char *)optarg,NULL,10);
                if(N<= 0)    {
                    fprintf(stderr,"[E] invalid bit N number %s\n",optarg);
                    exit(0);
                }
                FLAG_N = 1;
            break;
            case 'o':
                str_output = (char *)optarg;
            break;
            case 'p':
                set_publickey((char *)optarg);
                FLAG_PUBLIC = 1;
            break;
            case 'r':
                set_range((char *)optarg);
                FLAG_RANGE = 1;
            break;
            case 'R':
                FLAG_RANDOM = 1;
            break;
            case 'v':
                printf("version %s\n",version);
                exit(0);
            break;
            case 'l':
                set_look((char *)optarg);
            break;
            case 'f':
                set_format((char *)optarg);
            break;
        }
    }
    if((FLAG_BIT || FLAG_RANGE) && FLAG_PUBLIC && FLAG_N)    {
        if(str_output)    {
            OUTPUT = fopen(str_output,"a");
            if(OUTPUT == NULL)    {
                fprintf(stderr,"can't opent file %s\n",str_output);
                OUTPUT = stdout;
            }
        }
        else    {
            OUTPUT = stdout;
        }
        if(N % 2 == 1)    {
            N++;
        }
        M = N /2;
        mpz_sub(diff,max_range,min_range);
        mpz_init(base_publickey.x);
        mpz_init(base_publickey.y);
        mpz_init(sum_publickey.x);
        mpz_init(sum_publickey.y);
        mpz_init(negated_publickey.x);
        mpz_init(negated_publickey.y);
        mpz_init(dst_publickey.x);
        mpz_init(dst_publickey.y);
        mpz_init(base_key);
        mpz_init(sum_key);
    
        if(FLAG_RANDOM)    {
            gmp_randinit_mt(state);
            gmp_randseed_ui(state, ((int)clock()) + ((int)time(NULL)));
        }
        for(i=0;i<N;i++)    {
            if(FLAG_RANDOM)    {
                if(FLAG_MODE == 0)    {
                    mpz_urandomm(base_publickey.x,state,EC.p);
                }
                else    {
                    mpz_urandomm(base_publickey.y,state,EC.p);
                }
            }
            else    {
                mpz_add(base_publickey.x,min_range,diff);
            }
            if(FLAG_HIDECOMMENT == 0)    {
                printf("%ld\n",i);
            }
            if(!FLAG_PUBLIC)    {
                if(!FLAG_BIT)    {
                    if(FLAG_RANGE)    {
                        if (mpz_cmp(base_publickey.y, start_y) >= 0 && mpz_cmp(base_publickey.y, end_y) <= 0) {
                            switch(FLAG_FORMAT) {
                                case 0:
                                    generate_strpublickey(&base_publickey,FLAG_LOOK,str_publickey);
                                    fprintf(OUTPUT,"%s\n",str_publickey);
                                break;
                                case 1:
                                    generate_strrmd160(&base_publickey,FLAG_LOOK,str_rmd160);
                                    fprintf(OUTPUT,"%s\n",str_rmd160);
                                break;
                                case 2:
                                    generate_straddress(&base_publickey,FLAG_LOOK,str_address);
                                    fprintf(OUTPUT,"%s\n",str_address);
                                break;
                            }
                        }
                    }
                    else    {
                        switch(FLAG_FORMAT) {
                            case 0:
                                generate_strpublickey(&base_publickey,FLAG_LOOK,str_publickey);
                                fprintf(OUTPUT,"%s\n",str_publickey);
                            break;
                            case 1:
                                generate_strrmd160(&base_publickey,FLAG_LOOK,str_rmd160);
                                fprintf(OUTPUT,"%s\n",str_rmd160);
                            break;
                            case 2:
                                generate_straddress(&base_publickey,FLAG_LOOK,str_address);
                                fprintf(OUTPUT,"%s\n",str_address);
                            break;
                        }
                    }
                }
                else    {
                    mpz_mul_ui(sum_publickey.x,base_publickey.x,2);
                    mpz_add_ui(sum_publickey.x,sum_publickey.x,FLAG_BIT-1);
                    mpz_mod(sum_publickey.x,sum_publickey.x,EC.p);
                    if(FLAG_RANGE)    {
                        if (mpz_cmp(sum_publickey.y, start_y) >= 0 && mpz_cmp(sum_publickey.y, end_y) <= 0) {
                            switch(FLAG_FORMAT) {
                                case 0:
                                    generate_strpublickey(&sum_publickey,FLAG_LOOK,str_publickey);
                                    fprintf(OUTPUT,"%s\n",str_publickey);
                                break;
                                case 1:
                                    generate_strrmd160(&sum_publickey,FLAG_LOOK,str_rmd160);
                                    fprintf(OUTPUT,"%s\n",str_rmd160);
                                break;
                                case 2:
                                    generate_straddress(&sum_publickey,FLAG_LOOK,str_address);
                                    fprintf(OUTPUT,"%s\n",str_address);
                                break;
                            }
                        }
                    }
                    else    {
                        switch(FLAG_FORMAT) {
                            case 0:
                                generate_strpublickey(&sum_publickey,FLAG_LOOK,str_publickey);
                                fprintf(OUTPUT,"%s\n",str_publickey);
                            break;
                            case 1:
                                generate_strrmd160(&sum_publickey,FLAG_LOOK,str_rmd160);
                                fprintf(OUTPUT,"%s\n",str_rmd160);
                            break;
                            case 2:
                                generate_straddress(&sum_publickey,FLAG_LOOK,str_address);
                                fprintf(OUTPUT,"%s\n",str_address);
                            break;
                        }
                    }
                }
            }
        }
        mpz_clear(min_range);
        mpz_clear(max_range);
        mpz_clear(diff);
        mpz_clear(TWO);
        mpz_clear(target_publickey.x);
        mpz_clear(target_publickey.y);
        mpz_clear(base_publickey.x);
        mpz_clear(base_publickey.y);
        mpz_clear(sum_publickey.x);
        mpz_clear(sum_publickey.y);
        mpz_clear(negated_publickey.x);
        mpz_clear(negated_publickey.y);
        mpz_clear(dst_publickey.x);
        mpz_clear(dst_publickey.y);
        mpz_clear(base_key);
        mpz_clear(sum_key);
        if(str_output)    {
            fclose(OUTPUT);
        }
    }
    else    {
        showhelp();
    }
    mpz_clear(EC.p);
    mpz_clear(EC.n);
    mpz_clear(G.x);
    mpz_clear(G.y);
    return 0;
}

void showhelp()    {
    printf("Usage: ecc -b <bits> -p <publickey> -o <output file> -f <output format> -l <compressed or uncompressed> -r <min y range:max y range>\n");
    printf("        -b : number of bits\n");
    printf("        -p : set public key\n");
    printf("        -o : set output file, default is stdout\n");
    printf("        -f : set output format, 0=publickey, 1=rmd160, 2=address\n");
    printf("        -l : set compressed or uncompressed public key\n");
    printf("        -r : set minimum and maximum range for Y coordinate\n");
    printf("        -x : hide comment, useful for benchmarking\n");
    printf("        -h : this help\n");
    printf("        -v : version\n");
}

void set_format(char *param)    {
    int i;
    for(i=0;i<3;i++)    {
        if(strcmp(formats[i],param) == 0)    {
            FLAG_FORMAT = i;
            break;
        }
    }
}

void set_look(char *param)    {
    int i;
    for(i=0;i<2;i++)    {
        if(strcmp(looks[i],param) == 0)    {
            FLAG_LOOK = i;
            break;
        }
    }
}

void set_bit(char *param)    {
    int i;
    i = strtol(param,NULL,10);
    if(i>= 160 && i <= 512)    {
        FLAG_BIT = i;
    }
    else    {
        fprintf(stderr,"invalid bit %s\n",param);
        exit(0);
    }
}

void set_publickey(char *param)    {
    mpz_set_str(target_publickey.x,param,16);
}

void set_range(char *param)    {
    char *token;
    token = strtok(param,":");
    mpz_set_str(min_range,token,16);
    token = strtok(NULL,":");
    mpz_set_str(max_range,token,16);
}

void generate_straddress(struct Point *publickey,bool compress,char *dst)    {
    unsigned char buf[65];
    int len;
    len = sizeof(buf);
    point2buf(publickey,buf,compress);
    len = b58enc(dst,&len,buf);
}

void generate_strrmd160(struct Point *publickey,bool compress,char *dst)    {
    unsigned char sha_result[32],rmd_result[20];
    int len = 32;
    char buf[65];
    int i;
    point2buf(publickey,buf,compress);
    SHA256((unsigned char *)buf,strlen(buf),sha_result);
    RMD160((unsigned char *)sha_result,len,rmd_result);
    len = sizeof(buf);
    b58enc(dst,&len,rmd_result);
}

void generate_strpublickey(struct Point *publickey,bool compress,char *dst)    {
    unsigned char buf[65];
    int len;
    len = sizeof(buf);
    point2buf(publickey,buf,compress);
    len = sizeof(buf);
    b58enc(dst,&len,buf);
}
