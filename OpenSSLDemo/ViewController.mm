//
//  ViewController.m
//  OpenSSLDemo
//
//  Created by hsec on 2023/11/20.
//  

/*
 Test Key:
 
 -----BEGIN PUBLIC KEY-----
 MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1P9XJwjSPZDtGFcGpmAb
 TDzxVJxwf5i44f3qa3vb74HZkfc8BlOREzqaQVEFq50zOhYE8kSZrrXkzH0ASPwm
 Pv3KJ2ergyPGG5g5EzSueAoKnl1/airaSfBNG4SBObvF1IT9W4TDuvsyX5V92ZnR
 b4J2XIaML77VQXC0/oRosbYl+VhBg6qgwGp1E/hEO6u8IEhVCBnocGTaapfrn94H
 CxhqhZYPOxbgRHbpf92RBrxOQ1mEFELsWrsYiQuSiPxUIhJXge1PIwwfBlmKqpWL
 pTH540Qj9OwhvJ9VG4bzAw+/XQUTzlUcbAbNjkeCU9q3KEB7hk8KiBTzN1XoTC1E
 VQIDAQAB
 -----END PUBLIC KEY-----

 -----BEGIN PRIVATE KEY-----
 MIIEwAIBADANBgkqhkiG9w0BAQEFAASCBKowggSmAgEAAoIBAQDU/1cnCNI9kO0Y
 VwamYBtMPPFUnHB/mLjh/epre9vvgdmR9zwGU5ETOppBUQWrnTM6FgTyRJmuteTM
 fQBI/CY+/conZ6uDI8YbmDkTNK54CgqeXX9qKtpJ8E0bhIE5u8XUhP1bhMO6+zJf
 lX3ZmdFvgnZchowvvtVBcLT+hGixtiX5WEGDqqDAanUT+EQ7q7wgSFUIGehwZNpq
 l+uf3gcLGGqFlg87FuBEdul/3ZEGvE5DWYQUQuxauxiJC5KI/FQiEleB7U8jDB8G
 WYqqlYulMfnjRCP07CG8n1UbhvMDD79dBRPOVRxsBs2OR4JT2rcoQHuGTwqIFPM3
 VehMLURVAgMBAAECggEBAL6pxzEY82HLHoGgPUKnWyg2kWzFEOsXIcCik7odSHYw
 DTtdTez31zCYT8bSKTpC4L1JQqo/gDZlemcWKjArDm1qrw/w/BXK6yZ+b/DiQp8P
 lgvG9CxsKbTwF4XfafHtRRyE42qOAMua2q+3WM11pIWmCh+vDUQcFjebFVmT20ff
 e+dLRY3zqMupRzS6Sr1adueSBHp21QT5grVjx3EMQrgvVA0NKGdEI5BEMLKHyzeI
 pRQeB3v53kT1iK2WI4giiaZBtX5UGvtnhvzoV72Yy0F/w6nU7mn05CIiuP0bxlmb
 gbcPAYvU8470sF37ujK7QD1D5lxybT653jsAuHl0ZaECgYEA8qGWlDGIXBnL6yS5
 H09Gcww+mRltLteEa8ohrIZSYLxVeeLwOOij/umh91pvoZ5dL18+N0RBep0Kow7h
 Hso3O96uU5LDNEN4rJDUBx9HB84uiGux37/iklhhlv9uZdiCe19qLNcVeEz7GB94
 7KcrxKyZ6m7g04F3Z8vPzeOtBZkCgYEA4LvBdsBD+Himr8A5l2vbF8ALcco5DXyo
 hmfGR1FH32sqPOYtE63WLI3A7NP4Dtsbx+MuWX95q1AUysQxhngJk4KD6UNE25r2
 W9b9MiSRf9ZI3Hj8qrv1iNC1GqBm22t8NepAxlssE5/eApBQ3SsbuQgnhrekfiQx
 RonjGOAx8h0CgYEAiBi9lwilvUu3B4IE2Rwlnzj6D/SkOscm/zNVaim6IYriw0jZ
 iIJuIvm4IUA4J8bl7EGXa3a85+MY6VfaTOQO0WVaEYTcO/+wu9NNK2WO+UDc9ya5
 kpFWrNIog4Np0HT+0+c0bkyDPYSov+I/eTdYJKzQdSCWue0AJle7i3ivP9kCgYEA
 1Eyqg5s32sdneAoYndIXBEW4ygMmiHYl4eqw5fiD9CyRlzw+gyOqeyZihZfs82PL
 x7X2uDdzYgHh0ncq7gQBz+bw5HBW4Tpv1uyu/iqLhP+SjyyATG4JkvjOzVuQL2JH
 0cr87CV+6v8QRM2+hmDN7KsmY96iN0PLhP6HmZ1ZsYUCgYEAqZz8bBwaRtcPAu3a
 HmBWGa1RRLeDsS0a3yifHh9Ne+OdNedOtFOE7OI9dKltxdP/pvSaQMMGJtlw9zId
 vUvaV1YjTY0ZcDECwksYWpzNzLzf69R9iCiAQ5Td1OBRMXd8rxxm4B6W8aP/2HKk
 UkNMjn4wC3UrDZaezhLl8dOKUeY=
 -----END PRIVATE KEY-----

 SHA256(Left1.cfg)= b0e7bc39382fcffff89b73f0d277d8c3cc894fcdf03314e6bcd6b801b59946cc

 openssl-3.1.4
 
 MARK: tips：
 
 要比较两个RSA公钥或私钥对象是否相同，您可以比较它们的指数（exponent）和模数（modulus）
 
 EVP 在 OpenSSL 中代表高级密码接口库（EnVeloPe）
 
 RSA_sign 是专门用于 RSA 签名的函数，而 EVP_Sign 是通用的签名函数，可以适用于不同的签名算法。
 使用 RSA_sign 需要传入 RSA 私钥，而使用 EVP_Sign 需要传入 EVP_PKEY 对象，其中包含了私钥信息。
 在使用 EVP_Sign 时，可以根据 EVP_PKEY 对象中的私钥信息选择合适的签名算法，而不需要显式指定使用 RSA 签名。
 
 */

#import "ViewController.h"

#import <CommonCrypto/CommonCrypto.h>
#include <iostream>

//不打印可删
#include <iomanip>
#include <sstream>

#include "openssl/rsa.h"
#include "openssl/sha.h"
#include "openssl/pem.h"
//#include "openssl/ec.h"
//#include "openssl/evp.h"
//#include "openssl/bn.h"
//#include "openssl/conf.h"
//#include "openssl/err.h"

@interface ViewController ()

// hex打开 pem 显示 0A，所以手动添加 \n
#define PUBKEY @"-----BEGIN PUBLIC KEY-----\n" \
"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1P9XJwjSPZDtGFcGpmAb\n" \
"TDzxVJxwf5i44f3qa3vb74HZkfc8BlOREzqaQVEFq50zOhYE8kSZrrXkzH0ASPwm\n" \
"Pv3KJ2ergyPGG5g5EzSueAoKnl1/airaSfBNG4SBObvF1IT9W4TDuvsyX5V92ZnR\n" \
"b4J2XIaML77VQXC0/oRosbYl+VhBg6qgwGp1E/hEO6u8IEhVCBnocGTaapfrn94H\n" \
"CxhqhZYPOxbgRHbpf92RBrxOQ1mEFELsWrsYiQuSiPxUIhJXge1PIwwfBlmKqpWL\n" \
"pTH540Qj9OwhvJ9VG4bzAw+/XQUTzlUcbAbNjkeCU9q3KEB7hk8KiBTzN1XoTC1E\n" \
"VQIDAQAB\n" \
"-----END PUBLIC KEY-----\n"

#define PRIKEY @""

@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    // Do any additional setup after loading the view.
    NSString *pubKeyPath = [[NSBundle mainBundle]pathForResource:@"publicKey" ofType:@"pem"];
    
    NSString *priKeyPath = [[NSBundle mainBundle]pathForResource:@"privareKey" ofType:@"pem"];

    NSString *sigPath = [[NSBundle mainBundle]pathForResource:@"1" ofType:@"sig"];
    
    NSString *filePath = [[NSBundle mainBundle]pathForResource:@"Left1" ofType:@"cfg"];
    NSData *fileData = [NSData dataWithContentsOfFile:filePath];
    
    NSString *writeSigPath = [NSHomeDirectory() stringByAppendingFormat:@"/Library/Sig/signature.sig"];
    [self creatFile:writeSigPath];
    
    
    const char* file_path = [filePath UTF8String];
    const char* private_key_path = [priKeyPath UTF8String];
    const char* public_key_path = [pubKeyPath UTF8String];
    const char* signature_path = [sigPath UTF8String];
    const char* write_signature_path = [writeSigPath UTF8String];
    
    //读取写死字符串方式
    RSA* rsaPubKey_fromStr = get_publick_RSAKey_from_string(PUBKEY);
    RSA* rsaPriKey_fromStr = get_private_rsaKey_from_string(PRIKEY);
    //直接读取文件方式
    RSA* rsaPubKey_fromPath = get_publick_RSAKey_from_path(public_key_path);
    RSA* rsaPriKey_fromPath = get_private_RSAKey_from_path(private_key_path);

    //生成签名文件
    sign_file(file_path, rsaPriKey_fromPath, write_signature_path) ?: printf("*** sign_file 失败\n");
    //验签
    verify_signature(file_path, rsaPubKey_fromPath, signature_path) ?: printf("*** verify_signature 失败\n");
    
    //先计算HASH 再用hash签名，的方式实现
    [self signFile:fileData privateKey:rsaPriKey_fromPath];
    
    //计算hash 打印Hex
    compute_SHA256_with_filePath(file_path);
}

// MARK: 通用方法签名✍️
int sign_file(const char* file_path, RSA* rsa_key, const char* signature_path) {
    //b 二进制
    FILE* file = fopen(file_path, "rb");
    if (!file) {
        printf("Failed to open file\n");
        return 0;
    }
    if (!rsa_key) {
        printf("Failed to read private key\n");
        fclose(file);
        return 0;
    }


    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
    EVP_MD_CTX_init(md_ctx);
    EVP_SignInit(md_ctx, EVP_sha256());

    int len;
    unsigned char buffer[1024];
    //从文件中读取数据并更新验证上下文。EVP_SignUpdate 进行签名【代码由 ChatGPT 生成】
    while ((len = fread(buffer, 1, sizeof(buffer), file)) > 0) {
        EVP_SignUpdate(md_ctx, buffer, len);
    }
    
    EVP_PKEY* pkey1 = EVP_PKEY_new();
    EVP_PKEY_assign_RSA(pkey1, rsa_key);
    
    unsigned int signature_len;
    unsigned char signature[1024];
    EVP_SignFinal(md_ctx, signature, &signature_len, pkey1);
    EVP_MD_CTX_free(md_ctx);

    fclose(file);
    
    FILE* signature_file = fopen(signature_path, "wb");
    if (signature_file) {
        fwrite(signature, 1, signature_len, signature_file);
        fclose(signature_file);
        printf("File signed 👌\n");
        return 1;
    } else {
        printf("write signature file 🙅\n");
        return 0;
    }
}

// MARK: 通用方法👀验签
int verify_signature(const char* file_path, RSA* rsa_key, const char* signature_path) {
    FILE* file = fopen(file_path, "rb");
    if (!file) {
        printf("Failed to open file\n");
        return 0;
    }
    if (!rsa_key) {
        printf("Failed to read public key\n");
        fclose(file);
        return 0;
    }

    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
    EVP_MD_CTX_init(md_ctx);
    EVP_VerifyInit(md_ctx, EVP_sha256());
    
    int len;
    unsigned char buffer[1024];
    while ((len = fread(buffer, 1, sizeof(buffer), file)) > 0) {
        EVP_VerifyUpdate(md_ctx, buffer, len);
    }

    fclose(file);

    unsigned int signature_len;
    unsigned char signature[1024];
    FILE* signature_file = fopen(signature_path, "rb");
    if (signature_file) {
        signature_len = fread(signature, 1, sizeof(signature), signature_file);
        fclose(signature_file);
    } else {
        printf("Failed to read signature file\n");
        EVP_MD_CTX_free(md_ctx);
        return 0;
    }

    EVP_PKEY* pkey1 = EVP_PKEY_new();
    EVP_PKEY_assign_RSA(pkey1, rsa_key);
    
    int result = EVP_VerifyFinal(md_ctx, signature, signature_len, pkey1);
    EVP_MD_CTX_free(md_ctx);
    
    if (result == 1) {
        printf("Signature is valid 🍺🍺🍺\n");
        return 1;
    } else {
        printf("Signature is invalid\n");
        return 0;
    }
}


// MARK: EVP_Digest计算sha256 + RSA_sign 签名. 可使用 RSA_verify 验签
- (NSData *)signFile:(NSData *)fileData privateKey:(RSA *)privateRSAKey{
    unsigned char fikeHash[SHA256_DIGEST_LENGTH];
    unsigned int dgst_len = 0;
    
    EVP_MD_CTX *pMdCtx = EVP_MD_CTX_new();
    EVP_DigestInit(pMdCtx,EVP_sha256());
    EVP_DigestUpdate(pMdCtx, (const char *) fileData.bytes, (int)fileData.length);
    EVP_DigestFinal(pMdCtx, fikeHash, &dgst_len);
    EVP_MD_CTX_free(pMdCtx);
    
    unsigned int sig_len = 0;
    unsigned char sign_string[1024] = {0};
    int res = RSA_sign(NID_sha256, fikeHash, dgst_len, sign_string, &sig_len, privateRSAKey);

    NSLog(@"RSA_sign 方法 result is:%d",res);

    if (res == 1) {
        return [[NSData alloc] initWithBytes:sign_string length:sig_len];
    }
    
    return nil;
}
//MARK: - 获取公私钥方法
/*
 PEM_read_bio_RSA_PUBKEY -----BEGIN PUBLIC KEY-----开头 SubjectPublicKeyInfo 编码。\
 PEM_read_bio_RSAPublicKey -----BEGIN RSA PUBLIC KEY-----开头 RSAPublicKey 编码。
 
 PEM_read_bio_RSAPrivateKey -----BEGIN RSA PRIVATE KEY-----
 PEM_read_bio_PrivateKey -----BEGIN PRIVATE KEY-----
 */
RSA* get_publick_RSAKey_from_path(const char* publick_key_path){
    RSA* rsa_key = NULL;
    FILE* public_key_file = fopen(publick_key_path, "rb");
    if (public_key_file) {
        rsa_key = PEM_read_RSA_PUBKEY(public_key_file, NULL, NULL, NULL);
        fclose(public_key_file);
    }
    return rsa_key;
}
RSA* get_private_RSAKey_from_path(const char* public_key_path){
    RSA* rsa_key = NULL;
    FILE* private_key_file = fopen(public_key_path, "rb");
    if (private_key_file) {
        rsa_key = PEM_read_RSAPrivateKey(private_key_file, NULL, NULL, NULL);
        fclose(private_key_file);
    }
    return rsa_key;
}
RSA* get_publick_RSAKey_from_string(NSString* public_key_string){
    BIO *bio = BIO_new_mem_buf((void *)[public_key_string UTF8String], -1);
    RSA *rsa_key = PEM_read_bio_RSA_PUBKEY(bio, NULL, NULL, NULL);
    BIO_free(bio);
    return rsa_key;
}
RSA* get_private_rsaKey_from_string(NSString* private_key_string){
    BIO *bio = BIO_new_mem_buf((void *)[private_key_string UTF8String], -1);
    RSA *rsa_key = PEM_read_bio_RSAPrivateKey(bio, NULL, NULL, NULL);
    BIO_free(bio);
    return rsa_key;
}

//MARK: - 其他方法
// 旧的计算文件的哈希值的方法
unsigned char* compute_SHA256_with_filePath(const char* file_path){
    FILE* file = fopen(file_path, "rb");
    if (!file) {
        printf("Failed to open file\n");
        return nil;
    }
    
    unsigned char hash[SHA256_DIGEST_LENGTH];
    unsigned char buffer[1024];
    long len;
    
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    while ((len = fread(buffer, 1, sizeof(buffer), file)) != 0) {
        SHA256_Update(&sha256, buffer, len);
    }
    SHA256_Final(hash, &sha256);
    
    //  打印
    std::string hexString = hashToHexString(hash, SHA256_DIGEST_LENGTH);
    std::cout << hexString << std::endl;
    
    return hash;
}
//打印hash
std::string hashToHexString(const unsigned char* hash, size_t length) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (size_t i = 0; i < length; ++i) {
        ss << std::setw(2) << static_cast<unsigned>(hash[i]);
    }
    return ss.str();
}
//log rsa 会影响验签，待改进
void printRSA(RSA *rsa) {
    BIO *bio = BIO_new(BIO_s_mem());
    if (bio == NULL) {
        NSLog(@"Failed to create BIO");
        return;
    }
    
    EVP_PKEY* pkey = EVP_PKEY_new();
    EVP_PKEY_assign_RSA(pkey, rsa);
    //第一行不同需要使用不同的方法，这里都写上 方便 CP
    if (PEM_write_bio_PrivateKey(bio, pkey, NULL, NULL, 0, NULL, NULL) != 1 &&
        PEM_write_bio_RSA_PUBKEY(bio, rsa) != 1 &&
        PEM_write_bio_RSAPublicKey(bio, rsa) != 1) {
        NSLog(@"Failed to write RSA to BIO");
        BIO_free(bio);
        return;
    }
    
    char *buffer;
    long length = BIO_get_mem_data(bio, &buffer);
    if (length > 0) {
        NSString *rsaString = [[NSString alloc] initWithBytes:buffer length:length encoding:NSUTF8StringEncoding];
        NSLog(@"%@", rsaString);
    }
    
    EVP_PKEY_free(pkey);
    BIO_free(bio);
}

//hi OC
- (BOOL)creatFile:(NSString*)filePath{
    if (filePath.length==0) {
        return NO;
    }
    NSFileManager *fileManager = [NSFileManager defaultManager];
    if ([fileManager fileExistsAtPath:filePath]) {
        return YES;
    }
    NSError *error;
    NSString *dirPath = [filePath stringByDeletingLastPathComponent];
    BOOL isSuccess = [fileManager createDirectoryAtPath:dirPath withIntermediateDirectories:YES attributes:nil error:&error];
    if (error) {
        NSLog(@"creat File Failed:%@",[error localizedDescription]);
    }
    if (!isSuccess) {
        return isSuccess;
    }
    isSuccess = [fileManager createFileAtPath:filePath contents:nil attributes:nil];
    return isSuccess;
}

@end
