//
//  RCTSodium.m
//  RCTSodium
//
//  Created by Lyubomir Ivanov on 9/25/16.
//  Copyright © 2016 Lyubomir Ivanov. All rights reserved.
//
#define KEY_LEN 32
#import "RCTBridgeModule.h"
#import "RCTUtils.h"
#import "sodium.h"
#import "MF_Base64Additions.h"
#import "RCTSodium.h"

@implementation RCTSodium

static bool isInitialized;

NSString * const ESODIUM = @"ESODIUM";
NSString * const ERR_BAD_KEY = @"BAD_KEY";
NSString * const ERR_BAD_MAC = @"BAD_MAC";
NSString * const ERR_BAD_MSG = @"BAD_MSG";
NSString * const ERR_BAD_NONCE = @"BAD_NONCE";
NSString * const ERR_BAD_SEED = @"BAD_SEED";
NSString * const ERR_BAD_SIG = @"BAD_SIG";
NSString * const ERR_FAILURE = @"FAILURE";

RCT_EXPORT_MODULE();

+ (void) initialize
{
    [super initialize];
    isInitialized = sodium_init() != -1;
}

+ (BOOL)requiresMainQueueSetup
{
    return NO;
}

- (NSData*) randombytes_buf:(size_t)len {
    unsigned char buf[len];
    randombytes_buf(buf, len);
    NSData *random = [NSData dataWithBytes:buf length:len];
    return random;
}

- (NSString*) bin2b64:(NSData*) data {
    return [data base64UrlEncodedString];
}

- (NSData*) b642bin:(NSString*)b64{
    return [NSData dataWithBase64UrlEncodedString:b64];
}

-  (NSMutableDictionary *) crypto_pwhash:(nonnull NSString*)password salt:(NSString*)salt
{
    const char *dpassword = [password cStringUsingEncoding:NSUTF8StringEncoding];
    unsigned long dsalt_len = crypto_pwhash_saltbytes();
    NSData* dsalt;
    if (salt != NULL)
        dsalt = [self b642bin:salt];
    else {
        dsalt = [self randombytes_buf:dsalt_len];
    }
    
    unsigned long long key_len = 32;
    unsigned char *key = (unsigned char *) sodium_malloc(key_len);
    
    unsigned long long ops = 3;
    unsigned long long memlimit = 1024 * 1024 * 8;
    
    if (crypto_pwhash(key, key_len,
                      dpassword,
                      [password length],
                      [dsalt bytes],
                      ops,
                      memlimit, crypto_pwhash_alg_argon2i13()) != 0)
        return NULL;
    else {
        NSMutableDictionary* dict = [NSMutableDictionary dictionary];
        [dict setObject:[NSData dataWithBytesNoCopy:key length:key_len freeWhenDone:NO] forKey:@"key"];
        [dict setObject:dsalt forKey:@"salt"];
        return dict;
    }
}

RCT_EXPORT_METHOD(deriveKey:(NSString*)password salty:(NSString *)salty resolve: (RCTPromiseResolveBlock)resolve reject:(RCTPromiseRejectBlock)reject) {
    NSMutableDictionary* keySalt = [self crypto_pwhash:password salt:salty];
    if (keySalt == NULL)
        reject(ESODIUM, ERR_FAILURE, nil);
    NSData* key = (NSData*)[keySalt objectForKey:@"key"];
    NSData* salt = (NSData*)[keySalt objectForKey:@"salt"];
    [keySalt setValue:[self bin2b64:key] forKey:@"key"];
    [keySalt setValue:[self bin2b64:salt] forKey:@"salt"];
    resolve(keySalt);
}

RCT_EXPORT_METHOD(hashPassword:(NSString*)password email:(NSString *)email resolve: (RCTPromiseResolveBlock)resolve reject:(RCTPromiseRejectBlock)reject) {
    
    NSString *app_salt = @"oVzKtazBo7d8sb7TBvY9jw";
    const char *dpassword = [password cStringUsingEncoding:NSUTF8StringEncoding];
    const char *input = [[app_salt stringByAppendingString:email] cStringUsingEncoding:NSUTF8StringEncoding];
    unsigned long long input_len = strlen(input);
    unsigned char *hash = (unsigned char *) sodium_malloc(16);
    unsigned char *key = (unsigned char *) sodium_malloc(32);
    
    
    int result = crypto_generichash(hash, 16, (unsigned char *) input, input_len, NULL, 0);
    
    unsigned long long memlimit = 1024 * 1024 * 64;
    
    if (result != 0) reject(@"Error", nil,nil);
    
    if (crypto_pwhash(key ,
                      32,
                      dpassword,
                      [password length],
                      hash,
                      3,
                      memlimit, crypto_pwhash_alg_argon2id13()) != 0)
        reject(@"Error", nil,nil);
    
    else {
        
        NSString *value = [self bin2b64:[[NSData alloc] initWithBytes:key length:32]];
        resolve(value);
        
    }
    
}


RCT_EXPORT_METHOD(encrypt:(NSDictionary*)passwordOrKey data:(NSDictionary *)data resolve: (RCTPromiseResolveBlock)resolve reject:(RCTPromiseRejectBlock)reject)
{
    //unsigned long salt_len = crypto_pwhash_saltbytes();
    
    
    NSData* salt;
    NSData* key;
    if ([passwordOrKey objectForKey:@"key"] && [passwordOrKey objectForKey:@"salt"]) {
        salt = [self b642bin:[passwordOrKey objectForKey:@"salt"]];
        key = [self b642bin:[passwordOrKey objectForKey:@"key"]];
    } else if ([passwordOrKey objectForKey:@"password"]) {
        NSMutableDictionary* keySalt = [self crypto_pwhash:[passwordOrKey valueForKey:@"password"] salt:NULL];
        if (keySalt == NULL)
            reject(ESODIUM, ERR_FAILURE, nil);
        key = (NSData*)[keySalt objectForKey:@"key"];
        salt = (NSData*)[keySalt objectForKey:@"salt"];
    }
    
    NSData *ddata;
    
    if ([[data valueForKey:@"type"] isEqual:@"b64"]) {
        
        // ddata = [self b642bin:[data valueForKey:@"data"]];
        ddata = [[NSData alloc] initWithBase64EncodedString:[data valueForKey:@"data"] options:0];
    } else {
        ddata = [[data valueForKey:@"data"] dataUsingEncoding:NSUTF8StringEncoding];
        // ddata = (unsigned char*)[[data valueForKey:@"data"] cStringUsingEncoding:NSUTF8StringEncoding];
    }
    
    
    
    
    unsigned long long length = (unsigned long long)[ddata length] + crypto_aead_xchacha20poly1305_ietf_abytes();
    unsigned char ciphertext[length];
    
    NSData* iv = [self randombytes_buf:crypto_aead_xchacha20poly1305_ietf_npubbytes()];
    
    if (crypto_aead_xchacha20poly1305_ietf_encrypt(ciphertext, &length, [ddata bytes], (unsigned long long)[ddata length], NULL, 0, NULL, [iv bytes], [key bytes]) != 0) {
        reject(ESODIUM, ERR_FAILURE, nil);
    } else {
        NSMutableDictionary* dict = [NSMutableDictionary dictionary];
        NSString* base64Cipher = [self bin2b64:[NSData dataWithBytesNoCopy:ciphertext length:length freeWhenDone:NO]];
        NSString* base64IV = [self bin2b64:iv];
        NSString* base64Salt = [self bin2b64:salt];
        
        [dict setValue:base64IV forKey:@"iv"];
        [dict setValue:base64Salt forKey:@"salt"];
        [dict setValue:base64Cipher forKey:@"cipher"];
        [dict setObject:[NSNumber numberWithUnsignedLong:[ddata length]] forKey:@"length"];
        
        resolve(dict);
    }
}

RCT_EXPORT_METHOD(decrypt:(NSDictionary*)passwordOrKey cipher:(NSDictionary*)cipher resolve: (RCTPromiseResolveBlock)resolve reject:(RCTPromiseRejectBlock)reject)
{
    NSData* key;
    if ([passwordOrKey objectForKey:@"key"] && [passwordOrKey objectForKey:@"salt"]) {
        key = [self b642bin:[passwordOrKey objectForKey:@"key"]];
    } else if ([passwordOrKey objectForKey:@"password"] && [cipher objectForKey:@"salt"]) {
        NSMutableDictionary* keySalt = [self crypto_pwhash:[passwordOrKey valueForKey:@"password"] salt:[cipher valueForKey:@"salt"]];
        if (keySalt == NULL)
            reject(ESODIUM, ERR_FAILURE, nil);
        key = (NSData*)[keySalt objectForKey:@"key"];
    }
    NSNumber* length = (NSNumber*)[cipher valueForKey:@"length"];
    unsigned long long ulength =[length unsignedLongLongValue];

    //size_t data_len = ulength + crypto_aead_xchacha20poly1305_ietf_abytes();
    NSString* data = [cipher objectForKey:@"cipher"];
    NSData* cipherb = [self b642bin:data ];

    //size_t iv_len = crypto_aead_xchacha20poly1305_ietf_npubbytes();
    NSData* iv = [self b642bin:[cipher objectForKey:@"iv"]];
    
    unsigned char plaintext[ulength];
    
    if (crypto_aead_xchacha20poly1305_ietf_decrypt(plaintext, &ulength, NULL, [cipherb bytes], (unsigned long long)[cipherb length], NULL, 0,[iv bytes], [key bytes]) != 0) {
        reject(ESODIUM, ERR_FAILURE, nil);
    } else {
        
        if ([[cipher valueForKey:@"output"] isEqual:@"plain"]) {
            NSString* s =[[NSString alloc] initWithBytesNoCopy:plaintext length:ulength encoding:NSUTF8StringEncoding freeWhenDone:NO ];
            resolve(s);
        } else {
            resolve([[NSData dataWithBytesNoCopy:plaintext length:ulength freeWhenDone:NO] base64EncodedStringWithOptions:0]);
        }
       
        
     
    }
}

//RCT_EXPORT_METHOD(decrypt:(NSDictionary*)passwordOrKey cipher:(NSDictionary*)cipher resolve: (RCTPromiseResolveBlock)resolve reject:(RCTPromiseRejectBlock)reject)
//{
//    NSData* key;
//    if ([passwordOrKey objectForKey:@"key"] && [passwordOrKey objectForKey:@"salt"]) {
//        key = [self b642bin:[passwordOrKey objectForKey:@"key"]];
//    } else if ([passwordOrKey objectForKey:@"password"] && [cipher objectForKey:@"salt"]) {
//        NSMutableDictionary* keySalt = [self crypto_pwhash:[passwordOrKey valueForKey:@"password"] salt:[cipher valueForKey:@"salt"]];
//        if (keySalt == NULL)
//            reject(ESODIUM, ERR_FAILURE, nil);
//        key = (NSData*)[keySalt objectForKey:@"key"];
//    }
//    NSNumber* length = (NSNumber*)[cipher valueForKey:@"length"];
//    unsigned long long ulength =[length unsignedLongLongValue];
//    unsigned long bin_len;
//
//    //size_t data_len = ulength + crypto_aead_xchacha20poly1305_ietf_abytes();
//    NSString* data = [cipher valueForKey:@"cipher"];
//    const char * base64 = [data cStringUsingEncoding:NSUTF8StringEncoding];
//    unsigned long long bin_capacity = [data length] * 3 / 4 + 1;
//    unsigned char binary[bin_capacity];
//
//    if (sodium_base642bin(binary, sizeof binary, base64, [data length], "\n\r ", &bin_len, NULL, sodium_base64_VARIANT_URLSAFE_NO_PADDING) != 0) {
//        reject(ESODIUM, ERR_FAILURE, nil);
//        return;
//    }
//
//    //size_t iv_len = crypto_aead_xchacha20poly1305_ietf_npubbytes();
//    NSData* iv = [self b642bin:[cipher objectForKey:@"iv"]];
//
//    unsigned char plaintext[ulength];
//    if (crypto_aead_xchacha20poly1305_ietf_decrypt(plaintext, &ulength, NULL, binary, bin_len, NULL, 0,[iv bytes], [key bytes]) != 0) {
//        reject(ESODIUM, ERR_FAILURE, nil);
//    } else {
//
//        if ([[cipher valueForKey:@"output"] isEqual:@"plain"]) {
//            NSString* s =[[NSString alloc] initWithBytesNoCopy:plaintext length:ulength encoding:NSUTF8StringEncoding freeWhenDone:NO ];
//            resolve(s);
//        } else {
//            resolve([[NSData dataWithBytesNoCopy:plaintext length:ulength freeWhenDone:NO] base64EncodedStringWithOptions:0]);
//        }
//
//
//
//    }
//}

@end
