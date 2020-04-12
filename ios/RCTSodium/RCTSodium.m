//
//  RCTSodium.m
//  RCTSodium
//
//  Created by Lyubomir Ivanov on 9/25/16.
//  Copyright © 2016 Lyubomir Ivanov. All rights reserved.
//
#import "RCTBridgeModule.h"
#import "RCTUtils.h"
#import "sodium.h"

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

// *****************************************************************************
// * Random data generation
// *****************************************************************************

- (NSData*) randombytesbuf:(NSUInteger)size
{
    unsigned char *buf = (unsigned char *) sodium_malloc((u_int32_t)size);
    if (buf == NULL)
        return NULL;
    randombytes_buf(buf,(u_int32_t)size);
    NSData* data = [NSData dataWithBytes:(const void *)buf length:sizeof(unsigned char)*size];

    return data;
}


-  (NSMutableDictionary *) crypto_pwhash:(nonnull NSString*)password salt:(NSString*)salt
{
    const char *dpassword = [password cStringUsingEncoding:NSUTF8StringEncoding];
    NSData *dsalt;
    if (salt != NULL)
        dsalt = [[NSData alloc] initWithBase64EncodedString:salt options:0];
    else {
        dsalt = [self randombytesbuf:(NSUInteger)crypto_pwhash_saltbytes()];
        if (dsalt == NULL) return NULL;
    }
        
    unsigned long long key_len = crypto_aead_xchacha20poly1305_ietf_keybytes();
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

RCT_EXPORT_METHOD(deriveKey:(NSString*)password resolve: (RCTPromiseResolveBlock)resolve reject:(RCTPromiseRejectBlock)reject) {
    NSMutableDictionary* keySalt = [self crypto_pwhash:password salt:NULL];
    if (keySalt == NULL)
        reject(ESODIUM, ERR_FAILURE, nil);
    NSData* key = (NSData*)[keySalt objectForKey:@"key"];
    NSData* salt = (NSData*)[keySalt objectForKey:@"salt"];
    [keySalt setValue:[key base64EncodedStringWithOptions:0] forKey:@"key"];
    [keySalt setValue:[salt base64EncodedStringWithOptions:0] forKey:@"salt"];
    resolve(keySalt);
}

RCT_EXPORT_METHOD(encrypt:(NSDictionary*)passwordOrKey data:(NSString*)data resolve: (RCTPromiseResolveBlock)resolve reject:(RCTPromiseRejectBlock)reject)
{
    NSData* salt;
    NSData* key;
    if ([passwordOrKey objectForKey:@"key"] && [passwordOrKey objectForKey:@"salt"]) {
       salt = [[NSData alloc] initWithBase64EncodedString:[passwordOrKey objectForKey:@"salt"] options:0];
       key = [[NSData alloc] initWithBase64EncodedString:[passwordOrKey objectForKey:@"key"] options:0];
    } else if ([passwordOrKey objectForKey:@"password"]) {
        NSMutableDictionary* keySalt = [self crypto_pwhash:[passwordOrKey valueForKey:@"password"] salt:NULL];
        if (keySalt == NULL)
            reject(ESODIUM, ERR_FAILURE, nil);
        key = (NSData*)[keySalt objectForKey:@"key"];
        salt = (NSData*)[keySalt objectForKey:@"salt"];
    }
    
    const unsigned char *ddata = (unsigned char*)[data cStringUsingEncoding:NSUTF8StringEncoding];
    unsigned long long length = (unsigned long long)[data length] + crypto_aead_xchacha20poly1305_ietf_abytes();
    unsigned char ciphertext[length];

    NSData* iv = [self randombytesbuf:(NSUInteger)crypto_aead_xchacha20poly1305_ietf_npubbytes()];

    if (crypto_aead_xchacha20poly1305_ietf_encrypt(ciphertext, &length, ddata, (unsigned long long)[data length], NULL, 0, NULL, [iv bytes], [key bytes]) != 0) {
        reject(ESODIUM, ERR_FAILURE, nil);
    } else {
        NSMutableDictionary* dict = [NSMutableDictionary dictionary];
        NSString* base64Cipher = [[NSData dataWithBytesNoCopy:ciphertext length:length freeWhenDone:NO] base64EncodedStringWithOptions:0];
        NSString* base64IV = [iv base64EncodedStringWithOptions:0];
        NSString* base64Salt = [salt base64EncodedStringWithOptions:0];
        [dict setValue:base64IV forKey:@"iv"];
        [dict setValue:base64Salt forKey:@"salt"];
        [dict setValue:base64Cipher forKey:@"cipher"];
        [dict setObject:[NSNumber numberWithUnsignedLong:[data length]] forKey:@"length"];
        resolve(dict);
    }
}

RCT_EXPORT_METHOD(decrypt:(NSDictionary*)passwordOrKey cipher:(NSDictionary*)cipher resolve: (RCTPromiseResolveBlock)resolve reject:(RCTPromiseRejectBlock)reject)
{
    NSData* key;
    if ([passwordOrKey objectForKey:@"key"] && [passwordOrKey objectForKey:@"salt"]) {
       key = [[NSData alloc] initWithBase64EncodedString:[passwordOrKey objectForKey:@"key"] options:0];
    } else if ([passwordOrKey objectForKey:@"password"] && [cipher objectForKey:@"salt"]) {
        NSMutableDictionary* keySalt = [self crypto_pwhash:[passwordOrKey valueForKey:@"password"] salt:[cipher valueForKey:@"salt"]];
        if (keySalt == NULL)
            reject(ESODIUM, ERR_FAILURE, nil);
        key = (NSData*)[keySalt objectForKey:@"key"];
    }
    
    NSData* cipherb = [[NSData alloc] initWithBase64EncodedString:[cipher objectForKey:@"cipher"] options:0];
    NSData* iv = [[NSData alloc] initWithBase64EncodedString:[cipher objectForKey:@"iv"] options:0];
    NSNumber* length = (NSNumber*)[cipher valueForKey:@"length"];
    unsigned long long ulength =[length unsignedLongLongValue];
    unsigned char plaintext[ulength];

    if (crypto_aead_xchacha20poly1305_ietf_decrypt(plaintext, &ulength, NULL, [cipherb bytes], (unsigned long long)[cipherb length], NULL, 0,[iv bytes], [key bytes]) != 0) {
        reject(ESODIUM, ERR_FAILURE, nil);
    } else {
        NSString* s = [NSString stringWithCString:(char *)plaintext encoding:NSUTF8StringEncoding];
        resolve(s);
    }
}

@end
