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
#import "NAInterface.h"
#import "NAAEAD.h"
#import "NSData+XXHash.h"
#import "SimpleFilesCache.h"

@implementation RCTSodium

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
    NAChlorideInit();
}

+ (BOOL)requiresMainQueueSetup
{
    return YES;
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
    dispatch_async(dispatch_get_main_queue(), ^{
        NAChlorideInit();
        
        NSMutableDictionary* keySalt = [self crypto_pwhash:password salt:salty];
        if (keySalt == NULL)
            reject(ESODIUM, ERR_FAILURE, nil);
        NSData* key = (NSData*)[keySalt objectForKey:@"key"];
        NSData* salt = (NSData*)[keySalt objectForKey:@"salt"];
        [keySalt setValue:[self bin2b64:key] forKey:@"key"];
        [keySalt setValue:[self bin2b64:salt] forKey:@"salt"];
        resolve(keySalt);
        
    });
}

RCT_EXPORT_METHOD(hashPassword:(NSString*)password email:(NSString *)email resolve: (RCTPromiseResolveBlock)resolve reject:(RCTPromiseRejectBlock)reject) {
    dispatch_async(dispatch_get_main_queue(), ^{
        NAChlorideInit();
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
        
    });
    
}


RCT_EXPORT_METHOD(encryptFile:(NSDictionary*)passwordOrKey data:(NSDictionary *)data resolve: (RCTPromiseResolveBlock)resolve reject:(RCTPromiseRejectBlock)reject)
{
    dispatch_async(dispatch_get_main_queue(), ^{
    
    NSData *dataa;
    if ([data[@"type"]  isEqual: @"base64"]) {
        dataa = [[NSData alloc] initWithBase64EncodedString:[data valueForKey:@"data"] options:0];
    } else {
        NSString *path = data[@"uri"];
        NSFileManager *fmngr = [NSFileManager defaultManager];
        if ([fmngr fileExistsAtPath:path]) {
            dataa = [fmngr contentsAtPath:path];
        } else {
            reject(@"File Manager", @"File not found", nil);
            return;
        }
        
    }
    
    if (dataa != nil) {
        NSDictionary *encryptedInfo = [self _encryptFile:passwordOrKey data:dataa];
        resolve(encryptedInfo);
    } else {
        reject(ESODIUM, ERR_FAILURE, nil);
    }
        
    });
    
}





- (NSDictionary *) _encryptFile:(NSDictionary *)passwordOrKey data:(NSData *)data {
    
    NSData* salt;
    NSData* key;
    if ([passwordOrKey objectForKey:@"key"] && [passwordOrKey objectForKey:@"salt"]) {
        salt = [self b642bin:[passwordOrKey objectForKey:@"salt"]];
        key = [self b642bin:[passwordOrKey objectForKey:@"key"]];
    } else if ([passwordOrKey objectForKey:@"password"]) {
        NSMutableDictionary* keySalt = [self crypto_pwhash:[passwordOrKey valueForKey:@"password"] salt:NULL];
        if (keySalt == NULL)
            return nil;
        key = (NSData*)[keySalt objectForKey:@"key"];
        salt = (NSData*)[keySalt objectForKey:@"salt"];
    }
    
    NSData *ddata = data;
    
    size_t size_t_v = crypto_aead_xchacha20poly1305_ietf_npubbytes();
    NSData* iv = [self randombytes_buf:size_t_v];
    
    NAAEAD* AEAD = [[NAAEAD alloc] init];
    NSError *error = nil;
    
    NSData *encryptedData = [AEAD encryptChaCha20Poly1305:ddata nonce:iv key:key additionalData:NULL error:&error];
    if (error != nil) {
        return nil;
    } else {
        NSMutableDictionary* dict = [NSMutableDictionary dictionary];
        NSString* base64IV = [self bin2b64:iv];
        NSString* base64Salt = [self bin2b64:salt];
        
        NSString *hash = [data xxh3];
        
        [dict setValue:base64IV forKey:@"iv"];
        [dict setValue:base64Salt forKey:@"salt"];
        dict[@"hash"] = hash;
        dict[@"hashType"] = @"xxh3";
        [self removeFileIfExists:hash];
        [SimpleFilesCache saveToCacheDirectory:encryptedData withName:hash];
        
        [dict setObject:[NSNumber numberWithUnsignedLong:[ddata length]] forKey:@"length"];
        
        return dict;
    }
    
    
    
}

- (void) removeFileIfExists:(NSString *)name {
    NSFileManager *fmngr = [NSFileManager defaultManager];
    NSArray *paths = NSSearchPathForDirectoriesInDomains(NSCachesDirectory, NSUserDomainMask, YES);
    NSString *cachePath = [paths objectAtIndex:0];
    NSString *path = [cachePath stringByAppendingPathComponent:name];
    if ([fmngr fileExistsAtPath:path]) {
        [fmngr removeItemAtPath:path error:nil];
    }
}


RCT_EXPORT_METHOD(encrypt:(NSDictionary*)passwordOrKey data:(NSDictionary *)data resolve: (RCTPromiseResolveBlock)resolve reject:(RCTPromiseRejectBlock)reject)
{
    
    dispatch_async(dispatch_get_main_queue(), ^{
        
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
            
            ddata = [[NSData alloc] initWithBase64EncodedString:[data valueForKey:@"data"] options:0];
        } else {
            ddata = [[data valueForKey:@"data"] dataUsingEncoding:NSUTF8StringEncoding];
        }
        
        size_t size_t_v = crypto_aead_xchacha20poly1305_ietf_npubbytes();
        NSData* iv = [self randombytes_buf:size_t_v];
        
        NAAEAD* AEAD = [[NAAEAD alloc] init];
        NSError *error = nil;
        
        NSData *encryptedData = [AEAD encryptChaCha20Poly1305:ddata nonce:iv key:key additionalData:NULL error:&error];
        if (error != nil) {
            reject(ESODIUM, ERR_FAILURE, nil);
        } else {
            NSMutableDictionary* dict = [NSMutableDictionary dictionary];
            NSString* base64Cipher = [self bin2b64:encryptedData];
            NSString* base64IV = [self bin2b64:iv];
            NSString* base64Salt = [self bin2b64:salt];
            
            [dict setValue:base64IV forKey:@"iv"];
            [dict setValue:base64Salt forKey:@"salt"];
            [dict setValue:base64Cipher forKey:@"cipher"];
            [dict setObject:[NSNumber numberWithUnsignedLong:[ddata length]] forKey:@"length"];
            
            resolve(dict);
        }
    });
}

RCT_EXPORT_METHOD(decrypt:(NSDictionary*)passwordOrKey cipher:(NSDictionary*)cipher resolve: (RCTPromiseResolveBlock)resolve reject:(RCTPromiseRejectBlock)reject)
{
    dispatch_async(dispatch_get_main_queue(), ^{
        
        NSData* key;
        if ([passwordOrKey objectForKey:@"key"] && [passwordOrKey objectForKey:@"salt"]) {
            key = [self b642bin:[passwordOrKey objectForKey:@"key"]];
        } else if ([passwordOrKey objectForKey:@"password"] && [cipher objectForKey:@"salt"]) {
            NSMutableDictionary* keySalt = [self crypto_pwhash:[passwordOrKey valueForKey:@"password"] salt:[cipher valueForKey:@"salt"]];
            if (keySalt == NULL)
                reject(ESODIUM, ERR_FAILURE, nil);
            key = (NSData*)[keySalt objectForKey:@"key"];
        }
        NSString* data = [cipher objectForKey:@"cipher"];
        NSData* cipherb = [self b642bin:data];
        
        NSData* iv = [self b642bin:[cipher objectForKey:@"iv"]];
        
        NAAEAD* AEAD = [[NAAEAD alloc] init];
        NSError *error = nil;
        NSData *decryptedData = [AEAD decryptChaCha20Poly1305:cipherb nonce:iv key:key additionalData:NULL error:&error];
        
        if (error != nil) {
            reject(ESODIUM, ERR_FAILURE, nil);
        } else {
            if ([[cipher valueForKey:@"output"] isEqual:@"plain"]) {
                NSString* s =[[NSString alloc] initWithData:decryptedData encoding:NSUTF8StringEncoding];
                resolve(s);
            }
        }
        
    });
}

RCT_EXPORT_METHOD(decryptFile:(NSDictionary*)passwordOrKey cipher:(NSDictionary*)cipher b64:(BOOL )b64 resolve: (RCTPromiseResolveBlock)resolve reject:(RCTPromiseRejectBlock)reject)
{
    
    dispatch_async(dispatch_get_main_queue(), ^{
        
        NSData* key;
        if ([passwordOrKey objectForKey:@"key"] && [passwordOrKey objectForKey:@"salt"]) {
            key = [self b642bin:[passwordOrKey objectForKey:@"key"]];
        } else if ([passwordOrKey objectForKey:@"password"] && [cipher objectForKey:@"salt"]) {
            NSMutableDictionary* keySalt = [self crypto_pwhash:[passwordOrKey valueForKey:@"password"] salt:[cipher valueForKey:@"salt"]];
            if (keySalt == NULL)
                reject(ESODIUM, ERR_FAILURE, nil);
            key = (NSData*)[keySalt objectForKey:@"key"];
        }
        
        NSData* cipherb = [SimpleFilesCache cachedDataWithName:cipher[@"hash"]];
        
        
        
        NSData* iv = [self b642bin:[cipher objectForKey:@"iv"]];
        
        NAAEAD* AEAD = [[NAAEAD alloc] init];
        NSError *error = nil;
        NSData *decryptedData = [AEAD decryptChaCha20Poly1305:cipherb nonce:iv key:key additionalData:NULL error:&error];
        
        if (error != nil) {
            reject(ESODIUM, ERR_FAILURE, nil);
        } else {
            if (b64) {
                resolve([self bin2b64:decryptedData]);
            } else {
                NSString *path = cipher[@"uri"];
                NSFileManager *fmngr = [NSFileManager defaultManager];
                path = [path stringByAppendingString:cipher[@"fileName"]];
                [fmngr createFileAtPath:path contents:decryptedData attributes:nil];
                resolve(nil);
            }
        
        }
        
    });
}



@end
