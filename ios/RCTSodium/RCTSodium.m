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
#import <math.h>
#import "xxh3.h"

@implementation RCTSodium

NSString * const ESODIUM = @"ESODIUM";
NSString * const ERR_BAD_KEY = @"BAD_KEY";
NSString * const ERR_BAD_MAC = @"BAD_MAC";
NSString * const ERR_BAD_MSG = @"BAD_MSG";
NSString * const ERR_BAD_NONCE = @"BAD_NONCE";
NSString * const ERR_BAD_SEED = @"BAD_SEED";
NSString * const ERR_BAD_SIG = @"BAD_SIG";
NSString * const ERR_FAILURE = @"FAILURE";
bool hasListeners;
long STREAM_CHUNK_SIZE = 512 * 1024;

RCT_EXPORT_MODULE();

+ (void) initialize
{
    [super initialize];
    NAChlorideInit();
}

+ (BOOL)requiresMainQueueSetup
{
    return NO;
}

// Will be called when this module's first listener is added.
-(void)startObserving {
    hasListeners = YES;
}

// Will be called when this module's last listener is removed, or on dealloc.
-(void)stopObserving {
    hasListeners = NO;
}

- (NSData*) randombytes_buf:(size_t)len {
    unsigned char buf[len];
    randombytes_buf(buf, len);
    NSData *random = [NSData dataWithBytes:buf length:len];
    return random;
}

- (NSArray<NSString *> *)supportedEvents {
    return @[@"onSodiumProgress"];
}

- (NSString*) bin2b64:(NSData*) data {
    return [data base64UrlEncodedString];
}

- (NSData*) b642bin:(NSString*)b64{
    
    return [NSData dataWithBase64UrlEncodedString:b64];
}

-  (NSMutableDictionary *) crypto_pwhash:(nonnull NSString*)password salt:(NSString*)salt fallbackKey:(BOOL)fallbackKey
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
                      fallbackKey ? [password length] : strlen(dpassword),
                      [dsalt bytes],
                      ops,
                      memlimit, crypto_pwhash_alg_argon2i13()) != 0) {
        
        sodium_free(key);
        return NULL;
    } else {
        NSMutableDictionary* dict = [NSMutableDictionary dictionary];
        [dict setObject:[NSData dataWithBytesNoCopy:key length:key_len freeWhenDone:NO] forKey:@"key"];
        [dict setObject:dsalt forKey:@"salt"];
        
        return dict;
    }
}

RCT_EXPORT_METHOD(addListener : (NSString *)eventName) {
    // Keep: Required for RN built in Event Emitter Calls.
}

RCT_EXPORT_METHOD(removeListeners : (double)count) {
    // Keep: Required for RN built in Event Emitter Calls.
}

RCT_EXPORT_METHOD(deriveKeyFallback:(NSString*)password salty:(NSString *)salty resolve: (RCTPromiseResolveBlock)resolve reject:(RCTPromiseRejectBlock)reject) {
    NAChlorideInit();
    
    size_t bytes_len = strlen([password cStringUsingEncoding:NSUTF8StringEncoding]);
    if (bytes_len == [password length]) {
        resolve(nil);
        return;
    }
    
    NSMutableDictionary* keySalt = [self crypto_pwhash:password salt:salty fallbackKey:true];
    if (keySalt == NULL)
        reject(ESODIUM, ERR_FAILURE, nil);
    NSData* key = (NSData*)[keySalt objectForKey:@"key"];
    NSData* salt = (NSData*)[keySalt objectForKey:@"salt"];
    [keySalt setValue:[self bin2b64:key] forKey:@"key"];
    [keySalt setValue:[self bin2b64:salt] forKey:@"salt"];
    resolve(keySalt);
    
}

RCT_EXPORT_METHOD(deriveKey:(NSString*)password salty:(NSString *)salty resolve: (RCTPromiseResolveBlock)resolve reject:(RCTPromiseRejectBlock)reject) {
    NAChlorideInit();
    
    NSMutableDictionary* keySalt = [self crypto_pwhash:password salt:salty fallbackKey:false];
    if (keySalt == NULL)
        reject(ESODIUM, ERR_FAILURE, nil);
    NSData* key = (NSData*)[keySalt objectForKey:@"key"];
    NSData* salt = (NSData*)[keySalt objectForKey:@"salt"];
    [keySalt setValue:[self bin2b64:key] forKey:@"key"];
    [keySalt setValue:[self bin2b64:salt] forKey:@"salt"];
    resolve(keySalt);
    
}

RCT_EXPORT_METHOD(hashPasswordFallback:(NSString*)password email:(NSString *)email resolve: (RCTPromiseResolveBlock)resolve reject:(RCTPromiseRejectBlock)reject) {
    
    NAChlorideInit();
    NSString *app_salt = @"oVzKtazBo7d8sb7TBvY9jw";
    const char *dpassword = [password cStringUsingEncoding:NSUTF8StringEncoding];
    
    if (strlen(dpassword) == [password length]) {
        resolve(nil);
        return;
    }
    
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
    
    sodium_free(hash);
    sodium_free(key);
    
}

RCT_EXPORT_METHOD(hashPassword:(NSString*)password email:(NSString *)email resolve: (RCTPromiseResolveBlock)resolve reject:(RCTPromiseRejectBlock)reject) {
    
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
                      strlen(dpassword),
                      hash,
                      3,
                      memlimit, crypto_pwhash_alg_argon2id13()) != 0)
        
        reject(@"Error", nil,nil);

    else {
        
        NSString *value = [self bin2b64:[[NSData alloc] initWithBytes:key length:32]];
        resolve(value);

    }
    
    sodium_free(hash);
    sodium_free(key);
    
}

RCT_EXPORT_METHOD(hashFile:(NSDictionary *)data resolve: (RCTPromiseResolveBlock)resolve reject:(RCTPromiseRejectBlock)reject)
{
    resolve([self xxh64:data]);
}


- (NSString *) xxh64:(NSDictionary *)data {
    
    NSInputStream *inputStream;
    NSNumber *length;
    NSFileManager *fmngr = [NSFileManager defaultManager];
    
    if ([data[@"type"]  isEqual: @"base64"]) {
        NSData *b64 = [[NSData alloc] initWithBase64EncodedString:[data valueForKey:@"data"] options:0];
        length = [NSNumber numberWithLong:b64.length];
        inputStream = [NSInputStream inputStreamWithData:b64];
    } else {
        length = [NSNumber numberWithLong:[[fmngr attributesOfItemAtPath:data[@"uri"] error:nil] fileSize]];
        inputStream = [NSInputStream inputStreamWithFileAtPath:data[@"uri"]];
    }
    
    [inputStream open];
    static XXH64_state_t* state = NULL;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        state = XXH64_createState();
    });
    
    XXH_errorcode ec = XXH64_reset(state, 0);
    if (ec != XXH_OK) {
        @throw NSGenericException;
    }
    
    long chunk_size = 512 * 1024;
    
    double totalChunks = fmax(ceilf((float)length.longLongValue/(float)chunk_size), 1);
    
    uint8_t * buffer = malloc(chunk_size);
    
    for (int i=0;i < totalChunks;i++) {
        long start = i * chunk_size;
        int end = fmin(start + chunk_size, length.longLongValue);
        long chunk_length = end - start;
        
        [inputStream read:buffer maxLength:chunk_length];
        
        ec = XXH64_update (state, buffer, chunk_length);
        if (ec != XXH_OK) {
            @throw NSGenericException;
        }
    }
    
    free(buffer);
    
    unsigned long long val = XXH64_digest(state);
    [inputStream close];
    
    return [NSString stringWithFormat:@"%llx", val];
    
    
}


- (NSOutputStream *) getOutputStream:(NSDictionary *)data type:(NSString *)type {
    NSOutputStream *outputStream;
    if (data[@"iv"] != nil) {
        if ([type isEqualToString:@"text"] || [type isEqualToString:@"base64"]) {
            outputStream = [[NSOutputStream alloc] initToMemory];
        } else if ([type isEqualToString:@"cache"]) {
            
            NSFileManager *fmngr = [NSFileManager defaultManager];
            NSMutableString *path = [NSMutableString stringWithString:data[@"hash"]];
            [path appendString:@"_dcache"];
            NSString *outputPath = [SimpleFilesCache pathForName:path];
            [self removeFileIfExists:path];
            [fmngr createFileAtPath:outputPath contents:nil attributes:nil];
            outputStream = [NSOutputStream outputStreamToFileAtPath:outputPath append:NO];
        } else {
            NSString *path = data[@"uri"];
            NSFileManager *fmngr = [NSFileManager defaultManager];
            path = [path stringByAppendingString:data[@"fileName"]];
            [fmngr createFileAtPath:path contents:nil attributes:nil];
            outputStream = [NSOutputStream outputStreamToFileAtPath:path append:NO];
        }
        
    } else {
        NSFileManager *fmngr = [NSFileManager defaultManager];
        NSString *outputPath;
        if (data[@"appGroupId"] != nil) {
            NSURL *appGroupUrl = [fmngr containerURLForSecurityApplicationGroupIdentifier:data[@"appGroupId"]];
            outputPath = [appGroupUrl.path stringByAppendingPathComponent:data[@"hash"]];
            if ([fmngr fileExistsAtPath:outputPath]) {
                [fmngr removeItemAtPath:outputPath error:nil];
            }
        } else {
            outputPath = [SimpleFilesCache pathForName:data[@"hash"]];
            [self removeFileIfExists:data[@"hash"]];
        }
        [fmngr createFileAtPath:outputPath contents:nil attributes:nil];
        outputStream = [NSOutputStream outputStreamToFileAtPath:outputPath append:NO];
        
    }
    
    return outputStream;
}



-(int) transform:(crypto_secretstream_xchacha20poly1305_state)state inputStream:(NSInputStream *)inputStream outputStream:(NSOutputStream *)outputStream inputlength:(NSNumber *)inputLength chunkSize:(long)chunkSize decrypt:(BOOL)decrypt {
    
    unsigned long long length = inputLength.longLongValue;
    
    double totalChunks = fmax(ceilf((float)length/(float)chunkSize), 1);
    
    uint8_t * buffer = malloc(chunkSize);
    unsigned long max_output_chunk_length =  decrypt ? chunkSize - crypto_secretstream_xchacha20poly1305_abytes() :  chunkSize + crypto_secretstream_xchacha20poly1305_abytes();
    uint8_t * output_buffer = malloc(max_output_chunk_length);
    
    for (int i=0;i < totalChunks;i++) {
        long start = i * chunkSize;
        int end = fmin(start + chunkSize, length);
        long chunk_length = end - start;
        
        [inputStream read:buffer maxLength:chunk_length];
        
        unsigned long output_chunk_length =  decrypt ? chunk_length - crypto_secretstream_xchacha20poly1305_abytes() :  chunk_length + crypto_secretstream_xchacha20poly1305_abytes();
        
        int result = 0;
        if (decrypt) {
            
            unsigned char tag;
            result = crypto_secretstream_xchacha20poly1305_pull(&state, output_buffer, nil, &tag, buffer, chunk_length, nil, 0);
            
        }else {
            BOOL final = i == totalChunks - 1;
            unsigned char tag = final ? crypto_secretstream_xchacha20poly1305_tag_final() : crypto_secretstream_xchacha20poly1305_tag_message();
            result = crypto_secretstream_xchacha20poly1305_push(&state, output_buffer, NULL, buffer, chunk_length, NULL, 0, tag);
        }
        
        
        if (result != 0) {
            [outputStream close];
            [inputStream close];
            return result;
        }
        
        [outputStream write:output_buffer maxLength:output_chunk_length];
        
        [self sendProgressEvent:totalChunks progress:i];
        
    }
    
    free(buffer);
    free(output_buffer);
    
    return 0;
}

- (void) sendProgressEvent:(double)total progress:(int)progress {
    if (hasListeners) {
        [self sendEventWithName:@"onSodiumProgress" body:@{@"total": [NSNumber numberWithDouble:total],@"progress":[NSNumber numberWithInt:progress]}];
    }
}

- (int) encryptChunk:(crypto_secretstream_xchacha20poly1305_state)state chunkLength:(long)chunkLength input:(uint8_t *)input output:(unsigned char *)output final:(BOOL)final {
    unsigned char tag = final ? crypto_secretstream_xchacha20poly1305_tag_final() : crypto_secretstream_xchacha20poly1305_tag_message();
    int result = crypto_secretstream_xchacha20poly1305_push(&state, output, NULL, input, chunkLength, NULL, 0, tag);
    return result;
}

- (int) decryptChunk:(crypto_secretstream_xchacha20poly1305_state)state chunkLength:(long)chunkLength input:(uint8_t *)input output:(unsigned char *)output final:(BOOL)final {
    unsigned char tag;
    int result = crypto_secretstream_xchacha20poly1305_pull(&state, output, nil, &tag, input, chunkLength, nil, 0);
    
    return result;
    
}

- (void) removeFileIfExists:(NSString *)name {
    NSString *cachePath = [SimpleFilesCache cachesDirectoryName];
    NSString *path = [cachePath stringByAppendingPathComponent:name];
    NSFileManager *fmngr = [NSFileManager defaultManager];
    if ([fmngr fileExistsAtPath:path]) {
        [fmngr removeItemAtPath:path error:nil];
    }
}


RCT_EXPORT_METHOD(encryptMulti:(NSDictionary*)passwordOrKey array:(NSArray *)array resolve: (RCTPromiseResolveBlock)resolve reject:(RCTPromiseRejectBlock)reject)
{
    
    int size = (int) array.count;
    NSMutableArray * results = [NSMutableArray arrayWithCapacity:size];
    
    NSData* salt;
    NSData* key;
    if ([passwordOrKey objectForKey:@"key"] && [passwordOrKey objectForKey:@"salt"]) {
        salt = [self b642bin:[passwordOrKey objectForKey:@"salt"]];
        key = [self b642bin:[passwordOrKey objectForKey:@"key"]];
    } else if ([passwordOrKey objectForKey:@"password"]) {
        NSMutableDictionary* keySalt = [self crypto_pwhash:[passwordOrKey valueForKey:@"password"] salt:NULL fallbackKey:false];
        if (keySalt == NULL)
            reject(ESODIUM, ERR_FAILURE, nil);
        key = (NSData*)[keySalt objectForKey:@"key"];
        salt = (NSData*)[keySalt objectForKey:@"salt"];
    }
    
    for (int i=0;i < size; i++) {
        NSDictionary *data = array[i];
        
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
            [dict setValue:[NSNumber numberWithLong:STREAM_CHUNK_SIZE] forKey:@"chunkSize"];
            [dict setValue:base64IV forKey:@"iv"];
            [dict setValue:base64Salt forKey:@"salt"];
            [dict setValue:base64Cipher forKey:@"cipher"];
            [dict setObject:[NSNumber numberWithUnsignedLong:[ddata length]] forKey:@"length"];
            
            [results addObject:dict];
            
        }
        
    }
    
    resolve(results);
    
}


RCT_EXPORT_METHOD(encrypt:(NSDictionary*)passwordOrKey data:(NSDictionary *)data resolve: (RCTPromiseResolveBlock)resolve reject:(RCTPromiseRejectBlock)reject)
{
    
    NSData* salt;
    NSData* key;
    if ([passwordOrKey objectForKey:@"key"] && [passwordOrKey objectForKey:@"salt"]) {
        salt = [self b642bin:[passwordOrKey objectForKey:@"salt"]];
        key = [self b642bin:[passwordOrKey objectForKey:@"key"]];
    } else if ([passwordOrKey objectForKey:@"password"]) {
        NSMutableDictionary* keySalt = [self crypto_pwhash:[passwordOrKey valueForKey:@"password"] salt:NULL fallbackKey:false];
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
        [dict setValue:[NSNumber numberWithLong:STREAM_CHUNK_SIZE] forKey:@"chunkSize"];
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
        NSMutableDictionary* keySalt = [self crypto_pwhash:[passwordOrKey valueForKey:@"password"] salt:[cipher valueForKey:@"salt"] fallbackKey:false];
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
    
    
}

RCT_EXPORT_METHOD(decryptMulti:(NSDictionary*)passwordOrKey data:(NSArray *)data resolve: (RCTPromiseResolveBlock)resolve reject:(RCTPromiseRejectBlock)reject)
{
    int size = (int) data.count;
    
    NSMutableArray * results = [NSMutableArray arrayWithCapacity:size];
    for (int i=0;i < size; i++) {
        
        NSDictionary *cipher = data[i];
        
        NSData* key;
        if ([passwordOrKey objectForKey:@"key"] && [passwordOrKey objectForKey:@"salt"]) {
            key = [self b642bin:[passwordOrKey objectForKey:@"key"]];
        } else if ([passwordOrKey objectForKey:@"password"] && [cipher objectForKey:@"salt"]) {
            NSMutableDictionary* keySalt = [self crypto_pwhash:[passwordOrKey valueForKey:@"password"] salt:[cipher valueForKey:@"salt"] fallbackKey:false];
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
                results[i] = s;
            }
        }
        
    }
    
    resolve(results);
    
    
}



RCT_EXPORT_METHOD(encryptFile:(NSDictionary*)passwordOrKey data:(NSDictionary *)data resolve: (RCTPromiseResolveBlock)resolve reject:(RCTPromiseRejectBlock)reject)
{
    
    NAChlorideInit();
    long chunk_size = STREAM_CHUNK_SIZE;
    NSData* salt;
    NSData* key;
    
    if ([passwordOrKey objectForKey:@"key"] && [passwordOrKey objectForKey:@"salt"]) {
        salt = [self b642bin:[passwordOrKey objectForKey:@"salt"]];
        key = [self b642bin:[passwordOrKey objectForKey:@"key"]];
    } else if ([passwordOrKey objectForKey:@"password"]) {
        NSMutableDictionary* keySalt = [self crypto_pwhash:[passwordOrKey valueForKey:@"password"] salt:NULL fallbackKey:false];
        if (keySalt == NULL) return;
        key = (NSData*)[keySalt objectForKey:@"key"];
        salt = (NSData*)[keySalt objectForKey:@"salt"];
        
    }
    NSInputStream *inputStream;
    NSNumber *length;
    NSFileManager *fmngr = [NSFileManager defaultManager];
    NSString *hash = data[@"hash"];
    
    if (hash == nil) {
        hash = [self xxh64:data];
    }
    
    if ([data[@"type"]  isEqual: @"base64"]) {
        NSData *b64 = [[NSData alloc] initWithBase64EncodedString:[data valueForKey:@"data"] options:0];
        length = [NSNumber numberWithLong:b64.length];
        inputStream = [NSInputStream inputStreamWithData:b64];
    } else {
        length = [NSNumber numberWithLong:[[fmngr attributesOfItemAtPath:data[@"uri"] error:nil] fileSize]];
        inputStream = [NSInputStream inputStreamWithFileAtPath:data[@"uri"]];
    }
    
    crypto_secretstream_xchacha20poly1305_state state;
    NSMutableData * header = [[NSMutableData alloc] initWithLength:crypto_secretstream_xchacha20poly1305_HEADERBYTES];
    
    crypto_secretstream_xchacha20poly1305_init_push(&state,(unsigned char *) header.bytes, key.bytes);
    
    NSMutableDictionary *outputDic = [NSMutableDictionary dictionaryWithDictionary:data];
    [outputDic setValue:hash forKey:@"hash"];
    [outputDic setValue:data[@"appGroupId"] forKey:@"appGroupId"];
    NSOutputStream *outputStream = [self getOutputStream:outputDic type:@"file"];
    
    [outputStream open];
    [inputStream open];
    
    int result = [self transform:state inputStream:inputStream outputStream:outputStream inputlength:length chunkSize:chunk_size decrypt:false];
    
    if (result != 0) {
        reject(ESODIUM, ERR_FAILURE, nil);
        return;
    }
    
    [inputStream close];
    [outputStream close];
    
    NSMutableDictionary* dict = [NSMutableDictionary dictionary];
    [dict setValue:[NSNumber numberWithLong:STREAM_CHUNK_SIZE] forKey:@"chunkSize"];
    [dict setValue:[header base64UrlEncodedString] forKey:@"iv"];
    [dict setValue:[self bin2b64:salt] forKey:@"salt"];
    dict[@"hash"] = outputDic[@"hash"];
    dict[@"hashType"] = @"xxh64";
    [dict setObject:length forKey:@"size"];
    resolve(dict);
    
}

RCT_EXPORT_METHOD(decryptFile:(NSDictionary*)passwordOrKey cipher:(NSDictionary*)cipher type:(NSString*)type resolve: (RCTPromiseResolveBlock)resolve reject:(RCTPromiseRejectBlock)reject)
{
    
    NAChlorideInit();
    NSNumber *chunkSizeFromCipher = cipher[@"chunkSize"];
    long chunk_size = chunkSizeFromCipher.longValue + crypto_secretstream_xchacha20poly1305_abytes();
    
    NSData* key;
    if ([passwordOrKey objectForKey:@"key"] && [passwordOrKey objectForKey:@"salt"]) {
        key = [self b642bin:[passwordOrKey objectForKey:@"key"]];
    } else if ([passwordOrKey objectForKey:@"password"] && [cipher objectForKey:@"salt"]) {
        NSMutableDictionary* keySalt = [self crypto_pwhash:[passwordOrKey valueForKey:@"password"] salt:[cipher valueForKey:@"salt"] fallbackKey:false];
        if (keySalt == NULL)
            reject(ESODIUM, ERR_FAILURE, nil);
        key = (NSData*)[keySalt objectForKey:@"key"];
    }
    
    NSFileManager *fmngr = [NSFileManager defaultManager];
    
    NSString *path = [SimpleFilesCache pathForName:cipher[@"hash"]];
    BOOL exists = [fmngr fileExistsAtPath:path];
    
    NSInputStream *inputStream;
    if (exists) {
        inputStream = [NSInputStream inputStreamWithFileAtPath:path];
    }
    NSNumber *length = [NSNumber numberWithLong:[[fmngr attributesOfItemAtPath:path error:nil] fileSize]];
    
    if (length.longValue == 0 || !exists) {
        [inputStream close];
        NSURL *appGroupDir = [fmngr containerURLForSecurityApplicationGroupIdentifier:cipher[@"appGroupId"]];
        path = [appGroupDir.path stringByAppendingPathComponent:cipher[@"hash"]];
        inputStream = [NSInputStream inputStreamWithFileAtPath:path];
        length = [NSNumber numberWithLong:[[fmngr attributesOfItemAtPath:path error:nil] fileSize]];
    }
    
    if (length.longValue == 0) {
        reject(ESODIUM, ERR_FAILURE, nil);
        return;
    }
    NSData *iv = [self b642bin:[cipher objectForKey:@"iv"]];
    crypto_secretstream_xchacha20poly1305_state state;
    crypto_secretstream_xchacha20poly1305_init_pull(&state,[iv bytes], [key bytes]);
    NSOutputStream *outputStream = [self getOutputStream:cipher type:type];
    [outputStream open];
    [inputStream open];
    
    int result = [self transform:state inputStream:inputStream outputStream:outputStream inputlength:length chunkSize:chunk_size decrypt:YES];
    
    if (result != 0) {
        reject(ESODIUM, ERR_FAILURE, nil);
        return;
    }
    
    if ([type isEqualToString:@"base64"]) {
        NSData *data = [outputStream propertyForKey:NSStreamDataWrittenToMemoryStreamKey];
        resolve([data base64String]);
    } else if ([type isEqualToString:@"text"]) {
        NSData *data = [outputStream propertyForKey:NSStreamDataWrittenToMemoryStreamKey];
        resolve([[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding]);
    } else if ([type isEqualToString:@"cache"]) {
        NSMutableString *path = [NSMutableString stringWithString:cipher[@"hash"]];
        [path appendString:@"_dcache"];
        resolve(path);
    } else {
        resolve(nil);
    }
    [inputStream close];
    [outputStream close];
}

@end
