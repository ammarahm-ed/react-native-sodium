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
    if (key == NULL) return NULL;
    
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
        // Copy out and release the guarded allocation. dataWithBytesNoCopy with
        // freeWhenDone:NO meant nothing ever owned it, so every password based
        // call leaked a sodium_malloc region.
        [dict setObject:[NSData dataWithBytes:key length:key_len] forKey:@"key"];
        [dict setObject:dsalt forKey:@"salt"];
        sodium_free(key);
        
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
    if (keySalt == NULL) {
        reject(ESODIUM, @"deriveKeyFallback: crypto_pwhash failed", nil);
        return;
    }
    NSData* key = (NSData*)[keySalt objectForKey:@"key"];
    NSData* salt = (NSData*)[keySalt objectForKey:@"salt"];
    [keySalt setValue:[self bin2b64:key] forKey:@"key"];
    [keySalt setValue:[self bin2b64:salt] forKey:@"salt"];
    resolve(keySalt);
    
}

RCT_EXPORT_METHOD(deriveKey:(NSString*)password salty:(NSString *)salty resolve: (RCTPromiseResolveBlock)resolve reject:(RCTPromiseRejectBlock)reject) {
    NAChlorideInit();
    
    NSMutableDictionary* keySalt = [self crypto_pwhash:password salt:salty fallbackKey:false];
    if (keySalt == NULL) {
        reject(ESODIUM, @"deriveKey: crypto_pwhash failed", nil);
        return;
    }
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
    
    if (result != 0) {
        sodium_free(hash);
        sodium_free(key);
        reject(ESODIUM, @"hashPasswordFallback: crypto_generichash failed", nil);
        return;
    }
    
    if (crypto_pwhash(key ,
                      32,
                      dpassword,
                      [password length],
                      hash,
                      3,
                      memlimit, crypto_pwhash_alg_argon2id13()) != 0)
        
        reject(ESODIUM, @"hashPasswordFallback: crypto_pwhash failed", nil);
    
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
    
    if (result != 0) {
        sodium_free(hash);
        sodium_free(key);
        reject(ESODIUM, @"hashPassword: crypto_generichash failed", nil);
        return;
    }
    
    if (crypto_pwhash(key ,
                      32,
                      dpassword,
                      strlen(dpassword),
                      hash,
                      3,
                      memlimit, crypto_pwhash_alg_argon2id13()) != 0)
        
        reject(ESODIUM, @"hashPassword: crypto_pwhash failed", nil);

    else {
        
        NSString *value = [self bin2b64:[[NSData alloc] initWithBytes:key length:32]];
        resolve(value);

    }
    
    sodium_free(hash);
    sodium_free(key);
    
}

RCT_EXPORT_METHOD(hashFile:(NSDictionary *)data resolve: (RCTPromiseResolveBlock)resolve reject:(RCTPromiseRejectBlock)reject)
{
    NSError *error = nil;
    NSString *hash = [self xxh64:data error:&error];
    if (hash == nil) {
        reject(ESODIUM, error.localizedDescription ?: @"hashFile failed", error);
        return;
    }
    resolve(hash);
}


- (NSString *) xxh64:(NSDictionary *)data error:(NSError **)error {
    
    NSInputStream *inputStream;
    NSNumber *length;
    NSFileManager *fmngr = [NSFileManager defaultManager];
    
    if ([data[@"type"]  isEqual: @"base64"]) {
        NSString *b64String = data[@"data"];
        if (b64String == nil) {
            if (error) *error = NAError(NAErrorCodeInvalidData, @"hashFile: type is 'base64' but 'data' is missing");
            return nil;
        }
        NSData *b64 = [[NSData alloc] initWithBase64EncodedString:b64String options:0];
        if (b64 == nil) {
            if (error) *error = NAError(NAErrorCodeInvalidData, @"hashFile: 'data' is not valid base64");
            return nil;
        }
        length = [NSNumber numberWithLong:b64.length];
        inputStream = [NSInputStream inputStreamWithData:b64];
    } else {
        NSString *uri = data[@"uri"];
        if (uri == nil || [uri length] == 0) {
            if (error) *error = NAError(NAErrorCodeInvalidData, @"hashFile: 'uri' is missing");
            return nil;
        }
        // A missing file used to yield fileSize 0, which fmax(...,1) turned into
        // one chunk read over an uninitialised buffer: a plausible-looking hash
        // for a file that was never there.
        NSError *attributesError = nil;
        NSDictionary *attributes = [fmngr attributesOfItemAtPath:uri error:&attributesError];
        if (attributes == nil) {
            if (error) *error = NAError(NAErrorCodeInvalidData, ([NSString stringWithFormat:@"hashFile: cannot read %@: %@", uri, attributesError.localizedDescription]));
            return nil;
        }
        length = [NSNumber numberWithUnsignedLongLong:[attributes fileSize]];
        inputStream = [NSInputStream inputStreamWithFileAtPath:uri];
    }

    if (inputStream == nil) {
        if (error) *error = NAError(NAErrorCodeFailure, @"hashFile: could not open the input stream");
        return nil;
    }

    [inputStream open];

    // One state per call. A shared static state was only safe because the
    // module's method queue happened to serialise every caller.
    XXH64_state_t* state = XXH64_createState();
    if (state == NULL) {
        [inputStream close];
        if (error) *error = NAError(NAErrorCodeFailure, @"XXH64_createState failed");
        return nil;
    }

    XXH_errorcode ec = XXH64_reset(state, 0);
    if (ec != XXH_OK) {
        XXH64_freeState(state);
        [inputStream close];
        if (error) *error = NAError(NAErrorCodeFailure, @"XXH64_reset failed");
        return nil;
    }
    
    long chunk_size = 512 * 1024;
    
    double totalChunks = fmax(ceilf((float)length.longLongValue/(float)chunk_size), 1);
    
    uint8_t * buffer = malloc(chunk_size);
    
    for (int i=0;i < totalChunks;i++) {
        long start = i * chunk_size;
        int end = fmin(start + chunk_size, length.longLongValue);
        long chunk_length = end - start;
        
        long read = [self readFully:inputStream into:buffer length:chunk_length];
        if (read != chunk_length) {
            free(buffer);
            XXH64_freeState(state);
            [inputStream close];
            if (error) *error = NAError(NAErrorCodeFailure, ([NSString stringWithFormat:@"hashFile: short read on chunk %d of %d: wanted %ld bytes, got %ld",
                                                              i + 1, (int) totalChunks, chunk_length, read]));
            return nil;
        }

        ec = XXH64_update (state, buffer, chunk_length);
        if (ec != XXH_OK) {
            free(buffer);
            XXH64_freeState(state);
            [inputStream close];
            if (error) *error = NAError(NAErrorCodeFailure, @"XXH64_update failed");
            return nil;
        }
    }
    
    free(buffer);

    unsigned long long val = XXH64_digest(state);
    XXH64_freeState(state);
    [inputStream close];
    
    return [NSString stringWithFormat:@"%llx", val];
    
    
}


- (NSOutputStream *) getOutputStream:(NSDictionary *)data type:(NSString *)type path:(NSString **)outPath {
    NSOutputStream *outputStream;
    if (outPath) *outPath = nil;
    if (data[@"iv"] != nil) {
        if ([type isEqualToString:@"text"] || [type isEqualToString:@"base64"]) {
            outputStream = [[NSOutputStream alloc] initToMemory];
        } else if ([type isEqualToString:@"cache"]) {
            
            NSFileManager *fmngr = [NSFileManager defaultManager];
            if (data[@"hash"] == nil) return nil;
            NSMutableString *path = [NSMutableString stringWithString:data[@"hash"]];
            [path appendString:@"_dcache"];
            NSString *outputPath = [SimpleFilesCache pathForName:path];
            [self removeFileIfExists:path];
            [fmngr createFileAtPath:outputPath contents:nil attributes:nil];
            outputStream = [NSOutputStream outputStreamToFileAtPath:outputPath append:NO];
            if (outPath) *outPath = outputPath;
        } else {
            NSString *directory = data[@"uri"];
            NSString *fileName = data[@"fileName"];
            if (directory == nil || fileName == nil) return nil;
            NSFileManager *fmngr = [NSFileManager defaultManager];
            // stringByAppendingString: joined these with no separator, so the
            // decrypted file landed next to the target directory rather than in it.
            NSString *path = [directory stringByAppendingPathComponent:fileName];
            [fmngr createFileAtPath:path contents:nil attributes:nil];
            outputStream = [NSOutputStream outputStreamToFileAtPath:path append:NO];
            if (outPath) *outPath = path;
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
        if (outPath) *outPath = outputPath;
        
    }
    
    return outputStream;
}



/**
 * NSInputStream may return fewer bytes than asked for, and returns -1 on error.
 * Ignoring that left the tail of the buffer holding whatever was there before,
 * which then got encrypted as if it were file content.
 */
- (long) readFully:(NSInputStream *)inputStream into:(uint8_t *)buffer length:(long)length {
    long total = 0;
    while (total < length) {
        NSInteger read = [inputStream read:buffer + total maxLength:(NSUInteger)(length - total)];
        if (read < 0) return -1;
        if (read == 0) break;
        total += read;
    }
    return total;
}

-(int) transform:(crypto_secretstream_xchacha20poly1305_state)state inputStream:(NSInputStream *)inputStream outputStream:(NSOutputStream *)outputStream inputlength:(NSNumber *)inputLength chunkSize:(long)chunkSize decrypt:(BOOL)decrypt error:(NSError **)error {
    
    unsigned long long length = inputLength.longLongValue;
    
    double totalChunks = fmax(ceilf((float)length/(float)chunkSize), 1);
    
    uint8_t * buffer = malloc(chunkSize);
    unsigned long max_output_chunk_length =  decrypt ? chunkSize - crypto_secretstream_xchacha20poly1305_abytes() :  chunkSize + crypto_secretstream_xchacha20poly1305_abytes();
    uint8_t * output_buffer = malloc(max_output_chunk_length);
    
    for (int i=0;i < totalChunks;i++) {
        long start = i * chunkSize;
        long end = fmin(start + chunkSize, length);
        long chunk_length = end - start;

        long read = [self readFully:inputStream into:buffer length:chunk_length];
        if (read != chunk_length) {
            free(buffer);
            free(output_buffer);
            [outputStream close];
            [inputStream close];
            if (error) *error = NAError(NAErrorCodeFailure, ([NSString stringWithFormat:@"short read on chunk %d of %d: wanted %ld bytes, got %ld (%@)",
                                                              i + 1, (int) totalChunks, chunk_length, read,
                                                              inputStream.streamError.localizedDescription ?: @"end of stream"]));
            return -1;
        }

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
            free(buffer);
            free(output_buffer);
            [outputStream close];
            [inputStream close];
            if (error) *error = NAError(NAErrorCodeFailure, ([NSString stringWithFormat:@"%s failed on chunk %d of %d (chunk %ld bytes, stream %llu bytes)",
                                                              decrypt ? "crypto_secretstream_xchacha20poly1305_pull" : "crypto_secretstream_xchacha20poly1305_push",
                                                              i + 1, (int) totalChunks, chunk_length, length]));
            return result;
        }
        
        NSInteger written = [outputStream write:output_buffer maxLength:output_chunk_length];
        if (written != (NSInteger) output_chunk_length) {
            free(buffer);
            free(output_buffer);
            [outputStream close];
            [inputStream close];
            if (error) *error = NAError(NAErrorCodeFailure, ([NSString stringWithFormat:@"short write on chunk %d of %d: wanted %lu bytes, wrote %ld (%@)",
                                                              i + 1, (int) totalChunks, output_chunk_length, (long) written,
                                                              outputStream.streamError.localizedDescription ?: @"no error reported"]));
            return -1;
        }

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
        if (keySalt == NULL) {
            reject(ESODIUM, @"crypto_pwhash failed while deriving the key from the password", nil);
            return;
        }
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
            reject(ESODIUM, [NSString stringWithFormat:@"encryptMulti: item %d of %d failed: %@", i, size, error.localizedDescription], error);
            return;
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
        if (keySalt == NULL) {
            reject(ESODIUM, @"crypto_pwhash failed while deriving the key from the password", nil);
            return;
        }
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
        if (keySalt == NULL) {
            reject(ESODIUM, @"crypto_pwhash failed while deriving the key from the password", nil);
            return;
        }
        key = (NSData*)[keySalt objectForKey:@"key"];
    }
    NSString* data = [cipher objectForKey:@"cipher"];
    NSData* cipherb = [self b642bin:data];
    
    NSData* iv = [self b642bin:[cipher objectForKey:@"iv"]];
    
    NAAEAD* AEAD = [[NAAEAD alloc] init];
    NSError *error = nil;
    NSData *decryptedData = [AEAD decryptChaCha20Poly1305:cipherb nonce:iv key:key additionalData:NULL error:&error];
    
    if (error != nil) {
        reject(ESODIUM, ERR_FAILURE, error);
    } else if ([[cipher valueForKey:@"output"] isEqual:@"plain"]) {
        resolve([[NSString alloc] initWithData:decryptedData encoding:NSUTF8StringEncoding]);
    } else {
        // Previously fell through without resolving or rejecting, leaving the
        // promise pending forever. Android returns url-safe base64 here.
        resolve([self bin2b64:decryptedData]);
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
            if (keySalt == NULL) {
                reject(ESODIUM, @"crypto_pwhash failed while deriving the key from the password", nil);
                return;
            }
            key = (NSData*)[keySalt objectForKey:@"key"];
        }
        NSString* data = [cipher objectForKey:@"cipher"];
        NSData* cipherb = [self b642bin:data];
        
        NSData* iv = [self b642bin:[cipher objectForKey:@"iv"]];
        
        NAAEAD* AEAD = [[NAAEAD alloc] init];
        NSError *error = nil;
        NSData *decryptedData = [AEAD decryptChaCha20Poly1305:cipherb nonce:iv key:key additionalData:NULL error:&error];
        
        if (error != nil) {
            // Without the return the loop carried on and the next successful
            // item assigned past the end of results, raising NSRangeException
            // and taking the app down.
            reject(ESODIUM, ERR_FAILURE, error);
            return;
        }

        if ([[cipher valueForKey:@"output"] isEqual:@"plain"]) {
            NSString* s = [[NSString alloc] initWithData:decryptedData encoding:NSUTF8StringEncoding];
            if (s == nil) {
                reject(ESODIUM, [NSString stringWithFormat:@"decryptMulti: item %d of %d decrypted to invalid UTF-8", i, size], nil);
                return;
            }
            [results addObject:s];
        } else {
            [results addObject:[self bin2b64:decryptedData]];
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
        if (keySalt == NULL) {
            reject(ESODIUM, @"encryptFile: crypto_pwhash failed while deriving the key from the password", nil);
            return;
        }
        key = (NSData*)[keySalt objectForKey:@"key"];
        salt = (NSData*)[keySalt objectForKey:@"salt"];
        
    }
    NSInputStream *inputStream;
    NSNumber *length;
    NSFileManager *fmngr = [NSFileManager defaultManager];
    NSString *hash = data[@"hash"];
    
    if (hash == nil) {
        NSError *hashError = nil;
        hash = [self xxh64:data error:&hashError];
        if (hash == nil) {
            reject(ESODIUM, hashError.localizedDescription ?: @"encryptFile: could not hash the input", hashError);
            return;
        }
    }
    
    if ([data[@"type"]  isEqual: @"base64"]) {
        NSString *b64String = data[@"data"];
        NSData *b64 = b64String == nil ? nil : [[NSData alloc] initWithBase64EncodedString:b64String options:0];
        if (b64 == nil) {
            reject(ESODIUM, @"encryptFile: type is 'base64' but 'data' is missing or not valid base64", nil);
            return;
        }
        length = [NSNumber numberWithLong:b64.length];
        inputStream = [NSInputStream inputStreamWithData:b64];
    } else {
        NSString *uri = data[@"uri"];
        if (uri == nil || [uri length] == 0) {
            reject(ESODIUM, @"encryptFile: 'uri' is missing", nil);
            return;
        }
        // A missing file reported fileSize 0, which encrypted nothing and still
        // resolved with a valid looking cipher.
        NSError *attributesError = nil;
        NSDictionary *attributes = [fmngr attributesOfItemAtPath:uri error:&attributesError];
        if (attributes == nil) {
            reject(ESODIUM, [NSString stringWithFormat:@"encryptFile: cannot read %@: %@", uri, attributesError.localizedDescription], attributesError);
            return;
        }
        length = [NSNumber numberWithUnsignedLongLong:[attributes fileSize]];
        inputStream = [NSInputStream inputStreamWithFileAtPath:uri];
    }

    if (inputStream == nil) {
        reject(ESODIUM, @"encryptFile: could not open the input stream", nil);
        return;
    }
    
    crypto_secretstream_xchacha20poly1305_state state;
    NSMutableData * header = [[NSMutableData alloc] initWithLength:crypto_secretstream_xchacha20poly1305_HEADERBYTES];
    
    crypto_secretstream_xchacha20poly1305_init_push(&state,(unsigned char *) header.bytes, key.bytes);
    
    NSMutableDictionary *outputDic = [NSMutableDictionary dictionaryWithDictionary:data];
    [outputDic setValue:hash forKey:@"hash"];
    [outputDic setValue:data[@"appGroupId"] forKey:@"appGroupId"];
    NSOutputStream *outputStream = [self getOutputStream:outputDic type:@"file" path:nil];
    if (outputStream == nil) {
        reject(ESODIUM, [NSString stringWithFormat:@"encryptFile: could not create the output file for hash %@", hash], nil);
        return;
    }
    
    [outputStream open];
    [inputStream open];

    // Without this an unopenable destination silently swallowed every write and
    // the call still resolved with metadata for a file that was never written.
    if (outputStream.streamStatus == NSStreamStatusError) {
        NSError *streamError = outputStream.streamError;
        [outputStream close];
        [inputStream close];
        reject(ESODIUM, [NSString stringWithFormat:@"encryptFile: could not open the output file: %@", streamError.localizedDescription], streamError);
        return;
    }
    if (inputStream.streamStatus == NSStreamStatusError) {
        NSError *streamError = inputStream.streamError;
        [outputStream close];
        [inputStream close];
        reject(ESODIUM, [NSString stringWithFormat:@"encryptFile: could not open the input: %@", streamError.localizedDescription], streamError);
        return;
    }
    
    NSError *transformError = nil;
    int result = [self transform:state inputStream:inputStream outputStream:outputStream inputlength:length chunkSize:chunk_size decrypt:false error:&transformError];
    
    if (result != 0) {
        reject(ESODIUM, transformError.localizedDescription ?: ERR_FAILURE, transformError);
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
    // Ciphers written before chunkSize was recorded always used STREAM_CHUNK_SIZE.
    // A nil value used to give longValue 0, leaving chunk_size at just the tag
    // length and turning the loop into millions of 17 byte reads.
    NSNumber *chunkSizeFromCipher = cipher[@"chunkSize"];
    long plain_chunk_size = chunkSizeFromCipher.longValue > 0 ? chunkSizeFromCipher.longValue : STREAM_CHUNK_SIZE;
    long chunk_size = plain_chunk_size + crypto_secretstream_xchacha20poly1305_abytes();
    
    NSData* key;
    if ([passwordOrKey objectForKey:@"key"] && [passwordOrKey objectForKey:@"salt"]) {
        key = [self b642bin:[passwordOrKey objectForKey:@"key"]];
    } else if ([passwordOrKey objectForKey:@"password"] && [cipher objectForKey:@"salt"]) {
        NSMutableDictionary* keySalt = [self crypto_pwhash:[passwordOrKey valueForKey:@"password"] salt:[cipher valueForKey:@"salt"] fallbackKey:false];
        if (keySalt == NULL) {
            reject(ESODIUM, @"crypto_pwhash failed while deriving the key from the password", nil);
            return;
        }
        key = (NSData*)[keySalt objectForKey:@"key"];
    }
    
    NSFileManager *fmngr = [NSFileManager defaultManager];

    NSString *hash = cipher[@"hash"];
    if (hash == nil || [hash length] == 0) {
        reject(ESODIUM, @"decryptFile: 'hash' is missing", nil);
        return;
    }

    NSString *path = [SimpleFilesCache pathForName:hash];
    NSNumber *length = [NSNumber numberWithLong:[[fmngr attributesOfItemAtPath:path error:nil] fileSize]];

    if (length.longValue == 0) {
        // Fall back to the shared app group container. A nil identifier used to
        // produce a nil path and then crash in inputStreamWithFileAtPath:.
        NSString *appGroupId = cipher[@"appGroupId"];
        if (appGroupId == nil || [appGroupId length] == 0) {
            reject(ESODIUM, [NSString stringWithFormat:@"decryptFile: no encrypted file at %@ and no appGroupId to fall back to", path], nil);
            return;
        }

        NSURL *appGroupDir = [fmngr containerURLForSecurityApplicationGroupIdentifier:appGroupId];
        if (appGroupDir == nil) {
            reject(ESODIUM, [NSString stringWithFormat:@"decryptFile: app group '%@' is not available to this process", appGroupId], nil);
            return;
        }

        path = [appGroupDir.path stringByAppendingPathComponent:hash];
        length = [NSNumber numberWithLong:[[fmngr attributesOfItemAtPath:path error:nil] fileSize]];
    }

    if (length.longValue == 0) {
        reject(ESODIUM, [NSString stringWithFormat:@"decryptFile: encrypted file is missing or empty at %@", path], nil);
        return;
    }

    NSInputStream *inputStream = [NSInputStream inputStreamWithFileAtPath:path];
    NSData *iv = [self b642bin:[cipher objectForKey:@"iv"]];
    crypto_secretstream_xchacha20poly1305_state state;
    crypto_secretstream_xchacha20poly1305_init_pull(&state,[iv bytes], [key bytes]);
    NSString *writtenPath = nil;
    NSOutputStream *outputStream = [self getOutputStream:cipher type:type path:&writtenPath];
    if (outputStream == nil) {
        [inputStream close];
        reject(ESODIUM, [NSString stringWithFormat:@"decryptFile: could not create the output for type '%@'", type], nil);
        return;
    }
    [outputStream open];
    if (outputStream.streamStatus == NSStreamStatusError) {
        NSError *streamError = outputStream.streamError;
        [outputStream close];
        [inputStream close];
        reject(ESODIUM, [NSString stringWithFormat:@"decryptFile: could not open the output: %@", streamError.localizedDescription], streamError);
        return;
    }
    [inputStream open];
    
    NSError *transformError = nil;
    int result = [self transform:state inputStream:inputStream outputStream:outputStream inputlength:length chunkSize:chunk_size decrypt:YES error:&transformError];
    
    if (result != 0) {
        [inputStream close];
        [outputStream close];
        reject(ESODIUM, transformError.localizedDescription ?: ERR_FAILURE, transformError);
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
        // Previously resolved nil, forcing callers to rebuild the path themselves.
        resolve(writtenPath);
    }
    [inputStream close];
    [outputStream close];
}

@end
