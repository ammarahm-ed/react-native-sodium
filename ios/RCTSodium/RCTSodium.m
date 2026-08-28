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

// static: these had external linkage and could collide with any other object
// file in the app that defines a symbol of the same name.
/**
 * Values that come from JS are not ordinary Objective-C objects: an explicit
 * null arrives as NSNull rather than nil, and a caller can put any type under
 * any key. Reading one directly and sending it a selector raises
 * NSInvalidArgumentException, which leaves the module as a hard crash instead
 * of a rejected promise. Every read of a caller supplied dictionary goes
 * through these two.
 */
static NSString *NAStringValue(NSDictionary *dictionary, NSString *key) {
    id value = dictionary[key];
    if (value == nil || value == (id)[NSNull null]) return nil;
    return [value isKindOfClass:[NSString class]] ? (NSString *)value : nil;
}

static NSNumber *NANumberValue(NSDictionary *dictionary, NSString *key) {
    id value = dictionary[key];
    if (value == nil || value == (id)[NSNull null]) return nil;
    return [value isKindOfClass:[NSNumber class]] ? (NSNumber *)value : nil;
}

static NSString * const ESODIUM = @"ESODIUM";
static NSString * const ERR_FAILURE = @"FAILURE";
static const long STREAM_CHUNK_SIZE = 512 * 1024;

@implementation RCTSodium {
    // Was a file scope global, so every RCTSodium instance shared one flag.
    BOOL _hasListeners;
}

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

/**
 * Keeps argon2 and whole-file streaming off com.facebook.react.NativeModulesQueue,
 * where they blocked every other native module for the duration of the call.
 *
 * Concurrent is safe now that the xxhash state, the secretstream state and the
 * chunk buffers are all per-call rather than shared.
 */
- (dispatch_queue_t)methodQueue
{
    static dispatch_queue_t queue;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        queue = dispatch_queue_create("com.reactnativesodium.crypto", DISPATCH_QUEUE_CONCURRENT);
    });
    return queue;
}

// Will be called when this module's first listener is added.
-(void)startObserving {
    _hasListeners = YES;
}

// Will be called when this module's last listener is removed, or on dealloc.
-(void)stopObserving {
    _hasListeners = NO;
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

/**
 * Caller supplied payloads are decoded leniently: android decoded these with the
 * url-safe alphabet while iOS used the standard one and additionally rejected
 * unpadded input, so the same value worked on one platform and failed on the
 * other. Cipher fields keep using the strict url-safe variant.
 */
- (NSData*) b642binAny:(NSString*)b64 {
    if (b64 == nil) return nil;
    NSMutableString *normalized = [NSMutableString stringWithString:b64];
    NSRange all = NSMakeRange(0, normalized.length);
    [normalized replaceOccurrencesOfString:@"-" withString:@"+" options:0 range:all];
    all = NSMakeRange(0, normalized.length);
    [normalized replaceOccurrencesOfString:@"_" withString:@"/" options:0 range:all];
    while (normalized.length % 4 != 0) [normalized appendString:@"="];
    return [[NSData alloc] initWithBase64EncodedString:normalized options:0];
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

    // crypto_pwhash always reads crypto_pwhash_SALTBYTES from this pointer, so
    // a salt that decodes to anything shorter reads past the end of the buffer
    // and a nil one reads from NULL.
    if (dsalt == nil || [dsalt length] != dsalt_len) {
        return NULL;
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

/**
 * Single place that turns { key, salt } or { password } into a key.
 *
 * Previously each method inlined this and left `key` nil when neither form was
 * supplied, which reached libsodium as a NULL key pointer. A key of the wrong
 * length was passed through unchecked as well.
 *
 * allowNewSalt is YES for encryption, where a missing salt means "generate one",
 * and NO for decryption, where it means the cipher is unusable.
 */
- (NSData *) keyFor:(NSDictionary *)passwordOrKey cipherSalt:(NSString *)cipherSalt allowNewSalt:(BOOL)allowNewSalt salt:(NSData **)outSalt error:(NSError **)error {
    NSString *keyB64 = NAStringValue(passwordOrKey, @"key");
    NSString *saltB64 = NAStringValue(passwordOrKey, @"salt");
    NSString *password = NAStringValue(passwordOrKey, @"password");

    if (keyB64 != nil && saltB64 != nil) {
        NSData *key = [self b642bin:keyB64];
        if (key == nil) {
            if (error) *error = NAError(NAErrorCodeInvalidKey, @"getKey: 'key' is not valid url-safe base64");
            return nil;
        }
        if ([key length] != KEY_LEN) {
            if (error) *error = NAError(NAErrorCodeInvalidKey, ([NSString stringWithFormat:@"getKey: 'key' must decode to %d bytes but decoded to %lu", KEY_LEN, (unsigned long)[key length]]));
            return nil;
        }
        if (outSalt) *outSalt = [self b642bin:saltB64];
        return key;
    }

    if (password != nil) {
        if (!allowNewSalt && cipherSalt == nil) {
            if (error) *error = NAError(NAErrorCodeInvalidSalt, @"getKey: a password was given but the cipher carries no salt to derive the key with");
            return nil;
        }
        NSMutableDictionary *keySalt = [self crypto_pwhash:password salt:cipherSalt fallbackKey:false];
        if (keySalt == NULL) {
            if (error) *error = NAError(NAErrorCodeFailure, @"getKey: crypto_pwhash failed");
            return nil;
        }
        if (outSalt) *outSalt = (NSData *)keySalt[@"salt"];
        return (NSData *)keySalt[@"key"];
    }

    if (error) *error = NAError(NAErrorCodeInvalidKey, ([NSString stringWithFormat:@"getKey: expected { key, salt } or { password }, but got key=%@ salt=%@ password=%@",
                                                        keyB64 ? @"present" : @"missing",
                                                        saltB64 ? @"present" : @"missing",
                                                        password ? @"present" : @"missing"]));
    return nil;
}

RCT_EXPORT_METHOD(sodium_version_string:(RCTPromiseResolveBlock)resolve reject:(RCTPromiseRejectBlock)reject) {
    NAChlorideInit();
    resolve([NSString stringWithUTF8String:sodium_version_string()]);
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
    
    if ([NAStringValue(data, @"type") isEqualToString:@"base64"]) {
        NSString *b64String = NAStringValue(data, @"data");
        if (b64String == nil) {
            if (error) *error = NAError(NAErrorCodeInvalidData, @"hashFile: type is 'base64' but 'data' is missing");
            return nil;
        }
        NSData *b64 = [self b642binAny:b64String];
        if (b64 == nil) {
            if (error) *error = NAError(NAErrorCodeInvalidData, @"hashFile: 'data' is not valid base64");
            return nil;
        }
        length = [NSNumber numberWithLong:b64.length];
        inputStream = [NSInputStream inputStreamWithData:b64];
    } else {
        NSString *uri = NAStringValue(data, @"uri");
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
    if (NAStringValue(data, @"iv") != nil) {
        if ([type isEqualToString:@"text"] || [type isEqualToString:@"base64"]) {
            outputStream = [[NSOutputStream alloc] initToMemory];
        } else if ([type isEqualToString:@"cache"]) {
            
            NSFileManager *fmngr = [NSFileManager defaultManager];
            NSString *cacheHash = NAStringValue(data, @"hash");
            if (cacheHash == nil) return nil;
            NSMutableString *path = [NSMutableString stringWithString:cacheHash];
            [path appendString:@"_dcache"];
            NSString *outputPath = [SimpleFilesCache pathForName:path];
            [self removeFileIfExists:path];
            [fmngr createFileAtPath:outputPath contents:nil attributes:nil];
            outputStream = [NSOutputStream outputStreamToFileAtPath:outputPath append:NO];
            if (outPath) *outPath = outputPath;
        } else {
            NSString *directory = NAStringValue(data, @"uri");
            NSString *fileName = NAStringValue(data, @"fileName");
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
        NSString *outputHash = NAStringValue(data, @"hash");
        if (outputHash == nil) return nil;
        NSString *appGroupId = NAStringValue(data, @"appGroupId");
        if (appGroupId != nil) {
            NSURL *appGroupUrl = [fmngr containerURLForSecurityApplicationGroupIdentifier:appGroupId];
            if (appGroupUrl == nil) return nil;
            outputPath = [appGroupUrl.path stringByAppendingPathComponent:outputHash];
            if ([fmngr fileExistsAtPath:outputPath]) {
                [fmngr removeItemAtPath:outputPath error:nil];
            }
        } else {
            outputPath = [SimpleFilesCache pathForName:outputHash];
            [self removeFileIfExists:outputHash];
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
    if (_hasListeners) {
        [self sendEventWithName:@"onSodiumProgress" body:@{@"total": [NSNumber numberWithDouble:total],@"progress":[NSNumber numberWithInt:progress]}];
    }
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
    
    NSData* salt = nil;
    NSError* keyError = nil;
    NSData* key = [self keyFor:passwordOrKey cipherSalt:nil allowNewSalt:YES salt:&salt error:&keyError];
    if (key == nil) {
        reject(ESODIUM, keyError.localizedDescription, keyError);
        return;
    }
    
    for (int i=0;i < size; i++) {
        NSDictionary *data = array[i];
        
        NSData *ddata;
        
        NSString *payload = NAStringValue(data, @"data");
        if (payload == nil) {
            reject(ESODIUM, [NSString stringWithFormat:@"encryptMulti: item %d of %d has no 'data'", i, size], nil);
            return;
        }
        if ([NAStringValue(data, @"type") isEqualToString:@"b64"]) {
            ddata = [self b642binAny:payload];
            if (ddata == nil) {
                reject(ESODIUM, [NSString stringWithFormat:@"encryptMulti: item %d of %d has 'data' that is not valid base64", i, size], nil);
                return;
            }
        } else {
            ddata = [payload dataUsingEncoding:NSUTF8StringEncoding];
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
    
    NSData* salt = nil;
    NSError* keyError = nil;
    NSData* key = [self keyFor:passwordOrKey cipherSalt:nil allowNewSalt:YES salt:&salt error:&keyError];
    if (key == nil) {
        reject(ESODIUM, keyError.localizedDescription, keyError);
        return;
    }
    
    NSData *ddata;
    
    NSString *payload = NAStringValue(data, @"data");
    if (payload == nil) {
        reject(ESODIUM, @"encrypt: 'data' is missing", nil);
        return;
    }
    if ([NAStringValue(data, @"type") isEqualToString:@"b64"]) {
        ddata = [self b642binAny:payload];
        if (ddata == nil) {
            reject(ESODIUM, @"encrypt: 'data' is not valid base64", nil);
            return;
        }
    } else {
        ddata = [payload dataUsingEncoding:NSUTF8StringEncoding];
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
    
    
    NSError* keyError = nil;
    NSData* key = [self keyFor:passwordOrKey cipherSalt:NAStringValue(cipher, @"salt") allowNewSalt:NO salt:nil error:&keyError];
    if (key == nil) {
        reject(ESODIUM, keyError.localizedDescription, keyError);
        return;
    }

    NSString* cipherB64 = NAStringValue(cipher, @"cipher");
    if (cipherB64 == nil) {
        reject(ESODIUM, @"decrypt: 'cipher' is missing", nil);
        return;
    }
    NSString* ivB64 = NAStringValue(cipher, @"iv");
    if (ivB64 == nil) {
        reject(ESODIUM, @"decrypt: 'iv' is missing", nil);
        return;
    }

    NSData* cipherb = [self b642bin:cipherB64];
    NSData* iv = [self b642bin:ivB64];
    
    NAAEAD* AEAD = [[NAAEAD alloc] init];
    NSError *error = nil;
    NSData *decryptedData = [AEAD decryptChaCha20Poly1305:cipherb nonce:iv key:key additionalData:NULL error:&error];
    
    if (error != nil) {
        reject(ESODIUM, ERR_FAILURE, error);
    } else if ([NAStringValue(cipher, @"output") isEqualToString:@"plain"]) {
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
    NSString* cachedSalt = nil;
    NSData* cachedKey = nil;

    for (int i=0;i < size; i++) {
        
        NSDictionary *cipher = data[i];
        
        // Cached across items: a batch sharing one salt used to run argon2i
        // (8 MiB, 3 passes) once per element.
        NSString* cipherSalt = NAStringValue(cipher, @"salt");
        if (cachedKey == nil || !(cachedSalt == cipherSalt || [cachedSalt isEqualToString:cipherSalt])) {
            NSError* keyError = nil;
            cachedKey = [self keyFor:passwordOrKey cipherSalt:cipherSalt allowNewSalt:NO salt:nil error:&keyError];
            if (cachedKey == nil) {
                reject(ESODIUM, keyError.localizedDescription, keyError);
                return;
            }
            cachedSalt = cipherSalt;
        }
        NSData* key = cachedKey;
        NSString* cipherB64 = NAStringValue(cipher, @"cipher");
        if (cipherB64 == nil) {
            reject(ESODIUM, [NSString stringWithFormat:@"decryptMulti: item %d of %d has no 'cipher'", i, size], nil);
            return;
        }
        NSString* ivB64 = NAStringValue(cipher, @"iv");
        if (ivB64 == nil) {
            reject(ESODIUM, [NSString stringWithFormat:@"decryptMulti: item %d of %d has no 'iv'", i, size], nil);
            return;
        }

        NSData* cipherb = [self b642bin:cipherB64];
        NSData* iv = [self b642bin:ivB64];
        
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

        if ([NAStringValue(cipher, @"output") isEqualToString:@"plain"]) {
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
    NSData* salt = nil;
    NSError* keyError = nil;
    NSData* key = [self keyFor:passwordOrKey cipherSalt:nil allowNewSalt:YES salt:&salt error:&keyError];
    if (key == nil) {
        reject(ESODIUM, keyError.localizedDescription, keyError);
        return;
    }
    NSInputStream *inputStream;
    NSNumber *length;
    NSFileManager *fmngr = [NSFileManager defaultManager];
    NSString *hash = NAStringValue(data, @"hash");
    
    if (hash == nil) {
        NSError *hashError = nil;
        hash = [self xxh64:data error:&hashError];
        if (hash == nil) {
            reject(ESODIUM, hashError.localizedDescription ?: @"encryptFile: could not hash the input", hashError);
            return;
        }
    }
    
    if ([NAStringValue(data, @"type") isEqualToString:@"base64"]) {
        NSString *b64String = NAStringValue(data, @"data");
        NSData *b64 = [self b642binAny:b64String];
        if (b64 == nil) {
            reject(ESODIUM, @"encryptFile: type is 'base64' but 'data' is missing or not valid base64", nil);
            return;
        }
        length = [NSNumber numberWithLong:b64.length];
        inputStream = [NSInputStream inputStreamWithData:b64];
    } else {
        NSString *uri = NAStringValue(data, @"uri");
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
    [outputDic setValue:NAStringValue(data, @"appGroupId") forKey:@"appGroupId"];
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
    NSNumber *chunkSizeFromCipher = NANumberValue(cipher, @"chunkSize");
    long plain_chunk_size = chunkSizeFromCipher.longValue > 0 ? chunkSizeFromCipher.longValue : STREAM_CHUNK_SIZE;
    long chunk_size = plain_chunk_size + crypto_secretstream_xchacha20poly1305_abytes();
    
    NSError* keyError = nil;
    NSData* key = [self keyFor:passwordOrKey cipherSalt:NAStringValue(cipher, @"salt") allowNewSalt:NO salt:nil error:&keyError];
    if (key == nil) {
        reject(ESODIUM, keyError.localizedDescription, keyError);
        return;
    }
    
    NSFileManager *fmngr = [NSFileManager defaultManager];

    NSString *hash = NAStringValue(cipher, @"hash");
    if (hash == nil || [hash length] == 0) {
        reject(ESODIUM, @"decryptFile: 'hash' is missing", nil);
        return;
    }

    NSString *path = [SimpleFilesCache pathForName:hash];
    NSNumber *length = [NSNumber numberWithLong:[[fmngr attributesOfItemAtPath:path error:nil] fileSize]];

    if (length.longValue == 0) {
        // Fall back to the shared app group container. A nil identifier used to
        // produce a nil path and then crash in inputStreamWithFileAtPath:.
        NSString *appGroupId = NAStringValue(cipher, @"appGroupId");
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
    NSString *ivB64 = NAStringValue(cipher, @"iv");
    if (ivB64 == nil) {
        reject(ESODIUM, @"decryptFile: 'iv' is missing", nil);
        return;
    }
    NSData *iv = [self b642bin:ivB64];
    if ([iv length] != crypto_secretstream_xchacha20poly1305_HEADERBYTES) {
        reject(ESODIUM, [NSString stringWithFormat:@"decryptFile: 'iv' must decode to %d bytes but decoded to %lu",
                         (int) crypto_secretstream_xchacha20poly1305_HEADERBYTES, (unsigned long) [iv length]], nil);
        return;
    }
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
        NSMutableString *path = [NSMutableString stringWithString:hash];
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
