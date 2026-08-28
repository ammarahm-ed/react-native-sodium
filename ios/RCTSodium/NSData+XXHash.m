//
//  NSData+XXHash.m
//  xxHash-ObjC
//
//  Created by Matthew Smith on 3/24/16.
//  Copyright © 2016 Latte, Jed?. All rights reserved.
//

#import "NSData+XXHash.h"
#import "xxh3.h"

@implementation NSData (XXHash)

- (NSString *)xxh3 {
    
    XXH3_state_t * state = XXH3_createState();
    if (state == NULL) {
        return nil;
    }
    XXH_errorcode ec = XXH3_64bits_reset(state);
    if (ec != XXH_OK) {
        XXH3_freeState(state);
        return nil;
    }
    ec = XXH3_64bits_update(state, [self bytes], [self length]);
    if (ec != XXH_OK) {
        XXH3_freeState(state);
        return nil;
    }
    unsigned long long val = XXH3_64bits_digest(state);
    XXH3_freeState(state);
    return [NSString stringWithFormat:@"%llx", val];
}

- (NSString *)xxh64 {
    
    XXH64_state_t* state = XXH64_createState();
    if (state == NULL) {
        return nil;
    }

    XXH_errorcode ec = XXH64_reset(state, 0x5bd1e995);

    if (ec != XXH_OK) {
        XXH64_freeState(state);
        return nil;
    }
    ec = XXH64_update (state, [self bytes], [self length]);
    if (ec != XXH_OK) {
        XXH64_freeState(state);
        return nil;
    }
    unsigned long long val = XXH64_digest(state);
    XXH64_freeState(state);
    return [NSString stringWithFormat:@"%llx", val];
}


@end
