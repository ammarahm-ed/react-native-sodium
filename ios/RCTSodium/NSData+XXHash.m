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
    
    static XXH3_state_t * state = NULL;
    
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        state = XXH3_createState();
    });
    XXH_errorcode ec = XXH3_64bits_reset(state);
    if (ec != XXH_OK) {
        @throw NSGenericException;
    }
    ec = XXH3_64bits_update(state, [self bytes], [self length]);
    if (ec != XXH_OK) {
        @throw NSGenericException;
    }
    unsigned long long val = XXH3_64bits_digest(state);
    return [NSString stringWithFormat:@"%llx", val];
}


@end
