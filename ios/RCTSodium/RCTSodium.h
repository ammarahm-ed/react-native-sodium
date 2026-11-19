//
//  RCTSodium.h
//
//  Created by Lyubomir Ivanov on 9/25/16.
//  Copyright © 2016 Lyubomir Ivanov. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <React/RCTEventEmitter.h>

#ifdef RCT_NEW_ARCH_ENABLED
#import <RNSodiumSpec/RNSodiumSpec.h>
@interface RCTSodium : RCTEventEmitter <NativeSodiumSpec>
#else
@interface RCTSodium : RCTEventEmitter <RCTBridgeModule>
#endif

@end
