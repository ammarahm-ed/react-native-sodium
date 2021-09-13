//
//  RCTSodium.h
//
//  Created by Lyubomir Ivanov on 9/25/16.
//  Copyright © 2016 Lyubomir Ivanov. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface RCTSodium : NSObject <RCTBridgeModule>

- (NSDictionary *)_encryptFile:(NSDictionary*)passwordOrKey data:(NSData *)data;

@end
