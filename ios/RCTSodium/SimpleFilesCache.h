//
//  SimpleFilesCache.h
//

#import <Foundation/Foundation.h>

///
/// A static class for basic management of the NSCachesDirectory contents
///
@interface SimpleFilesCache : NSObject

// Data save/read

+(void)saveToCacheDirectory:(NSData *)data withName:(NSString *)name;
+(NSData *)cachedDataWithName:(NSString *)name;

// Image save/read

+(void)saveImageToCacheDirectory:(UIImage *)image withName:(NSString *)name;
+(UIImage *)cachedImageWithName:(NSString *)name;

//
-(id)initWithNamespace:(NSString *)cacheNamespace;

-(void)saveToCacheDirectory:(NSData *)data withName:(NSString *)name;
-(NSData *)cachedDataWithName:(NSString *)name;

-(void)saveImageToCacheDirectory:(UIImage *)image withName:(NSString *)name;
-(UIImage *)cachedImageWithName:(NSString *)name;

@end
