#import <Foundation/Foundation.h>
#import <SystemExtensions/SystemExtensions.h>
#import <NetworkExtension/NetworkExtension.h>
#import <Security/Security.h>
#import <Security/SecTask.h>
#include <stdlib.h>
#include <string.h>

static NSString *const endpointID=@"dev.agentmonitor.endpoint";
static NSString *const networkID=@"dev.agentmonitor.network";
static NSMutableDictionary<NSString *,NSString *> *states;
static NSMutableDictionary<NSString *,NSString *> *errors;
static NSMutableDictionary<NSString *,NSDictionary *> *bundleChecks;
static BOOL entitled(NSString *key) {
    SecTaskRef task=SecTaskCreateFromSelf(kCFAllocatorDefault);
    if (!task) return NO;
    CFTypeRef value=SecTaskCopyValueForEntitlement(task,(__bridge CFStringRef)key,NULL);
    BOOL result=value && CFGetTypeID(value)==CFBooleanGetTypeID() && CFBooleanGetValue(value);
    if(value) CFRelease(value);CFRelease(task);return result;
}
@interface MonitorExtensionDelegate:NSObject<OSSystemExtensionRequestDelegate>
@end
@implementation MonitorExtensionDelegate
-(void)requestNeedsUserApproval:(OSSystemExtensionRequest *)request {states[request.identifier]=@"approval_required";}
-(void)request:(OSSystemExtensionRequest *)request didFinishWithResult:(OSSystemExtensionRequestResult)result {states[request.identifier]=result==OSSystemExtensionRequestCompleted?@"activated":@"restart_required";}
-(void)request:(OSSystemExtensionRequest *)request didFailWithError:(NSError *)error {states[request.identifier]=@"failed";errors[request.identifier]=error.localizedDescription;}
-(OSSystemExtensionReplacementAction)request:(OSSystemExtensionRequest *)request actionForReplacingExtension:(OSSystemExtensionProperties *)existing withExtension:(OSSystemExtensionProperties *)replacement {
    (void)request;(void)existing;(void)replacement;return OSSystemExtensionReplacementActionReplace;
}
@end
static MonitorExtensionDelegate *delegate;
static void setup(void){if(!states){states=[NSMutableDictionary new];errors=[NSMutableDictionary new];bundleChecks=[NSMutableDictionary new];delegate=[MonitorExtensionDelegate new];}}
static NSDictionary *component(NSString *identifier, NSString *entitlement) {
    NSDictionary *cached=bundleChecks[identifier];
    if(cached) { NSMutableDictionary *result=[cached mutableCopy];result[@"activation"]=states[identifier]?:@"not_requested";result[@"error"]=errors[identifier]?:@"";return result; }
    NSString *path=[NSBundle.mainBundle.bundlePath stringByAppendingPathComponent:[NSString stringWithFormat:@"Contents/Library/SystemExtensions/%@.systemextension",identifier]];
    NSBundle *bundle=[NSBundle bundleWithPath:path];
    BOOL signedOK=NO;BOOL localSignature=NO;BOOL extensionEntitled=NO;
    if(bundle && [bundle.bundleIdentifier isEqualToString:identifier]) {
        SecStaticCodeRef code=NULL;
        if(SecStaticCodeCreateWithPath((__bridge CFURLRef)[NSURL fileURLWithPath:path],kSecCSDefaultFlags,&code)==errSecSuccess){
            signedOK=SecStaticCodeCheckValidity(code,kSecCSStrictValidate,NULL)==errSecSuccess;localSignature=signedOK;
            CFDictionaryRef information=NULL;
            if(SecCodeCopySigningInformation(code,kSecCSSigningInformation,&information)==errSecSuccess){
                NSDictionary *info=CFBridgingRelease(information);
                id value=info[(__bridge NSString *)kSecCodeInfoEntitlementsDict][entitlement];
                extensionEntitled=[value isKindOfClass:NSNumber.class] ? [value boolValue] : [value isKindOfClass:NSArray.class] && [value containsObject:@"content-filter-provider-systemextension"];
                // Ad-hoc signatures are not distributable system extension identities.
                signedOK=signedOK && [info[(__bridge NSString *)kSecCodeInfoTeamIdentifier] length]>0;
            }
            CFRelease(code);
        }
    }
    NSDictionary *result=@{@"identifier":identifier,@"bundled":@(bundle!=nil),@"signed":@(signedOK),@"local_signed":@(localSignature),@"entitled":@(extensionEntitled),@"activation":states[identifier]?:@"not_requested",@"error":errors[identifier]?:@""};
    bundleChecks[identifier]=result;return result;
}
static BOOL hostSigned(void){
    SecCodeRef code=NULL;CFDictionaryRef information=NULL;BOOL valid=NO;
    if(SecCodeCopySelf(kSecCSDefaultFlags,&code)==errSecSuccess){
        if(SecCodeCheckValidity(code,kSecCSStrictValidate,NULL)==errSecSuccess && SecCodeCopySigningInformation(code,kSecCSSigningInformation,&information)==errSecSuccess){
            NSDictionary *info=CFBridgingRelease(information);
            valid=[info[(__bridge NSString *)kSecCodeInfoTeamIdentifier] length]>0;
        }
        CFRelease(code);
    }
    return valid;
}
char *monitor_system_extensions_status(void){
    __block NSData *data;
    void (^work)(void)=^{setup();NSDictionary *result=@{@"supported":@YES,@"host_signed":@(hostSigned()),@"host_entitled":@(entitled(@"com.apple.developer.system-extension.install")),@"endpoint":component(endpointID,@"com.apple.developer.endpoint-security.client"),@"network":component(networkID,@"com.apple.developer.networking.networkextension")};data=[NSJSONSerialization dataWithJSONObject:result options:0 error:NULL];};
    if(NSThread.isMainThread)work();else dispatch_sync(dispatch_get_main_queue(),work);
    return strdup([[NSString alloc]initWithData:data encoding:NSUTF8StringEncoding].UTF8String?:"{}");
}
// Called only from an explicit UI action. No root shell command or SIP change.
int monitor_activate_system_extension(int kind, int development){
    __block int result=0;
    void (^work)(void)=^{
        setup();if(kind!=0&&kind!=1){result=1;return;}
        NSString *identifier=kind==0?endpointID:networkID;
        if(!entitled(@"com.apple.developer.system-extension.install")){result=2;return;}
        NSDictionary *info=component(identifier,kind==0?@"com.apple.developer.endpoint-security.client":@"com.apple.developer.networking.networkextension");
        if(![info[@"bundled"] boolValue]||!([info[@"signed"] boolValue]||(development&&[info[@"local_signed"] boolValue]))||![info[@"entitled"] boolValue]){result=3;return;}
        if([states[identifier] isEqualToString:@"activating"]||[states[identifier] isEqualToString:@"approval_required"]){return;}
        states[identifier]=@"activating";[errors removeObjectForKey:identifier];
        OSSystemExtensionRequest *request=[OSSystemExtensionRequest activationRequestForExtension:identifier queue:dispatch_get_main_queue()];
        request.delegate=delegate;[OSSystemExtensionManager.sharedManager submitRequest:request];
    };
    if(NSThread.isMainThread)work();else dispatch_sync(dispatch_get_main_queue(),work);
    return result;
}

// API keys stay in the login keychain. They are never returned to the WebView.
static NSDictionary *jevQuery(const char *account){return @{(__bridge id)kSecClass:(__bridge id)kSecClassGenericPassword,(__bridge id)kSecAttrService:@"Monitor.Jev",(__bridge id)kSecAttrAccount:[NSString stringWithUTF8String:account]};}
int monitor_jev_key_exists(const char *account){@autoreleasepool{return (int)SecItemCopyMatching((__bridge CFDictionaryRef)jevQuery(account),NULL);}}
int monitor_jev_key_save(const char *account,const char *key){@autoreleasepool{
    NSDictionary *query=jevQuery(account);NSData *data=[[NSString stringWithUTF8String:key] dataUsingEncoding:NSUTF8StringEncoding];
    if(data.length==0){OSStatus result=SecItemDelete((__bridge CFDictionaryRef)query);return result==errSecItemNotFound?0:(int)result;}
    NSDictionary *attributes=@{(__bridge id)kSecValueData:data};
    OSStatus result=SecItemUpdate((__bridge CFDictionaryRef)query,(__bridge CFDictionaryRef)attributes);
    if(result==errSecItemNotFound){NSMutableDictionary *item=[query mutableCopy];[item addEntriesFromDictionary:attributes];result=SecItemAdd((__bridge CFDictionaryRef)item,NULL);}
    return (int)result;
}}
int monitor_jev_key_get(const char *account,char **result){@autoreleasepool{
    *result=NULL;NSMutableDictionary *query=[jevQuery(account) mutableCopy];query[(__bridge id)kSecReturnData]=@YES;
    CFTypeRef value=NULL;OSStatus status=SecItemCopyMatching((__bridge CFDictionaryRef)query,&value);
    if(status!=errSecSuccess)return (int)status;
    NSData *data=CFBridgingRelease(value);NSString *key=[[NSString alloc]initWithData:data encoding:NSUTF8StringEncoding];
    if(!key)return (int)errSecDecode;*result=strdup(key.UTF8String);return *result?0:(int)errSecAllocate;
}}


// Activation and enabling the content-filter configuration are separate user actions.
char *monitor_set_network_filter(int enabled){
    @autoreleasepool {
        __block NSString *failure=nil;
        dispatch_semaphore_t done=dispatch_semaphore_create(0);
        NEFilterManager *manager=NEFilterManager.sharedManager;
        [manager loadFromPreferencesWithCompletionHandler:^(NSError *error){
            if(error){failure=error.localizedDescription;dispatch_semaphore_signal(done);return;}
            if(enabled){
                NEFilterProviderConfiguration *configuration=[NEFilterProviderConfiguration new];
                configuration.filterSockets=YES;
                configuration.filterDataProviderBundleIdentifier=networkID;
                manager.providerConfiguration=configuration;
                manager.localizedDescription=@"Monitor Agent Network Protection";
                manager.grade=NEFilterManagerGradeFirewall;
            }
            manager.enabled=enabled!=0;
            [manager saveToPreferencesWithCompletionHandler:^(NSError *saveError){failure=saveError.localizedDescription;dispatch_semaphore_signal(done);}];
        }];
        if(dispatch_semaphore_wait(done,dispatch_time(DISPATCH_TIME_NOW,30*NSEC_PER_SEC))!=0)return strdup("Network filter authorization timed out; check System Settings");
        return failure?strdup(failure.UTF8String):NULL;
    }
}
