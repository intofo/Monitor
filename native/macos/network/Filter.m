#import <Foundation/Foundation.h>
#import <NetworkExtension/NetworkExtension.h>
#include <bsm/libbsm.h>
#include <netinet/in.h>
extern int monitor_network_reload(void);
extern uint32_t monitor_network_decide(uint32_t,uint32_t,uint32_t,const char *,const char *,uint16_t,uint32_t);
@interface MonitorNetworkFilter : NEFilterDataProvider
@property dispatch_source_t reloadTimer;
@end
@implementation MonitorNetworkFilter
-(void)startFilterWithCompletionHandler:(void (^)(NSError *))completion {
    dispatch_queue_t queue=dispatch_queue_create("dev.agentmonitor.network.rules",DISPATCH_QUEUE_SERIAL);
    dispatch_async(queue, ^{
        if(monitor_network_reload()!=0){completion([NSError errorWithDomain:@"Monitor.Network" code:1 userInfo:@{NSLocalizedDescriptionKey:@"Trusted Endpoint Security process registry is unavailable"}]);return;}
        self.reloadTimer=dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER,0,0,queue);
        dispatch_source_set_timer(self.reloadTimer,dispatch_time(DISPATCH_TIME_NOW,NSEC_PER_SEC),NSEC_PER_SEC,NSEC_PER_MSEC*100);
        dispatch_source_set_event_handler(self.reloadTimer, ^{(void)monitor_network_reload();});
        dispatch_resume(self.reloadTimer);
        // NE defaults bypass loopback; explicit rules are required to prevent a
        // monitored Agent using a localhost proxy to escape its network policy.
        NSMutableArray *rules=[NSMutableArray new];
        for(NSString *address in @[@"127.0.0.0",@"::1"]){
            NENetworkRule *network=[[NENetworkRule alloc]initWithRemoteNetwork:[NWHostEndpoint endpointWithHostname:address port:@"0"] remotePrefix:[address containsString:@":"]?128:8 localNetwork:nil localPrefix:0 protocol:NENetworkRuleProtocolAny direction:NETrafficDirectionOutbound];
            [rules addObject:[[NEFilterRule alloc]initWithNetworkRule:network action:NEFilterActionFilterData]];
        }
        [self applySettings:[[NEFilterSettings alloc]initWithRules:rules defaultAction:NEFilterActionFilterData] completionHandler:completion];
    });
}
-(void)stopFilterWithReason:(NEProviderStopReason)reason completionHandler:(void (^)(void))completion {
    (void)reason;if(self.reloadTimer){dispatch_source_cancel(self.reloadTimer);self.reloadTimer=nil;}completion();
}
-(uint32_t)decision:(NEFilterFlow *)flow {
    if(flow.direction!=NETrafficDirectionOutbound)return 0;
    NSData *source=flow.sourceAppAuditToken;
    if(source.length!=sizeof(audit_token_t))return 0;
    audit_token_t token;memcpy(&token,source.bytes,sizeof(token));
    if(![flow isKindOfClass:NEFilterSocketFlow.class])return 0;
    NEFilterSocketFlow *socket=(NEFilterSocketFlow *)flow;
    NWEndpoint *remote=socket.remoteEndpoint;
    if(![remote isKindOfClass:NWHostEndpoint.class])return 1;
    NWHostEndpoint *host=(NWHostEndpoint *)remote;
    NSInteger port=host.port.integerValue;
    return monitor_network_decide(audit_token_to_pid(token),audit_token_to_pidversion(token),audit_token_to_ruid(token),host.hostname.UTF8String,socket.remoteHostname.UTF8String,(port>0&&port<=65535)?(uint16_t)port:0,(uint32_t)socket.socketProtocol);
}
-(NEFilterNewFlowVerdict *)handleNewFlow:(NEFilterFlow *)flow {
    if([self decision:flow]!=0)return [NEFilterNewFlowVerdict dropVerdict];
    // Re-check on subsequent outbound data, including heartbeat expiry. Do not
    // inspect or persist payload contents; TLS plaintext is not available here.
    return [NEFilterNewFlowVerdict filterDataVerdictWithFilterInbound:NO peekInboundBytes:0 filterOutbound:YES peekOutboundBytes:1];
}
-(NEFilterDataVerdict *)handleOutboundDataFromFlow:(NEFilterFlow *)flow readBytesStartOffset:(NSUInteger)offset readBytes:(NSData *)bytes {
    (void)offset;
    if([self decision:flow]!=0)return [NEFilterDataVerdict dropVerdict];
    return [NEFilterDataVerdict dataVerdictWithPassBytes:bytes.length peekBytes:1];
}
-(NEFilterDataVerdict *)handleInboundDataFromFlow:(NEFilterFlow *)flow readBytesStartOffset:(NSUInteger)offset readBytes:(NSData *)bytes {
    (void)flow;(void)offset;(void)bytes;return [NEFilterDataVerdict allowVerdict];
}
@end
int main(int argc,const char *argv[]){
    @autoreleasepool {
        if(argc==2&&strcmp(argv[1],"--check")==0){puts("{\"component\":\"network\",\"enforcement_active\":false}");return 0;}
        [NEProvider startSystemExtensionMode];dispatch_main();
    }
}
