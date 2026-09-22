#include "endpoint.h"
#include <EndpointSecurity/EndpointSecurity.h>
#include <Security/SecTask.h>
#include <CoreFoundation/CoreFoundation.h>
#include <bsm/libbsm.h>
#include <Security/CSCommon.h>
#include <sys/fcntl.h>
#include <sys/stat.h>
#include <dispatch/dispatch.h>
#include <signal.h>
#include <stdatomic.h>
#include <string.h>
#include <unistd.h>

static mon_text text(es_string_token_t token) { return (mon_text){(const unsigned char *)token.data, token.length}; }
static mon_process process(const es_process_t *p) {
    mon_process result = {0};
    if (!p) return result;
    result.pid = audit_token_to_pid(p->audit_token);
    result.version = audit_token_to_pidversion(p->audit_token);
    result.uid = audit_token_to_ruid(p->audit_token);
    result.valid_signature = (p->codesigning_flags & kSecCodeStatusValid) != 0;
    result.executable = text(p->executable->path);
    if (p->executable->path_truncated) result.executable.length = 0;
    result.signing_id = text(p->signing_id);
    result.team_id = text(p->team_id);
    memcpy(result.cdhash, p->cdhash, sizeof(result.cdhash));
    return result;
}
uint32_t mon_preflight(void) {
    uint32_t flags = geteuid() == 0 ? 2 : 0;
    SecTaskRef task = SecTaskCreateFromSelf(kCFAllocatorDefault);
    if (task) {
        CFTypeRef value = SecTaskCopyValueForEntitlement(task, CFSTR("com.apple.developer.endpoint-security.client"), NULL);
        if (value) { if (CFGetTypeID(value) == CFBooleanGetTypeID() && CFBooleanGetValue(value)) flags |= 1; CFRelease(value); }
        CFRelease(task);
    }
    return flags;
}
size_t mon_event_size(void) { return sizeof(mon_event); }
int mon_run(void *context, mon_decide decide, mon_result completed) {
    es_client_t *client = NULL;
    __block _Atomic int fatal = 0;
    CFRunLoopRef loop = CFRunLoopGetCurrent();
    es_new_client_result_t created = es_new_client(&client, ^(es_client_t *c, const es_message_t *message) {
        mon_event event = {0};
        event.process = process(message->process);
        if (message->version >= 4) { event.has_sequence = 1; event.sequence = message->global_seq_num; }
        const es_file_t *file = NULL;
        switch (message->event_type) {
            case ES_EVENT_TYPE_AUTH_OPEN: event.kind=0; file=message->event.open.file; event.readable=(message->event.open.fflag & FREAD) != 0; break;
            case ES_EVENT_TYPE_AUTH_MMAP: event.kind=1; file=message->event.mmap.source; event.readable=1; break;
            case ES_EVENT_TYPE_AUTH_READDIR: event.kind=2; file=message->event.readdir.target; event.readable=1; break;
            case ES_EVENT_TYPE_AUTH_CLONE: event.kind=3; file=message->event.clone.source; event.readable=1; break;
            case ES_EVENT_TYPE_AUTH_COPYFILE: event.kind=4; file=message->event.copyfile.source; event.readable=1; break;
            case ES_EVENT_TYPE_NOTIFY_EXEC: event.kind=5; event.related=process(message->event.exec.target); event.cwd_truncated=1; if(message->version>=3){event.cwd=text(message->event.exec.cwd->path);event.cwd_truncated=message->event.exec.cwd->path_truncated;} break;
            case ES_EVENT_TYPE_NOTIFY_FORK: event.kind=6; event.related=process(message->event.fork.child); break;
            case ES_EVENT_TYPE_NOTIFY_EXIT: event.kind=7; break;
            default: return;
        }
        if (file) { event.path=text(file->path); event.truncated=file->path_truncated; event.links=file->stat.st_nlink; event.regular_file=S_ISREG(file->stat.st_mode); }
        uint32_t scope=0;
        uint32_t verdict=decide(context,&event,&scope);
        // An unrecoverable identity/sequence failure revokes readiness. Do not
        // pretend to protect only the subset whose identities happened to survive.
        if (verdict == 3) { atomic_store(&fatal,200); CFRunLoopStop(loop); }
        if (message->action_type == ES_ACTION_TYPE_AUTH) {
            bool deny=verdict == 1 || verdict == 2 || verdict == 4;
            es_respond_result_t response = message->event_type == ES_EVENT_TYPE_AUTH_OPEN
                ? es_respond_flags_result(c,message,deny ? 0 : UINT32_MAX,false)
                : es_respond_auth_result(c,message,deny ? ES_AUTH_RESULT_DENY : ES_AUTH_RESULT_ALLOW,false);
            completed(context,&event,scope,verdict,response == ES_RESPOND_RESULT_SUCCESS);
            if (response != ES_RESPOND_RESULT_SUCCESS) { atomic_store(&fatal,201); CFRunLoopStop(loop); }
        }
    });
    if (created != ES_NEW_CLIENT_RESULT_SUCCESS) return (int)created;
    const es_event_type_t events[]={ ES_EVENT_TYPE_AUTH_OPEN, ES_EVENT_TYPE_AUTH_MMAP, ES_EVENT_TYPE_AUTH_READDIR, ES_EVENT_TYPE_AUTH_CLONE, ES_EVENT_TYPE_AUTH_COPYFILE, ES_EVENT_TYPE_NOTIFY_EXEC, ES_EVENT_TYPE_NOTIFY_FORK, ES_EVENT_TYPE_NOTIFY_EXIT };
    if (es_subscribe(client,events,sizeof(events)/sizeof(events[0])) != ES_RETURN_SUCCESS) { es_delete_client(client); return 100; }
    signal(SIGTERM,SIG_IGN); signal(SIGINT,SIG_IGN);
    dispatch_source_t term=dispatch_source_create(DISPATCH_SOURCE_TYPE_SIGNAL,SIGTERM,0,dispatch_get_main_queue());
    dispatch_source_t interrupt=dispatch_source_create(DISPATCH_SOURCE_TYPE_SIGNAL,SIGINT,0,dispatch_get_main_queue());
    dispatch_source_set_event_handler(term, ^{ CFRunLoopStop(loop); });
    dispatch_source_set_event_handler(interrupt, ^{ CFRunLoopStop(loop); });
    dispatch_resume(term); dispatch_resume(interrupt);
    if (atomic_load(&fatal)==0) CFRunLoopRun();
    dispatch_source_cancel(term); dispatch_source_cancel(interrupt);
    es_unsubscribe_all(client); es_delete_client(client);
    return atomic_load(&fatal);
}
