#import <Foundation/Foundation.h>
#import <Network/Network.h>
#import <Security/SecTask.h>
#import <dispatch/dispatch.h>
#import <errno.h>
#import <fcntl.h>
#import <stdbool.h>
#import <stdint.h>
#import <stdio.h>
#import <string.h>
#import <sys/socket.h>
#import <unistd.h>

typedef bool (*skyhook_cancelled_fn)(void *context);

@interface SkyhookMptcpBridge : NSObject {
    nw_connection_t _connection;
    dispatch_queue_t _queue;
    dispatch_queue_t _localWriteQueue;
    dispatch_source_t _localReadSource;
    dispatch_semaphore_t _connectSemaphore;
    int _localReadFD;
    int _localWriteFD;
    BOOL _localReadSuspended;
    BOOL _localEOF;
    BOOL _remoteEOF;
    BOOL _closed;
    BOOL _connectSignalled;
    int _connectErrorDomain;
    int _connectErrorCode;
    int _lastState;
    int _lastErrorDomain;
    int _lastErrorCode;
}

- (instancetype)initWithHost:(const char *)host
                     service:(const char *)service
                  sourceHost:(const char *)sourceHost
               sourceService:(const char *)sourceService
                   ipVersion:(int)ipVersion
               keepaliveSecs:(uint32_t)keepaliveSecs
             enableMultipath:(BOOL)enableMultipath
                   timeoutMs:(uint64_t)timeoutMs
                       peerFD:(int *)peerFD;
- (BOOL)waitUntilReadyWithTimeoutMs:(uint64_t)timeoutMs
                          cancelled:(skyhook_cancelled_fn)cancelled
                             context:(void *)context
                               error:(char *)error
                            capacity:(size_t)capacity;
- (void)cancel;
@end

static void skyhook_copy_error(char *target, size_t capacity, const char *message) {
    if (target == NULL || capacity == 0) {
        return;
    }
    snprintf(target, capacity, "%s", message != NULL ? message : "unknown Network.framework error");
}

@implementation SkyhookMptcpBridge

- (instancetype)initWithHost:(const char *)host
                     service:(const char *)service
                  sourceHost:(const char *)sourceHost
               sourceService:(const char *)sourceService
                   ipVersion:(int)ipVersion
               keepaliveSecs:(uint32_t)keepaliveSecs
             enableMultipath:(BOOL)enableMultipath
                   timeoutMs:(uint64_t)timeoutMs
                       peerFD:(int *)peerFD {
    self = [super init];
    if (self == nil) {
        return nil;
    }

    _localReadFD = -1;
    _localWriteFD = -1;
    _queue = dispatch_queue_create("com.yueqiu.skyhook.mptcp", DISPATCH_QUEUE_SERIAL);
    _localWriteQueue = dispatch_queue_create(
        "com.yueqiu.skyhook.mptcp.local-write", DISPATCH_QUEUE_SERIAL);
    _connectSemaphore = dispatch_semaphore_create(0);

    int sockets[2] = {-1, -1};
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) != 0) {
        return nil;
    }
    fcntl(sockets[0], F_SETFD, FD_CLOEXEC);
    fcntl(sockets[1], F_SETFD, FD_CLOEXEC);
    int readFD = dup(sockets[1]);
    if (readFD < 0) {
        close(sockets[0]);
        close(sockets[1]);
        return nil;
    }
    fcntl(readFD, F_SETFD, FD_CLOEXEC);
    _localReadFD = readFD;
    _localWriteFD = sockets[1];
    *peerFD = sockets[0];

    nw_parameters_t parameters = nw_parameters_create_secure_tcp(
        NW_PARAMETERS_DISABLE_PROTOCOL, NW_PARAMETERS_DEFAULT_CONFIGURATION);
    if (parameters == nil) {
        close(*peerFD);
        *peerFD = -1;
        [self closeLocalBridge];
        return nil;
    }

    nw_protocol_stack_t stack = nw_parameters_copy_default_protocol_stack(parameters);
    nw_protocol_options_t tcpOptions = nw_protocol_stack_copy_transport_protocol(stack);
    if (tcpOptions == nil) {
        close(*peerFD);
        *peerFD = -1;
        [self closeLocalBridge];
        return nil;
    }
    nw_tcp_options_set_no_delay(tcpOptions, true);
    if (keepaliveSecs > 0) {
        nw_tcp_options_set_enable_keepalive(tcpOptions, true);
        nw_tcp_options_set_keepalive_idle_time(tcpOptions, keepaliveSecs);
        nw_tcp_options_set_keepalive_interval(tcpOptions, MAX(keepaliveSecs / 3, 1));
        nw_tcp_options_set_keepalive_count(tcpOptions, 3);
    }
    if (enableMultipath) {
        nw_parameters_set_multipath_service(parameters, nw_multipath_service_interactive);
    }
    nw_protocol_options_t ipOptions = nw_protocol_stack_copy_internet_protocol(stack);
    if (ipOptions == nil) {
        close(*peerFD);
        *peerFD = -1;
        [self closeLocalBridge];
        return nil;
    }
    if (ipVersion == 4) {
        nw_ip_options_set_version(ipOptions, nw_ip_version_4);
    } else if (ipVersion == 6) {
        nw_ip_options_set_version(ipOptions, nw_ip_version_6);
    } else {
        nw_ip_options_set_version(ipOptions, nw_ip_version_any);
    }

    if (sourceHost != NULL && sourceHost[0] != '\0') {
        nw_endpoint_t localEndpoint = nw_endpoint_create_host(
            sourceHost,
            sourceService != NULL && sourceService[0] != '\0' ? sourceService : "0");
        if (localEndpoint != nil) {
            nw_parameters_set_local_endpoint(parameters, localEndpoint);
        }
    }

    nw_endpoint_t endpoint = nw_endpoint_create_host(host, service);
    if (endpoint == nil) {
        close(*peerFD);
        *peerFD = -1;
        [self closeLocalBridge];
        return nil;
    }
    _connection = nw_connection_create(endpoint, parameters);
    if (_connection == nil) {
        close(*peerFD);
        *peerFD = -1;
        [self closeLocalBridge];
        return nil;
    }

    __weak SkyhookMptcpBridge *weakSelf = self;
    nw_connection_set_queue(_connection, _queue);
    nw_connection_set_state_changed_handler(_connection, ^(nw_connection_state_t state, nw_error_t error) {
        SkyhookMptcpBridge *strongSelf = weakSelf;
        if (strongSelf == nil) {
            return;
        }
        strongSelf->_lastState = (int)state;
        if (error != nil) {
            strongSelf->_lastErrorDomain = (int)nw_error_get_error_domain(error);
            strongSelf->_lastErrorCode = nw_error_get_error_code(error);
        }
        if (state == nw_connection_state_ready) {
            [strongSelf signalConnectWithError:nil];
            [strongSelf startPumps];
        } else if (state == nw_connection_state_failed) {
            [strongSelf signalConnectWithError:error];
            if (!strongSelf->_localEOF) {
                [strongSelf failBridge];
            }
        } else if (state == nw_connection_state_cancelled) {
            [strongSelf signalConnectWithError:error];
            if (!(strongSelf->_localEOF && strongSelf->_remoteEOF)) {
                [strongSelf closeLocalBridge];
            }
        }
    });
    nw_connection_start(_connection);
    return self;
}

- (void)signalConnectWithError:(nw_error_t)error {
    if (_connectSignalled) {
        return;
    }
    _connectSignalled = YES;
    if (error != nil) {
        _connectErrorDomain = (int)nw_error_get_error_domain(error);
        _connectErrorCode = nw_error_get_error_code(error);
    }
    dispatch_semaphore_signal(_connectSemaphore);
}

- (BOOL)waitUntilReadyWithTimeoutMs:(uint64_t)timeoutMs
                          cancelled:(skyhook_cancelled_fn)cancelled
                             context:(void *)context
                               error:(char *)error
                            capacity:(size_t)capacity {
    uint64_t elapsed = 0;
    while (elapsed < timeoutMs) {
        uint64_t slice = MIN((uint64_t)50, timeoutMs - elapsed);
        long result = dispatch_semaphore_wait(
            _connectSemaphore,
            dispatch_time(DISPATCH_TIME_NOW, (int64_t)(slice * NSEC_PER_MSEC)));
        if (result == 0) {
            if (_connectErrorDomain == 0 && _connectErrorCode == 0) {
                return YES;
            }
            char message[192];
            snprintf(message, sizeof(message),
                     "Network.framework MPTCP connection failed (domain=%d code=%d)",
                     _connectErrorDomain, _connectErrorCode);
            skyhook_copy_error(error, capacity, message);
            return NO;
        }
        elapsed += slice;
        if (cancelled != NULL && cancelled(context)) {
            skyhook_copy_error(error, capacity, "Network.framework MPTCP connection cancelled");
            [self cancel];
            return NO;
        }
    }
    char message[224];
    snprintf(message, sizeof(message),
             "Network.framework MPTCP connection timed out (state=%d domain=%d code=%d)",
             _lastState, _lastErrorDomain, _lastErrorCode);
    skyhook_copy_error(error, capacity, message);
    [self cancel];
    return NO;
}

- (void)startPumps {
    if (_closed || _localReadSource != nil) {
        return;
    }
    __weak SkyhookMptcpBridge *weakSelf = self;
    _localReadSource = dispatch_source_create(
        DISPATCH_SOURCE_TYPE_READ, (uintptr_t)_localReadFD, 0, _queue);
    dispatch_source_set_event_handler(_localReadSource, ^{
        SkyhookMptcpBridge *strongSelf = weakSelf;
        [strongSelf pumpLocalToNetwork];
    });
    int readFD = _localReadFD;
    dispatch_source_set_cancel_handler(_localReadSource, ^{
        if (readFD >= 0) {
            close(readFD);
        }
    });
    dispatch_resume(_localReadSource);
    [self receiveFromNetwork];
}

- (void)pumpLocalToNetwork {
    if (_closed || _localEOF || _localReadSuspended) {
        return;
    }
    __weak SkyhookMptcpBridge *weakSelf = self;
    void *buffer = malloc(64 * 1024);
    if (buffer == NULL) {
        [self failBridge];
        return;
    }
    ssize_t count = read(_localReadFD, buffer, 64 * 1024);
    if (count > 0) {
        _localReadSuspended = YES;
        dispatch_suspend(_localReadSource);
        dispatch_data_t data = dispatch_data_create(
            buffer, (size_t)count, _queue, DISPATCH_DATA_DESTRUCTOR_FREE);
        nw_connection_send(_connection, data, NW_CONNECTION_DEFAULT_STREAM_CONTEXT, false,
                           ^(nw_error_t error) {
            SkyhookMptcpBridge *strongSelf = weakSelf;
            if (strongSelf == nil) {
                return;
            }
            if (error != nil) {
                [strongSelf failBridge];
                return;
            }
            if (strongSelf->_localReadSuspended && strongSelf->_localReadSource != nil) {
                strongSelf->_localReadSuspended = NO;
                dispatch_resume(strongSelf->_localReadSource);
            }
        });
        return;
    }
    free(buffer);
    if (count == 0) {
        _localEOF = YES;
        nw_connection_send(_connection, dispatch_data_empty,
                           NW_CONNECTION_DEFAULT_STREAM_CONTEXT, true,
                           ^(nw_error_t error) {
            SkyhookMptcpBridge *strongSelf = weakSelf;
            if (error != nil) {
                [strongSelf failBridge];
            } else {
                [strongSelf finishIfComplete];
            }
        });
    } else if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
        [self failBridge];
    }
}

- (void)receiveFromNetwork {
    if (_closed || _remoteEOF) {
        return;
    }
    __weak SkyhookMptcpBridge *weakSelf = self;
    nw_connection_receive(_connection, 1, 64 * 1024,
                          ^(dispatch_data_t content, nw_content_context_t context,
                            bool isComplete, nw_error_t error) {
        (void)context;
        SkyhookMptcpBridge *strongSelf = weakSelf;
        if (strongSelf == nil || strongSelf->_closed) {
            return;
        }
        size_t length = content != nil ? dispatch_data_get_size(content) : 0;
        BOOL finalChunk = isComplete || error != nil;
        if (length == 0) {
            if (error != nil) {
                if (strongSelf->_localEOF) {
                    [strongSelf markRemoteEOF];
                } else {
                    [strongSelf failBridge];
                }
            } else if (isComplete) {
                [strongSelf markRemoteEOF];
            } else {
                [strongSelf receiveFromNetwork];
            }
            return;
        }

        const BOOL receiveError = error != nil;
        dispatch_data_t receivedContent = content;
        int writeFD = strongSelf->_localWriteFD;
        dispatch_async(strongSelf->_localWriteQueue, ^{
            SkyhookMptcpBridge *writeSelf = weakSelf;
            if (writeSelf == nil || writeFD < 0) {
                return;
            }
            const void *bytes = NULL;
            size_t mappedLength = 0;
            dispatch_data_t contiguous = dispatch_data_create_map(
                receivedContent, &bytes, &mappedLength);
            size_t written = 0;
            int writeError = 0;
            while (written < mappedLength) {
                ssize_t count = send(writeFD,
                                     (const uint8_t *)bytes + written,
                                     mappedLength - written,
                                     MSG_NOSIGNAL);
                if (count > 0) {
                    written += (size_t)count;
                } else if (count < 0 && errno == EINTR) {
                    continue;
                } else {
                    writeError = count == 0 ? EPIPE : errno;
                    break;
                }
            }
            (void)contiguous;
            dispatch_async(writeSelf->_queue, ^{
                SkyhookMptcpBridge *finishSelf = weakSelf;
                if (finishSelf == nil || finishSelf->_closed) {
                    return;
                }
                if (writeError != 0) {
                    [finishSelf failBridge];
                } else if (finalChunk || receiveError) {
                    [finishSelf markRemoteEOF];
                } else {
                    [finishSelf receiveFromNetwork];
                }
            });
        });
    });
}

- (void)markRemoteEOF {
    if (_remoteEOF) {
        return;
    }
    _remoteEOF = YES;
    if (_localWriteFD >= 0) {
        shutdown(_localWriteFD, SHUT_WR);
    }
    [self finishIfComplete];
}

- (void)finishIfComplete {
    // Keep the socketpair alive until the Rust stream is released. Closing it
    // here with unread buffered data would truncate the final response.
}

- (void)failBridge {
    if (_closed) {
        return;
    }
    _closed = YES;
    if (_localReadFD >= 0) {
        shutdown(_localReadFD, SHUT_RDWR);
    }
    [self closeLocalBridge];
    if (_connection != nil) {
        nw_connection_cancel(_connection);
    }
}

- (void)closeLocalBridge {
    if (_localReadSource != nil) {
        if (_localReadSuspended) {
            _localReadSuspended = NO;
            dispatch_resume(_localReadSource);
        }
        dispatch_source_cancel(_localReadSource);
        _localReadSource = nil;
        _localReadFD = -1;
    } else if (_localReadFD >= 0) {
        close(_localReadFD);
        _localReadFD = -1;
    }
    if (_localWriteFD >= 0) {
        int writeFD = _localWriteFD;
        _localWriteFD = -1;
        shutdown(writeFD, SHUT_RDWR);
        dispatch_async(_localWriteQueue, ^{
            close(writeFD);
        });
    }
}

- (void)cancel {
    __strong SkyhookMptcpBridge *strongSelf = self;
    dispatch_async(_queue, ^{
        if (!strongSelf->_closed) {
            strongSelf->_closed = YES;
            if (strongSelf->_connection != nil) {
                nw_connection_cancel(strongSelf->_connection);
            }
            [strongSelf closeLocalBridge];
        }
    });
}

- (void)dealloc {
    if (_connection != nil) {
        nw_connection_set_state_changed_handler(_connection, nil);
        nw_connection_cancel(_connection);
    }
    [self closeLocalBridge];
}

@end

int skyhook_mptcp_connect(const char *host,
                          const char *service,
                          const char *sourceHost,
                          const char *sourceService,
                          int ipVersion,
                          uint32_t keepaliveSecs,
                          bool enableMultipath,
                          uint64_t timeoutMs,
                          skyhook_cancelled_fn cancelled,
                          void *cancelContext,
                          int *streamFD,
                          void **bridgeHandle,
                          char *error,
                          size_t errorCapacity) {
    if (host == NULL || service == NULL || streamFD == NULL || bridgeHandle == NULL) {
        skyhook_copy_error(error, errorCapacity, "invalid MPTCP bridge arguments");
        return -1;
    }
    *streamFD = -1;
    *bridgeHandle = NULL;
    SkyhookMptcpBridge *bridge = [[SkyhookMptcpBridge alloc]
        initWithHost:host
             service:service
          sourceHost:sourceHost
       sourceService:sourceService
           ipVersion:ipVersion
       keepaliveSecs:keepaliveSecs
     enableMultipath:enableMultipath
           timeoutMs:timeoutMs
               peerFD:streamFD];
    if (bridge == nil || *streamFD < 0) {
        skyhook_copy_error(error, errorCapacity, "failed to initialize Network.framework MPTCP bridge");
        return -1;
    }
    if (![bridge waitUntilReadyWithTimeoutMs:timeoutMs
                                  cancelled:cancelled
                                     context:cancelContext
                                       error:error
                                    capacity:errorCapacity]) {
        close(*streamFD);
        *streamFD = -1;
        [bridge cancel];
        return -1;
    }
    *bridgeHandle = (__bridge_retained void *)bridge;
    return 0;
}

void skyhook_mptcp_release(void *bridgeHandle) {
    if (bridgeHandle == NULL) {
        return;
    }
    SkyhookMptcpBridge *bridge = (__bridge_transfer SkyhookMptcpBridge *)bridgeHandle;
    [bridge cancel];
}

int skyhook_mptcp_backend_probe(void) {
    nw_parameters_t parameters = nw_parameters_create_secure_tcp(
        NW_PARAMETERS_DISABLE_PROTOCOL, NW_PARAMETERS_DEFAULT_CONFIGURATION);
    if (parameters == nil) {
        return 0;
    }
    nw_parameters_set_multipath_service(parameters, nw_multipath_service_interactive);
    return nw_parameters_get_multipath_service(parameters) == nw_multipath_service_interactive;
}

int skyhook_mptcp_entitlement_probe(void) {
    SecTaskRef task = SecTaskCreateFromSelf(kCFAllocatorDefault);
    if (task == NULL) {
        return 0;
    }
    CFTypeRef value = SecTaskCopyValueForEntitlement(
        task, CFSTR("com.apple.developer.networking.multipath"), NULL);
    CFRelease(task);
    if (value == NULL) {
        return 0;
    }
    int enabled = CFGetTypeID(value) == CFBooleanGetTypeID() &&
                  CFBooleanGetValue((CFBooleanRef)value);
    CFRelease(value);
    return enabled;
}
