#ifndef _AOS_CFNETWORK_CFPROXYSUPPORT_H_
#define _AOS_CFNETWORK_CFPROXYSUPPORT_H_

#include <CoreFoundation/CoreFoundation.h>
#include <CoreFoundation/CFStream.h>

#ifndef CFN_EXPORT
#define CFN_EXPORT extern
#endif

typedef void (*CFProxyAutoConfigurationResultCallback)(
  void *client,
  CFArrayRef proxyList,
  CFErrorRef _Nullable error
);

CFN_EXPORT CFDictionaryRef _Nullable CFNetworkCopySystemProxySettings(void);
CFN_EXPORT CFArrayRef CFNetworkCopyProxiesForURL(
  CFURLRef url,
  CFDictionaryRef proxySettings
);
CFN_EXPORT CFRunLoopSourceRef CFNetworkExecuteProxyAutoConfigurationURL(
  CFURLRef proxyAutoConfigURL,
  CFURLRef targetURL,
  CFProxyAutoConfigurationResultCallback callback,
  CFStreamClientContext *clientContext
);

CFN_EXPORT const CFStringRef kCFProxyTypeKey;
CFN_EXPORT const CFStringRef kCFProxyTypeAutoConfigurationURL;
CFN_EXPORT const CFStringRef kCFProxyAutoConfigurationURLKey;
CFN_EXPORT const CFStringRef kCFProxyTypeNone;
CFN_EXPORT const CFStringRef kCFProxyTypeSOCKS;
CFN_EXPORT const CFStringRef kCFProxyPortNumberKey;
CFN_EXPORT const CFStringRef kCFProxyHostNameKey;

#endif
