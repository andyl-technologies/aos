/* Prove that the CoreServices umbrella carries its canonical CFNetwork ABI. */
#include <CoreFoundation/CoreFoundation.h>
#include <CoreServices/CoreServices.h>

static void proxy_result(
  void *client,
  CFArrayRef proxy_list,
  CFErrorRef error
) {
  (void)client;
  (void)proxy_list;
  (void)error;
}

int main(void) {
  const void *proxy_keys[] = {
    &kCFProxyTypeKey,
    &kCFProxyTypeAutoConfigurationURL,
    &kCFProxyAutoConfigurationURLKey,
    &kCFProxyTypeNone,
    &kCFProxyTypeSOCKS,
    &kCFProxyPortNumberKey,
    &kCFProxyHostNameKey,
  };
  CFDictionaryRef settings = CFNetworkCopySystemProxySettings();
  CFURLRef url = NULL;
  CFArrayRef proxies = CFNetworkCopyProxiesForURL(url, settings);
  CFStreamClientContext context = { 0, NULL, NULL, NULL, NULL };
  CFRunLoopSourceRef source = CFNetworkExecuteProxyAutoConfigurationURL(
    url,
    url,
    proxy_result,
    &context
  );
  return settings == NULL && proxies == NULL && source == NULL &&
    proxy_keys[0] == NULL;
}
