##! Exercises JavaNativeFoundation's public Objective-C run-loop dispatch API.
{testing}: let
  program = ''
    #import <Foundation/Foundation.h>
    #include <dlfcn.h>
    #include <limits.h>
    #include <objc/message.h>
    #include <objc/runtime.h>
    #include <stdio.h>
    #include <stdlib.h>
    #include <string.h>

    @interface QualificationReceiver : NSObject {
        NSInteger answer;
        BOOL receivedOnMainThread;
    }
    - (void)record:(NSNumber *)value;
    - (BOOL)receivedAnswer;
    @end

    @implementation QualificationReceiver
    - (void)record:(NSNumber *)value {
        answer = [value integerValue];
        receivedOnMainThread = [NSThread isMainThread];
    }

    - (BOOL)receivedAnswer {
        return answer == 42 && receivedOnMainThread;
    }
    @end

    // These public Objective-C selectors do not require a JVM. Resolve their
    // class from the selected framework and check its image before dispatch,
    // so an operating-system copy cannot satisfy the package's probe.
    typedef id (*ClassQuery)(id, SEL);
    typedef void (*MainThreadDispatch)(id, SEL, SEL, id, id, BOOL);

    int main(int argc, char **argv) {
        if (argc != 3) return 2;

        NSAutoreleasePool *pool = [[NSAutoreleasePool alloc] init];
        void *framework = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
        if (framework == NULL) {
            fprintf(stderr, "framework load failed: %s\n", dlerror());
            return 2;
        }

        Class bridge = objc_getClass("JNFRunLoop");
        const char *image = bridge == Nil ? NULL : class_getImageName(bridge);
        char expectedImage[PATH_MAX];
        char actualImage[PATH_MAX];
        if (image == NULL || realpath(argv[1], expectedImage) == NULL ||
            realpath(image, actualImage) == NULL ||
            strcmp(expectedImage, actualImage) != 0) {
            fputs("run-loop class is not from the selected framework\n", stderr);
            return 2;
        }

        ClassQuery query = (ClassQuery)objc_msgSend;
        NSString *mode = query((id)bridge, sel_registerName("javaRunLoopMode"));
        if (![mode isEqualToString:@"AWTRunLoopMode"] || ![NSThread isMainThread]) {
            return 2;
        }

        QualificationReceiver *receiver = [[QualificationReceiver alloc] init];
        NSNumber *value = [NSNumber numberWithInteger:42];
        MainThreadDispatch dispatch = (MainThreadDispatch)objc_msgSend;
        SEL dispatchSelector = sel_registerName(
            "performOnMainThread:on:withObject:waitUntilDone:"
        );

        if (strcmp(argv[2], "primary") == 0) {
            dispatch((id)bridge, dispatchSelector, @selector(record:), receiver, value, YES);
            if (![receiver receivedAnswer]) return 3;

            [receiver release];
            [pool drain];
            puts("java-native-foundation dispatched answer 42 on the main thread");
            return 0;
        }

        if (strcmp(argv[2], "bad-input") != 0) return 2;

        @try {
            dispatch(
                (id)bridge, dispatchSelector,
                sel_registerName("qualificationMissingSelector:"), receiver, value, YES
            );
        } @catch (NSException *exception) {
            if (![[exception name] isEqualToString:NSInvalidArgumentException] ||
                [[exception reason] rangeOfString:@"qualificationMissingSelector:"].location
                    == NSNotFound) {
                return 3;
            }

            [receiver release];
            [pool drain];
            fputs("java-native-foundation rejected the unknown selector\n", stderr);
            return 7;
        }

        return 3;
    }
  '';
  operation = {
    mode,
    input,
    description,
    expected,
  }: {
    inherit input expected;
    operation = description;
    files."run-loop.m" = program;
    steps = [
      {
        argv = [
          "@cc@"
          "-Werror"
          "-fobjc-exceptions"
          "-fno-objc-arc"
          "run-loop.m"
          "-framework"
          "Foundation"
          "-lobjc"
          "-o"
          "run-loop"
        ];
        exit_code = 0;
        stdout.exact = "";
      }
      (
        {
          argv = [
            "@work@/${mode}/run-loop"
            "@out@/Library/Frameworks/JavaNativeFoundation.framework/JavaNativeFoundation"
            mode
          ];
          exit_code =
            if mode == "primary"
            then 0
            else 7;
          stdout.exact =
            if mode == "primary"
            then "java-native-foundation dispatched answer 42 on the main thread\n"
            else "";
          stderr.exact =
            if mode == "primary"
            then ""
            else "java-native-foundation rejected the unknown selector\n";
        }
        // (
          if mode == "bad-input"
          then {observes_rejection = true;}
          else {}
        )
      )
    ];
    artifacts = [];
  };
in {
  java-native-foundation = testing.mkQualificationPackageProbe {
    name = "java-native-foundation";
    spec = {
      schema_version = "aos.release.package-probe/v1";
      package = "java-native-foundation";
      primary = operation {
        mode = "primary";
        input = "An Objective-C receiver, its record: selector, and the integer 42.";
        description = "Load the selected framework and dispatch through JNFRunLoop's Java-compatible main-thread modes.";
        expected = "The selected framework delivers 42 to the receiver on the main thread.";
      };
      bad_input = operation {
        mode = "bad-input";
        input = "The same receiver with an unknown qualificationMissingSelector: selector.";
        description = "Request synchronous dispatch of the unsupported selector through JNFRunLoop.";
        expected = "Dispatch raises NSInvalidArgumentException naming the unknown selector.";
      };
    };
  };
}
