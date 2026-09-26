##! JavaNativeFoundation — Apple's Objective-C/JNI bridge framework
{
  lib,
  mkDerivation,
  fetchurl,
  stdenv,
  buildPackages,
  declarationOnly ? false,
}: let
  version = "80";
  platformSupport = {
    build = [{abi = ["gnu"]; os = ["linux"];}];
    host = [{abi = ["darwin"]; cpu = ["x86_64" "aarch64"]; os = ["darwin"];}];
    target = [];
    role = "public-package";
  };
  revision = "9718a5a15549857d1cbc1289ee4ba0591e1393b9";

  probeProgram = ''
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
  probeOperation = {
    mode,
    input,
    description,
    expected,
  }: {
    inherit input expected;
    operation = description;
    files."run-loop.m" = probeProgram;
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
      ({
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
        // lib.optionalAttrs (mode == "bad-input") {observes_rejection = true;})
    ];
    artifacts = [];
  };

  # Apple published JavaNativeFoundation as open source, but the former
  # opensource.apple.com tarball URL now redirects to a removed repository.
  # Diatrus preserves the unmodified raw Apple import at this exact commit.
  # Its later tag 80 is an iOS-oriented third-party fork and is deliberately
  # not used here.
  jnfSource = fetchurl {
    urls = [
      "https://github.com/Diatrus/JavaNativeFoundation/archive/${revision}.tar.gz"
    ];
    hash = "sha256-4/sFSwopp+cQuFPOnFjWwiHvR+kJoeTCQPSI3308jq0=";
  };

  # The raw Apple import intentionally does not vendor JNI. Build it against
  # the same pinned OpenJDK 8 headers as its only AOS consumer, without adding
  # a target-JDK dependency or a bootstrap cycle.
  jdkHeadersSource = fetchurl {
    urls = [
      "https://icedtea.classpath.org/download/drops/icedtea8/3.19.0/jdk.tar.xz"
    ];
    hash = "sha256-O8Pcqh+dEJ7ZkTnhEIppGWTGitkDdSFKhB/RUiqjgpw=";
  };
in
  if declarationOnly
  then {
    pname = "java-native-foundation";
    inherit platformSupport;
    unavailable = true;
  }
  else
  mkDerivation {
    inherit platformSupport;
    pname = "java-native-foundation";
    inherit version;
    qualification.packageProbe = lib.qualification.commandProbe {
      primary = probeOperation {
        mode = "primary";
        input = "An Objective-C receiver, its record: selector, and the integer 42.";
        description = "Load the selected framework and dispatch through JNFRunLoop's Java-compatible main-thread modes.";
        expected = "The selected framework delivers 42 to the receiver on the main thread.";
      };
      badInput = probeOperation {
        mode = "bad-input";
        input = "The same receiver with an unknown qualificationMissingSelector: selector.";
        description = "Request synchronous dispatch of the unsupported selector through JNFRunLoop.";
        expected = "Dispatch raises NSInvalidArgumentException naming the unknown selector.";
      };
    };

    src = jnfSource;

    buildDeps = [
      buildPackages.file
      buildPackages.llvm
    ];
    runtimeDeps = [];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd "JavaNativeFoundation-${revision}"

          mkdir jdk8-source
          tar xf ${jdkHeadersSource} -C jdk8-source --strip-components=1
        '';
      }
      {
        name = "build";
        script = ''
          test "${
            if stdenv.hostPlatform.isDarwin
            then "true"
            else "false"
          }" = true

          sourceDir=JavaNativeFoundation
          jniShared=jdk8-source/src/share/javavm/export
          jniDarwin=jdk8-source/src/macosx/javavm/export
          mkdir objects

          # JNFRunLoop uses the public Block_copy/Block_release convenience
          # macros but the raw source omits their canonical SDK header. Xcode
          # supplied this build context implicitly; make it explicit here.
          sourceCount=0
          for source in "$sourceDir"/*.m; do
            object=objects/$(basename "$source" .m).o
            "$CC" $CFLAGS \
              -fPIC \
              -fblocks \
              -fno-objc-arc \
              -fobjc-exceptions \
              -fvisibility=hidden \
              -include Block.h \
              -Werror \
              -Wno-error=deprecated-declarations \
              -I. \
              -I"$sourceDir" \
              -I"$jniShared" \
              -I"$jniDarwin" \
              -c "$source" \
              -o "$object"
            sourceCount=$((sourceCount + 1))
          done
          test "$sourceCount" -eq 15

          "$CC" $LDFLAGS \
            -dynamiclib \
            -Wl,-headerpad_max_install_names \
            -Wl,-install_name,@rpath/JavaNativeFoundation.framework/Versions/A/JavaNativeFoundation \
            -Wl,-current_version,80 \
            -Wl,-compatibility_version,1 \
            -framework Foundation \
            -framework CoreFoundation \
            -framework AppKit \
            -lobjc \
            -ldl \
            -lpthread \
            objects/*.o \
            -o JavaNativeFoundation.dylib

          ${buildPackages.file}/bin/file JavaNativeFoundation.dylib \
            | grep -q 'Mach-O 64-bit ${stdenv.hostPlatform.darwinArch} dynamically linked shared library'
          ${buildPackages.llvm}/bin/llvm-otool -D JavaNativeFoundation.dylib \
            | grep -qx '@rpath/JavaNativeFoundation.framework/Versions/A/JavaNativeFoundation'
          ${buildPackages.llvm}/bin/llvm-otool -L JavaNativeFoundation.dylib \
            | grep -q 'compatibility version 1.0.0, current version 80.0.0'
        '';
      }
      {
        name = "install";
        script = ''
          framework="$out/Library/Frameworks/JavaNativeFoundation.framework"
          versioned="$framework/Versions/A"
          mkdir -p \
            "$versioned/Headers" \
            "$versioned/Modules" \
            "$versioned/Resources" \
            "$out/share/licenses/java-native-foundation/source-notices"

          cp JavaNativeFoundation.dylib "$versioned/JavaNativeFoundation"
          cp JavaNativeFoundation/*.h "$versioned/Headers/"
          cp JavaNativeFoundation/Modules/module.modulemap "$versioned/Modules/"
          sed \
            -e 's/$(EXECUTABLE_NAME)/JavaNativeFoundation/g' \
            -e 's/$(PRODUCT_BUNDLE_IDENTIFIER)/com.apple.JavaNativeFoundation/g' \
            -e 's/$(PRODUCT_NAME)/JavaNativeFoundation/g' \
            -e 's/$(CURRENT_PROJECT_VERSION)/80/g' \
            JavaNativeFoundation/JavaNativeFoundation-Info.plist \
            > "$versioned/Resources/Info.plist"

          ln -s A "$framework/Versions/Current"
          ln -s Versions/Current/JavaNativeFoundation \
            "$framework/JavaNativeFoundation"
          ln -s Versions/Current/Headers "$framework/Headers"
          ln -s Versions/Current/Modules "$framework/Modules"
          ln -s Versions/Current/Resources "$framework/Resources"

          # Preserve every upstream per-file BSD notice verbatim in the
          # distributed output, including notices from implementation files.
          cp JavaNativeFoundation/*.h JavaNativeFoundation/*.m \
            "$out/share/licenses/java-native-foundation/source-notices/"
          test "$(find "$versioned/Headers" -type f | wc -l)" -eq 16
          test "$(find "$out/share/licenses/java-native-foundation/source-notices" \
            -type f | wc -l)" -eq 31
          grep -q 'Copyright (c) 2008-2020 Apple Inc.' \
            "$versioned/Headers/JNFAssert.h"
          for noticeSource in \
            "$out/share/licenses/java-native-foundation/source-notices"/*; do
            grep -q 'Redistribution and use in source and binary forms' \
              "$noticeSource"
          done
        '';
      }
    ];

    meta = {
      description = "Apple JavaNativeFoundation Objective-C/JNI bridge framework";
      homepage = "https://github.com/Diatrus/JavaNativeFoundation/tree/${revision}";
      license = "BSD-3-Clause";
      platforms = [
        "x86_64-darwin"
        "aarch64-darwin"
      ];
    };
  }
