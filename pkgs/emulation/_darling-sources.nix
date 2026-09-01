##! Immutable source manifest for Darling's core runtime.
{fetchurl}: let
  fetchGitHubArchive = {
    repository,
    revision,
    hash,
    ...
  }:
    fetchurl {
      urls = ["https://github.com/darlinghq/${repository}/archive/${revision}.tar.gz"];
      inherit hash;
    };

  mkSubmodule = source:
    source
    // {
      archive = fetchGitHubArchive source;
    };
in {
  revision = "098ebd4801cd496a9851454e81d5f04491a63770";

  archive = fetchGitHubArchive {
    repository = "darling";
    revision = "098ebd4801cd496a9851454e81d5f04491a63770";
    hash = "sha256-4vZk9weeIhV9yaMplBRts/ucFW1MmqxtEbSlI7DrdWU=";
  };

  # These are exactly the gitlinks reached by the unconditional core section
  # of src/CMakeLists.txt plus the SDK's header-only symlink targets. The nested
  # swift-corelibs-foundation tree supplies CoreFoundation's public headers;
  # nested ctest trees are unused with tests disabled.
  submodules = map mkSubmodule [
    {
      path = "src/external/AvailabilityVersions";
      repository = "darling-AvailabilityVersions";
      revision = "e28c029a8fa46fa933cbf6d6d9a1c00978c5fad1";
      hash = "sha256-ngQPAV16iQpHTbCH5BpyF0b0NDXjiLvnEZ8aQs0a/qc=";
    }
    {
      path = "src/external/IOKitUser";
      repository = "darling-iokituser";
      revision = "534684e6748dffbd875c6cd1942477a52b66a077";
      hash = "sha256-KTUQGg7W4wGr2aCTipF3Fjn+KBJgu+AdzFRIQB0zz3M=";
    }
    {
      path = "src/external/IOKitUser/darling/submodules/IOGraphics";
      repository = "darling-IOGraphics";
      revision = "905186151d713259296f3ae9458195a7097ea323";
      hash = "sha256-rMpGaM6cz1RqatreyqBrzgCLZPoiMJ1BJbpEh7+0J80=";
    }
    {
      path = "src/external/IOKitUser/darling/submodules/IOHIDFamily";
      repository = "darling-IOHIDFamily";
      revision = "189e98e32092d5f5a2c365cc85fd36ac7da2d371";
      hash = "sha256-+ryJT+wT9E/aUMKS5Ms1zjqUhTNtuqQapxzuSOdf9gw=";
    }
    {
      path = "src/external/foundation";
      repository = "darling-foundation";
      revision = "55a4341b470c2a56fea667c1d2167fb074226f04";
      hash = "sha256-kKODdVOzUEzfQocxn4K7M5IBuJbSVfHF9QPZJHEqWWg=";
    }
    {
      path = "src/external/cocotron";
      repository = "darling-cocotron";
      revision = "c8d38d16a9f613d300157bebbab2b9501bc0c274";
      hash = "sha256-YhVafn++DT1m6GVtVGT50lEmclERSs7t3ZDgb8XxTdA=";
    }
    {
      path = "src/external/mDNSResponder";
      repository = "darling-mDNSResponder";
      revision = "7e38ef562b4f3d41bffabb3e30d844d8042d3bbd";
      hash = "sha256-hPVgEJgzqCQA0xNHfdnwSIhKHaVFMHONnKY72L2Rk5c=";
    }
    {
      path = "src/external/librpcsvc";
      repository = "darling-librpcsvc";
      revision = "0cc1d42e53c61446616719597e96b29aeda51eb3";
      hash = "sha256-P2+P5ZA7rl14+fEbmsNJo47jrgE72cFf/sLC/jvbwSE=";
    }
    {
      path = "src/external/security";
      repository = "darling-security";
      revision = "3cfffcf2c5b5900169c964facdf42cc05c23005c";
      hash = "sha256-DJU6OXmIQV55OQU0Pz6BXZYmenaO8SH9tuIqsEjgyX8=";
    }
    {
      path = "src/external/cfnetwork";
      repository = "darling-cfnetwork";
      revision = "e7e3db881008d883f82914765a72ce842bcba735";
      hash = "sha256-NhquNwVY5b4xfwlsAtZZILvyzhCbi5ecMuztoKx1794=";
    }
    {
      path = "src/external/DirectoryService";
      repository = "darling-DirectoryService";
      revision = "feb9742f574ab812a210634fd3997f19b645095f";
      hash = "sha256-l4Uu6ePTesSk5/NDVnqp3gLIG4WA2m7whkdWJRqyBdM=";
    }
    {
      path = "src/external/Libinfo";
      repository = "darling-Libinfo";
      revision = "93d242ce3f86d1de67522279edb3a2dcb23f30c7";
      hash = "sha256-8JAyycWZzcvjW9bFHLYBUUBfwD0wQ7o3YsjMOFiVzcs=";
    }
    {
      path = "src/external/bootstrap_cmds";
      repository = "darling-bootstrap_cmds";
      revision = "0f300a7a04bb1174a3b7db58b57d738aadc14e13";
      hash = "sha256-tIO2mCnsza0Ckziuv1S8Z23FFJwmupAffTemiCv1+Nc=";
    }
    {
      path = "src/external/architecture";
      repository = "darling-architecture";
      revision = "63162c4744e9bd07673d4c29f8825f105f670e44";
      hash = "sha256-Hbqjhk9ajH570fosXhQW+jY8OGR5TmN+imWhHo75+Ug=";
    }
    {
      path = "src/external/bsm";
      repository = "darling-bsm";
      revision = "bec0dd61bb07469d1fcb3985822d350abc9934f7";
      hash = "sha256-1oiKgfrdul4KgnrvjNDzJM2KOuADDSevluy5xaAldlo=";
    }
    {
      path = "src/external/cctools";
      repository = "darling-cctools";
      revision = "8777b6dc7c4de87087c028e17db075795b3684d3";
      hash = "sha256-GzDbdWShxMWksO8WvFyb7VNXRRnScKItbNxEzAKXzsk=";
    }
    {
      path = "src/external/cctools-port";
      repository = "cctools-port";
      revision = "d9456c221e1f462e17c0b3297748bc089d5a861e";
      hash = "sha256-lvC4VjddJMVyNszhOjHFvy+kiEPhHsnCNR4zLuRCe/Q=";
    }
    {
      path = "src/external/commoncrypto";
      repository = "darling-commoncrypto";
      revision = "2434540f41a5f94f149cfddd67da244961b716e5";
      hash = "sha256-3G9m+RxX3nnLjTU2WdBRcXrM4VaSlFcEGnyPe5Djo0E=";
    }
    {
      path = "src/external/compiler-rt";
      repository = "darling-compiler-rt";
      revision = "5fd9bc0effa307b99b35da59ce579e8e031c22da";
      hash = "sha256-pvGTxprYQNhYbkdYhojxwIpbuPA/KadaeBfbOFii4JI=";
    }
    {
      path = "src/external/configd";
      repository = "darling-configd";
      revision = "98e52de19c52f7938e581ed20385f38abd7fa197";
      hash = "sha256-CsvGF2nTVE7BZSX2eceLrUeTP7rh0M6ZA5Jn4e00fTI=";
    }
    {
      path = "src/external/copyfile";
      repository = "darling-copyfile";
      revision = "ed6094c9a2f8ba19aa55b7b504c3665797078e8f";
      hash = "sha256-w82e7OX8W/ltVMh8IVDygLYQc/wmmAvsEX6VRiwMigY=";
    }
    {
      path = "src/external/corecrypto";
      repository = "darling-corecrypto";
      revision = "875f1cd9e75b0029d872b88ce8a77da276c00c84";
      hash = "sha256-L0XUt5iJSzzRqYFtK/4wEIqNeu2QITV5Vxz/OeHO204=";
    }
    {
      path = "src/external/corefoundation";
      repository = "darling-corefoundation";
      revision = "a3640a77410cf1825f7855172b1551ae7917c461";
      hash = "sha256-EBYcGdhN/yC+sognIdl25OjTxTP2tGxIZCD/JIhVA6I=";
    }
    {
      path = "src/external/corefoundation/submodules/swift-corelibs-foundation";
      repository = "darling-swift-corelibs-foundation";
      revision = "ea1ea0bb416025a8cc5a282df03c2e8f12788e2d";
      hash = "sha256-U8zWZYhVvPRQuT/2BDaLHP78QVFe7lfPlMQiXKkFntg=";
    }
    {
      path = "src/external/coretls";
      repository = "darling-coretls";
      revision = "b61a4f075726e7d5ef4652033f8d7b829c008d06";
      hash = "sha256-kXqv9mEoKH+LPS5ycYIxCnm9YiTPisbI3VASAkmoxt8=";
    }
    {
      path = "src/external/csu";
      repository = "darling-Csu";
      revision = "93b25cf0930a727b44fa50893bffd71056ad032f";
      hash = "sha256-m0m4h9Jn0DvXLziR0JNm94SwRFsUxiGFBTmt4vR0TQY=";
    }
    {
      path = "src/external/darlingserver";
      repository = "darlingserver";
      revision = "89751e64bc6c2082f7725061824ee0e33395b0de";
      hash = "sha256-cIKzqxLl9Nr/USkQvS4O18NpHeWtSH6JETQD2GXx6JI=";
    }
    {
      path = "src/external/dyld";
      repository = "darling-dyld";
      revision = "63f667cf06d7ed59553adebb0c8d70a117135ac9";
      hash = "sha256-bbRRJssa1xAZPI2EVzWxzdCnYXJaTTs5vuwC8rFy1aY=";
    }
    {
      path = "src/external/icu";
      repository = "darling-icu";
      revision = "6b609b2b0ce9a620543f357de4e549f09afec4ea";
      hash = "sha256-iyaQHn5cUKDHYt79/stPbSH5RQGRE0Lq2lY484TWe9g=";
    }
    {
      path = "src/external/keymgr";
      repository = "darling-keymgr";
      revision = "43b4230aec2e9018b0ffd3069b8b23a34ba257fb";
      hash = "sha256-fVBTZ049CFKwyjce5h2JHa1+Tje8uZLhkcw125aMjKM=";
    }
    {
      path = "src/external/libc";
      repository = "darling-Libc";
      revision = "5a38c8dabf9e76b39407c24bc13134e33e5594e6";
      hash = "sha256-wTLnwjtlYT2GL8GuyP1Z04HSGnGJUIcRaGZwrxRuYuc=";
    }
    {
      path = "src/external/libclosure";
      repository = "darling-libclosure";
      revision = "b4122f19c89512d9e930259a85c5f2674eff2b2b";
      hash = "sha256-b3+pUMtGLq+/4QjHAN0rz0lBhx2Q8wF8RXQ1CfYxaMo=";
    }
    {
      path = "src/external/libcxx";
      repository = "darling-libcxx";
      revision = "c47677d3ba33bdabbfb07e75f531831579355a2d";
      hash = "sha256-rPXQ+B3TdrrlnBQTekczaVxe23tURrT88Qw4vsSpwwk=";
    }
    {
      path = "src/external/libcxxabi";
      repository = "darling-libcxxabi";
      revision = "c9c851718eb304a9aefa097aeaaf8c3bd1dff1bc";
      hash = "sha256-3BpwlkU76i1MRgZCVMDsAe9dk1kiTm3RXTyWyc6GEdI=";
    }
    {
      path = "src/external/libdispatch";
      repository = "darling-libdispatch";
      revision = "380f03c180b80d940134fb35783ddc714784a53a";
      hash = "sha256-D7IAlxECGrqXzj78tutDhkFAQuCNi3LK2q6Apqgs/hI=";
    }
    {
      path = "src/external/libedit";
      repository = "darling-libedit";
      revision = "f9b44b8541614e33b09451fc2847f7e30bfb9b70";
      hash = "sha256-ur6ZgvhxrCYM6uQERAgpYUT/WtN5Nt5TdBnkYaWsnLo=";
    }
    {
      path = "src/external/libkqueue";
      repository = "darling-libkqueue";
      revision = "b0795a2e1dab5331116770139bfea8d832478f5f";
      hash = "sha256-TtNK2bwlvOviUnuzWbAO+RGqgnrS9R5HXQNhZGODtGA=";
    }
    {
      path = "src/external/libmalloc";
      repository = "darling-libmalloc";
      revision = "a57991e2651226a675654bd96e5d9ab6bec288c5";
      hash = "sha256-wL9OIw8JzuZFmIkd1tcmC8v9E7J2VnvTnIn0W4RWM/E=";
    }
    {
      path = "src/external/libnotify";
      repository = "darling-Libnotify";
      revision = "98156d3f847a3ced6c5f52c12a889047bc4f9b20";
      hash = "sha256-iM6HSFF71+XyqRMCJ7XwPIqybf936iMczAnCB26ommo=";
    }
    {
      path = "src/external/libplatform";
      repository = "darling-libplatform";
      revision = "5a3e5b529d25c70257dcfa97e94f1826e71e9f40";
      hash = "sha256-hhHYrc0O6HpmCtb4e7nEKIxXKd5p7yHf1Jfyrx/qUwo=";
    }
    {
      path = "src/external/libpthread";
      repository = "darling-libpthread";
      revision = "f07f265bfbcf071c1adfc808de971e053ea5edc5";
      hash = "sha256-R+te+rf4ivs0dnvKgqFpiLVVSTENHD98tTsneM9pOaQ=";
    }
    {
      path = "src/external/libresolv";
      repository = "darling-libresolv";
      revision = "cf955392e5449efb269b8b3510c755085fd36a2d";
      hash = "sha256-8wI7Pyt/X01bCO4BMyk2MXM7ipKwwScSn28vx5hRoac=";
    }
    {
      path = "src/external/libstdcxx";
      repository = "darling-libstdcxx";
      revision = "73eb757fe23170c372bef17d6de41787c1271c80";
      hash = "sha256-rJhBU/j4bWZ7pJrJOlwjSHKzdof2byRyZ1mgSK+Q1UE=";
    }
    {
      path = "src/external/libsystem";
      repository = "darling-Libsystem";
      revision = "08df454b6eb0df9400aa4c39839a7efd6efd2c3c";
      hash = "sha256-/g7jQAqJSXMVwgFoAL64Ar+9GOnUBDxczDdZuU1ojOY=";
    }
    {
      path = "src/external/libtrace";
      repository = "darling-libtrace";
      revision = "8cf07f02b15f7dca6436882a03678fff0392eaf6";
      hash = "sha256-nuWxkHqJT5UyZGG64fK2E10o+h0dTuUG5jHUsTHU+nM=";
    }
    {
      path = "src/external/libunwind";
      repository = "darling-libunwind";
      revision = "a91da1a0e262e04eb601152a84228ff733e48422";
      hash = "sha256-2ZwD1PRZveCoPPT1411FhVIfbxT3dUj8iZeBfBB+DiU=";
    }
    {
      path = "src/external/libxpc";
      repository = "darling-libxpc";
      revision = "394e033333d3c253a12f08a99090c113b0917d00";
      hash = "sha256-vLtO/uZtsw21X5vQu9JH/QfqRYZZdWOVnsNtDnT1v2A=";
    }
    {
      path = "src/external/ncurses";
      repository = "darling-ncurses";
      revision = "4cc72a9a1bce214593c10811b0154a8d51db0239";
      hash = "sha256-aefAwaESxjrNgfInHewzfvK/5QPp89iD6BYu1oS6Iz4=";
    }
    {
      path = "src/external/objc4";
      repository = "darling-objc4";
      revision = "1a12df76d12bfc9fdfffadb290f7742763568765";
      hash = "sha256-pO6N5R8x2J483xFI/PU0UI0AaV/10d4o8/pRrW0UWyA=";
    }
    {
      path = "src/external/removefile";
      repository = "darling-removefile";
      revision = "3cd493871f27130f9cf64c31daab9cca2ee17726";
      hash = "sha256-7yDzJ4uRuhYXV7ix6HmH1+tOxF33EhBiCSJcagG6e6g=";
    }
    {
      path = "src/external/syslog";
      repository = "darling-syslog";
      revision = "36ab27964cac4affe3907a598047bd21b8958919";
      hash = "sha256-5J+MpXNiHDQ/SXVCUu6i1mYZZ+qvUh/2MW2nKWQ7K+M=";
    }
    {
      path = "src/external/usertemplate";
      repository = "darling-usertemplate";
      revision = "5f8cca97aa03ff9290d6ccc0a4d185aa1a913875";
      hash = "sha256-B/sfvJxjvM1iDfOS56gCTHY0mTZaKFwzh1haje0Sn9E=";
    }
    {
      path = "src/external/vim";
      repository = "darling-vim";
      revision = "7f8da1dd66fc8f0654ebfa597b6013c8cf15185a";
      hash = "sha256-xrid2iZn9+sR6z8X3DURLykDXUirmu17nbtU4Sw7Lo8=";
    }
    {
      path = "src/external/xnu";
      repository = "darling-xnu";
      revision = "fa29287aa2f0115271e091f1031f53c9e024005d";
      hash = "sha256-7YKobVQNnsCI2kjGInfP72P/u1UrXBdEWAT/5UEmvac=";
    }
    {
      path = "src/external/zlib";
      repository = "darling-zlib";
      revision = "677de9b1c2bea1e428f56d8fc63300aa471eaf99";
      hash = "sha256-NJineP+s7aWBttrrZTqFnCQ9Ei5au09YHm4H2sHhqE8=";
    }
  ];
}
