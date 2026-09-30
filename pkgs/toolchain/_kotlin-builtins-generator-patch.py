"""Adapt the 2013 source generator to run without its test framework."""

from pathlib import Path

path = Path(
    "kotlin/generators/org/jetbrains/jet/generators/builtins/BuiltInsSerializer.java"
)
source = path.read_text()


def replace(old: str, new: str) -> None:
    global source
    if source.count(old) != 1:
        raise SystemExit(f"Generator patch did not match: {old}")
    source = source.replace(old, new)


replace("import org.jetbrains.jet.JetTestUtils;\n", "")
replace("import org.jetbrains.jet.lang.resolve.lazy.LazyResolveTestUtil;\n", "")
replace("import org.jetbrains.jet.lang.resolve.name.FqName;\n", "")
replace(
    "import com.google.common.base.Predicate;\n",
    "import com.google.common.base.Predicate;\n"
    "import com.intellij.openapi.project.Project;\n"
    "import org.jetbrains.jet.cli.jvm.compiler.CliLightClassGenerationSupport;\n"
    "import org.jetbrains.jet.di.InjectorForJavaDescriptorResolver;\n"
    "import org.jetbrains.jet.lang.ModuleConfiguration;\n"
    "import org.jetbrains.jet.lang.descriptors.ModuleDescriptorImpl;\n"
    "import org.jetbrains.jet.lang.psi.JetPsiFactory;\n"
    "import org.jetbrains.jet.lang.resolve.BindingTrace;\n"
    "import org.jetbrains.jet.lang.resolve.java.AnalyzerFacadeForJVM;\n"
    "import org.jetbrains.jet.lang.resolve.java.JavaDescriptorResolver;\n"
    "import org.jetbrains.jet.lang.resolve.java.PsiClassFinder;\n"
    "import org.jetbrains.jet.lang.resolve.lazy.ResolveSession;\n"
    "import org.jetbrains.jet.lang.resolve.lazy.declarations.FileBasedDeclarationProviderFactory;\n"
    "import org.jetbrains.jet.lang.resolve.lazy.storage.LockBasedStorageManager;\n"
    "import org.jetbrains.jet.lang.resolve.name.FqName;\n"
    "import org.jetbrains.jet.lang.resolve.scopes.JetScope;\n"
    "import org.jetbrains.jet.lang.resolve.scopes.WritableScope;\n",
)
replace(
    "import java.util.List;\n",
    "import java.util.ArrayList;\nimport java.util.Collections;\nimport java.util.List;\n",
)
replace(
    'private static final String BUILT_INS_SRC_DIR = "compiler/frontend/src";',
    'private static final String BUILT_INS_SRC_DIR = "kotlin/compiler/frontend/builtins";',
)
replace(
    'private static final String DEST_DIR = "compiler/frontend/" + BuiltInsSerializationUtil.BUILT_INS_DIR;',
    'private static final String DEST_DIR = "generated-builtins";',
)
replace("JetTestUtils.loadToJetFiles(environment, sourceFiles)", "loadToJetFiles(environment, sourceFiles)")
replace("LazyResolveTestUtil.resolveLazily(files, environment, false)", "resolveLazily(files, environment)")
replace(
    "        Disposable rootDisposable = Disposer.newDisposable();",
    "        Collections.sort(sourceFiles);\n"
    "        Disposable rootDisposable = Disposer.newDisposable();",
)

methods = r'''
    private static List<JetFile> loadToJetFiles(JetCoreEnvironment environment, List<File> files) throws IOException {
        List<JetFile> jetFiles = new ArrayList<JetFile>();
        for (File file : files) {
            jetFiles.add(JetPsiFactory.createPhysicalFile(
                    environment.getProject(), file.getName(), FileUtil.loadFile(file)));
        }
        return jetFiles;
    }

    private static ModuleDescriptor resolveLazily(List<JetFile> files, JetCoreEnvironment environment) {
        Project project = environment.getProject();
        CliLightClassGenerationSupport.getInstanceForCli(project).newBindingTrace();
        BindingTrace trace = CliLightClassGenerationSupport.getInstanceForCli(project).getTrace();
        ModuleDescriptorImpl javaModule = AnalyzerFacadeForJVM.createJavaModule("<java module>");
        InjectorForJavaDescriptorResolver injector = new InjectorForJavaDescriptorResolver(project, trace, javaModule);
        final PsiClassFinder classFinder = injector.getPsiClassFinder();
        final JavaDescriptorResolver javaResolver = injector.getJavaDescriptorResolver();

        LockBasedStorageManager storageManager = new LockBasedStorageManager();
        FileBasedDeclarationProviderFactory providers = new FileBasedDeclarationProviderFactory(
                storageManager, files, new Predicate<FqName>() {
                    @Override
                    public boolean apply(FqName fqName) {
                        return classFinder.findPsiPackage(fqName) != null || new FqName("jet").equals(fqName);
                    }
                });

        ModuleConfiguration configuration = new ModuleConfiguration() {
            @Override
            public void extendNamespaceScope(
                    @NotNull BindingTrace namespaceTrace,
                    @NotNull NamespaceDescriptor namespace,
                    @NotNull WritableScope scope) {
                FqName name = DescriptorUtils.getFQName(namespace).toSafe();
                if (classFinder.findPsiPackage(name) != null) {
                    JetScope javaScope = javaResolver.getJavaPackageScope(namespace);
                    if (javaScope == null) {
                        throw new IllegalStateException("Missing Java package scope: " + name);
                    }
                    scope.importScope(javaScope);
                }
            }
        };
        javaModule.setModuleConfiguration(configuration);

        ModuleDescriptorImpl lazyModule = AnalyzerFacadeForJVM.createJavaModule("<lazy module>");
        lazyModule.setModuleConfiguration(configuration);
        return new ResolveSession(project, storageManager, lazyModule, providers, trace).getRootModuleDescriptor();
    }
'''

index = source.rfind("\n}")
if index < 0:
    raise SystemExit("Missing generator class end")
source = source[:index] + "\n" + methods + source[index:]
path.write_text(source)
