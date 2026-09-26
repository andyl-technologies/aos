"""Apply source compatibility fixes for the serialized 2013 Kotlin stage."""

from pathlib import Path

root = Path("kotlin")


def replace(relative_path: str, original: str, replacement: str) -> None:
    path = root / relative_path
    source = path.read_text()
    if source.count(original) != 1:
        raise SystemExit(f"Kotlin compatibility patch did not match: {relative_path}")
    path.write_text(source.replace(original, replacement))


replace(
    "compiler/frontend/src/org/jetbrains/jet/lang/resolve/name/FqNameUnsafe.java",
    'StringUtil.join(names, ".")',
    'com.google.common.base.Joiner.on(".").join(names)',
)
replace(
    "compiler/jet.as.java.psi/src/org/jetbrains/jet/asJava/JetCodeBlockModificationListener.java",
    "event.isGenericChange()",
    "event.isGenericChildrenChange()",
)
replace(
    "compiler/jet.as.java.psi/src/org/jetbrains/jet/asJava/LightClassUtil.java",
    "import com.intellij.openapi.vfs.StandardFileSystems;\n",
    "",
)
replace(
    "compiler/jet.as.java.psi/src/org/jetbrains/jet/asJava/LightClassUtil.java",
    "StandardFileSystems.FILE_PROTOCOL",
    '"file"',
)

# Enumerating an entire Java package traverses virtual filesystem roots.
# Package metadata only describes declarations from the Kotlin source files.
replace(
    "compiler/backend/src/org/jetbrains/jet/codegen/NamespaceCodegen.java",
    "        ProtoBuf.Package packageProto = serializer.packageProto(descriptor).build();",
    """        ProtoBuf.Package.Builder packageBuilder = ProtoBuf.Package.newBuilder();
        BindingContext bindingContext = state.getBindingContext();
        for (JetFile file : files) {
            for (JetDeclaration declaration : file.getDeclarations()) {
                if (declaration instanceof JetNamedFunction) {
                    FunctionDescriptor function = bindingContext.get(BindingContext.FUNCTION, (JetNamedFunction) declaration);
                    if (function != null) {
                        packageBuilder.addMember(serializer.callableProto(function));
                    }
                }
                else if (declaration instanceof JetProperty) {
                    VariableDescriptor variable = bindingContext.get(BindingContext.VARIABLE, (JetProperty) declaration);
                    if (variable instanceof PropertyDescriptor) {
                        packageBuilder.addMember(serializer.callableProto((PropertyDescriptor) variable));
                    }
                }
            }
        }
        ProtoBuf.Package packageProto = packageBuilder.build();""",
)
