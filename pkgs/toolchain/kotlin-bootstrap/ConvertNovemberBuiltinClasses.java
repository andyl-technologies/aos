import java.io.FileInputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Stream;

import org.jetbrains.jet.descriptors.serialization.NameResolver;
import org.jetbrains.jet.descriptors.serialization.NameSerializationUtil;
import org.jetbrains.jet.descriptors.serialization.ProtoBuf;
import org.jetbrains.jet.lang.types.lang.BuiltInsSerializationUtil;

/** Adapts the source-generated August builtins class index to November's name field. */
public final class ConvertNovemberBuiltinClasses {
    public static void main(String[] args) throws Exception {
        Path root = Paths.get(args[0]);
        Map<String, Integer> classNames = new HashMap<String, Integer>();
        Map<String, Integer> simpleNames = new HashMap<String, Integer>();
        NameResolver names;
        try (InputStream input = new FileInputStream(root.resolve("jet/.kotlin_name_table").toFile())) {
            names = NameSerializationUtil.deserializeNameResolver(input);
        }
        ProtoBuf.SimpleNameTable.Builder simpleNameTable = names.getSimpleNameTable().toBuilder();
        ProtoBuf.QualifiedNameTable.Builder qualifiedNameTable = names.getQualifiedNameTable().toBuilder();
        for (int index = 0; index < names.getSimpleNameTable().getNameCount(); index++) {
            simpleNames.put(names.getSimpleNameTable().getName(index), index);
        }
        Integer packageName = null;
        for (int index = 0; index < names.getQualifiedNameTable().getQualifiedNameCount(); index++) {
            ProtoBuf.QualifiedNameTable.QualifiedName qualifiedName =
                    names.getQualifiedNameTable().getQualifiedName(index);
            if (qualifiedName.getKind() == ProtoBuf.QualifiedNameTable.QualifiedName.Kind.PACKAGE
                    && names.getFqName(index).asString().equals("jet")) {
                packageName = index;
            }
            if (qualifiedName.getKind() != ProtoBuf.QualifiedNameTable.QualifiedName.Kind.CLASS) {
                continue;
            }
            String path = BuiltInsSerializationUtil.getClassMetadataPath(names.getClassId(index));
            classNames.put(path, index);
        }
        if (packageName == null) {
            throw new IllegalStateException("Missing jet package name");
        }

        Path[] classFiles;
        try (Stream<Path> paths = Files.walk(root)) {
            classFiles = paths.filter(Files::isRegularFile)
                    .filter(path -> path.toString().endsWith(".kotlin_class"))
                    .sorted()
                    .toArray(Path[]::new);
        }

        for (Path path : classFiles) {
            String relative = root.relativize(path).toString();
            Integer className = classNames.get(relative);
            if (className == null) {
                String shortName = relative.substring("jet/".length(),
                        relative.length() - ".kotlin_class".length());
                if (shortName.contains(".")) {
                    throw new IllegalStateException("Nested class needs explicit parent: " + relative);
                }
                Integer shortNameIndex = simpleNames.get(shortName);
                if (shortNameIndex == null) {
                    shortNameIndex = simpleNameTable.getNameCount();
                    simpleNameTable.addName(shortName);
                    simpleNames.put(shortName, shortNameIndex);
                }
                className = qualifiedNameTable.getQualifiedNameCount();
                qualifiedNameTable.addQualifiedName(
                        ProtoBuf.QualifiedNameTable.QualifiedName.newBuilder()
                                .setParentQualifiedName(packageName)
                                .setShortName(shortNameIndex)
                                .setKind(ProtoBuf.QualifiedNameTable.QualifiedName.Kind.CLASS));
                classNames.put(relative, className);
            }

            ProtoBuf.Class.Builder classMessage = ProtoBuf.Class.newBuilder();
            try (InputStream input = Files.newInputStream(path)) {
                classMessage.mergeFrom(input);
            }
            classMessage.setFqName(className);
            try (OutputStream output = Files.newOutputStream(path)) {
                classMessage.build().writeTo(output);
            }
        }

        try (OutputStream output = Files.newOutputStream(root.resolve("jet/.kotlin_name_table"))) {
            simpleNameTable.build().writeDelimitedTo(output);
            qualifiedNameTable.build().writeDelimitedTo(output);
        }
        System.out.println("Converted " + classFiles.length + " builtin classes");
    }
}
