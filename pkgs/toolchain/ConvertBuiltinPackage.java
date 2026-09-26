import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import org.jetbrains.jet.descriptors.serialization.ProtoBuf;

/** Converts source-generated builtin callables to the later package envelope. */
public final class ConvertBuiltinPackage {
    public static void main(String[] args) throws IOException {
        ProtoBuf.Package.Builder result = ProtoBuf.Package.newBuilder();
        FileInputStream input = new FileInputStream(args[0]);
        try {
            ProtoBuf.Callable callable;
            while ((callable = ProtoBuf.Callable.parseDelimitedFrom(input)) != null) {
                result.addMember(callable);
            }
        } finally {
            input.close();
        }

        FileOutputStream output = new FileOutputStream(args[1]);
        try {
            result.build().writeTo(output);
        } finally {
            output.close();
        }
    }
}
