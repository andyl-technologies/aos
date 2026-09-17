import java.io.File;

/** Checks the Java values returned by native methods with unspecified high bits. */
public class JniReturns {
    private static native boolean falseValue();
    private static native boolean trueValue();
    private static native byte byteValue();
    private static native char charValue();
    private static native short shortValue();

    public static void main(String[] arguments) {
        System.load(arguments[0]);

        if (falseValue() || !trueValue()
                || byteValue() != -5 || charValue() != 0x1234
                || shortValue() != -1234) {
            throw new AssertionError("JNI narrow return value changed");
        }

        File absent = new File("nonexistent-file");
        if (absent.exists() || absent.isFile() || absent.isDirectory()) {
            throw new AssertionError("a nonexistent path has a file type");
        }

        System.out.println("JNI narrow returns passed");
    }
}
