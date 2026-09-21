import java.io.ByteArrayInputStream;
import java.io.InputStreamReader;

/** Checks interpreter operand slots shared by floating and integer values. */
public class FloatConversions {
    public static void main(String[] arguments) throws Exception {
        float value = arguments.length + 1f;
        double converted = value;
        if (converted != 1.0 || (int) (8192 * converted) != 8192
                || (float) converted != value) {
            throw new AssertionError("floating operand conversion changed");
        }

        byte[] input = {65};
        InputStreamReader reader = new InputStreamReader(
                new ByteArrayInputStream(input), "UTF-8");
        char[] output = new char[8192];
        if (reader.read(output, 0, output.length) != 1 || output[0] != 'A'
                || reader.read(output, 0, output.length) != -1) {
            throw new AssertionError("UTF-8 reader lost its input");
        }
        reader.close();

        System.out.println("Floating conversions passed");
    }
}
