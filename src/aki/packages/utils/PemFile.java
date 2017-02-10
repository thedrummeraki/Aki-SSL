package aki.packages.utils;

import java.io.*;
import java.nio.charset.StandardCharsets;

import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;

public class PemFile {

    private PemObject pemObject;

    public PemFile(byte[] contents) throws IOException {
        this(bytesToInputStringReader(contents));
    }

    public PemFile(String filename) throws IOException {
        this(new InputStreamReader(new FileInputStream(filename)));
    }

    public PemFile(InputStreamReader reader) throws IOException {
        PemReader pemReader = new PemReader(reader);
        try {
            this.pemObject = pemReader.readPemObject();
        } finally {
            pemReader.close();
        }
    }

    public PemObject getPemObject() {
        return pemObject;
    }

    public static InputStreamReader stringToInputStringReader(String string) {
        return bytesToInputStringReader(string.getBytes(StandardCharsets.UTF_8));
    }

    public static InputStreamReader bytesToInputStringReader(byte[] string) {
        InputStream stream = new ByteArrayInputStream(string);
        return new InputStreamReader(stream);
    }
}
