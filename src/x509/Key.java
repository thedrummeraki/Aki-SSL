package x509;

import sun.misc.IOUtils;
import tools.BashReader;

import java.io.IOException;
import java.io.RandomAccessFile;

/**
 * Created by aakintol on 28/06/16.
 */
public abstract class Key implements Dumpable {

    protected byte[] derContents;
    protected String pemContents;

    private String format;
    protected String algorithm;
    protected int bits;

    private boolean isPublic;
    private boolean isPrivate;

    Key() throws CertificateException {
        this(false, false);
    }

    Key(boolean isPrivate, boolean isPublic) throws CertificateException {
        if (isPrivate && isPublic) {
            throw new CertificateException("A key cannot be public AND private at the same time.");
        }
        this.isPrivate = isPrivate;
        this.isPublic = isPublic;
        bits = 2048;
        format = "X.509";
        algorithm = "rsa";

    }

    public void setFormat(String format) {
        this.format = format;
    }

    public void setAlgorithm(String algorithm) {
        this.algorithm = algorithm;
    }

    public void setBits(int bits) {
        this.bits = bits;
    }

    public void setDerContents(byte[] derContents) {
        this.derContents = derContents;
    }

    public static Key loadFromFile(String filename) {
        return null;
    }

    public abstract Key create();

    @Override
    public byte[] dumpDER() {
        if (derContents == null) {
            this.create();
        }
        return derContents;
    }

    @Override
    public String dumpPEM() {
        if (pemContents == null) {
            this.create();
        }
        return pemContents;
    }

    public static byte[] toDER(String pemContents) throws CertificateException {
        // openssl rsa -in key.pem -outform DER -out keyout.der
        if (pemContents == null) {
            throw new CertificateException("The PEM contents cannot be null");
        }

        if (pemContents.startsWith("-----BEGIN PRIVATE KEY-----") && pemContents.endsWith("-----END PRIVATE KEY-----") ||
                pemContents.startsWith("-----BEGIN RSA PRIVATE KEY-----") && pemContents.endsWith("-----END RSA PRIVATE KEY-----")) {
            String tempPEMFile = "tmp/pemtoder.pem";
            String tempDERFile = "tmp/keyout.der";
            String[] args = {"openssl", "rsa", "-in", tempPEMFile, "-outform", "DER", tempDERFile};
            try {
                BashReader.readAndThrow(args);
            } catch (Exception e) {
                throw new CertificateException("Could not make the conversion -> " + e);
            }

            // Read the file without tools.FileReader
            try {
                RandomAccessFile randomAccessFile = new RandomAccessFile(tempDERFile, "r");
                byte[] contents = new byte[(int) randomAccessFile.length()];
                randomAccessFile.read(contents);
                return contents;
            } catch (IOException e) {
                throw new CertificateException("Failed to read the contents of the file -> " + e);
            }
        }
        throw new CertificateException("Header or/and footer missing.");
    }

}
