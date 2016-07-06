package x509;

import sun.misc.IOUtils;
import tools.BashReader;
import tools.FileReader;
import tools.FileWriter;
import tools.Logger;

import java.io.File;
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

    Key() {
        bits = 2048;
        format = "X.509";
        algorithm = "rsa";
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
        if (derContents == null && pemContents == null) {
            this.create();
        } else if (pemContents != null) {
            try {
                derContents = toDER(pemContents);
            } catch (CertificateException e) {
                Logger.error(e.getClass(), e.getMessage(), true);
                derContents = new byte[0];
            }
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

    protected void setPublic() {
        this.isPrivate = false;
        this.isPublic = true;
    }

    protected void setPrivate() {
        this.isPrivate = true;
        this.isPublic = false;
    }

    public static byte[] toDER(String pemContents) throws CertificateException {
        // openssl rsa -in key.pem -outform DER -out keyout.der
        if (pemContents == null) {
            throw new CertificateException("The PEM contents cannot be null");
        }

        pemContents = pemContents.trim();

        if (pemContents.startsWith("-----BEGIN PRIVATE KEY-----") && pemContents.endsWith("-----END PRIVATE KEY-----") ||
                pemContents.startsWith("-----BEGIN RSA PRIVATE KEY-----") && pemContents.endsWith("-----END RSA PRIVATE KEY-----")) {
            String tempPEMFile = "tmp/pemtoder.pem";
            FileWriter.write(pemContents, tempPEMFile);
            String tempDERFile = "tmp/keyout.der";
            String[] args = {"openssl", "rsa", "-in", tempPEMFile, "-out", tempDERFile, "-outform", "DER"};
            BashReader br = BashReader.read(args);

            if (br == null) {
                throw new CertificateException("Invalid command used to convert PEM to DER.");
            }
            if (br.getExitValue() != 0) {
                throw new CertificateException(br.getErrorMessage().isEmpty() ? "PEM > DER error ("+br.getExitValue()+")" : br.getErrorMessage());
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

    public static void main(String[] args) {
        String contents = BashReader.toSingleString(FileReader.getLines("test-key.key"));
        PrivateKey privateKey = PrivateKey.loadPrivateKey(contents);
        System.out.println(privateKey.dumpPEM());
        System.out.println(new String(privateKey.dumpDER()));
    }

    public void setPemContents(String pemContents) {
        this.pemContents = pemContents;
    }

    public abstract void check(Certificate certificate) throws CertificateException;
}
