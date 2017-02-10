package aki.packages.scep;

import aki.packages.tools.BashReader;
import aki.packages.tools.MyFileReader;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;

import java.io.File;

/**
 * Created by aakintol on 09/08/16.
 */
public final class PKCS7 {

    private final static String HEADER = "-----BEGIN PKCS7-----";
    private final static String FOOTER = "-----END PKCS7-----";

    private String contents;
    private byte[] encoded;

    public enum EncType {
        PEM,
        DER;
    }

    private PKCS7(String contentsOrFile, EncType encType) {
        if (contentsOrFile == null) {
            throw new IllegalArgumentException("Illegal filename or contents (null).");
        }
        if (encType == null) {
            throw new IllegalArgumentException("Illegal encoding type (null)");
        }
        String contents = null;
        // Is it a file?
        File file = new File(contentsOrFile);
        if (file.isFile()) {
            contents = BashReader.toSingleString(MyFileReader.getLines(file.getPath()));
        } else {
            contents = contentsOrFile;
        }
        if (encType.equals(EncType.PEM)) {
            if (!contents.startsWith(HEADER) || !contents.endsWith(FOOTER)) {
                throw new IllegalArgumentException("Invalid PEM contents (header or footer missing)");
            }
            int se = HEADER.length();
            int es = contents.indexOf(FOOTER);
            String between = contents.substring(se, es);
            String[] tmpb = between.split(" ");
            between = "";
            for (String b : tmpb) {
                between += b;
                between += '\n';
            }
            between = between.trim();
            //System.out.println(between);
            byte[] enc = MyBase64.decode(between.getBytes());
            try {
                new CMSSignedData(enc);
                this.encoded = enc;
                this.contents = HEADER + "\n" + between + "\n" + FOOTER;
            } catch (CMSException e) {
                throw new IllegalArgumentException("Illegal PEM contents. "+e.getMessage());
            }
        } else if (encType.equals(EncType.DER)) {
            byte[] enc = contents.getBytes();
            try {
                new CMSSignedData(enc);
                this.encoded = enc;
                this.contents = contents;
            } catch (CMSException e) {
                e.printStackTrace();
                throw new IllegalArgumentException("Illegal DER contents. "+e.getMessage());
            }
        }
    }

    public int data() {
        int bytes = 0;
        char buffer[] = {0};
        if (this.contents == null) {
            return -1;
        }
        for (;;) {
            if (bytes <= 0) {
                break;
            }
        }
        return 0;
    }

    public String getContents() {
        return contents;
    }

    public byte[] getEncoded() {
        return encoded;
    }

    public static void main(String[] args) {
        String file = "/home/aakintol/Desktop/sscep/other_pkcs7";
        PKCS7 pkcs7 = new PKCS7(file, EncType.PEM);
        try {
            CMSSignedData s = new CMSSignedData(pkcs7.getEncoded());

        } catch (CMSException e) {
            e.printStackTrace();
        }
    }

}
