package x509;

import attributes.Attribute;
import attributes.AttributeSet;

import tools.BashReader;
import tools.FileReader;
import tools.FileWriter;
import tools.Logger;

import java.io.*;
import java.util.ArrayList;

/**
 * Created by aakintol on 28/06/16.
 */
public class Signable implements Dumpable {

    private static final String TAG = Signable.class.getSimpleName();
    private Certificate certSigner;
    private PrivateKey privateKeySigner;
    private FileType type;

    private AttributeSet signedAttributes;

    protected boolean isSigned;
    private String contents;
    private String signedDataPEM;
    private byte[] signedDataDER;

    private ArrayList<File> tempFiles;

    private String filename;
    private String contentsFilename;
    private String signerFilename;
    private String privateKeyFilename;
    private String signedFilenamePEM;
    private String signedFilenameDER;

    public Signable() {
        type = FileType.PEM;
        String tempHex = FileWriter.dumpFilename(5, true, "");
        contentsFilename = "tmp/temp-"+tempHex+"-contents.data";
        signerFilename = "tmp/temp-"+tempHex+"-contents.signer";
        privateKeyFilename = "tmp/temp-"+tempHex+"-contents.prkey";
        signedFilenamePEM = "tmp/temp-"+tempHex+"-contents.pem.signed";
        signedFilenameDER = "tmp/temp-"+tempHex+"-contents.der.signed";
    }

    @Override
    public byte[] dumpDER() {
        // Convert the blob of data to a DER contents
        if (contents == null) {
            return null;
        }
        return new byte[0];
    }

    @Override
    public String dumpPEM() {
        return contents;
    }

    public byte[] getSignedDataDER() {
        return signedDataDER;
    }

    public void setContents(String contents) {
        this.contents = contents;
        FileWriter.write(contents, contentsFilename);
    }

    public String getContents() {
        return contents;
    }

    public Certificate getCertSigner() {
        return certSigner;
    }

    public void setCertSigner(Certificate certSigner) {
        if (certSigner != null) {
            String blob = certSigner.getBlob();
            FileWriter.write(blob, signerFilename);
        }
        this.certSigner = certSigner;
    }

    public PrivateKey getPrivateKeySigner() {
        return privateKeySigner;
    }

    public void setPrivateKeySigner(PrivateKey privateKeySigner) {
        if (privateKeySigner != null) {
            String blob = privateKeySigner.dumpPEM();
            FileWriter.write(blob, privateKeyFilename);
        }
        this.privateKeySigner = privateKeySigner;
    }

    public String getSignedDataPEM() {
        return signedDataPEM;
    }

    public void setFilename(String filename) {
        this.filename = filename;
    }

    public String getFilename() {
        return getFilename(true);
    }

    public void setSignedFilenamePEM(String signedFilenamePEM) {
        this.signedFilenamePEM = signedFilenamePEM;
    }

    public String getSignedFilenamePEM() {
        return signedFilenamePEM;
    }

    public String getSignedFilenameDER() {
        return signedFilenameDER;
    }

    public String getContentsFilename() {
        return contentsFilename;
    }

    public void setContentsFilename(String contentsFilename) {
        this.contentsFilename = contentsFilename;
    }

    public String getSignerFilename() {
        return signerFilename;
    }

    public void setSignerFilename(String signerFilename) {
        this.signerFilename = signerFilename;
    }

    public String getPrivateKeyFilename() {
        return privateKeyFilename;
    }

    public void setPrivateKeyFilename(String privateKeyFilename) {
        this.privateKeyFilename = privateKeyFilename;
    }

    public void setType(FileType type) {
        this.type = type;
    }

    public FileType getType() {
        return type;
    }

    public void setData(String data) {
        if (data != null) {
            FileWriter.write(data, signedFilenamePEM);
        }
        signedDataPEM = data;
        isSigned = checkSigned();
    }

    public void setData(byte[] data) {
        if (data != null) {
            try {
                FileOutputStream fos = new FileOutputStream(contentsFilename);
                fos.write(data);
                fos.close();
            } catch (IOException e) {
                Logger.error(TAG, "Error while setting the data for the signable: "+e);
            }
        }
        signedDataDER = data;
        isSigned = checkSigned();
    }

    private boolean checkSigned() {
        return signedDataPEM != null && !signedDataPEM.isEmpty() && signedDataDER != null && signedDataDER.length != 0;
    }

    public String getFilename(boolean fullFilename) {
        if (filename == null) {
            filename = TAG;
        }
        return fullFilename ? filename + getFileExtension() : filename;
    }

    public boolean isSigned() {
        return isSigned;
    }

    public AttributeSet getSignedAttributes() {
        return signedAttributes;
    }

    public Attribute getAttribute(String key) {
        return this.signedAttributes.getAttribute(key);
    }

    private String getFileExtension() {
        switch (type.name()) {
            case "PEM": return ".pem";
            case "BER": return ".ber";
            case "CER": return ".cer";
            case "DER": return ".der";
            case "TEXT": return ".txt";
            default: return ".pem";
        }
    }

    protected void createFilename() {
        createFilename(20, true);
    }

    private void createFilename(int length, boolean hex) {
        this.filename = FileWriter.dumpFilename(length, hex, null);
    }

    public String getDERSignedDataAsString() {
        if (signedDataDER == null) {
            return null;
        }
        return new String(signedDataDER);
    }

    protected void addTempFile(File tempFile) {
        if (tempFiles == null) {
            tempFiles = new ArrayList<>();
        }
        tempFiles.add(tempFile);
    }

    protected boolean cleanTempFiles() {
        if (tempFiles == null || tempFiles.isEmpty()) {
            return true;
        }
        boolean ok = true;
        for (File file : tempFiles) {
            if (!file.delete()) {
                ok = false;
            }
        }
        tempFiles = null;
        return ok;
    }

    public boolean sign() throws CertificateException {
        Logger.debug(TAG, "Attempting to sign the "+getClass().getSimpleName());
        if (this.contents == null || this.contents.trim().isEmpty()) {
            throw new SignatureException("No contents were found!");
        }
        if (this.certSigner == null) {
            throw new SignatureException("You need to specify a signer!");
        }
        if (this.privateKeySigner == null) {
            if (this.certSigner.isSelfSigned()) {
                this.privateKeySigner = this.certSigner.getPrivateKey();
            }
            if (this.privateKeySigner == null) {
                throw new SignatureException("You need to specify a private key!");
            }
        }
        if (this.certSigner.getBlob() == null) {
            throw new SignatureException("It appears your certificate signer is empty");
        }
        if (isSigned && signedDataDER != null) {
            // no need to sign it twice
            return true;
        }

        // Make sure the private key and the certificate signer match
        Logger.debug(TAG, "Checking the private key...");
        this.privateKeySigner.check(this.certSigner);

        // Signs the raw data of the signable object
        // Create a temp file that will hold the raw data.
        File tempRawData = new File("tmp/temp-"+getFilename());
        Logger.debug(TAG, "Writing the raw data to a temp file: "+tempRawData.getPath());
        if (!FileWriter.write(this.contents, tempRawData.getAbsolutePath())) {
            throw new SignatureException("Couldn't write the data to a temp file.");
        }
//        addTempFile(tempRawData);
        //Create a temp file that will contain the signer
        File tempSignerBlob = new File("tmp/temp-"+getFilename(false)+".signer");
        Logger.debug(TAG, "Writing the signer's blob to a temp file: "+tempSignerBlob.getPath());
        if (!FileWriter.write(this.certSigner.getBlob(), tempSignerBlob.getAbsolutePath())) {
            throw new SignatureException("Couldn't write the signer's blob of data to the file.");
        }
        addTempFile(tempSignerBlob);

        //Create a temp file that will contain the private key
        File tempKey = new File("tmp/temp-"+getFilename(false)+".key");
        Logger.debug(TAG, "Writing the key to a temp file: "+tempKey.getPath());
        if (!FileWriter.write(this.privateKeySigner.dumpPEM(this.certSigner.getSubject()), tempKey.getAbsolutePath())) {
            throw new SignatureException("Couldn't write the signer's private key to the file.");
        }
        addTempFile(tempKey);

        signedFilenamePEM = "temp-"+getFilename(false)+".signed";

        /**
         * How would we sign the contents?
         * Choice 1:
         * openssl cms -sign -binary -in data.txt -out data.signed -signer signer.pem -inkey -signer.key
         *
         * Choice 2:
         * openssl cms -sign -md sha256 -binary -nocerts -noattr -in data.txt -out data.signed -outform DER -signer signer.pem -inkey signer.key
         * openssl cms -sign -md sha1 -binary -in data.txt -outform der -out signed.data -signer test-signer.pem -inkey test-key.key
         * */

        String[] args = {"openssl", "cms", "-sign", "-md", "sha1", "-binary", "-in", tempRawData.getAbsolutePath(), "-out", signedFilenamePEM,
                "-outform", "DER", "-signer", tempSignerBlob.getAbsolutePath(), "-inkey", tempKey.getAbsolutePath()};

        args = new String[] {"openssl", "cms", "-sign", "-md", "sha1", "-binary", "-in", tempRawData.getPath(), "-outform", "PEM",
                "-out", signedFilenamePEM, "-signer", tempSignerBlob.getPath(), "-inkey", tempKey.getPath()};

        Logger.debug(TAG, "Executing '"+BashReader.toSingleString(args)+"'");
        BashReader bashReader = BashReader.read(args);
        if (bashReader == null || bashReader.getExitValue() != 0) {
            if (bashReader == null) {
                throw new SignatureException("The command \"" + BashReader.toSingleString(args) + "\" failed (null).");
            }
            throw new SignatureException("The command \"" + BashReader.toSingleString(args) + "\" failed - " + bashReader.getOutput() + " ("+bashReader.getExitValue()+")");
        }

        args = new String[] {"openssl", "asn1parse", "-inform", "PEM", "-in", signedFilenamePEM};
        Logger.debug(TAG, "Executing '"+BashReader.toSingleString(args)+"'");
        BashReader br = BashReader.read(args);
        if (br == null || br.getExitValue() != 0) {
            if (br == null) {
                throw new SignatureException("The command \"" + BashReader.toSingleString(args) + "\" failed (null).");
            }
            throw new SignatureException("The command \"" + BashReader.toSingleString(args) + "\" failed - " + br.getOutput() + " ("+br.getExitValue()+")");
        }

        // Now we have a file with DER signed data.
        this.signedDataDER = BashReader.toSingleString(FileReader.getLines(signedFilenamePEM)).trim().getBytes();

//        args = new String[]{"openssl", "cms", "-sign", "-binary", "-outform", "DER", "-in", tempRawData.getAbsolutePath(), "-out", signedFilenamePEM,
//                "-signer", tempSignerBlob.getAbsolutePath(), "-inkey", tempKey.getAbsolutePath()};

//        bashReader = BashReader.read(args);
//        if (bashReader == null || bashReader.getExitValue() != 0) {
//            if (bashReader == null) {
//                throw new SignatureException("The command \"" + BashReader.toSingleString(args) + "\" failed (null).");
//            }
//            throw new SignatureException("The command \"" + BashReader.toSingleString(args) + "\" failed - " + bashReader.getOutput() + " ("+bashReader.getExitValue()+")");
//        }

        // Now we have a file with PEM signed data.
        this.signedDataPEM = BashReader.toSingleString(FileReader.getLines(signedFilenamePEM)).trim();
        this.isSigned = true;

//        if (cleanTempFiles()) {
//            Logger.debug(TAG, TAG + ".sign(): Temp files all cleaned up.");
//        } else {
//            Logger.debug(TAG, TAG + ".sign(): Temp files NOT cleaned up (all or some).");
//        }
        return isSigned;
    }

    public int verify() throws SignatureException {

        if (!isSigned || signedDataDER == null || signedDataPEM == null) {
            throw new SignatureException("You need to sign the data first by calling "+ TAG +".sign()");
        }
        // Locate the signature
        File tempSigned = new File(signedFilenamePEM);
        FileWriter.write(this.getDERSignedDataAsString(), tempSigned.getPath());
        String[] args = {"openssl", "asn1parse", "-inform", "PEM", "-in", signedFilenamePEM};
        BashReader br = BashReader.read(args);
        if (br == null || br.getExitValue() != 0) {
            if (br == null) {
                throw new SignatureException("The command \"" + BashReader.toSingleString(args) + "\" failed (null).");
            }
            throw new SignatureException("The command \"" + BashReader.toSingleString(args) + "\" failed - " + br.getOutput() + " ("+br.getExitValue()+")");
        }

        // Extract the binary RSA encrypted hash
        int offset = 0, header = 0, length = 0;
        String hashAlg = "sha1";
        File ddOfFile = new File("signed-"+hashAlg+".bin");
        try {
            ArrayList<String> outputLines = br.getLines();
            String lastLine = outputLines.get(outputLines.size()-1);
            /**
             * The last line should look like something like this:
             * >>> 1245:d=5  hl=4 l= 256 prim: OCTET STRING      [HEX
             * We need:
             *  > 1245 as the offset
             *  > 4 as the header
             *  > 256 as the length
             * */

            // Get the index of the colon and get the trimmed string before that: that is the offset
            // Get the index of the colon and get the trimmed string before that: that is the offset
            int index = lastLine.indexOf(":");
            String s = lastLine.substring(1, index);
            offset = Integer.parseInt(s);

            // Get the index of "hl=": add numbers between "=" and the next letter: this is the header
            String toFind = "hl=";
            index = lastLine.indexOf(toFind)+toFind.length();
            char current = lastLine.charAt(index);
            s = "";
            for (int i = index; current >= 48 && current <= 57; i++) {
                current = lastLine.charAt(i);
                s += current;
            }
            s = s.trim();
            header = Integer.parseInt(s);

            // Get the index of "l= ": add numbers between " " and the next letter: here is the length
            toFind = "l= ";
            index = lastLine.indexOf(toFind)+toFind.length();
            current = lastLine.charAt(index);
            s = "";
            for (int i = index; current >= 48 && current <= 57; i++) {
                current = lastLine.charAt(i);
                s += current;
            }
            s = s.trim();
            length = Integer.parseInt(s);

//            args = new String[] {"dd", String.format("if=%s", tempSigned.getPath()), String.format("of=%s", ddOfFile.getPath()), "bs=1", "skip=$[",
//                    Integer.toString(offset), "+", Integer.toString(header), "]", String.format("count=%s", length)};

            Object[] oargs = new Object[] {"python", "dder.py", tempSigned.getPath(), ddOfFile.getPath(), 1, offset, header, length};

            br = BashReader.read(oargs);
            if (br == null || br.getExitValue() != 0) {
                if (br == null) {
                    throw new SignatureException("The command \"" + BashReader.toSingleString(args) + "\" failed (null).");
                }
                throw new SignatureException("The command \"" + BashReader.toSingleString(args) + "\" failed - " + br.getOutput() + " ("+br.getExitValue()+")");
            }

            // Add a temp if the command succeeded.
            addTempFile(ddOfFile);

        } catch (Exception e) {
            e.printStackTrace();
            throw new SignatureException("Error while verifying the PKCS7 (parsing the as1nparse output) -> "+e);
        }
        /**
         * How to verify PKCS7 signed data?
         *
         * 1) Generate a RSA test key and certificate if no one is available
         * openssl req -x509 -nodes -newkey rsa:2048 -keyout keyfile.key -out certificate.cer -subj "my subject"
         *
         * 2) Get the file to be signed:
         * echo "My data to be signed" > data.txt
         *
         * 3) Sign the data with the signer and its key
         * openssl cms -sign -md sha256 -binary -nocerts -noattr -in data.txt -out data.signed -outform DER -inkey keyfile.key -signer certificate.cer
         *
         * 4) Locate the signature
         * openssl asn1parse -inform der -in data.signed
         *
         * 5) Extract binary RSA encrypted hash
         * dd if=data.signed of=signed-sha256.bin bs=1 skip=$[ 171 + 3 ] count=128
         *
         * 6) Verify the extracted data
         * hexdump -C signed-sha256.bin
         *
         * 7) Extract the public key from the certificate
         * openssl x509 -inform PEM -in certificate.cer -noout -pubkey > pubkey.pem
         *
         * 8) Verify the signature
         * openssl rsautl -verify -pubin -inkey pubkey.pem < signed-sha256.bin > verified.bin
         *
         * 9) Run hexdump -C verified.bin
         * hexdump -C verified.bin
         *
         * 10) Do another asn1parse to compare last command's hex dump to this one's
         * openssl asn1parse -inform DER -in verified.bin
         *
         * (taken from: http://qistoph.blogspot.ca/2012/01/manual-verify-pkcs7-signed-data-with.html)
         * */

        // Verify the extracted signature (for Logging purposes).
        args = new String[] {"python", "hexdump", "-in", ddOfFile.getPath()};
        br = BashReader.read(args);
        if (br != null) {
            Logger.debug(TAG, "python hexdump output: "+br.getOutput());
        }

        // Extract the public key from the certificate signer
        File tempSigner = new File("tmp/temp-signer.pem");
        Logger.debug(TAG, "Writing the signer's blob to a temp file: "+tempSigner.getPath());
        if (!FileWriter.write(this.certSigner.getBlob(), tempSigner.getAbsolutePath())) {
            throw new SignatureException("Couldn't write the signer's blob of data to the file.");
        }
        addTempFile(tempSigner);

        File tempSignerPubKey = new File("tmp/temp-signer-pubkey.pem");

        args = new String[] {"openssl", "x509", "-inform", "PEM", "-in", tempSigner.getPath(), "-noout", "-pubkey", "-out", tempSignerPubKey.getPath()};
        br = BashReader.read(args);
        if (br == null || br.getExitValue() != 0) {
            if (br == null) {
                throw new SignatureException("The command \"" + BashReader.toSingleString(args) + "\" failed (null).");
            }
            throw new SignatureException("The command \"" + BashReader.toSingleString(args) + "\" failed - " + br.getOutput() + " ("+br.getExitValue()+")");
        }

        Logger.debug(TAG, br.getOutput());
        FileWriter.write(br.getOutput(), tempSignerPubKey.getPath(), false);

        // Verify the signature
        File tempVerifiedBinary = new File("tmp/verified.bin");
        args = new String[] {"openssl", "rsautl", "-verify", "-pubin", "-inkey", tempSignerPubKey.getPath(), "-in", ddOfFile.getPath(), "-out", tempVerifiedBinary.getPath()};
        br = BashReader.read(args);
        if (br == null || br.getExitValue() != 0) {
            if (br == null) {
                throw new SignatureException("The command \"" + BashReader.toSingleString(args) + "\" failed (null).");
            }
            throw new SignatureException("The command \"" + BashReader.toSingleString(args) + "\" failed - " + br.getOutput() + " ("+br.getExitValue()+")");
        }

        // And, asn1parse on that verified signature
        final String HEX_DUMP = "[HEX DUMP]:";
        args = new String[] {"openssl", "asn1parse", "-inform", "DER", "-in", tempVerifiedBinary.getPath()};
        br = BashReader.read(args);
        if (br == null || br.getExitValue() != 0) {
            if (br == null) {
                throw new SignatureException("The command \"" + BashReader.toSingleString(args) + "\" failed (null).");
            }
            throw new SignatureException("The command \"" + BashReader.toSingleString(args) + "\" failed - " + br.getOutput() + " ("+br.getExitValue()+")");
        }
        String hexdump = null;
        ArrayList<String> hexdumpLines = br.getLines();
        for (String hexdumpLine : hexdumpLines) {
            if (hexdumpLine.contains(HEX_DUMP)) {
                int start = hexdumpLine.indexOf(HEX_DUMP) + HEX_DUMP.length();
                int end = hexdumpLine.length();
                hexdump = hexdumpLine.substring(start, end);
            }
        }
        if (hexdump == null) {
            return 1;
        }
        File sha1sum = new File("tmp/shatemp.file");
        FileWriter.write(this.contents, sha1sum.getPath());
        args = new String[] {"sha1sum", sha1sum.getPath()};
        br = BashReader.read(args);
        if (br == null || br.getExitValue() != 0) {
            if (br == null) {
                throw new SignatureException("The command \"" + BashReader.toSingleString(args) + "\" failed (null).");
            }
            throw new SignatureException("The command \"" + BashReader.toSingleString(args) + "\" failed - " + br.getOutput() + " ("+br.getExitValue()+")");
        }
        String sha1sumOutput = br.getOutput().substring(0, 40);

        hexdump = hexdump.trim();
        sha1sumOutput = sha1sumOutput.trim();

        Logger.info(getClass(), "Hexdump1: "+hexdump, false);
        Logger.info(getClass(), "Hexdump2: "+sha1sumOutput, false);

        return hexdump.equals(sha1sumOutput) ? 0 : 1;
    }

    public boolean clean() {
        return new File(contentsFilename).delete() && new File(signedFilenamePEM).delete()
                && new File(privateKeyFilename).delete();
    }
}
