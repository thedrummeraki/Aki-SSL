package x509;

import attributes.AttributeSet;

import tools.BashReader;
import tools.FileReader;
import tools.FileWriter;
import tools.Logger;

import java.io.File;
import java.util.ArrayList;

/**
 * Created by aakintol on 28/06/16.
 */
public class Signable implements Dumpable {

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
    }

    public String getContents() {
        return contents;
    }

    public Certificate getCertSigner() {
        return certSigner;
    }

    public void setCertSigner(Certificate certSigner) {
        this.certSigner = certSigner;
    }

    public PrivateKey getPrivateKeySigner() {
        return privateKeySigner;
    }

    public void setPrivateKeySigner(PrivateKey privateKeySigner) {
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

    public void setType(FileType type) {
        this.type = type;
    }

    public FileType getType() {
        return type;
    }

    public String getFilename(boolean fullFilename) {
        return fullFilename ? filename + getFileExtension() : filename;
    }

    public boolean isSigned() {
        return isSigned;
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

    public void createFilename() {
        createFilename(20, true);
    }

    private void createFilename(int length, boolean hex) {
        this.filename = FileWriter.dumpFilename(length, hex, getFileExtension());
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

    public boolean sign() throws SignatureException {
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
        // Signs the raw data of the signable object
        // Create a temp file that will hold the raw data.
        File tempRawData = new File("tmp/temp-"+getFilename());
        if (!FileWriter.write(this.contents, tempRawData.getAbsolutePath())) {
            throw new SignatureException("Couldn't write the data to a temp file.");
        }
        addTempFile(tempRawData);
        //Create a temp file that will contain the signer
        File tempSignerBlob = new File("tmp/temp-"+getFilename(false)+".signer");
        if (!FileWriter.write(this.certSigner.getBlob(), tempSignerBlob.getAbsolutePath())) {
            throw new SignatureException("Couldn't write the signer's blob of data to the file.");
        }
        addTempFile(tempSignerBlob);

        //Create a temp file that will contain the private key
        File tempKey = new File("tmp/temp-"+getFilename(false)+".key");
        Logger.debug("PKCS7", "Trying to write to the file.");
        if (!FileWriter.write(this.privateKeySigner.dumpPEM(this.certSigner.getSubject()), tempKey.getAbsolutePath())) {
            throw new SignatureException("Couldn't write the signer's private key to the file.");
        }
        addTempFile(tempKey);

        String outFile = "temp-"+getFilename(false)+".signed";

        /**
         * How would we sign the contents?
         * Choice 1:
         * openssl cms -sign -binary -in data.txt -out data.signed -signer signer.pem -inkey -signer.key
         *
         * Choice 2:
         * openssl cms -sign -md sha256 -binary -nocerts -noattr -in data.txt -out data.signed -outform DER -signer signer.pem -inkey signer.key
         * */

        String[] args = {"openssl", "cms", "-sign", "-binary", "-in", tempRawData.getAbsolutePath(), "-out", outFile,
                "-signer", tempSignerBlob.getAbsolutePath(), "-inkey", tempKey.getAbsolutePath()};

        BashReader bashReader = BashReader.read(args);
        if (bashReader == null || bashReader.getExitValue() != 0) {
            if (bashReader == null) {
                throw new SignatureException("The command \"" + BashReader.toSingleString(args) + "\" failed (null).");
            }
            throw new SignatureException("The command \"" + BashReader.toSingleString(args) + "\" failed - " + bashReader.getOutput() + " ("+bashReader.getExitValue()+")");
        }

        // Now we have a file with DER signed data.
        this.signedDataDER = BashReader.toSingleString(FileReader.getLines(outFile)).trim().getBytes();

        args = new String[]{"openssl", "cms", "-sign", "-binary", "-outform", "DER", "-in", tempRawData.getAbsolutePath(), "-out", outFile,
                "-signer", tempSignerBlob.getAbsolutePath(), "-inkey", tempKey.getAbsolutePath()};

        bashReader = BashReader.read(args);
        if (bashReader == null || bashReader.getExitValue() != 0) {
            if (bashReader == null) {
                throw new SignatureException("The command \"" + BashReader.toSingleString(args) + "\" failed (null).");
            }
            throw new SignatureException("The command \"" + BashReader.toSingleString(args) + "\" failed - " + bashReader.getOutput() + " ("+bashReader.getExitValue()+")");
        }

        // Now we have a file with PEM signed data.
        this.signedDataPEM = BashReader.toSingleString(FileReader.getLines(outFile)).trim();
        this.isSigned = true;

        if (cleanTempFiles()) {
            Logger.debug("PKCS7", "PKCS7.sign(): Temp files all cleaned up.");
        } else {
            Logger.debug("PKCS7", "PKCS7.sign(): Temp files NOT cleaned up (all or some).");
        }
        return isSigned;
    }

    public void verify() throws SignatureException {

        if (!isSigned || signedDataDER == null || signedDataPEM == null) {
            sign();
        }
        // Locate the signature
        File tempSigned = new File("tmp/temp-signed.txt");
        FileWriter.write(this.getDERSignedDataAsString(), tempSigned.getPath());
        String[] args = {"openssl", "-inform", "DER", "-in", tempSigned.getPath()};
        BashReader br = BashReader.read(args);
        if (br == null || br.getExitValue() != 0) {
            if (br == null) {
                throw new SignatureException("The command \"" + BashReader.toSingleString(args) + "\" failed (null).");
            }
            throw new SignatureException("The command \"" + BashReader.toSingleString(args) + "\" failed - " + br.getOutput() + " ("+br.getExitValue()+")");
        }

        Logger.debug("PKCS7", "ASN1 Located signature: "+br.getOutput());

        // Extract the binary RSA encrypted hash
        int offset = 0, header = 0, length = 0;
        String hashAlg = "sha256";
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

            args = new String[] {"dd", String.format("if=%s", tempSigned.getPath()), String.format("of=%s", ddOfFile.getPath()), "bs=1", "skip$[",
                    Integer.toString(offset), "+", Integer.toString(header), "]", String.format("count=%s", length)};

            br = BashReader.read(args);
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
        args = new String[] {"hexdump", "-C", ddOfFile.getPath()};
        br = BashReader.read(args);
        if (br != null) {
            Logger.debug("PKCS7", "Extracted signature: "+br.getOutput());
        }

        // Extract the public key from the certificate signer
        File tempSigner = new File("tmp/temp-signer.pem");
        File tempSignerPubKey = new File("tmp/temp-signer.pem");
        args = new String[] {"openssl", "x509", "-inform", "PEM", "-in", tempSigner.getPath(), "-noout", "-pubkey > ", tempSignerPubKey.getPath()};
    }
}
