package utils;

import tools.BashReader;
import tools.FileReader;
import tools.FileWriter;
import tools.Logger;
import x509.*;

import java.io.File;
import java.util.ArrayList;

import static utils.Constants.*;

/**
 * Created by aakintol on 05/07/16.
 */
public final class SignUtils {

    /**
     * This class contains static methods that allows a Signable object to
     * execute signing methods. Please make sure to fully initialize the object prior
     * to using this method with the following attributes:
     * - Certificate signer
     * - Certificate signer filename
     * - Private key
     * - Private key filename
     * - Data
     * - Data filename
     *
     * These above can all be created with the method Signable.create().
     * Each method returns an integer, which is the return code of the method.
     * The return codes can be found in the package utils.Constants
     * */

    private SignUtils() {}

    private static boolean catchNullInOneOf(Object... objects) {
        for (Object o : objects) {
            if (o == null)
                return false;
        }
        return true;
    }

    public static boolean check(Signable signable) {
        if (signable == null) {
            Logger.debug("2 for 0");
        }
        if (signable.getCertSigner() == null) {
            Logger.debug("2 for 1");
        }
        if (signable.getPrivateKeySigner() == null) {
            Logger.debug("2 for 2");
        }
        if (!signable.getPrivateKeySigner().doCheck(signable.getCertSigner())) {
            Logger.debug("2 for 3");
        }
        return signable != null && signable.getCertSigner() != null && signable.getPrivateKeySigner() != null &&
                signable.getPrivateKeySigner().doCheck(signable.getCertSigner()) && signable.getContents() != null;
    }

    public static int checkCertificateAndPrivateKey(Certificate certificate, PrivateKey privateKey) {
        if (certificate == null || privateKey == null) {
            return NULL_OBJECT_ERROR;
        }
        try {
            privateKey.check(certificate);
        } catch (CertificateException e) {
            return CHECK_CERTIFICATE_PRIVATE_KEY_ERROR;
        }
        return 0;
    }

    public static int writeRawData(File outFile, Signable signable) {
        if (!catchNullInOneOf(outFile, signable, signable.getContents())) {
            return NULL_OBJECT_ERROR;
        }
        if (!FileWriter.write(signable.getContents(), outFile.getPath())) {
            return IO_WRITE_ERROR;
        }
        return 0;
    }

    public static int writeSignerBlob(File outFile, Signable signable) {
        if (!catchNullInOneOf(outFile, signable, signable.getCertSigner()) || !check(signable)) {
            return NULL_OBJECT_ERROR;
        }
        if (!FileWriter.write(signable.getCertSigner().getBlob(), outFile.getPath())) {
            return IO_WRITE_ERROR;
        }
        return 0;
    }

    public static int writePrivateKey(File outFile, Signable signable) {
        if (!catchNullInOneOf(outFile, signable, signable.getPrivateKeySigner()) || !check(signable)) {
            return NULL_OBJECT_ERROR;
        }
        if (!FileWriter.write(signable.getPrivateKeySigner().dumpPEM(signable.getCertSigner().getSubject()), outFile.getPath())) {
            return IO_WRITE_ERROR;
        }
        return 0;
    }

    public static int setSignedFilename(File file, Signable signable) {
        if (!catchNullInOneOf(file, signable)) {
            return NULL_OBJECT_ERROR;
        }
        signable.setSignedFilenamePEM(file.getPath());
        return 0;
    }

    public static int execOpenSSLCMSSign(String alg, Signable signable) {
        return execOpenSSLCMSSign(alg, true, false, false, signable);
    }

    public static int execOpenSSLCMSSign(String alg, boolean binary, Signable signable) {
        return execOpenSSLCMSSign(alg, binary, false, false, signable);
    }

    public static int execOpenSSLCMSSign(String alg, boolean binary, boolean noCerts, boolean noAttr, Signable signable) {
        if (!catchNullInOneOf(alg, signable)) {
            return NULL_OBJECT_ERROR;
        }
        if (!check(signable)) {
            return CHECK_SIGNABLE_INVALID_OR_NOT_SIGNED_ERROR;
        }

        String in = signable.getContentsFilename();
        String inKey = signable.getPrivateKeyFilename();
        String signer = signable.getSignerFilename();

        String outform = "PEM";
        String out = signable.getSignedFilenamePEM();
        String[] args = getCMSSignArgs(alg, binary, noCerts, noAttr, outform, in, out, inKey, signer);
        Logger.debug(BashReader.toSingleString(false, args));


        BashReader br = BashReader.read(args);
        if (br == null) {
            return NULL_OBJECT_RESULT_ERROR;
        }
        PEM_SIGNED_DATA = BashReader.toSingleString(true, FileReader.getLines(out));

        outform = "DER";
        out = signable.getSignedFilenameDER();
        args = getCMSSignArgs(alg, binary, noCerts, noAttr, outform, in, out, inKey, signer);
        Logger.debug(BashReader.toSingleString(false, args));

        br = BashReader.read(args);
        if (br == null) {
            return NULL_OBJECT_RESULT_ERROR;
        }
        Logger.debug(br.getOutput());
        DER_SIGNED_DATA = BashReader.toSingleString(true, FileReader.getLines(out)).getBytes();

        setSignedData(signable);

        return br.getExitValue();
    }

    private static String[] getCMSSignArgs(String alg, boolean binary, boolean noCerts, boolean noAttr, String outform,
                                                String in, String out, String inkey, String signer) {
        ArrayList<String> args = new ArrayList<>();
        args.add("openssl");
        args.add("cms");
        args.add("-sign");
        args.add("-md");
        args.add(alg);
        if (binary) args.add("-binary");
        if (noAttr) args.add("-noattr");
        if (noCerts) args.add("-nocerts");
        args.add("-outform");
        args.add(outform);
        args.add("-in");
        args.add(in);
        args.add("-out");
        args.add(out);
        args.add("-inkey");
        args.add(inkey);
        args.add("-signer");
        args.add(signer);

        return args.toArray(new String[0]);
    }

    public static int execOpenSSLASN1Parse(String inform, Signable signable, boolean showOutput) {
        if (!catchNullInOneOf(inform, signable)) {
            return NULL_OBJECT_ERROR;
        }

        String in = signable.getContentsFilename() + ".signed";

        String[] args = {"openssl", "asn1parse", "-inform", inform, "-in", in};

        BashReader br = BashReader.read(args);

        if (br == null) {
            return NULL_OBJECT_RESULT_ERROR;
        }
        if (showOutput) {
            Logger.info("SignUtils", "execOpenSSLASN1Parse - "+br.getOutput());
        }

        return br.getExitValue();
    }

    public static int setSignedData(Signable signable) {
        if (!catchNullInOneOf(signable, PEM_SIGNED_DATA, DER_SIGNED_DATA)) {
            return NULL_OBJECT_ERROR;
        }
        signable.setData(PEM_SIGNED_DATA);
        signable.setData(DER_SIGNED_DATA);
        return 0;
    }


    private static String PEM_SIGNED_DATA;
    private static byte[] DER_SIGNED_DATA;

}
