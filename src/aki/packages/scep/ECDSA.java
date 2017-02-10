package aki.packages.scep;

import aki.packages.cmp.RACMPClient;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECParameterSpec;

import javax.xml.bind.DatatypeConverter;
import java.io.File;
import java.io.IOException;
import java.security.*;
import java.util.Enumeration;
import java.util.HashMap;

import org.bouncycastle.openssl.PEMWriter;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;

/**
 * Created by aakintol on 18/01/17.
 */
public class ECDSA {

    private static final String DEFAULT_CURVE = "secp384r1";


    public static int generateECDSAKey(HashMap<String, String> fileOut) {
        return generateECDSAKey(fileOut, DEFAULT_CURVE);
    }

    public static int generateECDSAKey(HashMap<String, String> fileOut, String curveName) {
        Enumeration enumeration = ECNamedCurveTable.getNames();
        Object name;
        boolean found = false;
        while(enumeration.hasMoreElements()) {
            name = enumeration.nextElement();
            if (name.equals(curveName)) {
                found = true;
                break;
            }
            // System.out.println("Looked for " + name);
        }
        if (!found) {
            System.err.println("Invalid curve name: " + curveName);
            return 1;
        }

        ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec(curveName);
        KeyPairGenerator generator;
        try {
            generator = KeyPairGenerator.getInstance("ECDSA", "BC");
            generator.initialize(ecSpec, new SecureRandom());
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidAlgorithmParameterException e) {
            System.err.println(e.getLocalizedMessage());
            return 1;
        }


        KeyPair pair = generator.generateKeyPair();
        byte[] privEnc = pair.getPrivate().getEncoded();

        String outPriv = fileOut.get("priv");

        try {
            PemObject pemObject = new PemObject("EC PRIVATE KEY", pair.getPrivate().getEncoded());
            PEMWriter pemWriter = new PEMWriter(new java.io.FileWriter(outPriv));
            pemWriter.writeObject(pemObject);
            pemWriter.flush();
            System.out.println("Private key written to " + outPriv);
        } catch (IOException e) {
            System.err.println(e.getLocalizedMessage());
            return 3;
        }

//        if (!MyFileWriter.safeByteArrayToFile(outPriv, privEnc)) {
//            System.err.println("Could not write to file \"" + outPriv + "\".");
//            return 2;
//        } else {
//            System.out.println("Private key written to " + outPriv);
//        }

        String outPub = fileOut.get("pub");
        if (outPub != null) {
//            byte[] pubEnc = pair.getPublic().getEncoded();
//            if (!MyFileWriter.safeByteArrayToFile(outPub, pubEnc)) {
//                System.err.println("Could not write to file \"" + outPub + "\".");
//                return 2;
//            } else {
//                System.out.println("Public key written to " + outPub);
//            }

            try {
                PemObject pemObject = new PemObject("ECDSA PUBLIC KEY", pair.getPublic().getEncoded());
                JcaPEMWriter pemWriter = new JcaPEMWriter(new java.io.FileWriter(outPub));
                pemWriter.writeObject(pair.getPublic().getEncoded());
                System.out.println("Public key written to " + outPub);

            } catch (IOException e) {
                System.err.println(e.getLocalizedMessage());
                return 3;
            }
        }

        return 0;
    }

}
