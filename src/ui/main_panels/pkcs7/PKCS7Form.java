package ui.main_panels.pkcs7;

import aki.packages.pkcs7.PKCS7;
import aki.packages.pkcs7.PKCS7Exception;
import aki.packages.tools.BashReader;
import aki.packages.tools.FileReader;
import aki.packages.x509.*;
import ui.main_panels.HostPanel;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;

import java.awt.datatransfer.*;
import java.awt.Toolkit;

/**
 * Created by aakintol on 29/06/16.
 */
public class PKCS7Form implements HostPanel {

    private JPanel panel1;
    private JButton importCertButton;
    private JButton importKeyButton;
    private JButton signButton;
    private JButton resetButton;
    private JTextArea textArea1;
    private JTextArea textArea2;
    private JLabel certPath;
    private JLabel keyPath;
    private JLabel pkcs7Path;
    private JButton importPKCS7Button;
    private JButton saveResultsButton;
    private JLabel modulusPKey;
    private JLabel modulusCert;
    private JLabel modulusCompare;
    private JCheckBox encryptAfterSigningCheckBox;
    private JLabel resultStatus;
    private JButton copyResultsToClipboardButton;
    private JButton selectAllButton;
    private JFrame parent;

    private String certModulus, keyModulus;

    private File certFile, keyFile, pkcs7File;
    private static PKCS7Form form;

    // In order to sign a PKCS7, we need a certificate and it's private key.
    private void addListeners() {
        importCertButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent actionEvent) {
                JFileChooser fileChooser = new JFileChooser(System.getProperty("user.dir"));
                int n = fileChooser.showDialog(parent, "Choose a certificate signer");
                if (n == JFileChooser.APPROVE_OPTION) {
                    certFile = fileChooser.getSelectedFile();
                    certPath.setText("../"+certFile.getParentFile().getName()+"/"+certFile.getName());
                    try {
                        certModulus = Modulus.get(certFile, true);
                        modulusCert.setText("Cert modulus: "+ (certModulus == null ? "Invalid certificate!" : certModulus));
                    } catch (Exception e) {
                        e.printStackTrace();
                        modulusCert.setText("Cert modulus: Invalid file!");
                    } finally {
                        if (certModulus != null && keyModulus != null) {
                            modulusCompare.setText(keyModulus.equals(certModulus) ? "They match!" : "They don't match");
                        }
                    }
                }
                if (certFile != null && certModulus != null) {
                    importCertButton.setText("You're good to go!");
                } else {
                    importCertButton.setText("Click here to import your cert. signer");
                }
            }
        });

        importKeyButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent actionEvent) {
                JFileChooser fileChooser = new JFileChooser(System.getProperty("user.dir"));
                int n = fileChooser.showDialog(parent, "Choose this signer's private key");
                if (n == JFileChooser.APPROVE_OPTION) {
                    keyFile = fileChooser.getSelectedFile();
                    keyPath.setText("../"+keyFile.getParentFile().getName()+"/"+keyFile.getName());
                    try {
                        keyModulus = Modulus.get(keyFile, false);
                        modulusPKey.setText("PKey modulus: "+ (keyModulus == null ? "Invalid private key!" : keyModulus));
                    } catch (Exception e) {
                        e.printStackTrace();
                        modulusPKey.setText("PKey modulus: Invalid file!");
                    } finally {
                        if (certModulus != null && keyModulus != null) {
                            modulusCompare.setText(keyModulus.equals(certModulus) ? "They match!" : "They don't match");
                        }
                    }
                }
                if (keyFile != null && keyModulus != null) {
                    importKeyButton.setText("You're good to go!");
                } else {
                    importKeyButton.setText("Click here to import your signer's key");
                }
            }
        });

        importPKCS7Button.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent actionEvent) {
                JFileChooser fileChooser = new JFileChooser(System.getProperty("user.dir"));
                int n = fileChooser.showDialog(parent, "Choose your PKCS7 file");
                if (n == JFileChooser.APPROVE_OPTION) {
                    pkcs7File = fileChooser.getSelectedFile();
                    pkcs7Path.setText("../"+pkcs7File.getParentFile().getName()+"/"+pkcs7File.getName());
                    textArea1.setText(BashReader.toSingleString(FileReader.getLines(pkcs7File)));
                }
            }
        });

        signButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent actionEvent) {
                copyResultsToClipboardButton.setText("Copy results to clipboard");
                String errorMessage = "<html>You are missing the following:<br><ul>";
                boolean hasErrors = false;
                if (pkcs7File == null && textArea1.getText().trim().isEmpty()) {
                    errorMessage += "<li>A PKCS7 file or its contents (place them on the left pane)</li>";
                }
                if (certFile == null) {
                    errorMessage += "<li>Your certificate signer file</li>";
                }
                if (keyFile == null) {
                    errorMessage += "<li>Your signer's private key file</li>";
                }
                hasErrors = (pkcs7File == null && textArea1.getText().trim().isEmpty()) || certFile == null || keyFile == null;
                errorMessage += "</ul></html>";
                if (hasErrors) {
                    JOptionPane.showMessageDialog(parent, errorMessage, "Error while signing the PKCS7 message.", JOptionPane.ERROR_MESSAGE);
                    return;
                }
                Signable pkcs7 = new Signable();
                if (pkcs7File != null) {
                    pkcs7.setContents(BashReader.toSingleString(FileReader.getLines(pkcs7File)));
                } else {
                    pkcs7.setContents(textArea1.getText().trim());
                }
                Certificate signer;
                try {
                    signer = Certificate.loadCertificateFromFile(certFile);
                } catch (CertificateException e) {
                    e.printStackTrace();
                    JOptionPane.showMessageDialog(parent, "Your certificate signer is not valid.", "Error while signing the PKCS7 message.", JOptionPane.ERROR_MESSAGE);
                    return;
                }
                pkcs7.setCertSigner(signer);
                try {
                    PrivateKey privateKey = PrivateKey.loadPrivateKey(keyFile);
                    pkcs7.setPrivateKeySigner(privateKey);
                    pkcs7.sign();
                    if (encryptAfterSigningCheckBox.isSelected()) {
//                        pkcs7.encrypt();
                    }
                } catch (PKCS7Exception e) {
                    e.printStackTrace();
                    JOptionPane.showMessageDialog(parent, "The signature has failed: "+e, "Error while signing the PKCS7 message.", JOptionPane.ERROR_MESSAGE);
                    return;
                } catch (CertificateException e) {
                    e.printStackTrace();
                    JOptionPane.showMessageDialog(parent, "The private key is invalid or it does't match with the certificate.",
                            "Error while signing the PKCS7 message.", JOptionPane.ERROR_MESSAGE);
                    return;
                }
                if (encryptAfterSigningCheckBox.isSelected()) {
                    JOptionPane.showMessageDialog(parent, "The signing is complete! You can view the results on the right pane.");
//                    textArea2.setText(pkcs7.getEncryptedDataAsString());
                } else {
                    JOptionPane.showMessageDialog(parent, "The encryption is complete! You can view the results on the right pane.");
                    textArea2.setText(pkcs7.getDERSignedDataAsString());
                }
                textArea2.setCaretPosition(0);
            }
        });

        encryptAfterSigningCheckBox.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent actionEvent) {
                boolean selected = encryptAfterSigningCheckBox.isSelected();
                resultStatus.setText(selected ? "Your encrypted PKCS7:" : "Your signed PKCS7:");
                signButton.setText(selected ? "Encrypt my data!" : "Sign my data!");
            }
        });

        selectAllButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent actionEvent) {
                textArea2.selectAll();
            }
        });

        copyResultsToClipboardButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent actionEvent) {
                String string = textArea2.getText();
                StringSelection stringSelection = new StringSelection(string);
                Clipboard clpbrd = Toolkit.getDefaultToolkit().getSystemClipboard();
                clpbrd.setContents(stringSelection, null);
                copyResultsToClipboardButton.setText("Copied!");
            }
        });
    }

    private PKCS7Form(JFrame p) {
        this.parent = p;
        parent.setContentPane(panel1);
        parent.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        parent.setSize(700, 550);
        parent.setVisible(true);

        addListeners();
    }

    @Override
    public void updateInParent() {
        this.parent.setContentPane(panel1);
        this.parent.revalidate();

        this.parent.setTitle("Sign a PKCS7...");
        JMenuBar jMenuBar = this.parent.getJMenuBar();
        JMenuBar newBar = new JMenuBar();
        for (int i = 0; i<jMenuBar.getMenuCount(); i++) {
            newBar.add(jMenuBar.getMenu(i));
        }
        newBar.add(new JMenu("Test"));
        this.parent.setJMenuBar(newBar);
    }

    public static void loadForm(JFrame parent) {
        form = new PKCS7Form(parent);
        form.updateInParent();
    }

    private void createUIComponents() {
        // TODO: place custom component creation code here
        certPath = new JLabel();
        keyPath = new JLabel();
        pkcs7Path = new JLabel();
    }

    public static Container panel() {
        return form.panel1;
    }
}
