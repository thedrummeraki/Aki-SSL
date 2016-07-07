package ui.main_panels;

import ui.main_panels.pkcs7.PKCS7Form;

import javax.swing.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;

/**
 * Created by aakintol on 29/06/16.
 */
public class MainFrame extends JFrame {

    static {
        DEFAULT_MENU_BAR = new JMenuBar();
    }

    public static final JMenuBar DEFAULT_MENU_BAR;

    private boolean hasLoadedPanel;

    public MainFrame(String title) {
        if (title == null || title.trim().isEmpty()) {
            title = "Certificate Tools";
        }

        JPanel main = new JPanel();
        main.setBorder(BorderFactory.createEmptyBorder(5,5,5,5));
        hasLoadedPanel = false;

        setTitle(title);
        setDefaultCloseOperation(DO_NOTHING_ON_CLOSE);
        addWindowListener(new WindowAdapter() {
            @Override
            public void windowClosing(WindowEvent e) {
                if (JOptionPane.showConfirmDialog(MainFrame.this, "Do you want to exit?",
                        "Exit", JOptionPane.YES_NO_CANCEL_OPTION) == JOptionPane.YES_OPTION) {
                    dispose();
                }
            }
        });

        setupMenu();

        setJMenuBar(DEFAULT_MENU_BAR);

        setSize(700, 600);
        setLocationRelativeTo(null);
    }

    private void setupMenu() {
        JMenu menu = new JMenu("Options");
        JMenu decodeMenu = new JMenu("Decode");
        JMenuItem decodeMenuCert = new JMenuItem("Certificate");
        JMenuItem decodeMenuPKCS7 = new JMenuItem("PKCS7");
        JMenuItem decodeMenuCSR = new JMenuItem("Certificate Request");
        JMenuItem decodeMenuPrivKey = new JMenuItem("Private Key");
        decodeMenu.add(decodeMenuCert);
        decodeMenu.add(decodeMenuPKCS7);
        decodeMenu.add(decodeMenuPrivKey);
        decodeMenu.add(decodeMenuCSR);
        JMenu modulusMenu = new JMenu("Modulus");
        JMenuItem modulusMenuCertKey = new JMenuItem("Certificate + Private Key");
        modulusMenu.add(modulusMenuCertKey);

        JMenu pkcs7Menu = new JMenu("PKCS7");
        JMenuItem pkcs7MenuSign = new JMenuItem("Sign...");
        pkcs7Menu.add(pkcs7MenuSign);

        decodeMenuCert.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent actionEvent) {
                setupMenu();
                CertForm.loadForm(MainFrame.this);
                hasLoadedPanel = true;
            }
        });

        pkcs7MenuSign.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent actionEvent) {
                setupMenu();
                PKCS7Form.loadForm(MainFrame.this);
                hasLoadedPanel = true;
            }
        });

        menu.add(decodeMenu);
        menu.add(pkcs7Menu);
        menu.add(modulusMenu);

        DEFAULT_MENU_BAR.add(menu);
    }

    @Override
    public void revalidate() {
//        if (hasLoadedPanel) {
//            int n = JOptionPane.showConfirmDialog(MainFrame.this, "Do you want to switch? All changes made will not be saved.",
//                        "Switch layouts", JOptionPane.YES_NO_CANCEL_OPTION);
//            if (n == JOptionPane.YES_NO_OPTION) {
//                super.revalidate();
//            }
//        } else {
            super.revalidate();
//        }
    }

    public static void main(String[] args) {

//        try {
//            UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
//        } catch (Exception e) {
//            e.printStackTrace();
//        }

        MainFrame mainFrame = new MainFrame(null);
        mainFrame.setVisible(true);
    }
}
