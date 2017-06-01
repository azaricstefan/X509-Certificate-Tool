package implementation;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.List;


import code.GuiException;
import implementation.Beans.CertificateSubject;
import x509.v3.CodeV3;

import java.security.cert.Certificate;
import java.security.cert.CertificateException;

public class MyCode extends CodeV3 {

    public MyCode(boolean[] algorithm_conf, boolean[] extensions_conf)
            throws GuiException {
        super(algorithm_conf, extensions_conf);
        // TODO Auto-generated constructor stub
    }

    @Override
    public Enumeration<String> loadLocalKeystore() {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public void resetLocalKeystore() {
        // TODO Auto-generated method stub

    }

    @Override
    public boolean exportKeypair(String name, String file, String password) {
        // TODO Auto-generated method stub
        return false;
    }

    @Override
    public boolean importKeypair(String keypair_name, String file, String password) {
        try { //TODO import keypair!
            FileInputStream fis = new FileInputStream(file);
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            keyStore.load(fis, password.toCharArray());

            fis.close();

            Enumeration<String> aliases = keyStore.aliases();
            String selectedAlias = aliases.nextElement();


            Key key = keyStore.getKey(selectedAlias, password.toCharArray());
            Certificate[] chain = keyStore.getCertificateChain(selectedAlias);
            //chain[0].getPublicKey();
            //KeyStore ks = KeyPairsStore.getInstance();

            //chain[0].getPublicKey();
            String passForNewProtection = "";
        } catch (UnrecoverableKeyException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (KeyStoreException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (CertificateException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }


        return false;
    }

    @Override
    public boolean removeKeypair(String keypair_name) {
        // TODO Auto-generated method stub
        return false;
    }

    @Override
    public int loadKeypair(String keypair_name) {
        // TODO Auto-generated method stub
        return 0;
    }

    @Override
    public boolean saveKeypair(String keypair_name) {
        CertificateSubject bean = getCertificateSubjectDataFromGUI();
        KeyPair keyPair = null;
        try {
            keyPair = Functions.createKeyPair("RSA", Integer.parseInt(bean.getKeyLength()));
            PublicKey PUa = keyPair.getPublic();
            PrivateKey PRa = keyPair.getPrivate();
            X509Certificate certificate = Functions.createCertificate(PUa, PRa, bean);

            //TODO: CREATE KEY STORE IMPLEMENTATION
            //KeyStore ks = KeyPairsStore.getInstance();

            Certificate[] chain = new Certificate[1];
            chain[0] = certificate;

            //TODO: password?
            //ks.setKeyEntry(keypair_name, PRa, passwordField.getPassword(), chain);

            //TODO:
            //KeyPairsStore.save();

            access.addKeypair(keypair_name);

        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return false;
    }

    private CertificateSubject getCertificateSubjectDataFromGUI() {
        CertificateSubject ret = new CertificateSubject(
                access.getSubjectCountry(),
                access.getSubjectState(),
                access.getSubjectLocality(),
                access.getSubjectOrganization(),
                access.getSubjectOrganizationUnit(),
                access.getSubjectCommonName(),
                access.getPublicKeySignatureAlgorithm(),
                access.getSerialNumber(),
                access.getPublicKeyParameter(),
                access.getNotBefore(),
                access.getNotAfter(),
                access.getKeyUsage(),
                access.getAlternativeName(6), //2 keyUsage, 6 altName, 13 issuerinhibit
                access.getInhibitAnyPolicy()
        );

        ret.setIssuerAlternativeNameCritical(
                access.isCritical(6) //2 keyUsage, 6 altName, 13 issuerinhibit
        );

        ret.setKeyUsageCritical(
                access.isCritical(2) //2 keyUsage, 6 altName, 13 issuerinhibit
        );

        ret.setInhibitAndPolicyCritical(
                access.isCritical(13) //2 keyUsage, 6 altName, 13 issuerinhibit
        );
        return ret;
    }

    @Override
    public boolean exportCertificate(File file, int encoding) {
        // TODO Auto-generated method stub
        return false;
    }

    @Override
    public boolean generateCSR(String keypair_name) {
        // TODO Auto-generated method stub
        return false;
    }

    @Override
    public String getIssuer(String arkeypair_nameg0) {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public String getIssuerPublicKeyAlgorithm(String keypair_name) {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public List<String> getIssuers(String keypair_name) {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public int getRSAKeyLength(String keypair_name) {
        // TODO Auto-generated method stub
        return 0;
    }

    @Override
    public boolean importCertificate(File file, String keypair_name) {
        // TODO Auto-generated method stub
        return false;
    }


    @Override
    public boolean signCertificate(String issuer, String algorithm) {
        // TODO Auto-generated method stub
        return false;
    }

}
