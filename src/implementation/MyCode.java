package implementation;

import java.io.*;
import java.security.*;
import java.security.cert.*;
import java.security.cert.Certificate;
import java.security.cert.Extension;
import java.util.*;


import code.GuiException;
import implementation.Beans.CertificateSubject;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.util.ASN1Dump;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.jcajce.provider.keystore.bc.BcKeyStoreSpi.BouncyCastleStore;
import org.bouncycastle.jcajce.provider.keystore.pkcs12.PKCS12KeyStoreSpi;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import sun.security.x509.InhibitAnyPolicyExtension;
import x509.v3.CodeV3;

public class MyCode extends CodeV3 {

    //KeyStore keyStore;
    BouncyCastleStore keyStore; //Da li njega koristiti?
    private static final String keyStoreName = "keyStore.p12";
    private static final String keyStoreInstanceName = "PKCS12";
    private static final String keyStorePassword = "sifra";

    public MyCode(boolean[] algorithm_conf, boolean[] extensions_conf)
            throws GuiException {
        super(algorithm_conf, extensions_conf);
        // TODO Auto-generated constructor stub
    }

    public void saveLocalKeyStore(){
        FileOutputStream fos = null;
        try {
            fos = new FileOutputStream(keyStoreName);
            keyStore.engineStore(fos, keyStorePassword.toCharArray());
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }finally {
            if (fos != null)
                try {fos.close();}
                catch (IOException e) {e.printStackTrace();}
        }
    }

    @Override
    public Enumeration<String> loadLocalKeystore() {
        FileInputStream fis = null;
        try {
            //keyStore = new BouncyCastleStore.insta.getInstance(keyStoreInstanceName, new BouncyCastleProvider());
            keyStore = new BouncyCastleStore();

            if(!(new File(keyStoreName).exists())){
                keyStore.engineLoad(null,null);
            } else {
                fis = new FileInputStream(keyStoreName);
                keyStore.engineLoad(fis,keyStorePassword.toCharArray()); //TODO: CHECK THIS OUT...
                return keyStore.engineAliases();
            }
        } catch (FileNotFoundException e){
            e.printStackTrace(); //TODO: create file if not exists
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            if (fis != null){
                try { fis.close(); }
                catch (IOException e) { e.printStackTrace(); }
            }
        }
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
            KeyStore tmpKeyStore = KeyStore.getInstance(keyStoreInstanceName, new BouncyCastleProvider());


            //keyStore = KeyStore.getInstance(keyStoreInstanceName); //NOT NEEDED
            keyStore.engineLoad(fis, password.toCharArray());

            fis.close();
            Enumeration<String> aliases = keyStore.engineAliases();
            String selectedAlias = aliases.nextElement();


            Key key = keyStore.engineGetKey(selectedAlias, password.toCharArray());
            Certificate[] chain = keyStore.engineGetCertificateChain(selectedAlias);

            //sad dialozi
            //KeyStore ks = KeyPairsStore.getInstance();

            //nova sifra?
            keyStore.engineSetKeyEntry(selectedAlias, key, password.toCharArray(), chain);
            //KeyPairsStore.save();

            saveLocalKeyStore();

            access.addKeypair(keypair_name);


        } catch (UnrecoverableKeyException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (KeyStoreException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
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
        try {
            Key key = keyStore.engineGetKey(keypair_name, keyStorePassword.toCharArray());
            Enumeration<String> aliases = keyStore.engineAliases();
            String selectedAlias = aliases.nextElement();
            Certificate[] chain = keyStore.engineGetCertificateChain(selectedAlias);
            X509Certificate certificate = (X509Certificate) chain[0];
            setCertificateSubjectDataFromKeyStore(certificate);

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (UnrecoverableKeyException e) {
            e.printStackTrace();
        } catch (CertificateParsingException e) {
            e.printStackTrace();
        } catch (CertificateEncodingException e) {
            e.printStackTrace();
        }

        return 0;
    }

    private void setCertificateSubjectDataFromKeyStore(X509Certificate certificate)
            throws CertificateParsingException, CertificateEncodingException {

        System.out.println("READING: "+ certificate); //DEBUG

        JcaX509CertificateHolder certHolder = new JcaX509CertificateHolder((X509Certificate) certificate);
        X500Name name = certHolder.getSubject();

        access.setVersion(certHolder.getVersionNumber()-1); //because index of buttons[] should be -1

        //populate GUI from certificate
        if(name.getRDNs(BCStyle.C).length > 0)
            access.setSubjectCountry(IETFUtils.valueToString(name.getRDNs(BCStyle.C)[0].getFirst().getValue()));
        if(name.getRDNs(BCStyle.ST).length > 0)
            access.setSubjectState(IETFUtils.valueToString(name.getRDNs(BCStyle.ST)[0].getFirst().getValue()));
        if(name.getRDNs(BCStyle.L).length > 0)
            access.setSubjectLocality(IETFUtils.valueToString(name.getRDNs(BCStyle.L)[0].getFirst().getValue()));
        if(name.getRDNs(BCStyle.O).length > 0)
            access.setSubjectOrganization(IETFUtils.valueToString(name.getRDNs(BCStyle.O)[0].getFirst().getValue()));
        if(name.getRDNs(BCStyle.OU).length > 0)
            access.setSubjectOrganizationUnit(IETFUtils.valueToString(name.getRDNs(BCStyle.OU)[0].getFirst().getValue()));
        if(name.getRDNs(BCStyle.CN).length > 0)
            access.setSubjectCommonName(IETFUtils.valueToString(name.getRDNs(BCStyle.CN)[0].getFirst().getValue()));
        access.setSubjectSignatureAlgorithm(certHolder.getSignatureAlgorithm().toString()); //TODO: PROVERA?
        access.setPublicKeySignatureAlgorithm(certificate.getPublicKey().getAlgorithm()); //treba?

        access.setSerialNumber(String.valueOf(certificate.getSerialNumber()));
        access.setPublicKeyParameter(certificate.getPublicKey().toString()); //TODO check if ok toString
        access.setNotBefore(certificate.getNotBefore());
        access.setNotAfter(certificate.getNotAfter());

        //=========GET KEY USAGE=================
        if(certificate.getKeyUsage() != null && certificate.getKeyUsage().length != 0)
            access.setKeyUsage(certificate.getKeyUsage());

        //=========GET ALTERNATIVE NAMES=========
        String issuerAltNames = getAlternativeNames(certificate, 0);
        if(issuerAltNames != null){
            access.setAlternativeName(6, issuerAltNames); //5 subject AltName,6 issuerAltName, 2 keyUsage,13 issuerinhibit
        }
        String subjectAltNames = getAlternativeNames(certificate,1);
        if(subjectAltNames != null){
            access.setAlternativeName(5, subjectAltNames);
        }


        //========GET INHIBIT ANY POLICY=========
        ASN1Primitive prim = null;
        String decoded = null;
        byte[] tt = certificate.getExtensionValue("2.5.29.54");
        if(tt != null){
            try {
                prim = JcaX509ExtensionUtils.parseExtensionValue(tt);
                decoded = prim.toString();
            } catch (IOException e) {
                e.printStackTrace();
            }
            access.setSkipCerts(decoded);
            access.setInhibitAnyPolicy(true);
        }
    }

    /**
     *
     * @param certificate take the info from
     * @param what Issuer 0, Subject 1
     * @return {@link String} allNames
     * @throws CertificateParsingException
     */
    private String getAlternativeNames(X509Certificate certificate, int what)
            throws CertificateParsingException {
        Collection<List<?>> allNames;
        if(what == 0)
            allNames = certificate.getIssuerAlternativeNames();
        else
            allNames = certificate.getSubjectAlternativeNames();
        String altNames;
        //citanje imena
        if(allNames != null) {
            Iterator<List<?>> it = allNames.iterator();
            StringBuilder stringBuilder = new StringBuilder();
            while (it.hasNext()) {
                List<?> list = it.next();
                stringBuilder.append(list.get(1));
            }
            altNames = stringBuilder.toString();
            return  altNames;
        }
        return null;
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
            keyStore.engineSetKeyEntry(keypair_name, PRa, keyStorePassword.toCharArray(), chain);

            //TODO:
            //KeyPairsStore.save();
            saveLocalKeyStore();
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
        ret.setInhibitAndPolicy(access.getInhibitAnyPolicy());
        ret.setInhibitAnyPolicySkipCerts(access.getSkipCerts());
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
