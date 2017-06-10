package implementation;

import implementation.Beans.CertificateSubject;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509v1CertificateBuilder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509v1CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.X509KeyUsage;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.util.encoders.Base64;
import sun.security.x509.InhibitAnyPolicyExtension;


import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

/**
 * Project name: zp-projekat
 * Created by staz on 1.6.2017. 11:43
 */
public class Functions {

    public static KeyPair createKeyPair(String encryptType, int bitCount)
            throws NoSuchProviderException, NoSuchAlgorithmException {

        KeyPairGenerator kpg = KeyPairGenerator.getInstance(encryptType);
        kpg.initialize(bitCount);
        return kpg.genKeyPair();
    }

    public static X509Certificate createCertificate(PublicKey publicKey, PrivateKey privateKey,
                                                    CertificateSubject bean) throws Exception {
        X500NameBuilder builder = new X500NameBuilder(BCStyle.INSTANCE);
        builder.addRDN(BCStyle.CN, bean.getCN());
        builder.addRDN(BCStyle.O, bean.getO());
        builder.addRDN(BCStyle.OU, bean.getOU());
        builder.addRDN(BCStyle.L, bean.getL());
        builder.addRDN(BCStyle.ST, bean.getST());
        builder.addRDN(BCStyle.C, bean.getC());

        String signatureAlgorithm = bean.getSA();
        ContentSigner sigGen = new JcaContentSignerBuilder(signatureAlgorithm).build(privateKey);

        //V1 or V3?
        int version = bean.getVersion();
        X509v1CertificateBuilder certGenV1 = null;
        X509v3CertificateBuilder certGen = null;
        switch(version){
            case 0: //1
                certGenV1 = new JcaX509v1CertificateBuilder(builder.build(),
                        new BigInteger(bean.getSN()), bean.getValidNotBefore(), bean.getValidNotAfter(), builder.build(),
                        publicKey);
                break;
            case 2: //3
                certGen = new JcaX509v3CertificateBuilder(builder.build(),
                        new BigInteger(bean.getSN()), bean.getValidNotBefore(), bean.getValidNotAfter(), builder.build(),
                        publicKey);
                break;
            default:
                throw new Exception("Version doesn't exist!(" + version + ")");
        }

        //==============KeyUsage extension==============
        int keyUsage = 0;
        boolean criticalKeyUsage = bean.isKeyUsageCritical();

        if (bean.isEnabled(CertificateSubject.KeyUsageBox.CERTIFICATE_SIGNING))
            keyUsage |= X509KeyUsage.keyCertSign;
        if (bean.isEnabled(CertificateSubject.KeyUsageBox.CRL_SIGNING))
            keyUsage |= X509KeyUsage.cRLSign;
        if (bean.isEnabled(CertificateSubject.KeyUsageBox.DATA_ENCIPHERMENT))
            keyUsage |= X509KeyUsage.dataEncipherment;
        if (bean.isEnabled(CertificateSubject.KeyUsageBox.DECIPHER_ONLY))
            keyUsage |= X509KeyUsage.decipherOnly;
        if (bean.isEnabled(CertificateSubject.KeyUsageBox.DIGITAL_SIGNATURE))
            keyUsage |= X509KeyUsage.digitalSignature;
        if (bean.isEnabled(CertificateSubject.KeyUsageBox.ENCIPHER_ONLY))
            keyUsage |= X509KeyUsage.encipherOnly;
        if (bean.isEnabled(CertificateSubject.KeyUsageBox.KEY_AGREEMENT))
            keyUsage |= X509KeyUsage.keyAgreement;
        if (bean.isEnabled(CertificateSubject.KeyUsageBox.KEY_ENCIPHERMENT))
            keyUsage |= X509KeyUsage.keyEncipherment;
        if(bean.isEnabled(CertificateSubject.KeyUsageBox.CONTENT_COMMITMENT)) //same as nonRepudiation
            keyUsage |= X509KeyUsage.nonRepudiation;


        if (keyUsage != 0) {
            X509KeyUsage keyuse = new X509KeyUsage(keyUsage);
            certGen.addExtension(Extension.keyUsage, criticalKeyUsage, keyuse.getEncoded());
        }

        //===========Issuer alternative names===========

        boolean criticalIAN = bean.isIssuerAlternativeNameCritical();
        if (bean.getIssuerAlternativeNames().length > 0) {
            GeneralName[] all = new GeneralName[bean.getIssuerAlternativeNames().length];
            int i = 0;
            for (String it : bean.getIssuerAlternativeNames()) {
                //all[i++] = new GeneralName(new X500Name(it));
                all[i++] = new GeneralName(GeneralName.rfc822Name,it);
            }
            GeneralNames names = new GeneralNames(all);
            certGen.addExtension(Extension.issuerAlternativeName, criticalIAN, names);
        }

        //===========Inhibit any Policy===========

        boolean criticalIAP = bean.isInhibitAndPolicyCritical();
        if (bean.isInhibitAndPolicy()){
            //GET skipCert
            String skipCerts = bean.getInhibitAnyPolicySkipCerts();
            InhibitAnyPolicyExtension i = new InhibitAnyPolicyExtension(Integer.parseInt(skipCerts));
            criticalIAP = true; //MUST BE!
            certGen.addExtension(Extension.inhibitAnyPolicy, criticalIAP, i.getExtensionValue());
            //2nd way
            //InhibitAnyPolicy iap = new InhibitAnyPolicy(new BigInteger(skipCerts));
            //certGen.addExtension(Extension.inhibitAnyPolicy, criticalIAP, iap);
        }

        //========FINAL BUILD========
        X509Certificate cert = null;
        //v3
        if(version == 2) {
            cert = new JcaX509CertificateConverter().getCertificate(certGen.build(sigGen));
        }
        //v1
        if(version == 0) {
            cert = new JcaX509CertificateConverter().getCertificate(certGenV1.build(sigGen));
        }
        System.out.println("CREATION: "+ cert); //DEBUG
        return cert;
    }

    public static boolean writeCertificateToFile(String file, String encoded) {
        FileOutputStream fos;
        try {
            fos = new FileOutputStream(file);
            PrintWriter pw = new PrintWriter(fos, true);
            pw.write(encoded);

            pw.close();
            fos.close();
            return true; //OK
        } catch (IOException e) {
            e.printStackTrace();
            return false;
        }
    }

    public static String PEMBase64Encode(X509Certificate certificate) {
        byte[] derCert = null;
        try {
            derCert = certificate.getEncoded();
        } catch (CertificateEncodingException e) {
            e.printStackTrace();
        }
        String pemCert = new String(Base64.encode(derCert));             //TODO: WTF ?!
        return pemCert;
    }

    public static byte[] DEREncode(X509Certificate cert) {
        byte[] derCert = null;
        try {
            derCert = cert.getEncoded();
        } catch (CertificateEncodingException e) { e.printStackTrace(); }
        return derCert;
    }

    //=====================================      CSR      =========================================================
    public static final String keyExtensionName[] = { "Digital Signature", "Non Repudiation", "Key Enchipherment",
            "Data Enchipherment", "Key Agreement", "Certificate Signing", "CRL Signing", "Encipher Only",
            "Decipher Only" };

    public static int getX509KeyUsage(int i) {
        switch (i) {
            case 0:
                return X509KeyUsage.digitalSignature;
            case 1:
                return X509KeyUsage.nonRepudiation;
            case 2:
                return X509KeyUsage.keyEncipherment;
            case 3:
                return X509KeyUsage.dataEncipherment;
            case 4:
                return X509KeyUsage.keyAgreement;
            case 5:
                return X509KeyUsage.keyCertSign;
            case 6:
                return X509KeyUsage.cRLSign;
            case 7:
                return X509KeyUsage.encipherOnly;
            case 8:
                return X509KeyUsage.decipherOnly;
        }
        return 0;
    }

    public static void addToGeneratorExtensions(ExtensionsGenerator extGen, X509Certificate cert) throws Exception {
        JcaX509CertificateHolder certHolder = null;
        try {
            certHolder = new JcaX509CertificateHolder(cert);
        } catch (CertificateEncodingException e1) { e1.printStackTrace(); }
        Set criticalExtensions = certHolder.getCriticalExtensionOIDs();
        boolean[] keyUsage = cert.getKeyUsage();
        int keyUse = 0;
        if (keyUsage != null) {
            for (int i = 0; i < Functions.keyExtensionName.length; i++) {
                if (keyUsage[i]) {
                    keyUse |= Functions.getX509KeyUsage(i);
                }
            }
            extGen.addExtension(Extension.keyUsage, criticalExtensions.contains(Extension.keyUsage),
                    new KeyUsage(keyUse));
        }
        Collection<List<?>> allNames = cert.getIssuerAlternativeNames();
        if (allNames != null) {
            Iterator<List<?>> it = allNames.iterator();
            GeneralName[] all = new GeneralName[allNames.size()];
            int i = 0;
            while (it.hasNext()) {
                List<?> list = it.next();
                int generalNameFormat = (Integer) list.get(0);
                String genName = (String) list.get(1);
                all[i++] = new GeneralName(generalNameFormat, genName);
            }
            GeneralNames names = new GeneralNames(all);
            extGen.addExtension(Extension.issuerAlternativeName,
                    criticalExtensions.contains(Extension.issuerAlternativeName), names);
        }
        //TODO: add inhibitAnyPolicy?
        //TODO: why is this needed?
    }

    public static void addExtensionsToBuilder(X509v3CertificateBuilder certificateBuilder, Extensions allExt)
            throws CertIOException {
        //TODO: why this?
        ASN1ObjectIdentifier[] allId = allExt.getExtensionOIDs();
        for (ASN1ObjectIdentifier aoi : allId)
            certificateBuilder.addExtension(allExt.getExtension(aoi));
    }
}
