package implementation.Beans;

import java.util.Date;

/**
 * Project name: zp-projekat
 * Created by staz on 1.6.2017. 11:01
 */
public class CertificateSubject {

    //Certificate Subject

    /**
     * Country
     */
    private String C;
    /**
     * State
     */
    private String ST;
    /**
     * Locality
     */
    private String L;
    /**
     * Organization
     */
    private String O;
    /**
     * Organization unit
     */
    private String OU;
    /**
     * Common name
     */
    private String CN;
    /**
     * Signature Algorithm
     */
    private String SA;


    /**
     * Serial Number
     */
    private String SN;

    /**
     * RSA Key length {512,1024,2048,4096}
     */
    private String keyLength;

    /**
     * Valid not before
     */
    private Date validNotBefore;

    /**
     * Valid not after
     */
    private Date validNotAfter;

    //ISSUER SUBJECT

    private String iC;
    private String iST;
    private String iL;
    private String iO;
    private String iOU;
    private String iCN;
    /**
     * Issuer signature algorithm
     */
    private String iSN;


    public enum KeyUsageBox {
        DIGITAL_SIGNATURE(0),
        CONTENT_COMMITMENT(1),
        KEY_ENCIPHERMENT(2),
        DATA_ENCIPHERMENT(3),
        KEY_AGREEMENT(4),
        CERTIFICATE_SIGNING(5),
        CRL_SIGNING(6),
        ENCIPHER_ONLY(7),
        DECIPHER_ONLY(8);

        private int val;
        KeyUsageBox(int i) {
            val = i;
        }

        public int getVal(){ return val; }
    }
    /**
     * Extension 1
     * Key usage
     * 0. Digital Signature [0]
     * 1. Content Commitment FALI? [1]
     * 2. Key Encipherment [2]
     * 3. Data Encipherment [3]
     * 4. Key Agreement [4]
     * 5. Certificate Signing [5]
     * 6. CRL Signing [6]
     * 7. Encipher Only [7]
     * 8. Decipher Only [8]
     */
    private boolean[] keyUsage;

    /**
     * Checkbox for Key Usage {CRITICAL}
     */
    private boolean keyUsageCritical;

    /**
     * Extension 2
     * Issuer alternative name (CommaSeparatedValues)
     */
    private String[] issuerAlternativeNames;

    /**
     * Checkbox for Issuer Alternative name {CRITICAL}
     */
    private boolean issuerAlternativeNameCritical;

    /**
     * Extension 3
     * Inhibit and policy
     */
    private boolean inhibitAndPolicy;

    /**
     * Checkbox for Inhibit and policy {CRITICAL}
     */
    private boolean inhibitAndPolicyCritical;

    /**
     * Inside checkbox
     */
    private boolean inhibitAnyPolicy;

    /**
     * Textbox field Skip Certs
     */
    private String inhibitAnyPolicySkipCerts;

    /**
     * Certificate version {1 or 3}
     */
    private int version;
    // bc1 Certificate Authority
    // bc2 Path Length Constraint
    // ian Issuer Alternative Name
    // BOOLEAN: digitalSignature, keyAgreement, decipherOnly, nonRepudation
    // BOOLEAN: dataEncipherment, basicConstraints, issuerAlternativeNames, keyUsage, validFromD, validUntilD


    public CertificateSubject(String C, String ST, String L, String O, String OU, String CN, String SA,
                              String SN, String keyLength, Date validNotBefore, Date validNotAfter,
                              boolean[] keyUsage, String[] issuerAlternativeNames, boolean inhibitAndPolicy, int version) {
        this.C = C;
        this.ST = ST;
        this.L = L;
        this.O = O;
        this.OU = OU;
        this.CN = CN;
        this.SA = SA;
        this.SN = SN;
        this.keyLength = keyLength;
        this.validNotBefore = validNotBefore;
        this.validNotAfter = validNotAfter;
        this.keyUsage = keyUsage;
        this.issuerAlternativeNames = issuerAlternativeNames;
        this.inhibitAndPolicy = inhibitAndPolicy;
        this.version = version;
    }

    /**
     * Returns if that checkbox is enabled
     * @param kub {@link KeyUsageBox}
     * @return boolean value of that checkbox.
     */
    public boolean isEnabled(KeyUsageBox kub){
        return keyUsage[kub.getVal()];
    }

    public int getVersion() {
        return version;
    }

    public void setVersion(int version) {
        this.version = version;
    }

    public boolean isInhibitAnyPolicy() {
        return inhibitAnyPolicy;
    }

    public void setInhibitAnyPolicy(boolean inhibitAnyPolicy) {
        this.inhibitAnyPolicy = inhibitAnyPolicy;
    }

    public String getInhibitAnyPolicySkipCerts() {
        return inhibitAnyPolicySkipCerts;
    }

    public void setInhibitAnyPolicySkipCerts(String inhibitAnyPolicySkipCerts) {
        this.inhibitAnyPolicySkipCerts = inhibitAnyPolicySkipCerts;
    }

    public String getIssuerAlternativeName(int index){
        if(index > 0 && index < issuerAlternativeNames.length)
            return issuerAlternativeNames[index];
        throw new IndexOutOfBoundsException();
    }

    public boolean isKeyUsageCritical() {
        return keyUsageCritical;
    }

    public void setKeyUsageCritical(boolean keyUsageCritical) {
        this.keyUsageCritical = keyUsageCritical;
    }

    public boolean isIssuerAlternativeNameCritical() {
        return issuerAlternativeNameCritical;
    }

    public void setIssuerAlternativeNameCritical(boolean issuerAlternativeNameCritical) {
        this.issuerAlternativeNameCritical = issuerAlternativeNameCritical;
    }

    public boolean isInhibitAndPolicyCritical() {
        return inhibitAndPolicyCritical;
    }

    public void setInhibitAndPolicyCritical(boolean inhibitAndPolicyCritical) {
        this.inhibitAndPolicyCritical = inhibitAndPolicyCritical;
    }

    /**
     * Get Country
     */
    public String getC() {
        return C;
    }

    /**
     * Set Country
     */
    public void setC(String c) {
        C = c;
    }

    /**
     * Get State
     */
    public String getST() {
        return ST;
    }

    /**
     * Set State
     */
    public void setST(String ST) {
        this.ST = ST;
    }

    /**
     * Get Locality
     */
    public String getL() {
        return L;
    }

    /**
     * Set Locality
     */
    public void setL(String l) {
        L = l;
    }

    /**
     * Get Organization
     */
    public String getO() {
        return O;
    }

    /**
     * Set Organization
     */
    public void setO(String o) {
        O = o;
    }

    /**
     * Get Organization Unit
     */
    public String getOU() {
        return OU;
    }

    /**
     * Set Organization Unit
     */
    public void setOU(String OU) {
        this.OU = OU;
    }

    /**
     * Get Common Name
     */
    public String getCN() {
        return CN;
    }

    /**
     * Set Common Name
     */
    public void setCN(String CN) {
        this.CN = CN;
    }

    /**
     * Get Signature Algorithm
     */
    public String getSA() {
        return SA;
    }

    /**
     * Set Signature Algorithm
     */
    public void setSA(String SA) {
        this.SA = SA;
    }

    /**
     * Get Serial Number
     */
    public String getSN() {
        return SN;
    }

    /**
     * Set Serial Number
     */
    public void setSN(String SN) {
        this.SN = SN;
    }

    public String getKeyLength() {
        return keyLength;
    }

    public void setKeyLength(String keyLength) {
        this.keyLength = keyLength;
    }

    public Date getValidNotBefore() {
        return validNotBefore;
    }

    public void setValidNotBefore(Date validNotBefore) {
        this.validNotBefore = validNotBefore;
    }

    public Date getValidNotAfter() {
        return validNotAfter;
    }

    public void setValidNotAfter(Date validNotAfter) {
        this.validNotAfter = validNotAfter;
    }

    public boolean[] isKeyUsage() {
        return keyUsage;
    }

    public void setKeyUsage(boolean[] keyUsage) {
        this.keyUsage = keyUsage;
    }

    public String[] getIssuerAlternativeNames() {
        return issuerAlternativeNames;
    }

    public void setIssuerAlternativeNames(String[] issuerAlternativeNames) {
        this.issuerAlternativeNames = issuerAlternativeNames;
    }

    public boolean isInhibitAndPolicy() {
        return inhibitAndPolicy;
    }

    public void setInhibitAndPolicy(boolean inhibitAndPolicy) {
        this.inhibitAndPolicy = inhibitAndPolicy;
    }

    public String getiC() {
        return iC;
    }

    public void setiC(String iC) {
        this.iC = iC;
    }

    public String getiST() {
        return iST;
    }

    public void setiST(String iST) {
        this.iST = iST;
    }

    public String getiL() {
        return iL;
    }

    public void setiL(String iL) {
        this.iL = iL;
    }

    public String getiO() {
        return iO;
    }

    public void setiO(String iO) {
        this.iO = iO;
    }

    public String getiOU() {
        return iOU;
    }

    public void setiOU(String iOU) {
        this.iOU = iOU;
    }

    public String getiCN() {
        return iCN;
    }

    public void setiCN(String iCN) {
        this.iCN = iCN;
    }

    public String getiSN() {
        return iSN;
    }

    public void setiSN(String iSN) {
        this.iSN = iSN;
    }
}
