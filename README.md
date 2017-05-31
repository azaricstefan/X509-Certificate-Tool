# zp-projekat
ZP projekat 

Podesiti RUNTIME configuration: 
Program arguments: config.txt
Main Class: X509_2017->code->X509

Korisni linkovi:
- Dokumentacija neka siromasna https://bouncycastle.org/docs/pkixdocs1.5on/index.html
- https://www.mayrhofer.eu.org/create-x509-certs-in-java
- Neki projekat https://github.com/mitap94/ir3-zp-projekat/blob/master/zp-projekat/src/crypto/utils/BouncyCastleX509Builder.java
- http://www.bouncycastle.org/wiki/display/JA1/BC+Version+2+APIs
- Java code examples for java.security.cert.X509Certificate http://www.programcreek.com/java-api-examples/java.security.cert.X509Certificate

FAQ:

1. #ЗП Је ли ко користио
JcaContentSignerBuilder да потпише сертификтате и је ли му ради за RIPEMDxxxwithRSA?
Ђорђе Живановић Jovan Djukicево решење:
static 
{
Security.addProvider(new BouncyCastleProvider());
}
Ово решава потписивање, али не решава дохваћено име алгоритма.
Nikola Miljkovic x509vXcertificatebuilder ima operaciju build(...);
Nikola Miljkovic u okviru koje mozes da specifiras algoritam i kljuc potpisa
Ђорђе Живановић Ма неће да ради за овај алгоритам, јер вуче јавину имплементацију. 😐
Nikola Miljkovic u odredjenim funkcijama ima paramatera za provider gde se kao string prosledi "BC"
Ђорђе Живановић Ј**и га сад. 😂 Ово ти решава све те двосмислене проблеме. Јер сигурно још негде ће се појавити.


2. #ЗП enabledKeyIdentifiers, чему служи ?
Dohvata vrednost onog checkboxa iz GUI-ja za key identifiers, ako je to ono sto mislim, proveri.
Pa sluzi da odlucis da li da dodas tu ekstenziju ili ne. Dodajes samo ako je true.

3. [#ZP projekat] Je l' neko probao issuer alternative name da doda? I je l' prolazi javni test kad to doda?
Aleksa Mitrovic: Meni baca error: Certificate contains unsupported critical extensions: [2.5.29.18] - sto je issuer alternative name...
Čukanović resio - ne podrzava ako stavite critical na true...

4. [ZP] Da li je neko uspeo da upise x400Address u Subject/issuer alternative names?
Mihailo Petric Da li si probao gn = new GeneralName(GeneralName.x400Address, new X500Name("C=....,ST=..."))
napravis niz GeneralNames[] i to prosledis addExtension kao ASN1Encodable ?
Stevan Ognjanovic
Stevan Ognjanovic Nisam to probao, nesto drugo jesam pa je puklo u konstruktoru. Da li si takodje uspeo za ediPartyName i othername?
Mihailo Petric
Mihailo Petric za othername mi je nesto cudno pisalo u sertifikatu. Koristio sam DERIA5String(String). Ja i dalje nisam siguran sta sve moze da se prosledi kod subject/issuer name, ali ono sto sam ja gledao u raznim sertifikatima po netu to je uvek dns.

5. #ZP #projekat za EC algoritam - kako se implementira Set i Curve sa sve one opcije sa GUI-ja?
Branislava Ivković ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec(access.getPublicKeyECCurve());
Milica Stanković To je iz Bouncy Castle?
Branislava Ivković Da. Moze i u obicnoj Javi da se koristi to ime curve-a za generisanje kljuceva, ali cini mi se da meni nije radilo za sve one iz GUI-ja, pa sam zato presla na ovo.
Milica Stanković Hvala puno :)
Branislava Ivković Set sluzi samo da promeni sta se nalazi u drop down meniju za curve.

6. #ЗП Је ли зна неко како да се дохвати issuer alterantive name?
Пошто ова метода getAlternativeName увек враћа низ стрингова величине 0.
getAlternativeName(6)

