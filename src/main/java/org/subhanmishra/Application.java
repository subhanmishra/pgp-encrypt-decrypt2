package org.subhanmishra;


//bouncy castle imports

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.CompressionAlgorithmTags;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.openpgp.operator.PublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.bc.*;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyDataDecryptorFactoryBuilder;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Date;
import java.util.Iterator;
import java.util.Scanner;


public class Application {

    static final ClassLoader loader = Application.class.getClassLoader();

    public static void main(String[] args) {
        try {

            // get some input
            Scanner scanInput = new Scanner(System.in);
            System.out.println("Enter a string: ");
            String message = scanInput.nextLine();
            System.out.println("The input is : " + message);
            scanInput.close();


            // hardcoded for demo purpose
            String privateKeyPassword = "hongkong";

            PGPPublicKey pubKey = null;
            // Load public key
            try (InputStream pubKeyInputStream = loader
                    .getResourceAsStream("sign-and-encrypt_pub.asc")){
                pubKey = readPublicKey(pubKeyInputStream);
            } catch (IOException | PGPException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            }

            if (pubKey != null) {
                System.out.println("Successfully read public key: ");
                // System.out.println("Key Owner: "+pubKey.getUserIDs());
                // System.out.println("Key Stength: "+pubKey.getBitStrength());
                // System.out.println("Key Algorithm: "+pubKey.getAlgorithm()+"\n\n");
            }

            // Load private key, **NOTE: still secret, we haven't unlocked it yet**
            PGPSecretKey pgpSec = null;
            try (InputStream privKeyInputStream = loader
                    .getResourceAsStream("sign-and-encrypt_priv.asc")){
                pgpSec = readSecretKey(privKeyInputStream);
            } catch (IOException | PGPException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            }

            InputStream inputMsgStream = new ByteArrayInputStream(message.getBytes());
            String outputFileName = "encrypted_msg.pgp";

            OutputStream outputStream = new FileOutputStream("C:\\IntelliJ_Workspace\\pgp-encrypt-decrypt2\\src\\main\\resources\\" + outputFileName);

            fEncryptOnePassSignatureLocal(outputFileName, pubKey, outputStream, privateKeyPassword, pgpSec, inputMsgStream);

            byte[] read = Files.readAllBytes(Paths.get("C:\\IntelliJ_Workspace\\pgp-encrypt-decrypt2\\src\\main\\resources\\encrypted_msg.pgp"));
            fDecryptOnePassSignatureLocal(new ByteArrayInputStream(read), pubKey, pgpSec, privateKeyPassword, new FileOutputStream("C:\\IntelliJ_Workspace\\pgp-encrypt-decrypt2\\src\\main\\resources\\decrypted_msg.txt"));

        } catch (Exception ex) {
            ex.printStackTrace();
        }

    }

    /**
     * This is the primary function that will create encrypt a file and sign it
     * with a one pass signature.
     *
     * @param targetFileName           -- file name on drive systems that will contain encrypted content
     * @param pubKey                   -- Public Key used for encryption
     * @param targetFileStream         -- The stream for the encrypted target file
     * @param secretKeyPassphrase      -- The private key password for the key retrieved from
     *                                 collection used for signing
     * @param pgpSec                   -- Password protected Secret key containing the Private Key
     * @param contentStream            -- Input message stream for Plain text data
     * @throws Exception
     */
    public static void fEncryptOnePassSignatureLocal(String targetFileName,
                                                     PGPPublicKey pubKey,
                                                     OutputStream targetFileStream, String secretKeyPassphrase,
                                                     PGPSecretKey pgpSec, InputStream contentStream) throws Exception {

        char[] password = secretKeyPassphrase.toCharArray();
        int BUFFER_SIZE = 1 << 16; // should always be power of 2(one shifted bitwise 16 places)
        //for now we will always do integrity checks and armor file
        boolean armor = true;
        boolean withIntegretyCheck = true;
        //set default provider, we will pass this along
        BouncyCastleProvider bcProvider = new BouncyCastleProvider();

        // armor stream if set
        if (armor)
            targetFileStream = new ArmoredOutputStream(targetFileStream);

        // Init encrypted data generator
        BcPGPDataEncryptorBuilder dataEncryptor = new BcPGPDataEncryptorBuilder(PGPEncryptedData.AES_256);
        dataEncryptor.setWithIntegrityPacket(true);
        dataEncryptor.setSecureRandom(new SecureRandom());


        PGPEncryptedDataGenerator encryptedDataGenerator = new PGPEncryptedDataGenerator(dataEncryptor);
        encryptedDataGenerator.addMethod(new BcPublicKeyKeyEncryptionMethodGenerator(pubKey));


        OutputStream encryptedOut = encryptedDataGenerator.open(targetFileStream, new byte[BUFFER_SIZE]);

        // start compression
        PGPCompressedDataGenerator compressedDataGenerator = new PGPCompressedDataGenerator(
                CompressionAlgorithmTags.ZIP);
        OutputStream compressedOut = compressedDataGenerator.open(encryptedOut);

        //start signature
        PBESecretKeyDecryptor keyDecryptor = new JcePBESecretKeyDecryptorBuilder()
                .setProvider(bcProvider).build(password);
        PGPPrivateKey pgpPrivKey = pgpSec.extractPrivateKey(keyDecryptor);

        PGPSignatureGenerator signatureGenerator = new PGPSignatureGenerator(
                new BcPGPContentSignerBuilder(pgpSec.getPublicKey().getAlgorithm(), HashAlgorithmTags.SHA384));


        signatureGenerator.init(PGPSignature.BINARY_DOCUMENT, pgpPrivKey);
        // iterate to find first signature to use
        for (@SuppressWarnings("rawtypes")
             Iterator i = pgpSec.getPublicKey().getUserIDs(); i.hasNext(); ) {
            String userId = (String) i.next();
            PGPSignatureSubpacketGenerator spGen = new PGPSignatureSubpacketGenerator();
            spGen.setSignerUserID(false, userId);
            signatureGenerator.setHashedSubpackets(spGen.generate());
            // Just the first one!
            break;
        }
        signatureGenerator.generateOnePassVersion(false).encode(compressedOut);

        // Create the Literal Data generator output stream
        PGPLiteralDataGenerator literalDataGenerator = new PGPLiteralDataGenerator();
        // get file handle
        File actualFile = new File(targetFileName);
        // create output stream
        OutputStream literalOut = literalDataGenerator.open(compressedOut,
                PGPLiteralData.BINARY, PGPLiteralData.CONSOLE,
                new Date(actualFile.lastModified()), new byte[BUFFER_SIZE]);


        // read input file and write to target file using a buffer
        byte[] buf = new byte[BUFFER_SIZE];
        int len;
        while ((len = contentStream.read(buf, 0, buf.length)) > 0) {
            literalOut.write(buf, 0, len);
            signatureGenerator.update(buf, 0, len);
        }
        // close everything down we are done
        literalOut.close();
        literalDataGenerator.close();
        signatureGenerator.generate().encode(compressedOut);
        compressedOut.close();
        compressedDataGenerator.close();
        encryptedOut.close();
        encryptedDataGenerator.close();
        contentStream.close();


        if (armor) targetFileStream.close();

    }

    /**
     * Try to find a public key in the Key File or Key Ring File
     * We will use the first one for now.
     *
     * @param in -- File Stream to KeyRing or Key
     * @return first public key
     * @throws IOException
     * @throws PGPException
     * @author Bilal Soylu
     */
    private static PGPPublicKey readPublicKey(InputStream in)
            throws IOException, PGPException {
        in = PGPUtil.getDecoderStream(in);

        PGPPublicKeyRingCollection pgpPub = new PGPPublicKeyRingCollection(in, new JcaKeyFingerprintCalculator());

        //
        // we are only looking for the first key that matches
        //

        //
        // iterate through the key rings.
        //
        Iterator rIt = pgpPub.getKeyRings();

        while (rIt.hasNext()) {
            PGPPublicKeyRing kRing = (PGPPublicKeyRing) rIt.next();
            Iterator kIt = kRing.getPublicKeys();

            while (kIt.hasNext()) {
                PGPPublicKey k = (PGPPublicKey) kIt.next();

                if (k.isEncryptionKey()) {
                    return k;
                }
            }
        }

        throw new IllegalArgumentException(
                "Can't find encryption key in key ring.");
    }


    /**
     * Find first secret key in key ring or key file.
     * A secret key contains a private key that can be accessed with a password.
     *
     * @param in     -- input Key file or key ring file
     * @return matching private key
     * @throws IOException
     * @throws PGPException
     * @throws NoSuchProviderException
     * @author Bilal Soylu
     */
    private static PGPSecretKey readSecretKey(InputStream in)
            throws IOException, PGPException, NoSuchProviderException {

        PGPSecretKey sKey = null;
        try {
            in = PGPUtil.getDecoderStream(in);
            PGPSecretKeyRingCollection pgpPriv = new PGPSecretKeyRingCollection(in, new JcaKeyFingerprintCalculator());

            // we just loop through the collection till we find a key suitable for
            // decrypt
            Iterator it = pgpPriv.getKeyRings();
            PGPSecretKeyRing pbr = null;

            while (sKey == null && it.hasNext()) {
                Object readData = it.next();
                if (readData instanceof PGPSecretKeyRing) {
                    pbr = (PGPSecretKeyRing) readData;
                    sKey = pbr.getSecretKey();
                }
            }

            if (sKey == null) {
                throw new IllegalArgumentException("secret key for message not found.");
            }
        } catch (PGPException e) {
            System.err.println(e);
            if (e.getUnderlyingException() != null) {
                e.getUnderlyingException().printStackTrace();
            }
        }
        return sKey;
    }


    /**
     * fDecryptOnePassSignature will decrypt a file that was encrypted using
     * public key, then signed with a private key as one pass signature based on
     * example of verifyAndDecrypt() by Raul
     *
     * @param encryptedInputStream
     * @param pubKey
     * @param pgpSec
     * @param secretKeyPassphrase
     * @return
     * @throws Exception
     */
    public static void fDecryptOnePassSignatureLocal(InputStream encryptedInputStream,
                                                     PGPPublicKey pubKey,
                                                     PGPSecretKey pgpSec, String secretKeyPassphrase,
                                                     OutputStream targetStream) throws Exception {

        Security.addProvider(new BouncyCastleProvider());

        // The decrypted results.
        // StringBuffer result = new StringBuffer();
        // The private key we use to decrypt contents.
        PGPPrivateKey privateKey = null;
        // The PGP encrypted object representing the data to decrypt.
        PGPPublicKeyEncryptedData encryptedData = null;

        // Get the list of encrypted objects in the message. The first object in
        // the
        // message might be a PGP marker, however, so we skip it if necessary.
        PGPObjectFactory objectFactory = new PGPObjectFactory(PGPUtil.getDecoderStream(encryptedInputStream), new BcKeyFingerprintCalculator());
        Object firstObject = objectFactory.nextObject();
        System.out.println("firstObject is " + firstObject);
        PGPEncryptedDataList dataList = (PGPEncryptedDataList) (firstObject instanceof PGPEncryptedDataList ? firstObject
                : objectFactory.nextObject());

        // Find the encrypted object associated with a private key in our key
        // ring.
        @SuppressWarnings("rawtypes")
        Iterator dataObjectsIterator = dataList.getEncryptedDataObjects();
        while (dataObjectsIterator.hasNext()) {
            encryptedData = (PGPPublicKeyEncryptedData) dataObjectsIterator.next();
            System.out.println("next data object is " + encryptedData);

            if (pgpSec != null) {
                // This object was encrypted for this key. If the passphrase is
                // incorrect, this will generate an error.
                PBESecretKeyDecryptor keyDecryptor = new JcePBESecretKeyDecryptorBuilder()
                        .setProvider("BC").build(secretKeyPassphrase.toCharArray());
                privateKey = pgpSec.extractPrivateKey(keyDecryptor);
                break;
            }
        }

        if (privateKey == null) {
            System.out.println();
            throw new RuntimeException("secret key for message not found");
        }

        // Get a handle to the decrypted data as an input stream
        PublicKeyDataDecryptorFactory decryptorFactory = new JcePublicKeyDataDecryptorFactoryBuilder()
                .setProvider("BC").build(privateKey);
        InputStream clearDataInputStream = encryptedData.getDataStream(decryptorFactory);
        PGPObjectFactory clearObjectFactory = new PGPObjectFactory(clearDataInputStream, new JcaKeyFingerprintCalculator());
        Object message = clearObjectFactory.nextObject();

        System.out.println("message for PGPCompressedData check is " + message);

        // Handle case where the data is compressed
        if (message instanceof PGPCompressedData) {
            PGPCompressedData compressedData = (PGPCompressedData) message;
            objectFactory = new PGPObjectFactory(compressedData.getDataStream(), new JcaKeyFingerprintCalculator());
            message = objectFactory.nextObject();
        }

        System.out.println("message for PGPOnePassSignature check is " + message);

        PGPOnePassSignature calculatedSignature = null;
        if (message instanceof PGPOnePassSignatureList) {
            calculatedSignature = ((PGPOnePassSignatureList) message).get(0);
            calculatedSignature.init(new BcPGPContentVerifierBuilderProvider(), pubKey);
            message = objectFactory.nextObject();
        }

        System.out.println("message for PGPLiteralData check is " + message);

        // We should only have literal data, from which we can finally read the
        // decrypted message.
        if (message instanceof PGPLiteralData) {
            InputStream literalDataInputStream = ((PGPLiteralData) message).getInputStream();
            int nextByte;

            while ((nextByte = literalDataInputStream.read()) >= 0) {
                // InputStream.read guarantees to return a byte (range 0-255),
                // so we
                // can safely cast to char.
                calculatedSignature.update((byte) nextByte); // also update
                // calculated
                // one pass
                // signature
                // result.append((char) nextByte);
                // add to file instead of StringBuffer
                targetStream.write((char) nextByte);
            }
            targetStream.close();
        } else {
            throw new RuntimeException("unexpected message type " + message.getClass().getName());
        }

        if (calculatedSignature != null) {
            PGPSignatureList signatureList = (PGPSignatureList) objectFactory.nextObject();
            System.out.println("signature list (" + signatureList.size() + " sigs) is " + signatureList.get(0).getKeyID());
            PGPSignature messageSignature = (PGPSignature) signatureList.get(0);

            if (!calculatedSignature.verify(messageSignature)) {
                throw new RuntimeException("Signature verification FAILED!!!");
            }
            System.out.println("Signature verification SUCCESSFUL!!!! ");
        }

        if (encryptedData.isIntegrityProtected()) {
            if (encryptedData.verify()) {
                System.out.println("message integrity protection verification succeeded");
            } else {
                throw new RuntimeException("message failed integrity check");
            }
        } else {
            System.out.println("message not integrity protected");
        }

        //close streams
        clearDataInputStream.close();


    }
}