import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.File;
import java.io.FileNotFoundException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.util.ArrayList;
import java.util.Scanner;

public class dictionaryAttack {

    private static String textFile = "english.txt";
    private ArrayList<String> english = new ArrayList<String>();
    private static String modulus = "94801787427845109838236728375666349987454945725838876203740747814072264" +
            "21330733592511058205667267093204635129817409488492200510791935107378276179891226731";
    private static int exponent = 65537;
    private PublicKey publicKey;
    private final static char[] hexArray = "0123456789ABCDEF".toCharArray();
    private static String ciphertext = "4863521ADFED0EFA990B8939DFA92FE13C2A6255E37D4873023BBC96996FDEA48A484E" +
            "54141942E8650F773A383F8C5BC558B5D97791146461661BE192E21610";

    public dictionaryAttack(String textFile) throws FileNotFoundException, InvalidKeySpecException,
            NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException,
            InvalidKeyException {
        createEnglishList();
        createPublicKey();
        RSAencrypt();

        System.out.println(modulus + " " + exponent);

    }

    private void createPublicKey() throws NoSuchAlgorithmException, InvalidKeySpecException {

        BigInteger exponentInt = new BigInteger("65537");
        BigInteger modulusInt = new BigInteger(modulus);
        RSAPublicKeySpec keySpec = new RSAPublicKeySpec(modulusInt, exponentInt);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");

        this.publicKey = keyFactory.generatePublic(keySpec);
    }

    public void createEnglishList() throws FileNotFoundException {
        // Add all words into array list
        ArrayList<String> english = new ArrayList<String>();

        File file = new File(textFile);
        Scanner sc = new Scanner(file);

        while (sc.hasNextLine()){
            english.add(sc.nextLine());
        }

        this.english = english;
        System.out.println("Word List created");
    }


    public void RSAencrypt() throws InvalidKeyException, BadPaddingException, IllegalBlockSizeException,
            NoSuchPaddingException, NoSuchAlgorithmException {

        for (String word : english) {

                Cipher cipher = Cipher.getInstance("RSA/ECB/NoPadding");
                cipher.init(Cipher.ENCRYPT_MODE, this.publicKey);
                byte[] encryptedData = cipher.doFinal(word.getBytes());

                String hexEncrypted = bytesToHex(encryptedData);

                if(hexEncrypted.equalsIgnoreCase(ciphertext)){
                    System.out.println(word);
                }
        }

    }

    public static String bytesToHex(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for ( int j = 0; j < bytes.length; j++ ) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }
        return new String(hexChars);
    }

        public static void main(String[] args) throws FileNotFoundException, InvalidKeySpecException,
                NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, NoSuchPaddingException, IllegalBlockSizeException {
            dictionaryAttack decrypt = new dictionaryAttack(textFile);
        }
}

