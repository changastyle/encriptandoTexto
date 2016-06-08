package crypto;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import org.apache.commons.codec.binary.Base64;

public class CryptoUtil
{
    private static String password = "123456";
    public static SecretKey generateKey()
    {
        SecretKey salida = null;
        try
        {
            salida = new SecretKeySpec(password.getBytes(), "AES");
        } 
        catch (Exception e)
        {
            e.printStackTrace();
        }
        return salida;
    }
    public static byte[] encryptMsg(String message, SecretKey secret)
    {
        byte[] cipherText  = null;
        try
        {
            Cipher cipher = null;
            cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, secret);
            cipherText = cipher.doFinal(message.getBytes("UTF-8"));

        }
        catch(NoSuchAlgorithmException e)
        {

        }catch(NoSuchPaddingException e)
        {

        } catch(InvalidKeyException e)
        {

        } catch(IllegalBlockSizeException e)
        {

        }catch(BadPaddingException e)
        {

        }catch(UnsupportedEncodingException e)
        {

        }
        return cipherText;
    }
    public static String decryptMsg(byte[] cipherText, SecretKey secret)
    {
        String decryptString = null;
        try
        {
            Cipher cipher = null;
            cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, secret);

            decryptString = new String(cipher.doFinal(cipherText), "UTF-8");

        }
        catch(NoSuchPaddingException e)
        {

        }catch( NoSuchAlgorithmException e)
        {

        } catch( InvalidKeyException e)
        {

        }catch( BadPaddingException e)
        {

        }catch( IllegalBlockSizeException e)
        {

        }catch( UnsupportedEncodingException e)
        {

        }
        return decryptString;
    }

    public static String encriptar(String texto) {

        String secretKey = "qualityinfosolutions"; //llave para encriptar datos
        String base64EncryptedString = "";

        try {

            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] digestOfPassword = md.digest(secretKey.getBytes("utf-8"));
            byte[] keyBytes = Arrays.copyOf(digestOfPassword, 24);

            SecretKey key = new SecretKeySpec(keyBytes, "DESede");
            Cipher cipher = Cipher.getInstance("DESede");
            cipher.init(Cipher.ENCRYPT_MODE, key);

            byte[] plainTextBytes = texto.getBytes("utf-8");
            byte[] buf = cipher.doFinal(plainTextBytes);
            byte[] base64Bytes = Base64. encodeBase64(buf);
            base64EncryptedString = new String(base64Bytes);

        } catch (Exception ex) {
        }
        return base64EncryptedString;
}

    public static String desencriptar(String textoEncriptado){

            String secretKey = "qualityinfosolutions"; //llave para desenciptar datos
            String base64EncryptedString = "";

            try {
                byte[] message = Base64.decodeBase64(textoEncriptado.getBytes("utf-8"));
                MessageDigest md = MessageDigest.getInstance("MD5");
                byte[] digestOfPassword = md.digest(secretKey.getBytes("utf-8"));
                byte[] keyBytes = Arrays.copyOf(digestOfPassword, 24);
                SecretKey key = new SecretKeySpec(keyBytes, "DESede");

                Cipher decipher = Cipher.getInstance("DESede");
                decipher.init(Cipher.DECRYPT_MODE, key);

                byte[] plainText = decipher.doFinal(message);

                base64EncryptedString = new String(plainText, "UTF-8");

            } catch (Exception ex) {
            }
            return base64EncryptedString;
    }

}
