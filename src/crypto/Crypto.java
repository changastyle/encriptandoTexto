package crypto;

import javax.crypto.SecretKey;

public class Crypto
{

    public static void main(String[] args)
    {
        SecretKey claveSuperSecreta = CryptoUtil.generateKey();
        System.out.println("Clave super secreta: " + claveSuperSecreta);
        
        String cajaPandora = CryptoUtil.encriptar("hola como estas??");
        System.out.println("mensaje encriptado: " + cajaPandora );
        System.out.println("mensaje descencriptado : "+ CryptoUtil.desencriptar(cajaPandora));
        //System.out.println("" + CryptoUtil.decryptMsg(cajaPandora,claveSuperSecreta));
        
    }
    
}
