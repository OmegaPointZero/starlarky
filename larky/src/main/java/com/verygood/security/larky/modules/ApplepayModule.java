//package ECCderiveKey;
package com.verygood.security.larky.modules;

import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;

import net.starlark.java.annot.StarlarkBuiltin;
import net.starlark.java.eval.StarlarkValue;
import net.starlark.java.annot.StarlarkMethod;
import net.starlark.java.eval.StarlarkBytes;
import net.starlark.java.eval.StarlarkThread;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

@StarlarkBuiltin(
    name = "japplepay",
    category = "BUILTIN",
    doc = ""
)

public class ApplepayModule implements StarlarkValue {
    
    // Constructor
    public ApplepayModule()
    {
        Security.addProvider(new BouncyCastleProvider());  // Use BouncyCastlr
    }
        // Provide private and public keys in Base64, the derived key will return in Base64
      @StarlarkMethod(name = "deriveKey", useStarlarkThread = true)
      public String deriveKey(String privKeyAstr, String pubKeyBstr, StarlarkThread thread) {
            
          
          KeyFactory factory;
            PrivateKey privateKeyA = null ;
            PublicKey   publicKeyB = null ;
            try {
                factory = KeyFactory.getInstance("ECDH", BouncyCastleProvider.PROVIDER_NAME);
                
                byte[]  publicKeyBarray = Base64.getDecoder().decode(pubKeyBstr);
                publicKeyB = factory.generatePublic(new X509EncodedKeySpec(publicKeyBarray));
                
                
                byte[] privateKayAarray = Base64.getDecoder().decode(privKeyAstr);
                privateKeyA = factory.generatePrivate(new PKCS8EncodedKeySpec(privateKayAarray));
                

                
            } catch (NoSuchAlgorithmException e2) {
                // catch block
                e2.printStackTrace();
            } catch (NoSuchProviderException e2) {
                // catch block
                e2.printStackTrace();
            } catch (InvalidKeySpecException e1) {
                // catch block
                e1.printStackTrace();
            }
            
            // Derive the AES secret keys to encrypt/decrypt the message
            SecretKey secretKeyX = deriveKeyForSymmEncryption(privateKeyA, publicKeyB);
            byte[] byteArrrayEncodedKeyX = secretKeyX.getEncoded();
            String encodedB64KeyX = Base64.getEncoder().encodeToString(secretKeyX.getEncoded());
        return encodedB64KeyX;
          
      }
      
      public  SecretKey deriveKeyForSymmEncryption(PrivateKey privateKey, PublicKey publicKey) {
        try {
          KeyAgreement keyAgreement = KeyAgreement.getInstance("ECDH", BouncyCastleProvider.PROVIDER_NAME);
          keyAgreement.init(privateKey);
          keyAgreement.doPhase(publicKey, true);

          SecretKey key = keyAgreement.generateSecret("AES");
          return key;
        } catch (InvalidKeyException | NoSuchAlgorithmException |
          NoSuchProviderException e) {
          // catch block
          e.printStackTrace();
          return null;
        }
      }

}
