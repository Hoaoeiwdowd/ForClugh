using System;
using System.Linq;
using Sodium;

namespace ClashRoyaleProxy
{
    class ClientCrypto
    {
        public static byte[] DecryptPacket(Packet p)
        {
            // CLIENTSTATE
            int messageId = p.PacketID;
            byte[] cipherText = p.Payload;
            byte[] plainText;

            if (messageId == 20100 || (messageId == 20103 && Crypto.ServerState_sharedKey == null))
            {
                plainText = cipherText;
            }
            else if (messageId == 20103 || messageId == 20104)
            {
                byte[] nonce = GenericHash.Hash(Crypto.ClientState_nonce.Concat(Crypto.ClientState_clientKey.PublicKey).Concat(Keys.OriginalPublicKey).ToArray(), null, 24);
                plainText = PublicKeyBox.Open(cipherText, nonce, Crypto.ClientState_clientKey.PrivateKey, Keys.OriginalPublicKey);
                Crypto.ServerState_nonce = plainText.Take(24).ToArray();
                Crypto.ServerState_sharedKey = plainText.Skip(24).Take(32).ToArray();
                plainText = plainText.Skip(24).Skip(32).ToArray();
            }
            else
            {
                Crypto.ServerState_nonce = Utilities.Increment(Utilities.Increment(Crypto.ServerState_nonce));
                plainText = SecretBox.Open(new byte[16].Concat(cipherText).ToArray(), Crypto.ServerState_nonce, Crypto.ServerState_sharedKey);

            }
            return plainText;
        }

        public static byte[] EncryptPacket(Packet p)
        {
            int messageId = p.PacketID;
            byte[] cipherText;
            byte[] plainText = p.Payload;

            if (messageId == 10100)
            {
                cipherText = plainText;
            }
            else if (messageId == 10101)
            {
                byte[] nonce = GenericHash.Hash(Crypto.ClientState_clientKey.PublicKey.Concat(Keys.OriginalPublicKey).ToArray(), null, 24);
                plainText = Crypto.ServerState_sessionKey.Concat(Crypto.ClientState_nonce).Concat(plainText).ToArray();
                cipherText = PublicKeyBox.Create(plainText, nonce, Crypto.ClientState_clientKey.PrivateKey, Keys.OriginalPublicKey);
                cipherText = Crypto.ClientState_clientKey.PublicKey.Concat(cipherText).ToArray();
            }
            else
            {
                cipherText = SecretBox.Create(plainText, Crypto.ClientState_nonce, Crypto.ServerState_sharedKey).Skip(16).ToArray();
            }
            return cipherText;
        }
    }
}
