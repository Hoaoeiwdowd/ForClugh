using System;
using System.Linq;
using Sodium;

namespace ClashRoyaleProxy
{
    class ServerCrypto
    {
        public static byte[] DecryptPacket(Packet p)
        {
            //ServerState
            int messageId = p.PacketID;
            byte[] cipherText = p.Payload;
            byte[] plainText;

            if (messageId == 10100)
            {
                plainText = cipherText;
            }
            else if (messageId == 10101)
            {
                Crypto.ServerState_clientKey = cipherText.Take(32).ToArray();
                byte[] nonce = GenericHash.Hash(Crypto.ServerState_clientKey.Concat(Keys.ModdedPublicKey).ToArray(), null, 24);
                cipherText = cipherText.Skip(32).ToArray();
                plainText = PublicKeyBox.Open(cipherText, nonce, Keys.GeneratedPrivateKey, Crypto.ServerState_clientKey);
                Crypto.ServerState_sessionKey = plainText.Take(24).ToArray();
                Crypto.ClientState_nonce = plainText.Skip(24).Take(24).ToArray();
                plainText = plainText.Skip(24).Skip(24).ToArray();
            }
            else
            {
                Crypto.ClientState_nonce = Utilities.Increment(Utilities.Increment(Crypto.ClientState_nonce));
                plainText = SecretBox.Open(new byte[16].Concat(cipherText).ToArray(), Crypto.ClientState_nonce, Crypto.ServerState_sharedKey);
            }
            return plainText;
        }

        public static byte[] EncryptPacket(Packet p)
        {
            int messageId = p.PacketID;
            byte[] plainText = p.Payload;
            byte[] cipherText;
            if (messageId == 20100 || (messageId == 20103 && Crypto.ServerState_sharedKey == null))
            {
                cipherText = plainText;
            }
            else if (messageId == 20103 || messageId == 20104)
            {
                byte[] nonce = GenericHash.Hash(Crypto.ClientState_nonce.Concat(Crypto.ServerState_clientKey).Concat(Keys.ModdedPublicKey).ToArray(), null, 24);
                plainText = Crypto.ServerState_nonce.Concat(Crypto.ServerState_sharedKey).Concat(plainText).ToArray();
                cipherText = PublicKeyBox.Create(plainText, nonce, Keys.GeneratedPrivateKey, Crypto.ServerState_clientKey);
            }
            else
            {
                // nonce was already incremented in ClientCrypto.DecryptPacket
                cipherText = SecretBox.Create(plainText, Crypto.ServerState_nonce, Crypto.ServerState_sharedKey).Skip(16).ToArray();
            }
            return cipherText;
        }
    }
}
