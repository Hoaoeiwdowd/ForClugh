using Sodium;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ClashRoyaleProxy
{
    class Crypto
    {
        // ClientState
        public static KeyPair ClientState_clientKey = Sodium.PublicKeyBox.GenerateKeyPair();
        public static byte[] ClientState_serverKey, ClientState_nonce;

        // ServerState
        public static byte[] ServerState_clientKey, ServerState_nonce, ServerState_sessionKey, ServerState_sharedKey;
    }
}
