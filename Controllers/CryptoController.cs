using System;
using System.IO;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using NSec.Cryptography;

namespace EncryptionService.Controllers
{
    [Route("api/")]
    [ApiController]
    public class EncryptionController : ControllerBase
    {
        readonly byte[] motherKey = new byte[32] { 0x04, 0x21, 0x60, 0x1F, 0xA1, 0x33, 0x00, 0x21, 0x60, 0x1F, 0xC1, 0x23, 0x04, 0x21, 0x60, 0x4F, 0xA3, 0x33, 0x00, 0x24, 0x62, 0x1F, 0xB1, 0x32, 0x33, 0x34, 0x21, 0xB1, 0x32, 0x33, 0x34, 0x21 };


        // GET api/
        [HttpGet]
        public ActionResult<string> Get()
        {
            return "It's working!";
        }


        // POST api/encrypt
        [HttpPost]
        [Route("encrypt")]
        public async Task<ActionResult> Encrypt()
        {

            string path = Environment.GetEnvironmentVariable("PATH");
            string binDir = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Bin");
            Environment.SetEnvironmentVariable("PATH", path + ";" + binDir);

            using (var stream = new MemoryStream())
            {
                await Request.Body.CopyToAsync(stream);
                byte[] plaintext = stream.ToArray();
                Console.WriteLine(BitConverter.ToString(plaintext));
                Console.WriteLine("Plaintext size: " + plaintext.Length);

                int sec = GetSeconds();
                byte[] seconds = BitConverter.GetBytes(sec);
                Console.WriteLine("Seconds: " + sec);

                SharedSecret secret = SharedSecret.Import(motherKey);

                Key keyCipher = KeyDerivationAlgorithm.HkdfSha256.DeriveKey(secret, seconds, null, ChaCha20Poly1305.ChaCha20Poly1305);

                byte[] ivbytes = RandomGenerator.Default.GenerateBytes(12);
                Console.WriteLine("IV: " + BitConverter.ToString(ivbytes));

                Nonce IV = new Nonce(fixedField: ivbytes, counterFieldSize: 0);
                Console.WriteLine("IV size: " + IV.Size);


                byte[] ciphertext = ChaCha20Poly1305.ChaCha20Poly1305.Encrypt(keyCipher, IV, null, plaintext);
                Console.WriteLine("Cyphertext: " + BitConverter.ToString(ciphertext));
                Console.WriteLine("Cyphertext length: " + ciphertext.Length);


                byte[] result = new byte[seconds.Length + ivbytes.Length + ciphertext.Length];
                Array.Copy(seconds, 0, result, 0, seconds.Length);
                Array.Copy(ivbytes, 0, result, 4, ivbytes.Length);
                Array.Copy(ciphertext, 0, result, 16, ciphertext.Length);
                Console.WriteLine("result: " + BitConverter.ToString(result));

                return File(result, "application/octet-stream");
            }
        }


        // POST api/decrypt
        [HttpPost]
        [Route("decrypt")]
        public async Task<ActionResult> Decrypt()
        {

            string path = Environment.GetEnvironmentVariable("PATH");
            string binDir = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Bin");
            Environment.SetEnvironmentVariable("PATH", path + ";" + binDir);


            using (var stream = new MemoryStream())
            {
                await Request.Body.CopyToAsync(stream);
                byte[] data = stream.ToArray();

                Console.WriteLine("Mother key: " + BitConverter.ToString(motherKey));
                SharedSecret secret = SharedSecret.Import(motherKey);

                byte[] seconds = new byte[4];
                Array.Copy(data, 0, seconds, 0, 4);
                Console.WriteLine("Seconds size: " + seconds.Length);
                Console.WriteLine("Seconds: " + BitConverter.ToInt32(seconds));

                byte[] IV = new byte[12];
                Array.Copy(data, 4, IV, 0, 12);
                Console.WriteLine("IV size: " + IV.Length);
                Console.WriteLine("IV: " + BitConverter.ToString(IV));

                byte[] ciphertext = new byte[data.Length - 16];
                Array.Copy(data, 16, ciphertext, 0, ciphertext.Length);
                Console.WriteLine("Ciphertext size: " + ciphertext.Length);
                Console.WriteLine("Ciphertext: " + BitConverter.ToString(ciphertext));

                Key keyCipher = KeyDerivationAlgorithm.HkdfSha256.DeriveKey(secret, seconds, null, ChaCha20Poly1305.ChaCha20Poly1305);

                byte[] plaintext = new byte[ciphertext.Length - ChaCha20Poly1305.ChaCha20Poly1305.TagSize];

                bool decrypt = ChaCha20Poly1305.ChaCha20Poly1305.Decrypt(keyCipher, new Nonce(IV, 0), null, ciphertext, plaintext);
                if (decrypt)
                {
                    Console.WriteLine("Decryption successful, plaintext: " + BitConverter.ToString(plaintext));
                    return File(plaintext, "application/octet-stream");
                }
                else
                {
                    return NotFound();
                }
            }
        }


        public static int GetSeconds()
        {
            DateTime origin = new DateTime(2000, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc);
            TimeSpan diff = DateTime.Now - origin;
            return Convert.ToInt32(Math.Floor(diff.TotalSeconds));
        }

    }
}
