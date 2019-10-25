using System;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using NSec.Cryptography;

namespace EncryptionService.Controllers
{
    [Route("api/")]
    [ApiController]
    public class EncryptionController : ControllerBase
    {
        readonly byte[] motherKey;


        public EncryptionController()
        {
            String[] arguments = Environment.GetCommandLineArgs();
            Console.WriteLine("Reading mother key from: " + arguments[1]);
            string key = System.IO.File.ReadAllText(arguments[1]);
            Console.WriteLine("Mother key: " + key);
            motherKey = Encoding.ASCII.GetBytes(key);
            Console.WriteLine("Key bytes: " + BitConverter.ToString(motherKey));
        }


        // GET api/
        [HttpGet]
        public ActionResult<string> Get()
        {
            return "It's working!";
        }


        public byte[] encrypt(byte[] plaintext)
        {
            Console.WriteLine("Plaintext: " + BitConverter.ToString(plaintext));
            Console.WriteLine("Plaintext size: " + plaintext.Length);

            int sec = GetSeconds();
            Console.WriteLine("Seconds: " + sec);
            byte[] seconds = BitConverter.GetBytes(sec);
            Console.WriteLine("Seconds size: " + seconds.Length);


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

            return result;
        }


        // POST api/encryptFile
        [HttpPost]
        [Route("encryptFile")]
        public async Task<ActionResult> EncryptFile()
        {
            using (var stream = new MemoryStream())
            {
                await Request.Body.CopyToAsync(stream);
                byte[] plaintext = stream.ToArray();

                byte[] result = encrypt(plaintext);
                Console.WriteLine("Result: " + BitConverter.ToString(result));

                return File(result, "application/octet-stream");
            }
        }


        // POST api/encryptString
        [HttpPost]
        [Route("encryptString")]
        public async Task<String> EncryptString()
        {
            using (var stream = new MemoryStream())
            {
                await Request.Body.CopyToAsync(stream);
                byte[] plaintext = stream.ToArray();

                byte[] result = encrypt(plaintext);

                Console.WriteLine("Result: " + BitConverter.ToString(result));
                Console.WriteLine("Result in base64: " + Convert.ToBase64String(result));
                return Convert.ToBase64String(result);
            }
        }


        public byte[] decrypt(byte[] data)
        {
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
                return plaintext;
            }
            else
            {
                Console.WriteLine("Decryption unsuccessful");
                return null;
            }
        }


        // POST api/decryptFile
        [HttpPost]
        [Route("decryptFile")]
        public async Task<ActionResult> DecryptFile()
        {
            using (var stream = new MemoryStream())
            {
                await Request.Body.CopyToAsync(stream);
                byte[] data = stream.ToArray();

                byte[] plaintext = decrypt(data);
                if (plaintext != null)
                {
                    return File(plaintext, "application/octet-stream");
                }
                else
                {
                    return NotFound();
                }
            }
        }

        // POST api/decryptString
        [HttpPost]
        [Route("decryptString")]
        public async Task<ActionResult> DecryptString()
        {
            using (var stream = new StreamReader(Request.Body))
            {
                string content = await stream.ReadToEndAsync();
                Console.WriteLine("Content in base64: " + content);
                byte[] data = Convert.FromBase64String(content);
                Console.WriteLine("Content: " + BitConverter.ToString(data));

                byte[] plaintext = decrypt(data);
                if (plaintext != null)
                {
                    Console.WriteLine("Plaintext: " + Encoding.UTF8.GetString(plaintext));
                    return Content(Encoding.UTF8.GetString(plaintext));
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
