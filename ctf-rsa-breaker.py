import sys, getopt, os
import requests
import struct, codecs
from Crypto.PublicKey import RSA

# Reads and checks input parameters.
def read_input(argv):
   usage = "ctf-rsa-breaker.py -p|--pubKey <public_key_file> -e|--encFile <encrypted_file> -o|--out <output_file>"
   public_key = None
   encrypted_file = None
   output_file = None
   
   try:
      opts, args = getopt.getopt(argv,"hp:e:o:",["pubKey=", "encFile=", "out="])
   except getopt.GetoptError:
      print usage
      sys.exit(2)
      
   if len(opts) < 1:
      print usage
      sys.exit(2)
	  
   for opt, arg in opts:
      if opt in ("-h", "--help"):
         print usage
         sys.exit()
      elif opt in ("-p", "--pubKey"):
         check_file_parameter(opt, arg)
         public_key = arg.strip()
      elif opt in ("-e", "-encFile"):
         check_file_parameter(opt, arg)
         encrypted_file = arg.strip()
      elif opt in ("-o", "--out"):
         check_filename_parameter(opt, arg)
         output_file = arg.strip()

   return public_key, encrypted_file, output_file

# Checks if a passed parameter is really a file.
def check_file_parameter(parameter_key, parameter_value):
   check_filename_parameter(parameter_key, parameter_value)
   print "[*] Input file of '{}' is: '{}'.".format(parameter_key, parameter_value.strip())
   
   if not os.path.isfile(parameter_value):
      print "[!] Input file of '{}' provided is not a file!".format(parameter_key)
      sys.exit(2)

# Checks if a passed parameter is a valid a filename.
def check_filename_parameter(parameter_key, parameter_value):
   if parameter_value is None or len(parameter_value.strip()) < 1:
      print "[!] The input file name of '{}' can not be empty!".format(parameter_key)
      sys.exit(2)

# Analyzes the public key file to get modulus and exponent.
def analyze_public_key(public_key):
   print "[*] Analyzing public key file."
   
   with open(public_key, "r") as public_key_file:
      public_key_string = public_key_file.read()
   print public_key_string
   
   key = RSA.importKey(public_key_string)
   modulus = key.n
   exponent = key.e
   print "[*] Modulus ....: {}".format(modulus)
   print "[*] Exponent ...: {}".format(exponent)
   
   return modulus, exponent

# Factorizes the modulus using a remote service.
def factorize_modulus(modulus):
   print "[*] Factorizing modulus."
   
   remote_service = "http://factordb.com/api"
   print "[*] Contacting service: {}.".format(remote_service)
   response = requests.get(remote_service, params={"query": str(modulus)}).json()
   
   if response is not None and len(response["factors"]) != 2:
      print "[!] {} factors returned.".format(len(response["factors"]))
      sys.exit(2)

   p = int(response["factors"][0][0])
   q = int(response["factors"][1][0])
   print "[*] p ..........: {}".format(p)
   print "[*] q ..........: {}".format(q)
   
   return p, q

# Computes value for decrypt operation.
def compute_values(exponent, p, q):
   print "[*] Computing values."
   
   # Compute phi(n).
   phi = (p - 1) * (q - 1)
   print "[*] phi ........: {}".format(phi)

   # Compute modular inverse of e.
   gcd, a, b = egcd(exponent, phi)
   d = a
   print "[*] d ..........: {}".format(d)
   
   return d

# Modular inverse.
def egcd(a, b):
   x,y, u,v = 0,1, 1,0
   while a != 0:
      q, r = b//a, b%a
      m, n = x-u*q, y-v*q
      b,a, x,y, u,v = a,r, u,v, m,n
      gcd = b
   return gcd, x, y

# Decrypting the encrypted file.
def decrypt(encrypted_file, modulus, d):
   print "[*] Decrypting."
   
   # Reading file to decrypt.
   content_to_decrypt = 0
   with open(encrypted_file, "rb") as f:
    byte = f.read(1)
    while byte != "":
       content_to_decrypt = (content_to_decrypt << 8) | struct.unpack(">H", "\x00" + byte)[0]
       byte = f.read(1)
   
   print "[*] Encrypted content (numeric):"
   print hex(content_to_decrypt)
   
   # Decrypt operation.
   plain_content = pow(content_to_decrypt, d, modulus)

   print "[*] Decrypted content (numeric):"
   print hex(plain_content)
   print "[*] Decrypted content (ASCII):"
   print codecs.decode(str(hex(plain_content)).replace("0x", "").replace("L", ""), "hex")

   return plain_content

# Writes decrypted file.
def write_plain_file(plain_content, output_file):
   print "[*] Writing decrypted file."
   
   # Reading bytes and setting the right order.
   bytes_to_write = []
   while plain_content != 0:
      byte = extract_bits(plain_content, 8, 1)
      bytes_to_write.append(byte)
      plain_content = plain_content >> 8
   bytes_to_write.reverse()
   
   # Writing file.
   with open(output_file, 'wb') as f:
      f.write(bytearray(bytes_to_write))

# Function to extract k bits from p position  
# and returns the extracted value as integer.
def extract_bits(number, k, p):    
   return ( ((1 << k) - 1)  &  (number >> (p-1) ) ); 

# Main execution.
if __name__ == "__main__":
   print "CTF RSA Breaker - v1.0 (2019-01-28)"
   try:
      public_key, encrypted_file, output_file = read_input(sys.argv[1:])
      modulus, exponent = analyze_public_key(public_key)
      p, q = factorize_modulus(modulus)
      d = compute_values(exponent, p, q)
      plain_content = decrypt(encrypted_file, modulus, d)
      write_plain_file(plain_content, output_file)
   except KeyboardInterrupt:
      print "[-] Interrupted!"
   except:
      print "[!] Unexpected exception: {}".format(sys.exc_info()[0])
   print "Finished."