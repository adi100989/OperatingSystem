echo "Encryption task started!"
./hw3.o -x qwerty /usr/src/hw3-cse506g02/hw3/test/output/large_encrypt_output.txt /usr/src/hw3-cse506g02/hw3/test/input/large_input1.txt
echo "Encryption task ended!"
echo "Decryption task started!"
./hw3.o -y qwerty /usr/src/hw3-cse506g02/hw3/test/output/large_encrypt_input.txt /usr/src/hw3-cse506g02/hw3/test/output/large_encrypt_output.txt
echo "Decryption task ended!"
echo "Running diff of the input of encryption and output of decryption!"
diff /usr/src/hw3-cse506g02/hw3/test/input/large_input1.txt /usr/src/hw3-cse506g02/hw3/test/output/large_encrypt_input.txt



