echo "Compression task started!"
./hw3.o -c /usr/src/hw3-cse506g02/hw3/test/output/large_compress_output.txt /usr/src/hw3-cse506g02/hw3/test/input/large_input1.txt
echo "Compression task ended!"
echo "Decompression task started!"
./hw3.o -d /usr/src/hw3-cse506g02/hw3/test/output/large_decompress_output.txt /usr/src/hw3-cse506g02/hw3/test/output/large_compress_output.txt
echo "Decompression task ended!"
echo "Running diff of the input of compression and output of decompression!"
diff /usr/src/hw3-cse506g02/hw3/test/input/large_input1.txt /usr/src/hw3-cse506g02/hw3/test/output/large_decompress_output.txt



