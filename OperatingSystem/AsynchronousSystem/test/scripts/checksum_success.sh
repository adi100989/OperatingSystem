echo "Checksum task started!"
./hw3.o -k /usr/src/hw3-cse506g02/hw3/test/output/small_checksum_output.txt /usr/src/hw3-cse506g02/hw3/test/input/small_input1.txt
echo "Checksum task ended!"
echo "Checksum calculated is: "
cat /usr/src/hw3-cse506g02/hw3/test/output/small_checksum_output.txt
echo ""
echo "Checksum given by md5sum command is: "
md5sum /usr/src/hw3-cse506g02/hw3/test/input/small_input1.txt


