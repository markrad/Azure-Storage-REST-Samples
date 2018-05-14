# List-Blobs
This sample demonstrates how to call the Azure Storage REST API to list the blobs within a storage container. 

https://docs.microsoft.com/en-us/rest/api/storageservices/list-blobs

To run the sample you will need a development cURL package and OpenSSL. These can be installed on Windows but I have only tested it on Linux.

To build and run this code:
```
git clone https://github.com/markrad/Azure-Storage-REST-Samples.git
cd Azure-Storage-REST-Samples\List-Blobs
```
Edit main.cpp to add your storage key and storage account name.
```
mkdir cmake
cd cmake
cmake ..
make
./listblobs
```

