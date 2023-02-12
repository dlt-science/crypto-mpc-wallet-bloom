find_package(PkgConfig REQUIRED)
#set(OPENSSL_USE_STATIC_LIBS TRUE)
find_package(OpenSSL REQUIRED)
set(CMAKE_PREFIX_PATH "${CMAKE_PREFIX_PATH};/Users/parshantsingh/projects/safeheron-crypto-suites-cpp/")
set(SafeheronCryptoSuites_DIR "/Users/parshantsingh/projects/safeheron-crypto-suites-cpp/build")
find_package(SafeheronCryptoSuites REQUIRED)

add_library(${CMAKE_PROJECT_NAME} SHARED
        crypto-tss-rsa/RSAPrivateKeyShare.cpp
        crypto-tss-rsa/RSAPublicKey.cpp
        crypto-tss-rsa/RSAKeyMeta.cpp
        crypto-tss-rsa/RSASigShare.cpp
        crypto-tss-rsa/KeyGenParam.cpp
        crypto-tss-rsa/RSASigShareProof.cpp
        crypto-tss-rsa/tss_rsa.cpp
        crypto-tss-rsa/emsa_pss.cpp
        crypto-tss-rsa/proto_gen/tss_rsa.pb.switch.cc
        )

target_include_directories(${CMAKE_PROJECT_NAME} PRIVATE
        ${SafeheronCryptoSuites_INCLUDE_DIRS}
        ${OPENSSL_INCLUDE_DIR}
        /usr/local/include
        )

target_link_directories(${CMAKE_PROJECT_NAME} PRIVATE /usr/local/lib)

target_link_libraries(${CMAKE_PROJECT_NAME}
        SafeheronCryptoSuites
        OpenSSL::Crypto
        -ldl
        )
