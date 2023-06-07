//#
//# Copyright (C) 2018-2021 QuasarApp.
//# Distributed under the lgplv3 software license, see the accompanying
//# Everyone is permitted to copy and distribute verbatim copies
//# of this license document, but changing it is not allowed.
//#

#include <QByteArray>
#include <qrsaencryption.h>
#include <QDateTime>
#include <qdebug.h>
#include <cmath>
#include <time.h>
#include <iostream>
#include <QCryptographicHash>
#include "qaesencryption.h"

//const int testSize = 20;
static const QMap<QRSAEncryption::Rsa, int > testSize = {
    {QRSAEncryption::RSA_64, 128},
    {QRSAEncryption::RSA_128, 64},
    {QRSAEncryption::RSA_256, 32},
    {QRSAEncryption::RSA_512, 16},
    {QRSAEncryption::RSA_1024, 8},
    {QRSAEncryption::RSA_2048, 4},
    {QRSAEncryption::RSA_3072, 2},
    {QRSAEncryption::RSA_4096, 2},
    {QRSAEncryption::RSA_6144, 1},
    {QRSAEncryption::RSA_8192, 0}
};

QByteArray randomArray(int length = -1) {
    srand(static_cast<unsigned int>(time(nullptr)));
    QByteArray res;

    if (length == -1) {
        length = rand() % 124 * 1;
    }

    for (int i = 0; i < length; ++i) {
        res.push_back(static_cast<char>(rand() % 0xFD) + 1);
    }

    return res;
}

void print(const QString& str) {
    std::cout << str.toStdString() << std::endl;
}

bool checkKeys(const QByteArray& pubKey, const QByteArray& privKey,
               QRSAEncryption::Rsa rsa) {
    QRSAEncryption e(rsa);

    print( QString("Private key: %0").arg(QString(pubKey.toHex())));
    print( QString("Public key: %0").arg(QString(privKey.toHex())));

    if (pubKey.size() != rsa / 4) {
        print("pubKey size wrong RSA" + QString::number(rsa));
        return false;
    }

    if (privKey.size() != rsa / 4) {
        print("privKey size wrong RSA" + QString::number(rsa));
        return false;
    }

    for (int i = 0; i < testSize[rsa]; i++) {
        auto base = randomArray();

        auto encodeData = e.encode(base, pubKey);
        auto decodeData = e.decode(encodeData, privKey);

        if ( base != decodeData) {
            print("encode/decode data error RSA" + QString::number(rsa));
            return false;
        }

        encodeData = e.signMessage(base, privKey);

        if (!e.checkSignMessage(encodeData, pubKey)) {
            print("sig message error RSA" + QString::number(rsa));
            return false;
        }

        encodeData += "work it";

        if (e.checkSignMessage(encodeData, pubKey)) {
            print("sig message error RSA with added value to back" + QString::number(rsa));
            return false;
        }

        encodeData.push_front("not work");

        if (e.checkSignMessage(encodeData, pubKey)) {
            print("sig message error RSA with added value to front" + QString::number(rsa));
            return false;
        }
    }

    return true;
}

bool testGenesis(const QRSAEncryption& e) {
    QByteArray
    pubGenesis1, privGenesis1,
    pubGenesis2, privGenesis2;

    // check genesis
    auto genesis = randomArray(0xFFFF);
    if (!e.generatePairKey(pubGenesis1, privGenesis1, genesis)) {
        print( "Fail to test genesis got generation keys " + QString::number(e.getRsa()));
        return false;
    }

    if (!e.generatePairKey(pubGenesis2, privGenesis2, genesis)) {
        print( "Fail to test genesis got generation keys " + QString::number(e.getRsa()));
        return false;
    }

    return pubGenesis1 == pubGenesis2 && privGenesis1 == privGenesis2;
};

bool testCrypto(QRSAEncryption::Rsa rsa) {

    QByteArray pub, priv;

    QRSAEncryption e(rsa);

    for (int i = 0; i < testSize[rsa]; i++) {

        print(QString("Test RSA-%0 (%1/%2):").arg(rsa).arg(i + 1).arg(testSize[rsa]));

        if (!e.generatePairKey(pub, priv)) {
            print( "key not generated RSA" + QString::number(rsa));
            return false;
        }

        if (!testGenesis(e)) {
            print( "Test genesis failed. RSA" + QString::number(rsa));
            return false;
        }

        if (!checkKeys(pub, priv, rsa)) {
            return false;
        }
    }

    return true;
}

bool testExample() {
    QByteArray pub, priv;
    QRSAEncryption e(QRSAEncryption::Rsa::RSA_2048);
    e.generatePairKey(pub, priv); // or other rsa size
    QString pubHex = QString::fromUtf8( pub.toHex().data() );
    QString privHex = QString::fromUtf8( priv.toHex().data() );
    print( "pubHex:" + pubHex);
    print( "privHex:" + privHex);

    QByteArray msg = "test message";

    auto signedMessage = e.signMessage(msg, priv);

    if (e.checkSignMessage(signedMessage, pub)) {
        print(" message signed success");
        return true;
    }

    return false;

}



bool testExample2() {
    QString privateKeyHexString ="0146050a344f21fd19af746a5560f174593aa053628cee3d035cac300dd9c37218b1469b5d9835dca0cef0cd8b559cb5c54dd47955ed7d4fce988fc6f2a90b5bbb21b8196a752af3153a3ecb7366af5f7ca3a455fd65fafb81f8c5680be5a4738aff15457c82527808d474f09b8f45abbbabf4156b3c45de160525865038d0c6693659ec83eb04f36d6bb61ed3ef0345c1d27e3ba2ebcc0be0d14a71f66454e428c30e766998750c1261758637524c64be5081c1e5b01de98699cfc77695d2feb0280e1adff8f6b8291a184c7ca5f8b9fe842d0b6c02013710a968cdc0d51496666fada7c76c62ef659a09e8178194d087fc590324eaaae8e4a96d732c7eecad0f6093f7ff25e0943eb7482cbfffb1834b82166d90a263f9aecb48e1aaaa7551f28df99afaa3bffabe60b97eb251c3153d4b2ab8cbb405fd336a11cd6144caafdaa7dec8038553009e0d0dfdea6732d7a2c03fe42da5ab72647b6853140ab74b3c9f252469891bfebcb8a16f67ed1f67f2c87c4e54a2e9d10f3c81ac98cfc072609a69438c234bb73cbb44d6fc95feb63276ed597d3c7bdc3cea8ea461e09895d3bf83d0a148a213a00f6ebc2e8ae6540d4b2e8df47a64fdd82cce4f3a79771c86051309142d88efb1c1706865bb07a8eefe2914d242581e671bbd25bb3bfcc2bf94387b5b25172aa587f17a2bf7fcfcab89fe7f3ca8523320f7ffae4a1179af";
    QByteArray priv = QByteArray::fromHex(privateKeyHexString.toUtf8());

    qDebug() << "priv Hex: " << QString(priv.toHex());

    QString publicKeyHexString ="007d5a9553241327d95ff3542bbb809f165123858133f19d985a1aa2820dd7d9bf82d6b6b4c27cc3b4ac3388cbc56702c454ad778f284a0119c3ff8f73d159571dee70390e0c8f6779f4bd22c744869e982574143c78e73da265900ae9af54e036147c9b219b7fc72b08d1fc475dc3b5a4b9c7531a05c2e9a9dd4e232eb49b07b70597509884d0a623f892d0205e5eee35af2a25745ca2ce9042ec4ca4e86c12a4312bf8ee4036ccd8210fcfbeb94ae4dad1ad1402d6ca882bf1051d331e8d54ead8d4e19cb71e151bb80a6476b5ac60a62095ce31134e213304b0a9ac448c57a8838c153a81123d4ddc8e179466930819483f7128aefca408e588c7f7faeaed0f6093f7ff25e0943eb7482cbfffb1834b82166d90a263f9aecb48e1aaaa7551f28df99afaa3bffabe60b97eb251c3153d4b2ab8cbb405fd336a11cd6144caafdaa7dec8038553009e0d0dfdea6732d7a2c03fe42da5ab72647b6853140ab74b3c9f252469891bfebcb8a16f67ed1f67f2c87c4e54a2e9d10f3c81ac98cfc072609a69438c234bb73cbb44d6fc95feb63276ed597d3c7bdc3cea8ea461e09895d3bf83d0a148a213a00f6ebc2e8ae6540d4b2e8df47a64fdd82cce4f3a79771c86051309142d88efb1c1706865bb07a8eefe2914d242581e671bbd25bb3bfcc2bf94387b5b25172aa587f17a2bf7fcfcab89fe7f3ca8523320f7ffae4a1179af";
    QByteArray pub = QByteArray::fromHex(publicKeyHexString.toUtf8());

    qDebug() << "pub Hex: " << QString(pub.toHex());

    QRSAEncryption e(QRSAEncryption::Rsa::RSA_2048);
    QString pubHex = QString::fromUtf8( pub.toHex().data() );
    QString privHex = QString::fromUtf8( priv.toHex().data() );
    qDebug() << "pubHex:" << pubHex;
    qDebug() << "privHex:" << privHex;


    QByteArray msg = "Test message of encrypkey";
    QByteArray hash = QCryptographicHash::hash(msg, QCryptographicHash::Sha256);
    qDebug() << "hash: " << hash.toHex();


    // encoded 51
    QString encodedString ="3031300d060960864801650304020105000420";
    QByteArray encodedPrefix = QByteArray::fromHex(encodedString.toUtf8());
    QByteArray encoded = encodedPrefix.append(hash);
    // padding 256
    QString padV15String = "0001ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff00";
    QByteArray padV15 = QByteArray::fromHex(padV15String.toUtf8());
    padV15 = padV15.append(encoded);
    qDebug() << "padV15: " << padV15.toHex() << " len: " << padV15.length();


    auto encryptMessage = e.encode(hash, priv, QRSAEncryption::Auto);
    qDebug() << "encryptMessage: " << encryptMessage.toHex() << " len: " << encryptMessage.length();

    auto decryptMessage = e.decode(encryptMessage, pub, QRSAEncryption::Auto);
    qDebug() << "decryptMessage: " << decryptMessage.toHex() << " len: " << decryptMessage.length();


    auto signedMessage = e.signMessageJava(msg, priv, QRSAEncryption::Auto);
    qDebug() << "signed: " << QString(signedMessage.toHex());


    if (e.checkSignMessageJava(msg, signedMessage, pub, QRSAEncryption::Auto)) {
        print(" message signed success");
        return true;
    } else {
        print(" message signed failed");
        return false;
    }
}

bool testExample3() {
    QString privateKeyHexString ="0146050a344f21fd19af746a5560f174593aa053628cee3d035cac300dd9c37218b1469b5d9835dca0cef0cd8b559cb5c54dd47955ed7d4fce988fc6f2a90b5bbb21b8196a752af3153a3ecb7366af5f7ca3a455fd65fafb81f8c5680be5a4738aff15457c82527808d474f09b8f45abbbabf4156b3c45de160525865038d0c6693659ec83eb04f36d6bb61ed3ef0345c1d27e3ba2ebcc0be0d14a71f66454e428c30e766998750c1261758637524c64be5081c1e5b01de98699cfc77695d2feb0280e1adff8f6b8291a184c7ca5f8b9fe842d0b6c02013710a968cdc0d51496666fada7c76c62ef659a09e8178194d087fc590324eaaae8e4a96d732c7eecad0f6093f7ff25e0943eb7482cbfffb1834b82166d90a263f9aecb48e1aaaa7551f28df99afaa3bffabe60b97eb251c3153d4b2ab8cbb405fd336a11cd6144caafdaa7dec8038553009e0d0dfdea6732d7a2c03fe42da5ab72647b6853140ab74b3c9f252469891bfebcb8a16f67ed1f67f2c87c4e54a2e9d10f3c81ac98cfc072609a69438c234bb73cbb44d6fc95feb63276ed597d3c7bdc3cea8ea461e09895d3bf83d0a148a213a00f6ebc2e8ae6540d4b2e8df47a64fdd82cce4f3a79771c86051309142d88efb1c1706865bb07a8eefe2914d242581e671bbd25bb3bfcc2bf94387b5b25172aa587f17a2bf7fcfcab89fe7f3ca8523320f7ffae4a1179af";
    QByteArray priv = QByteArray::fromHex(privateKeyHexString.toUtf8());

    //qDebug() << "priv Hex: " << QString(priv.toHex());

    QString publicKeyHexString ="007d5a9553241327d95ff3542bbb809f165123858133f19d985a1aa2820dd7d9bf82d6b6b4c27cc3b4ac3388cbc56702c454ad778f284a0119c3ff8f73d159571dee70390e0c8f6779f4bd22c744869e982574143c78e73da265900ae9af54e036147c9b219b7fc72b08d1fc475dc3b5a4b9c7531a05c2e9a9dd4e232eb49b07b70597509884d0a623f892d0205e5eee35af2a25745ca2ce9042ec4ca4e86c12a4312bf8ee4036ccd8210fcfbeb94ae4dad1ad1402d6ca882bf1051d331e8d54ead8d4e19cb71e151bb80a6476b5ac60a62095ce31134e213304b0a9ac448c57a8838c153a81123d4ddc8e179466930819483f7128aefca408e588c7f7faeaed0f6093f7ff25e0943eb7482cbfffb1834b82166d90a263f9aecb48e1aaaa7551f28df99afaa3bffabe60b97eb251c3153d4b2ab8cbb405fd336a11cd6144caafdaa7dec8038553009e0d0dfdea6732d7a2c03fe42da5ab72647b6853140ab74b3c9f252469891bfebcb8a16f67ed1f67f2c87c4e54a2e9d10f3c81ac98cfc072609a69438c234bb73cbb44d6fc95feb63276ed597d3c7bdc3cea8ea461e09895d3bf83d0a148a213a00f6ebc2e8ae6540d4b2e8df47a64fdd82cce4f3a79771c86051309142d88efb1c1706865bb07a8eefe2914d242581e671bbd25bb3bfcc2bf94387b5b25172aa587f17a2bf7fcfcab89fe7f3ca8523320f7ffae4a1179af";
    QByteArray pub = QByteArray::fromHex(publicKeyHexString.toUtf8());

    //qDebug() << "pub Hex: " << QString(pub.toHex());

    QRSAEncryption e(QRSAEncryption::Rsa::RSA_2048);
    QString pubHex = QString::fromUtf8( pub.toHex().data() );
    QString privHex = QString::fromUtf8( priv.toHex().data() );
    //qDebug() << "pubHex:" << pubHex;
    //qDebug() << "privHex:" << privHex;


    QByteArray msg = "Test message of encrypkey";
    QString signedHexString ="0d8a8b53bbe5730336f8b98f8f5185bb51ab4dc4e54fb64cf7b45366122a93f8ca397997c88ebc862fb90f9b559b2d87bd41792e004816d548707ee630234f68fba722c2cb9d96f1cb9546c2b63e75515ef33d52d41deaeaf5e201cd55d89c8c6a4490aa88838ebb63684c5afa31c90ef1fe4d45e9dd20db892b84b885370d686fe102fc51dbe3fcc9a5da01068bd34cc0be1709ef6b5352c6fc3a6ae3f0ac8b7d8b9a537ac1f8f1540d9b49e793412ff3250d0a12f9044e986f5eaecd3e0bc3ca20d9023c80f6085af0cf0ac2d54932890c68f03efcee299ba3475b0afbcc876ce9d11d1f85574859e480b06ad0cc5f2332eb239e3fe9d2f82e6aa9ec559515";
    QByteArray signedMessage = QByteArray::fromHex(signedHexString.toUtf8());
    qDebug() << "signedMessage:" << signedHexString;
    if (e.checkSignMessagePKCS15(msg, signedMessage, pub, QRSAEncryption::Auto)) {
        print(" message signed success");
        return true;
    } else {
        print(" message signed failed");
        return false;
    }
}

bool testGetKeyRsaType() {
    print("Check GetKeyRsaType function");

    QByteArray pub, priv;
    QRSAEncryption e(QRSAEncryption::Rsa::RSA_512);
    e.generatePairKey(pub, priv); // or other rsa size

    QByteArray invalidKey, validSizeKey;

    invalidKey = randomArray();

    validSizeKey = randomArray(
                static_cast<int>(
                    QRSAEncryption::getKeyBytesSize(QRSAEncryption::Rsa::RSA_512)));

    if (QRSAEncryption::getKeyRsaType(pub) != QRSAEncryption::Rsa::RSA_512) {
        return false;
    }

    if (QRSAEncryption::getKeyRsaType(priv) != QRSAEncryption::Rsa::RSA_512) {
        return false;
    }

    if (QRSAEncryption::getKeyRsaType(invalidKey) != QRSAEncryption::Rsa::Invalid) {
        return false;
    }
    print("success");
    return true;
}

bool testEncryptAndDecryptExample() {

    QByteArray pub, priv;
    QRSAEncryption e(QRSAEncryption::Rsa::RSA_2048);
    e.generatePairKey(pub, priv); // or other rsa size

    QByteArray msg = "test message";

    auto encryptMessage = e.encode(msg, pub);

    if (encryptMessage == msg)
        return false;

    auto decodeMessage = e.decode(encryptMessage, priv);

    return decodeMessage == msg;
}

bool testEncryptAndDecryptAESExample() {

    print("Begin test AES alghoritms");

    QAESEncryption encryption(QAESEncryption::AES_256, QAESEncryption::CBC);

    QString inputStr("The Advanced Encryption Standard (AES), also known by its original name Rijndael "
                     "is a specification for the encryption of electronic data established by the U.S. "
                    "National Institute of Standards and Technology (NIST) in 2001");
    QString key("your-string-key");
    QString iv("your-IV-vector");

    QByteArray hashKey = QCryptographicHash::hash(key.toLocal8Bit(), QCryptographicHash::Sha256);
    QByteArray hashIV = QCryptographicHash::hash(iv.toLocal8Bit(), QCryptographicHash::Md5);

    QByteArray encodeText = encryption.encode(inputStr.toLocal8Bit(), hashKey, hashIV);
    QByteArray decodeText = encryption.decode(encodeText, hashKey, hashIV);

    QString decodedString = QString(encryption.removePadding(decodeText));

    if (decodedString != inputStr)
        return false;

    print("AES test finished successful");
    return true;
}

int main() {

    if (!testGetKeyRsaType()) {
        return 1;
    }

    if(!testExample()) {
        return 1;
    }

    if (!testEncryptAndDecryptExample()) {
        return 1;
    }

    if (!testEncryptAndDecryptAESExample()) {
        return 1;
    }

    for (auto testCase = testSize.begin(); testCase != testSize.end(); ++testCase) {
        if(!testCrypto(testCase.key())) {
            return 1;
        }
    }

    print("Tests passed successfully");

    return 0;
}
