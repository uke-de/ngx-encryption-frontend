# Web Encryption Frontend

The **Web Encryption Frontend** is a browser-based application that can encrypt and decrypt any files in the web browser on the local device.

## Technology

The Web Encryption Frontend is a single page web application based on the Angular framework (version 10). It can be served as a static web page by any web server.

The UI is written in Angular Material.

All cryptographic functions, including encryption, decryption, key generation, generation of the initialization vector, are realized through the [Web Crypto API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API) which is implemented in all modern browsers. The Web Crypto API is a standardized, secure and highly performant interface for cryptographic web applications.

The cryptographic functions are used in accordance to [RFC 7518](https://tools.ietf.org/html/rfc7518) (JSON Web Algorithms (JWA)).


## Components

All code artifacts (source code (.ts), templates (.html), style sheets (.css, .scss, .sass)) are combined into an `EncryptionModule` Angular module.

The cryptographic functions of the Web Crypto API are provided by the `EncryptionService` class. An `EncryptionComponent` will be provided with an instance of an `EncryptionService`.

An `EncryptionComponent` instance can be used either for encryption or decryption (not both). When an application needs to provide both encryption and decryption, it should create two separate `EncryptionComponent` instances which will operate independently from each other. 


## Security

All cryptographic processes are executed in the web client. No data will be sent to the web server or any other system at any time.

Files are encrypted with AES-GCM, a symmetric authenticated encryption method which provides security, authenticity and integrity. The key length is 256 bit.

For each encryption, a new initialization vector (IV) is generated to guarantee the uniqueness of the IV. The IV will be prepended to the encrypted output file. Upon decryption, the first 12 Byte of the encrypted file will be interpreted as the IV.

The downloadable key file contains the key. When the key file is secured with a password, the key will be encrypted by another key derived from the password ("wrapping key"). Otherwise, the key file contains the key in plain text. The key file must be kept safely by the user and secured against unwanted loss or dissemination.

The key file can also be encrypted by an asymmetrical RSA encryption and sent via e-mail. The recipients and their public keys are listed in the `public_keys.json`, which is delivered along with the encryption frontend. By clicking on "Sent key via e-mail", the key is encrypted with the public key of the selected recipient and an e-mail is generated with pre-filled recipient, subject and body. The user can then send the generated e-mail with their e-mail client.

### Technical details

#### Data encryption
* Method as per RFC 7518: `A256GCM`
* Algorithm: AES-GCM
* Key length: 256 bit
* Initialization Vector: 12 Byte
* Encrypted file format: `Initialization Vector (first 12 Byte) + raw encrypted contents`

#### Key file encryption (optional)
##### Password-encrypted
* Method as per RFC 7518: `PBES2-HS512+A256KW`
* Minimum password length: 8 characters
* Key derivation function: PBKDF2 with SHA-512
* Iterations: 100000
* Key wrapping algorithm: AES-KW, 256 bit

##### RSA encrypted
* Method as per RFC 7518: `RSA-OAEP-256`
* Key wrapping algorithm: RSA-OAEP


#### Key file format
* Unencrypted: JSON Web Key (JWK) as per [RFC 7517](https://tools.ietf.org/html/rfc7517)
* Encrypted (with a password or an RSA key): `JWE Protected Header (base64-encoded) as per RFC 7517 + . (period) + raw wrapped key (base64-encoded)`



#### RSA Key generation
##### Generate a new private key with OpenSSL
`openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out my_key`

A minimum key size of 2048 bits must be used as per RFC 7518.

##### Extract public key from private key
`openssl rsa -in my_key -pubout -out my_key.pub`


## Limitations

### File size

The Web Crypto API requires the input and output data to be kept in memory. The maximum file size is set to 2 GB by default to prevent excessive swapping on devices with low amounts of physical memory. The maximum file size can be overridden with the `maxFileSize` attribute of the `EncryptionComponent`.

### Browser compatibility

#### Browser requirements
-	Angular/TypeScript JS compatibility: ES2015
-	Web Crypto API

#### Browser support

* Chrome 44+, Firefox 35+, Opera 31+, Safari 9+, Edge 79+


## Localization

The encryption frontend is available in English and German. Translation will be performed at run-time depending on the browser's locale setting.

This app uses the `$localize` global from `@angular/localize` to perform the run-time localization. Translated messages for all languages are saved as a single JSON file in `l10n/messages.json`. Localization is initialized in `polyfill.ts`.


## License

MIT License. See LICENSE.md.

## Contributions

Code and documentation: Marcus Wurlitzer.

This project is part of the [Hamburg Open Science](https://openscience.hamburg.de/) program.


## Appendix

This project was generated with [Angular CLI](https://github.com/angular/angular-cli) version 9.1.1 and upgraded to Angular version 10.

### Development server

Run `ng serve` for a dev server. Navigate to `http://localhost:4200/`. The app will automatically reload if you change any of the source files.

### Build

Run `ng build` to build the project. The build artifacts will be stored in the `dist/` directory. Use the `--prod` flag for a production build.

### Test

Run `ng test` to run the tests.
