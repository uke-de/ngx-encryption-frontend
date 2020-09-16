import {FileReaderTools, IProgressUpdate} from './file-reader-tools';
import {JsonObject} from "@angular/compiler-cli/ngcc/src/packages/entry_point";
import {PublicKeyItem} from "../app/app.component";
import { Injectable } from "@angular/core";


export enum EncryptMode {
  Encrypt,
  Decrypt
}

export enum Steps {
  Idle,
  Loading,
  Encrypting,
  Finished,
  Error
}

enum WrappingMode {
  Password,
  Key
}

interface WrappingParams {
  mode: WrappingMode
}

interface PasswordWrappingParams extends WrappingParams {
  mode: WrappingMode.Password
  password: string;
  salt?: Uint8Array | ArrayBuffer;
}

interface KeyWrappingParams extends WrappingParams {
  mode: WrappingMode.Key
  key: CryptoKey;
}


export interface IStepUpdate {
  (step: Steps) : void;
}


export class WrongPasswordError extends Error {
  constructor(m?: string) {
    super(m);
    Object.setPrototypeOf(this, WrongPasswordError.prototype);
  }
}


export class WrongWrappingKeyError extends Error {
  constructor(m?: string) {
    super(m);
    Object.setPrototypeOf(this, WrongWrappingKeyError.prototype);
  }
}


export class WrappingKeyImportError extends Error {
  constructor(m?: string) {
    super(m);
    Object.setPrototypeOf(this, WrappingKeyImportError.prototype);
  }
}






/**
 * Encryption parameter constants are provided here for convenience.
 * They are NOT meant to be user-configurable and may not be changed independently of the
 * EncryptionServiceTools class because implementation details may differ depending on the chosen algorithm(s).
 */
abstract class EncryptionConfiguration {

  /// Algorithm to use for file encryption
  static readonly Algorithm     = 'AES-GCM';
  static readonly KeyLength     = 256;
  static readonly IvLength      = 12;
  /// Name of the encryption algorithm per RFC 7518
  static readonly AlgorithmName = 'A256GCM';

  /// Algorithms to use for key wrapping with a password
  static readonly KeyWrapAlgorithm      = 'AES-KW';
  static readonly KeyWrapKeyLength      = 256;
  static readonly KeyWrapKDF            = 'PBKDF2';
  static readonly KeyWrapHMAC           = 'SHA-512';

  /// "A Salt Input value containing 8 or more octets MUST be used." (RFC 7518)
  static readonly KeyWrapSaltLength     = 16;

  /// Number of iterations of the HMAC function (a minimum of 1000 is recommended per RFC 7518)
  static readonly KeyWrapHMACIterations = 100000;

  /// Name of the key wrapping algorithm per RFC 7518
  static readonly KeyWrapAlgorithmName  = 'PBES2-HS512+A256KW';


  /// Algorithms to use for key wrapping with an RSA key
  static readonly RSAWrapAlgorithm     = 'RSA-OAEP';
  static readonly RSAWrapHash          = 'SHA-256';
  static readonly RSAPublicKeyFormat   = 'spki';
  static readonly RSAPrivateKeyFormat  = 'pkcs8';

  /// Name of the key wrapping algorithm for RSA encryption of the key per RFC 7518
  static readonly RSAWrapAlgorithmName = 'RSA-OAEP-256';

  /// Max File size which will be reported by the EncryptionService.
  /// See comment on EncryptionService.maxFileSize for details.
  static readonly maxFileSize = 2 * 1024 * 1024 * 1024;
}


@Injectable()
export class EncryptionService {

  /**
   * Maximum suggested file size for encryption and decryption. Currently a fixed value.
   * This is a "soft limit" which will not be enforced EncryptionService, but a front end
   * (e. g. EncryptionComponent) may decide to reject any files larger than this.
   *
   * Since the maximum file size is system-dependent, this function could be implemented in a system-specific manner,
   * e. g. by querying navigator.deviceMemory, but not all browsers support it.
   */
  get maxFileSize(): number { return EncryptionConfiguration.maxFileSize; }

  static readonly IvLength = EncryptionConfiguration.IvLength;

  private _fileObj: File;
  private _plainContents: ArrayBuffer;
  private _encryptedContents: ArrayBuffer;

  get fileObj(): File { return this._fileObj; }
  set fileObj(value: File) { this._fileObj = value; }

  get plainContents(): ArrayBuffer { return this._plainContents; }
  get encryptedContents(): ArrayBuffer { return this._encryptedContents; }


  private _key: CryptoKey;
  get key(): CryptoKey { return this._key; }

  private _iv: ArrayBuffer;


  readonly EncryptionAlgorithm = EncryptionConfiguration.Algorithm.split('-')[0];
  readonly EncryptionKeyLength = EncryptionConfiguration.KeyLength;


  constructor() {
  }

  /**
   * Clears the input and output buffers.
   */
  clearContents() {
    this._plainContents = null;
    this._encryptedContents = null;
  }

  /**
   * Reads the input file into plainContents (mode == EncryptMode.Encrypt) or encryptedContents (mode == EncryptMode.Decrypt).
   * For decrypting, the first `EncryptionConfiguration.IvLength` bytes will be read into the IV
   *
   * @param mode Mode of operation, either EncryptMode.Encrypt or EncryptMode.Decrypt
   * @param progressCallback Callback function to report the current progress to
   */
  private async readFile(mode: EncryptMode, progressCallback?: IProgressUpdate) {

    let filebuf = await FileReaderTools.readFileAsArrayBufferAsync(this._fileObj, progressCallback);

    if (mode == EncryptMode.Encrypt) {
      this._plainContents = filebuf;
      this._encryptedContents = null;
    }

    else if (mode == EncryptMode.Decrypt) {
      if (filebuf.byteLength < EncryptionConfiguration.IvLength) {
        throw new Error('Input file too small - invalid encrypted file.');
      }

      this._plainContents = null;
      this._encryptedContents = filebuf.slice(EncryptionConfiguration.IvLength);

      this._iv = filebuf.slice(0, EncryptionConfiguration.IvLength);
    }
  }

  /**
   * Imports a keyfile in JWT format into this.key
   * Exceptions will pass-through from called functions
   * @param file
   * @param password
   * @param wrappingkeyfile
   */
  async importKey(file: File, password?: string, wrappingkeyfile?: File) {
    // importKeyFromFile may throw an error, which will be passed-through
    let newkey = await EncryptionServiceTools.importKeyFromFile(file, password, wrappingkeyfile);

    if (!newkey) throw new Error('Import of keyfile failed.');

    this._key = newkey;
  }


  /**
   * Generates a new key and saves it into this.key
   */
  async generateKey() {
    this._key = await EncryptionServiceTools.generateKey();
  }

  async exportKeyString(hashed = false, length = Infinity) {
    let exported = (await this.exportKeyJWK()).k;

    if (hashed) exported = await EncryptionServiceTools.sha256(exported);

    return exported.substr(0, length);
  }

  async exportKeyJWK() {
    return EncryptionServiceTools.exportKey(this._key);
  }

  async exportKeyJWKString() {
    return EncryptionServiceTools.exportKeyString(this._key);
  }

  /**
   * Export JWK as string and base-64 encode the output. Currently unused in favor of exportKeyJWKString,
   * where the keyfile is human-readable, so plain-text keyfiles can be clearly distinguished from encrypted key files.
   */
  async exportKeyJWKSeralized() {
    return EncryptionServiceTools.exportKeySerialized(this._key);
  }

  /**
   * Wraps the encryption key `this._key` with a wrapping key derived from the given password
   * and exports the wrapped key as a JSON (JWK) string.
   * This method generates a new salt on every call.
   * This method will be called by `downloadKey(password)` when password != null. It can also be used directly when needed.
   * Password strength is NOT enforced by this method.
   * Throws pass-through Exceptions.
   * @param wrappingParams PasswordWrappingParams | KeyWrappingParams. Password to derive the wrapping key from or the wrapping key directly.
   */
  async exportKeyEncryptedSerialized(wrappingParams: WrappingParams) {
    let wrappingKey;

    if (wrappingParams.mode == WrappingMode.Password) {

      (wrappingParams as PasswordWrappingParams).salt = self.crypto.getRandomValues(new Uint8Array(EncryptionConfiguration.KeyWrapSaltLength));

      wrappingKey = await EncryptionServiceTools.deriveKeyFromPassword(
        (wrappingParams as PasswordWrappingParams).password,
        (wrappingParams as PasswordWrappingParams).salt,
        EncryptionConfiguration.KeyWrapHMACIterations);
    }


    if (wrappingParams.mode == WrappingMode.Key) {
      wrappingKey = (wrappingParams as KeyWrappingParams).key;
    }


    const encryptedKey = (await EncryptionServiceTools.wrapKey(this._key, wrappingKey, wrappingParams.mode));

    return EncryptionServiceTools.exportWrappedRawKeySerialized(encryptedKey, wrappingParams);
  }




  /**
   * Encrypts the given file with the loaded key. Alias for encryptOrDecrypt(..., EncryptMode.Encrypt, ... )
   * @param file
   * @param stepCallback
   * @param progressCallback
   */
  async encrypt(file: File, stepCallback?: IStepUpdate, progressCallback?: IProgressUpdate) {
    return this.encryptOrDecrypt(file, EncryptMode.Encrypt, stepCallback, progressCallback);
  }

  /**
   * Decrypts the given file with the loaded key. Alias for encryptOrDecrypt(..., EncryptMode.Decrypt, ... )
   * @param file
   * @param stepCallback
   * @param progressCallback
   */
  async decrypt(file: File, stepCallback?: IStepUpdate, progressCallback?: IProgressUpdate) {
    return this.encryptOrDecrypt(file, EncryptMode.Decrypt, stepCallback, progressCallback);
  }

  /**
   * Encrypts or decrypts the given file with the loaded key.
   * @param file
   * @param mode
   * @param stepCallback
   * @param progressCallback
   */
  async encryptOrDecrypt(file: File,
                         mode: EncryptMode,
                         stepCallback: IStepUpdate = () => {},
                         progressCallback: IProgressUpdate = () => {}) {

    if (!file) throw new Error('No input file specified.');
    if (!this._key) throw new Error('No key specified.');

    this._fileObj = file;

    stepCallback(Steps.Loading);
    progressCallback(0);

    try {
      await this.readFile(mode, progressCallback);
    }
    catch (e) {
      stepCallback(Steps.Error);
      throw new Error('Error: ' + e.message);
    }

    stepCallback(Steps.Encrypting);
    // No progress can be reported for encrypting, so we report -1 ('indeterminate')
    progressCallback(-1);

    if (mode == EncryptMode.Encrypt) {
      // Always generate a new IV
      this._iv = EncryptionServiceTools.generateIV();

      try {
        this._encryptedContents = await EncryptionServiceTools.encryptWithAPI(this._plainContents, this._key, this._iv);
      }
      catch (e) {
        stepCallback(Steps.Error);
        progressCallback(-1);
        throw new Error('Encryption failed: ' + e.message);
      }
      finally {
        // free input buffer to release memory
        this._plainContents = null;
      }
    }

    else if (mode == EncryptMode.Decrypt) {
      try {
        this._plainContents = await EncryptionServiceTools.decryptWithAPI(this._encryptedContents, this._key, this._iv);
      }
      catch (e) {
        stepCallback(Steps.Error);
        progressCallback(-1);
        throw new Error('Decryption failed: Invalid input file or invalid key.');
      }
      finally {
        // free input buffer to release memory
        this._encryptedContents = null;
      }
    }

    // report progress
    stepCallback(Steps.Finished);
    progressCallback(100);

    // wait 100 ms before finishing so stepCallback and progressCallback can be processed before
    return new Promise(resolve => setTimeout(resolve, 100));
  }


  /**
   * Generates download of the key file (via DOM element)
   * When a password is given, the key file is encrypted and stored serialized (base64)
   * When no password is given, the key file will be downloaded as a JWK JSON string
   * @param password Password to encrypt the key file with, or null for no encryption
   */
  async downloadKey(password?: string) {
    if (!this._key) throw new Error('No key available.');

    let filename = this._fileObj ? this._fileObj.name + '.key' : 'key.jwk';
    let json;

    try {
      json = password ?
          (await this.exportKeyEncryptedSerialized(<PasswordWrappingParams>{
            mode: WrappingMode.Password,
            password: password
          })) :

          // (await this.exportKeyJWKSerialized());
          // exporting unencrypted keyfiles as a JWK String (non-base64)
          // so an encrypted keyfile can be discerned from an unencrypted one more easily
          (await this.exportKeyJWKString());
    }
    catch (e) {
      throw new Error('Could not generate keyfile: ' + e.message);
    }

    EncryptionServiceTools.generateDownloadFromString(json, filename);
  }


  async generateEmailWithEncryptedKey(publicKeyItem: PublicKeyItem) {
    let wrappingKey;
    try {
      wrappingKey = await EncryptionServiceTools.importRSAKeyFromString(publicKeyItem.key, 'PUBLIC');
    }
    catch (e) {
      throw new Error('generateEmailWithEncryptedKey: Could not import public key. Error: ' + e.message);
    }

    let encryptedKey;
    try {
      encryptedKey = await this.exportKeyEncryptedSerialized(<KeyWrappingParams>{
        mode: WrappingMode.Key,
        key: wrappingKey
      });
    }
    catch (e) {
      throw new Error('generateEmailWithEncryptedKey: Could not export key encrypted with public key: '+e.message);
    }

    const mailbody = '-----BEGIN ENCRYPTED AES KEY-----\n' + encryptedKey + '\n-----END ENCRYPTED AES KEY-----';

    EncryptionServiceTools.generateEmail(
      publicKeyItem.name,
      publicKeyItem.email,
      'Keyfile for: ' + (this.fileObj ?
        EncryptionServiceTools.fileNameEncrypted(this.fileObj.name) :
        '(no file selected)'),
      mailbody
    );
  }



  /**
   * Generates a download of the processed (encrypted or decrypted) data.
   * Prepends the IV in encryption mode.
   * @param mode EncryptMode.Encrypt or EncryptMode.Decrypt
   */
  async downloadResult(mode: EncryptMode) {
    if (mode == EncryptMode.Encrypt) {
      EncryptionServiceTools.generateDownloadFromArrayBuffer(
        new Blob([this._iv, this._encryptedContents]),
        EncryptionServiceTools.fileNameEncrypted(this._fileObj.name)
      )
    }

    else if (mode == EncryptMode.Decrypt) {
      EncryptionServiceTools.generateDownloadFromArrayBuffer(
        new Blob([this._plainContents]),
        EncryptionServiceTools.fileNameDecrypted(this._fileObj.name)
      );
    }
  }


}





// noinspection ExceptionCaughtLocallyJS
export abstract class EncryptionServiceTools {

  /**
   * Maximum allowed key file size in bytes to avoid accidental import of very large files as keyfiles.
   * EncryptionServiceTools.importKeyFromFile will reject any key file larger than this.
   */
  static MaxKeyFileSize = 4000;

  static fileNameDecrypted(filename: string) {
    return filename.endsWith('.enc') ?
      filename.substr(0, filename.length - 4) :
      filename + '.decrypted';
  }

  static fileNameEncrypted(filename: string) {
    return filename + '.enc';
  }


  static async sha256(input: string) {
    const enc = new TextEncoder();
    const hash = await crypto.subtle.digest('SHA-256', enc.encode(input));

    return FileReaderTools.buffer2hex(hash);
  }


  /**
   * Generates a download of Blob `buffer` as `filename` via createObjectURL.
   * @param buffer Blob holding the data to download.
   * @param filename Filename to suggest for download
   */
  static generateDownloadFromArrayBuffer(buffer: Blob, filename: string) {
    // Code modified from download.js https://github.com/rndme/download, MIT License
    let elem = document.createElement("a");

    elem.href = self.URL.createObjectURL(buffer);
    elem.setAttribute("download", filename);
    elem.style.display = "none";

    document.body.appendChild(elem);

    setTimeout(() => {
        elem.click();
        document.body.removeChild(elem);
        setTimeout(() => { self.URL.revokeObjectURL(elem.href);}, 250 );
      },
      100);

  }

  /**
   * Generates a download of string `str` as `filename` via btoa (base64).
   * @param str String holding the data to download.
   * @param filename Filename to suggest for download
   */
  static generateDownloadFromString(str: string, filename: string) {
    let elem = document.createElement("a");

    elem.href = 'data:text/plain;base64,' + btoa(str);
    elem.setAttribute("download", filename);
    elem.style.display = "none";

    document.body.appendChild(elem);

    setTimeout(() => {
        elem.click();
        document.body.removeChild(elem);
      },
      100);
  }


  static generateEmail(mailtoname: string, mailtoaddress: string, subject: string, body: string) {
    const mailurl = 'mailto:' + encodeURIComponent(mailtoname) +
      '<' + encodeURIComponent(mailtoaddress) + '>' +
      '?subject=' + encodeURIComponent(subject) +
      '&body=' + encodeURIComponent(body);

    window.location.href = mailurl;
  }


  /**
   * Generates a 256 bit key for AES-GCM encryption and decryption. Wrapper for crypto.subtle.generateKey.
   */
  static async generateKey() {
    return self.crypto.subtle.generateKey(
      {
        name: EncryptionConfiguration.Algorithm,
        length: EncryptionConfiguration.KeyLength
      },
      true,
      ["encrypt", "decrypt"]
    );
  }

  /**
   * Exports a CryptoKey in the JWK format. Wrapper for crypto.subtle.exportKey.
   * @param key CryptoKey to export.
   */
  static async exportKey(key: CryptoKey) {
    return self.crypto.subtle.exportKey("jwk", key);
  }

  /**
   * Exports a CryptoKey in the JWK format as a string.
   * @param key CryptoKey to export.
   */
  static async exportKeyString(key: CryptoKey) {
    return JSON.stringify(await EncryptionServiceTools.exportKey(key));
  }

  /**
   * Exports a CryptoKey in the 'compact serialized' (base64) JWK format.
   * @param key CryptoKey to export.
   */
  static async exportKeySerialized(key: CryptoKey) {
    return btoa(await EncryptionServiceTools.exportKeyString(key));
  }

  static async exportWrappedRawKeySerialized(wrappedrawkey: ArrayBuffer, wrappingParams: WrappingParams) {

    let header;

    if (wrappingParams.mode == WrappingMode.Password) {
      header = {
        'alg': EncryptionConfiguration.KeyWrapAlgorithmName,
        'p2s': await FileReaderTools.arrayBufferToBase64((wrappingParams as PasswordWrappingParams).salt),
        'p2c': EncryptionConfiguration.KeyWrapHMACIterations,
        'enc': EncryptionConfiguration.AlgorithmName,
        'cty': 'raw'
      };
    }

    if (wrappingParams.mode == WrappingMode.Key) {
      header = {
        'alg': EncryptionConfiguration.RSAWrapAlgorithmName,
        'enc': EncryptionConfiguration.AlgorithmName,
        'cty': 'raw'
      };
    }

    let content = await FileReaderTools.arrayBufferToBase64(wrappedrawkey);

    return btoa(JSON.stringify(header)) + '.' + content;
  }

  /**
   *
   * Exceptions will pass-through.
   * @param header
   * @param rawEncryptedKey
   * @param password
   */
  static async importWrappedRawKeySerialized(header: JsonObject, rawEncryptedKey: ArrayBuffer, password: string) {
    if (
      typeof header['alg'] == 'string' && header['alg'] == EncryptionConfiguration.KeyWrapAlgorithmName &&
      typeof header['p2s'] == 'string' && (header['p2s'] as string).length > 0 &&
      typeof header['p2c'] == 'number' && (header['p2c'] as number) > 0 &&
      typeof header['enc'] == 'string' && header['enc'] == EncryptionConfiguration.AlgorithmName &&
      typeof header['cty'] == 'string' && header['cty'] == 'raw'
    ) {
      let derivedKey = await EncryptionServiceTools.deriveKeyFromPassword(
        password,
        await FileReaderTools.arrayBufferFromBase64(header['p2s']),
        header['p2c']);

      try {
        return await EncryptionServiceTools.unwrapKey(rawEncryptedKey, derivedKey, WrappingMode.Password);
      }
      catch (e) {
        // when unwrapKey fails, a wrong password is assumed
        throw new WrongPasswordError();
      }
    }

    throw new Error('importWrappedRawKeySerialized: Invalid header found.');
  }


  /**
   *
   * Exceptions will pass-through.
   * @param header
   * @param rawEncryptedKey
   * @param wrappingKey
   */
  static async importRSAWrappedRawKeySerialized(header: JsonObject, rawEncryptedKey: ArrayBuffer, wrappingKey: CryptoKey) {
    if (
      typeof header['alg'] == 'string' && header['alg'] == EncryptionConfiguration.RSAWrapAlgorithmName &&
      typeof header['enc'] == 'string' && header['enc'] == EncryptionConfiguration.AlgorithmName &&
      typeof header['cty'] == 'string' && header['cty'] == 'raw'
    ) {
      try {
        return await EncryptionServiceTools.unwrapKey(rawEncryptedKey, wrappingKey, WrappingMode.Key);
      }
      catch (e) {
        throw new WrongWrappingKeyError();
      }
    }

    throw new Error('importRSAWrappedRawKeySerialized: Invalid header found in encrypted keyfile.');
  }


  /**
   * Generates a `EncryptionConfiguration.IvLength` byte random IV using self.crypto.getRandomValues
   * @returns {Uint8Array}
   */
  static generateIV() {
    return self.crypto.getRandomValues(new Uint8Array(EncryptionConfiguration.IvLength));
  }

  /**
   * Derives a key from a password with PBKDF2 and AES-KW using crypto.subtle.importKey and crypto.subtle.deriveKey.
   * Specified in RFC 7518 as PBES2-HS512+A256KW
   * @param password Password to use.
   * @param salt Salt to use. "A Salt Input value containing 8 or more octets MUST be used. A new Salt Input value MUST be generated randomly for every encryption operation." (RFC 7518)
   * @param iterations Number of iterations of the HMAC function (a minimum of 1000 is recommended per RFC 7518)
   */
  static async deriveKeyFromPassword(password: string, salt: Uint8Array | ArrayBuffer, iterations: number) {
    const enc = new TextEncoder();
    let importedKey = await self.crypto.subtle.importKey(
      "raw",
      enc.encode(password),
      EncryptionConfiguration.KeyWrapKDF,
      false,
      ["deriveBits", "deriveKey"]
    );

    return self.crypto.subtle.deriveKey(
      {
        "name": EncryptionConfiguration.KeyWrapKDF,
        "salt": salt,
        "iterations": iterations,
        "hash": EncryptionConfiguration.KeyWrapHMAC
      },
      importedKey,
      {
        "name": EncryptionConfiguration.KeyWrapAlgorithm,
        "length": EncryptionConfiguration.KeyWrapKeyLength
      },
      true,
      ["wrapKey", "unwrapKey"]
    );
  }

  /**
   * Encrypts key `mainKey` with another key `wrapKey` with AES-KW. Wrapper for crypto.subtle.wrapKey.
   * @param mainKey Main key to encrypt
   * @param wrapKey Key to encrypt the mainKey with
   * @param mode WrappingMode to use
   */
  static async wrapKey(mainKey: CryptoKey, wrapKey: CryptoKey, mode: WrappingMode) {
    return self.crypto.subtle.wrapKey(
      "raw",
      mainKey,
      wrapKey,
      mode == WrappingMode.Password ?
        EncryptionConfiguration.KeyWrapAlgorithm :
        { name: EncryptionConfiguration.RSAWrapAlgorithm }
    );
  }

  /**
   * Decrypts key `wrappedKey` with `unwrappingKey` with AES-KW. Wrapper for crypto.subtle.unwrapKey.
   * Exceptions pass-through.
   * @param wrappedKey Encrypted key to decrypt
   * @param unwrappingKey Key to decrypt the wrappedKey with
   * @param mode WrappingMode to use
   */
  static async unwrapKey(wrappedKey: ArrayBuffer, unwrappingKey: CryptoKey, mode: WrappingMode) {
    return self.crypto.subtle.unwrapKey(
      "raw",
      wrappedKey,
      unwrappingKey,
      mode == WrappingMode.Password ?
        EncryptionConfiguration.KeyWrapAlgorithm :
        { name: EncryptionConfiguration.RSAWrapAlgorithm },
      EncryptionConfiguration.Algorithm,
      true,
      [ "encrypt", "decrypt" ]
    );
  }


  /**
   * Imports a key from keyFileObj, parses the content as JSON and calls crypto.subtle.importKey
   * Supported formats:
   *  - plain JSON JWK (jwk+json)
   *  - base64-encoded JSON JWK
   *  - base64-encoded encrypted raw key
   *  Throws a `WrongPasswordError` when keyfile is encrypted but a wrong or no password was specified.
   *  Throws an Error on failure.
   * @param keyFileObj
   * @param password Optional: password to decrypt the keyfile OR the wrapping keyfile. Ignored if keyfile is not encrypted.
   * @param wrappingKeyFileObj Optional: wrapping key to decrypt the keyfile with. May itself be password-encrypted.
   */
  static async importKeyFromFile(keyFileObj: File, password?: string, wrappingKeyFileObj?: File) {
    if (!keyFileObj) return null;

    // key files larger than MaxKeyFileSize are implausible - reject
    if (keyFileObj.size > EncryptionServiceTools.MaxKeyFileSize)
      throw new Error('Could not import keyfile (file too large).');

    let keyFileContents = await FileReaderTools.readFileAsTextAsync(keyFileObj);


    // First try: import as JSON JWK
    try {
      // will throw an exception when the import fails and therefore not return
      return await EncryptionServiceTools.importKeyFromFileAsJWK(keyFileContents);
    }
    catch (e) {}


    // Second try: import as base64
    try {
      // period (.) separates header from encrypted key
      let base64contents = keyFileContents.split('.');
      let headerdecoded = atob(base64contents[0]);
      let header = JSON.parse(headerdecoded);


      // plain keyfile. header == key then
      if (header['alg'] == EncryptionConfiguration.AlgorithmName) {
        return await EncryptionServiceTools.importKeyFromFileAsJWK(headerdecoded);
      }


      // password-encrypted keyfile. header == header, base64contents[1] == encrypted raw key
      if (header['alg'] == EncryptionConfiguration.KeyWrapAlgorithmName) {
        if (base64contents.length < 2) throw new Error('Header indicates an encrypted key, but no key was found.');

        if (!password) throw new WrongPasswordError('Please specify the password.');

        // importWrappedRawKeySerialized also throws a WrongPasswordError when the import fails
        return await EncryptionServiceTools.importWrappedRawKeySerialized(
          header,
          await FileReaderTools.arrayBufferFromBase64(base64contents[1].trim()),
          password);
      }


      // wrapping-keyfile-encrypted keyfile. same as above but requires another key file
      if (header['alg'] == EncryptionConfiguration.RSAWrapAlgorithmName) {

        if (base64contents.length < 2) throw new Error('Header indicates an encrypted key, but no key was found.');

        if (!wrappingKeyFileObj) throw new WrongWrappingKeyError('Please select an RSA key to decrypt the keyfile.');

        let wrappingKey;
        try {
          let wrappingKeyFileContents = await FileReaderTools.readFileAsTextAsync(wrappingKeyFileObj);

          wrappingKey = await EncryptionServiceTools.importRSAKeyFromString(wrappingKeyFileContents,'PRIVATE');
        }
        catch (e) {
          throw new WrappingKeyImportError('importKeyFromFile: Could not import RSA private key: ' + e.message);
        }

        return await EncryptionServiceTools.importRSAWrappedRawKeySerialized(
          header,
          await FileReaderTools.arrayBufferFromBase64(base64contents[1].trim()),
          wrappingKey
        );
      }

    }
    catch (e) {
      // rethrow the specific Errors so the caller can react accordingly
      if (e instanceof WrongPasswordError ||
          e instanceof WrappingKeyImportError ||
          e instanceof WrongWrappingKeyError) throw e;

      throw new Error('Another import error: ' + e.message);
    }


    // No more ways to import the keyfile: import has failed.
    throw new Error('Could not import keyfile ' + keyFileObj?.name);
  }


  /**
   * Import a string as JWK key. Use in try block to catch Exceptions.
   * @param keyFileContents
   */
  static async importKeyFromFileAsJWK(keyFileContents: string) {
    let json = JSON.parse(keyFileContents);

    return await self.crypto.subtle.importKey(
      "jwk",
      json,
      { "name": EncryptionConfiguration.Algorithm, "length": EncryptionConfiguration.KeyLength },
      true,
      [ "encrypt", "decrypt" ]
    );
  }


  static async importRSAKeyFromString(keyContents: string, keyType : 'PUBLIC' | 'PRIVATE') {
    const header = '-----BEGIN ' + keyType + ' KEY-----';
    const footer = '-----END ' + keyType + ' KEY-----';

    keyContents = keyContents.replace(/[\r\n]/g, '');

    const headerpos = keyContents.indexOf(header);
    const footerpos = keyContents.indexOf(footer);

    let contents: string;
    if (headerpos >= 0 || footerpos >= 0) contents = keyContents.substring(headerpos + header.length, footerpos);

    if (!contents) throw new Error('importRSAKeyFromString: No ' + keyType.toLowerCase() + ' RSA key provided.');

    console.log('importRSAKeyFromString: Importing key: '+contents.trim());

    if (keyType == 'PUBLIC') {
      return window.crypto.subtle.importKey(
        EncryptionConfiguration.RSAPublicKeyFormat,
        await FileReaderTools.arrayBufferFromBase64(contents.trim()),
        {
          name: EncryptionConfiguration.RSAWrapAlgorithm,
          hash: EncryptionConfiguration.RSAWrapHash
        },
        true,
        [ 'wrapKey' ]
      );
    }

    else if (keyType == 'PRIVATE') {
      return window.crypto.subtle.importKey(
        EncryptionConfiguration.RSAPrivateKeyFormat,
        await FileReaderTools.arrayBufferFromBase64(contents.trim()),
        {
          name: EncryptionConfiguration.RSAWrapAlgorithm,
          hash: EncryptionConfiguration.RSAWrapHash
        },
        true,
        [ 'unwrapKey' ]
      );
    }

  }



  static async rawKeyToJWK(rawkey: ArrayBuffer) {
    let key = await self.crypto.subtle.importKey(
      "raw",
      rawkey,
      { "name": EncryptionConfiguration.Algorithm, "length": EncryptionConfiguration.KeyLength },
      true,
      [ "encrypt", "decrypt" ]
    );

    return self.crypto.subtle.exportKey("jwk", key);
  }



  /**
   * Encrypts data with key and iv with EncryptionConfiguration.Algorithm. Wrapper for crypto.subtle.encrypt
   * @param data
   * @param key
   * @param iv
   */
  static async encryptWithAPI(data, key, iv) {
    return self.crypto.subtle.encrypt(
      { name: EncryptionConfiguration.Algorithm, iv },
      key,
      data
    );
  }

  /**
   * Decrypts data with key and iv with EncryptionConfiguration.Algorithm. Wrapper for self.crypto.subtle.decrypt
   * @param data
   * @param key
   * @param iv
   */
  static async decryptWithAPI(data, key, iv) {
    return self.crypto.subtle.decrypt(
      { name: EncryptionConfiguration.Algorithm, iv },
      key,
      data
    );
  }




}
