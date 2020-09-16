import { fromByteArray, toByteArray } from "base64-js";

export interface IProgressUpdate {
  (progress: number): void;
}

/**
 * Provides low-level functions for file I/O and base64 conversion
 */
export class FileReaderTools {

  /**
   * Creates a FileReader object and reads contents from file as an ArrayBuffer. Executes async and returns a Promise.
   * @param file File object to read
   * @param progressCallback Callback function to report the current progress to
   * @returns {Promise<ArrayBuffer>}
   */
  static async readFileAsArrayBufferAsync(file: File | Blob, progressCallback?: IProgressUpdate) {
    return new Promise<ArrayBuffer>((resolve, reject) => {
      let fr = new FileReader();

      fr.addEventListener('load', (e) => {
        resolve(e.target.result as ArrayBuffer);
      });

      let onAbortOrError = (e: ProgressEvent<FileReader>) => { reject(new Error('FileReader: '+e.target.error)); };
      fr.addEventListener('error', onAbortOrError);
      fr.addEventListener('abort', onAbortOrError);

      if (progressCallback) {
        let onProgress = (e: ProgressEvent<FileReader>) => { progressCallback(Math.floor(e.loaded / e.total * 100)); };

        // do not listen to 'load' and 'loadend', they may fire after completion:
        fr.addEventListener('loadstart', onProgress);
        fr.addEventListener('progress', onProgress);
      }

      fr.readAsArrayBuffer(file);
    });
  }


  /**
   * Creates a FileReader object and reads contents from file as a String. Executes async and returns a Promise.
   * @param file File object to read
   * @returns {Promise<String>}
   */
  static async readFileAsTextAsync(file: File | Blob) {
    return new Promise<string>((resolve, reject) => {
      let fr = new FileReader();

      fr.onabort = fr.onerror = ((e) => { reject(new Error('FileReader: '+e.target.error)); });
      fr.onload = ((e) => { resolve(e.target.result as string); });

      fr.readAsText(file);
    });
  }



  /**
   * Encodes ArrayBuffer buffer as a base64 string using base64-js
   * @param buffer
   */
  static async arrayBufferToBase64(buffer: ArrayBuffer) {
    return fromByteArray(new Uint8Array(buffer));
  }

  /**
   * Decodes a base64 string into an ArrayBuffer using base64-js
   * @param base64 String to be converted. Must not contain any whitespaces (replace or trim before passing).
   */
  static async arrayBufferFromBase64(base64: string) {
    return toByteArray(base64).buffer;
  }

  /**
   * Returns the hexadecimal representation of ArrayBuffer buffer
   * @param buffer
   */
  static buffer2hex(buffer: ArrayBuffer): string {
    return Array.prototype.map.call(
      new Uint8Array(buffer),
      (x: number) => ('00' + x.toString(16)).slice(-2)
    ).join('');
  }
}
