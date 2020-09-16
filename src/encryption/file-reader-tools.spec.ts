import { FileReaderTools } from './file-reader-tools';

describe('FileReaderTools', () => {

  it('should base64-encode and decode 10 random buffers of lengths 1 to 100',  async () => {

    for (let i = 0; i < 10; i++) {
      let randomlen = Math.ceil(Math.random() * 100);
      let buf = self.crypto.getRandomValues(new Uint8Array(randomlen));


      // base64 encode and decode again
      let base64 = await FileReaderTools.arrayBufferToBase64(buf);
      let base64dec = new Uint8Array(await FileReaderTools.arrayBufferFromBase64(base64));

      expect(buf.every(
        (value, index) => value === base64dec[index]
      )).toBeTrue();
    }
  });


});
