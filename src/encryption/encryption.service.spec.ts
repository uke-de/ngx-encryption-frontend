import { TestBed } from '@angular/core/testing';
import { EncryptionService, EncryptionServiceTools } from './encryption.service';
import { HttpClientModule, HttpClient } from "@angular/common/http";


async function getTextAsset(http: HttpClient, url: string) {
  let contents;

  await http.get(url, { responseType: 'text' }).toPromise().then(
    (value) => { contents = value; }
  );

  return contents;
}


describe('EncryptionService', () => {
  let service: EncryptionService;
  let http: HttpClient;

  beforeEach(() => {
    TestBed.configureTestingModule({
      imports: [ HttpClientModule ],
      providers: [ HttpClient, EncryptionService ]
    });

    service = TestBed.inject(EncryptionService);
    http = TestBed.inject(HttpClient);
  });



  it('should be created', () => {
    expect(service).toBeTruthy();
  });



  it('should import and export JWK key', async () => {

    let keyfilecontents = await getTextAsset(http, '/base/test/testkey.jwk');

    if (!keyfilecontents) {
      fail('No key file contents retrieved.');
      return;
    }

    // Convert text to a virtual file via Blob
    let blob = new Blob([keyfilecontents], { type: 'text/plain' });
    blob["lastModifiedDate"] = "";
    blob["name"] = "filename";

    let blobFile = <File>blob;

    // Import the virtual file and export as JWK string
    await service.importKey(blobFile);
    let keyexported = await service.exportKeyJWKString();

    expect(keyexported).toBe(keyfilecontents);
  });

});




describe('EncryptionServiceTools', () => {

  let http: HttpClient;

  beforeEach(() => {
    TestBed.configureTestingModule({
      imports: [ HttpClientModule ],
      providers: [ HttpClient ]
    });

    http = TestBed.inject(HttpClient);
  });




  it('should import JWK key', async () => {
    let keyfilecontents = await getTextAsset(http, '/base/test/testkey.jwk');

    if (!keyfilecontents) {
      fail('Could not retrieve content of testkey.jwk');
      return;
    }

    // console.log(keyfilecontents);

    let key = await EncryptionServiceTools.importKeyFromFileAsJWK(keyfilecontents);
    let keyexported = await EncryptionServiceTools.exportKey(key);

    expect(keyexported.k).toBe('x0-KVTzGjSXyO3DleyzLT-1fI2jqMqX42OLjPCW8XbQ');
  });





  it('should import RSA public key', async () => {
    let keyfilecontents = await getTextAsset(http, '/base/test/rsa_key.pub');

    if (!keyfilecontents) {
      fail('Could not retrieve content of rsa_key.pub');
      return;
    }

    // console.log(keyfilecontents);

    let key = await EncryptionServiceTools.importRSAKeyFromString(keyfilecontents, 'PUBLIC');
    let keyexported = await EncryptionServiceTools.exportKey(key);

    // console.log('RSA public key is '+keyexported);

    expect(keyexported.alg).toBe('RSA-OAEP-256');
    expect(keyexported.n).toBe('0Pc6hrmgfBWfwfpLpKvOn1b3xPoNL3SIWkoqbI35Q_kEe1Jub1_Eit1pGdwmRsE3ciMf_8GJX7Sd4TxJp_cVlNL9JbuDz4tYB46jQpcUi3DUe0ps9Q7BESeT5Z59Bu4HMShQ5ZP9NOydig7Ky4P_7CL4ZLyP-hSO8hjnyEFC-3sMfGBRTSBjELgRHhH9DE1lzdas2AhYMhBpZu9SyVtFJIvXo3ikNuWdhGI5mEDINHIYCUd9ZPWlJ1z9hePmjkf9zz2_Q16_5zMwoYhEaPfHnoVTPmB62WbCqXlEpEEcIcWOfqJtYQVb68s53KZbvnOBkCoHw5KdSvq_1iCytGm_UQ');

  });





  it('should import RSA private key', async () => {
    let keyfilecontents = await getTextAsset(http, '/base/test/rsa_key');

    if (!keyfilecontents) {
      fail('Could not retrieve content of rsa_key');
      return;
    }

    // console.log(keyfilecontents);

    let key = await EncryptionServiceTools.importRSAKeyFromString(keyfilecontents, 'PRIVATE');
    let keyexported = await EncryptionServiceTools.exportKey(key);

    // console.log('RSA private key is '+JSON.stringify(keyexported));

    expect(keyexported.alg).toBe('RSA-OAEP-256');
    expect(keyexported.p).toBe('9syvvc6mEKaA-0y1ypose9F1zU_0yNxbcpA02WtcMhrIMfMhiLUjulx1P_K2CMtm_Z0fRQ_QPAmYN4PmtysAab2cc4wwBIlh8QAl_WB6hpR5BW6pO4Q8Tlni2F8xLolFw9-vCXco6ReDrdtzBKISiNGat4vBZ6u-AyHtCNMWr7U');

  });

});
