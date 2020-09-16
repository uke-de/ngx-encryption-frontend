import { Component, ViewEncapsulation } from '@angular/core';
import { Title } from "@angular/platform-browser";
import { VersionInfo } from "../version";
import { HttpClient } from "@angular/common/http";



export interface PublicKeyItem {
  name: string,
  email: string,
  key: string
}

export interface PublicKeysJson {
  public_keys: PublicKeyItem[]
}


@Component({
  selector: 'app-root',
  templateUrl: './app.component.html',
  styleUrls: ['./app.component.sass'],

  /// Encapsulation is being realized by the CSS itself
  encapsulation: ViewEncapsulation.None
})
export class AppComponent {
  title = 'ngx-encryption-frontend';

  versionShort = '0.0.0';
  versionLong  = '0.0.0-dev';

  buildYear = '';

  publicKeys: PublicKeyItem[] = [];

  public constructor(
    private titleService: Title,
    private versionInfo: VersionInfo,
    private http: HttpClient
  ) {
    this.titleService.setTitle($localize`:@@app.title:Web Encryption Frontend`);

    this.versionLong  = this.versionInfo.versionLong;
    this.versionShort = this.versionInfo.versionShort;

    this.buildYear    = this.versionInfo.buildYear;

    this.getPublicKeys();
  }


  private getPublicKeys() {
    this.http.get<PublicKeysJson>('assets/public_keys.json').toPromise().then(
      (value) => { this.publicKeys = value.public_keys; }
    );
  }
}
