import { Injectable } from "@angular/core";
// @ts-ignore
import gitVersion from "../git-version.json";


@Injectable({
  providedIn: 'root'
})
export class VersionInfo {
  readonly version:string = gitVersion?.version ?? 'dev';
  readonly versionLong = this.version;
  readonly versionShort = this.version.replace(/-.*/, '');

  readonly buildDate:string = gitVersion?.date ?? '';
  readonly buildYear = this.buildDate.replace(/-.*/, '');
}
