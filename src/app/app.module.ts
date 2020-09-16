import {BrowserModule, Title} from '@angular/platform-browser';
import {NgModule} from '@angular/core';

import { AppComponent } from './app.component';
import { BrowserAnimationsModule } from '@angular/platform-browser/animations';

import { EncryptionModule } from "../encryption/encryption.module";
import {HttpClientModule} from "@angular/common/http";

// import { Observable, throwError } from 'rxjs';
// import { catchError, retry } from 'rxjs/operators';

@NgModule({
  declarations: [
    AppComponent
  ],
  imports: [
    BrowserModule,
    BrowserAnimationsModule,

    HttpClientModule,

    EncryptionModule
  ],
  providers: [Title],
  bootstrap: [AppComponent]
})
export class AppModule { }
