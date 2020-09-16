import { NgModule } from '@angular/core';
import { CommonModule } from '@angular/common';

import {EncryptionComponent, KeyfilePasswordDialog} from './encryption.component';

import { MatExpansionModule } from '@angular/material/expansion';
import { FormsModule, ReactiveFormsModule } from "@angular/forms";

import {MatButtonModule} from '@angular/material/button';
import {MatProgressSpinnerModule} from "@angular/material/progress-spinner";
import {MatDividerModule} from "@angular/material/divider";
import {MatStepperModule} from "@angular/material/stepper";
import {MatFormFieldModule} from "@angular/material/form-field";
import {MatSelectModule} from "@angular/material/select";
import {MatInputModule} from "@angular/material/input";
import {MatTooltipModule} from "@angular/material/tooltip";
import {MatProgressBarModule} from "@angular/material/progress-bar";
import {MatIconModule} from "@angular/material/icon";
import {MatCheckboxModule} from "@angular/material/checkbox";
import {MatDialogModule} from "@angular/material/dialog";
import {ByteFormatPipeModule} from "../external/byte-format.pipe";

@NgModule({
  declarations: [EncryptionComponent, KeyfilePasswordDialog],
  imports: [
    CommonModule,

    MatExpansionModule,
    MatButtonModule,
    MatProgressSpinnerModule,
    MatDividerModule,
    ReactiveFormsModule,
    MatStepperModule,
    MatFormFieldModule,
    MatSelectModule,
    MatInputModule,
    ByteFormatPipeModule,
    FormsModule,
    MatTooltipModule,
    MatProgressBarModule,
    MatIconModule,
    MatCheckboxModule,
    MatDialogModule
  ],

  exports: [
    EncryptionComponent
  ]
})
export class EncryptionModule {



}

