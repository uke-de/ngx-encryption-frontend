import {Component, EventEmitter, Inject, Input, OnInit, Output, ViewEncapsulation} from '@angular/core';
import {FormBuilder} from "@angular/forms";
import {EncryptionService, EncryptMode, WrongPasswordError, Steps, WrongWrappingKeyError, WrappingKeyImportError} from "./encryption.service";
import {MatSnackBar} from "@angular/material/snack-bar";
import {MAT_DIALOG_DATA, MatDialog, MatDialogRef, MatDialogState} from "@angular/material/dialog";
import {PublicKeyItem} from "../app/app.component";
// import {FileReaderTools} from "./file-reader-tools";



enum KeySource {
  Generated,
  Imported
}

interface KeyfileWithPasswordOrWrappingKey {
  keyfile: File,
  password?: string,
  wrappingKeyFile?: File
}

@Component({
  selector: 'app-encryption',
  templateUrl: './encryption.component.html',
  styleUrls: ['./encryption.component.sass'],

  /// Encapsulation is being realized by the CSS itself
  encapsulation: ViewEncapsulation.None,

  providers: [
    EncryptionService,
    MatSnackBar
  ]
})
export class EncryptionComponent implements OnInit {

  /** The minimum password length allowed by the component to encrypt keyfiles */
  static MinKeyfilePasswordLength = 8;

  // Enum 'imports'
  KeySource = KeySource;
  Steps = Steps;
  EncryptMode = EncryptMode;


  /** Mode = 'encrypt' | 'decrypt'
   * Usage: <app-encryption mode="encrypt">
   *   Note: Any value other than 'decrypt' will make the component operate in encrypt mode
   */
  @Input('mode') _mode: string = 'encrypt';

  // getters for convenience
  get getMode()       { return this._mode == 'decrypt' ? EncryptMode.Decrypt : EncryptMode.Encrypt; }
  get isEncryptMode() { return this.getMode == EncryptMode.Encrypt; }
  get isDecryptMode() { return this.getMode == EncryptMode.Decrypt; }


  @Input('publicKeys') publicKeys: PublicKeyItem[] = [];

  /**
   * The maximum file size which the component will allow. Default is EncryptionService.maxFileSize.
   * Note that the EncryptionService does NOT impose any limits, only the EncryptionComponent does.
   * It may be overridden with the maxFileSize attribute, e. g.:
   * - <app-encryption maxFileSize="1024000">
   * - <app-encryption [maxFileSize]="1024*1024*200">
   */
  get maxFileSize() {
    // allow for additional EncryptionService.IvLength bytes in decryption mode
    let ivsize = this.isDecryptMode ? EncryptionService.IvLength : 0;

    return (this._maxFileSize && this._maxFileSize > 0) ?
      this._maxFileSize + ivsize :
      this._encryptionService.maxFileSize + ivsize;
  }

  /**
   * Specifies the maximum file size allowed for encryption and decryption.
   */
  @Input('maxFileSize') _maxFileSize: number;


  inputFile: File;
  inputKeyFile: File;

  /**
   * Input key, for validation (key present or not) and display only.
   * Can be obfuscated to avoid displaying the real key.
   */
  inputKey: string;

  /**
   * Stores whether the key has been generated or imported. For display only.
   */
  keySource: KeySource;

  /**
   * Stores whether the key file has been downloaded.
   */
  keyFileDownloaded = false;

  /**
   * The current step, for application behaviour and progress indication.
   */
  currentStep = Steps.Idle;

  /**
   * The current progress (0-100) for progress bar display. -1 = indeterminate
   */
  currentProgress = -1;


  /// Form fields

  encryptKeyfile = false;

  keyfilePassword = '';
  keyfilePasswordConfirm = '';
  keyfilePasswordVisible = false;

  _keyfilePasswordDialogRef: MatDialogRef<KeyfilePasswordDialog>;


  /**
   * Validates the entered password for keyfile encryption.
   */
  get keyfilePasswordIsValid() {
    if (!this.encryptKeyfile)
      return true;

    if (this.keyfilePassword.length < EncryptionComponent.MinKeyfilePasswordLength)
      return false;

    return this.keyfilePasswordVisible || this.keyfilePassword == this.keyfilePasswordConfirm;
  }


  emailRecipient: string;


  get encryptionAlgorithm() { return this._encryptionService.EncryptionAlgorithm; }
  get encryptionKeyLength() { return this._encryptionService.EncryptionKeyLength; }


  constructor(
    private _formBuilder: FormBuilder,
    private _encryptionService: EncryptionService,
    private _snackBar: MatSnackBar,
    public matDialog: MatDialog
  ) {
  }





  ngOnInit(): void {
  }




  toggleKeyfilePasswordVisible() {
    this.keyfilePasswordVisible = !this.keyfilePasswordVisible;

    // sync confirm password on hide
    if (!this.keyfilePasswordVisible) this.keyfilePasswordConfirm = this.keyfilePassword;
  }


  async onInputFileSelect(file: File) {
    if (!file) return;

    if (file.size > this.maxFileSize) {
      this.userNotice($localize`:@@error.fileTooLarge:Input file ${file.name}:filename: is too large.`);
      return;
    }

    this.inputFile = file;
    this._encryptionService.fileObj = file;

    this.resetStatus(false);
  }


  async generateKey() {
    await this._encryptionService.generateKey();
    this.keySource = KeySource.Generated;

    this.resetStatus(); // reset status and invalidate previous encryption, if any

    return this.updateKeyFromService(); // pass-through of the Promise
  }


  async updateKeyFromService() {
    this.inputKey = await this._encryptionService.exportKeyString(true, 7);
  }


  async importKeyFile(file: File, password?: string, wrappingkeyfile?: File) {
    if (!file) return;

    try {
      await this._encryptionService.importKey(file, password, wrappingkeyfile);
    }
    catch (e) {
      if (e instanceof WrongPasswordError) {
        console.log(e.message);
        this.createOrRetryKeyfilePasswordModal(file, true, false, e);
        return;
      }

      if (e instanceof WrongWrappingKeyError || e instanceof WrappingKeyImportError) {
        console.log(e.message);
        this.createOrRetryKeyfilePasswordModal(file, false, true, e);
        return;
      }

      this.userNotice($localize`:@@error.keyfileImportFailed:Could not import keyfile ${file.name}:filename:`);
      console.log(e.message);

      return;
    }

    this.closeKeyFilePasswordModal(); // close, if it exists

    this.inputKeyFile = file;
    this.keySource = KeySource.Imported;

    this.resetStatus();

    return this.updateKeyFromService(); // pass-through of the Promise
  }


  createOrRetryKeyfilePasswordModal(file: File, needsPassword = false, needsKeyfile = false, error?: WrongPasswordError | WrappingKeyImportError | WrongWrappingKeyError) {

    const dialogData = <KeyfilePasswordDialogData>{
      keyfile: file,
      needsPassword: needsPassword,
      needsKeyfile: needsKeyfile
    };

    // Check if an existing instance of the modal can be reused
    // dialogData may change in the future during the lifecycle of the modal - if so, destroy and re-create the modal
    if (this._keyfilePasswordDialogRef &&

      this._keyfilePasswordDialogRef.getState() == MatDialogState.OPEN &&

      this._keyfilePasswordDialogRef.componentInstance.dialogData.keyfile == dialogData.keyfile &&
      this._keyfilePasswordDialogRef.componentInstance.dialogData.needsPassword == dialogData.needsPassword &&
      this._keyfilePasswordDialogRef.componentInstance.dialogData.needsKeyfile == dialogData.needsKeyfile) {
        // do nothing
    }
    else {
      // destroy any old instances first - nulls this._keyfilePasswordDialogRef
      this.closeKeyFilePasswordModal();
    }

    // Create modal
    if (!this._keyfilePasswordDialogRef) {
      this._keyfilePasswordDialogRef = this.matDialog.open<KeyfilePasswordDialog, KeyfilePasswordDialogData>(
        KeyfilePasswordDialog,
        { data: dialogData }
      );

      // remove reference on dialog close
      this._keyfilePasswordDialogRef.afterClosed().subscribe(() => {
        this._keyfilePasswordDialogRef = null;
      });

      // listen for clicks on import
      this._keyfilePasswordDialogRef.componentInstance.importClicked.subscribe(
        (data: KeyfileWithPasswordOrWrappingKey) => {

          // call importKeyFile again with the given password
          // importKeyFile will call this function again when the password is wrong
          this.importKeyFile(data.keyfile, data.password, data.wrappingKeyFile);
        }
      );
    }

    if (error) this._keyfilePasswordDialogRef.componentInstance.reportError(error);
  }


  closeKeyFilePasswordModal() {
    if (this._keyfilePasswordDialogRef instanceof MatDialogRef) {
      this._keyfilePasswordDialogRef.componentInstance.importClicked.unsubscribe();
      this._keyfilePasswordDialogRef.close();
    }

    this._keyfilePasswordDialogRef = null;
  }


  /** Resets the status properties to their defaults
   *
   * @param newKeyFile Whether a new keyfile has been loaded. newKeyFile = true will also reset this.keyFileDownloaded.
   */
  resetStatus(newKeyFile = true) {
    this.currentStep = Steps.Idle;
    this.currentProgress = -1;
    if (newKeyFile) this.keyFileDownloaded = false;

    this._encryptionService.clearContents();
  }

  async encryptAndDownload() {
    // assertions - not translated because they should not occur normally
    if (!this.inputFile) throw new Error('No input file selected.');
    if (!this.inputKey) throw new Error('No key selected.');

    let starttime, endtime;

    /// only start encryption when idle
    if (this.currentStep == Steps.Idle) {
      starttime = performance.now();

      const message = this.isEncryptMode ?
        $localize`:@@notice.encryptingFileX:Encrypting file ${this.inputFile.name}:filename:...` :
        $localize`:@@notice.decryptingFileX:Decrypting file ${this.inputFile.name}:filename:...`;
      this.userNotice(message);

      try {
        await this._encryptionService.encryptOrDecrypt(
          this.inputFile,
          this.getMode,
          (step) => { this.currentStep = step; },
          (progress) => { this.currentProgress = (0 <= progress && progress <= 100) ? progress : -1; }
        );
      }
      catch (e) {
        this.userNotice(e.message);

        this.currentStep = Steps.Error;
        this.currentProgress = -1;

        return;
      }

      endtime = performance.now();

      const duration = Math.round((endtime - starttime) / 100)/10;
      const message2 = this.isEncryptMode ?
        $localize`:@@notice.encryptedFileInTDownloading:File encrypted in ${duration}:seconds: s. Downloading...` :
        $localize`:@@notice.decryptedFileInTDownloading:File decrypted in ${duration}:seconds: s. Downloading...`;
      this.userNotice(message2);
    }

    // start download if finished
    if (this.currentStep == Steps.Finished) {
      // when no starttime was set, the file will be retrieved from memory
      if (!starttime) {
        const message3 = this.isEncryptMode ?
          $localize`:@@notice.restartingDownloadEncrypted:Restarting download of encrypted file...` :
          $localize`:@@notice.restartingDownloadDecrypted:Restarting download of decrypted file...` ;
        this.userNotice(message3);
      }

      return this._encryptionService.downloadResult(this.getMode); // pass-through Promise<void>
    }
  }


  /**
   * Initiates a download of the keyfile in the EncryptionService.
   * The password to encrypt the keyfile with will be passed along if set.
   * Does NOT check whether the password is valid (minimum requirements, confirmation),
   * use this.keyfilePasswordIsValid if this is desired.
   */
  async downloadKeyFile() {
    // Pass the password to encrypt the keyfile with or null for unencrypted keyfile
    let password = this.encryptKeyfile ? this.keyfilePassword : null;

    try {
      await this._encryptionService.downloadKey(password);
    }
    catch (e) {
      this.userNotice($localize`:@@error.downloadKeyFile:Could not download the keyfile` + ': ' + e.message);
      return;
    }

    this.keyFileDownloaded = true;
  }




  async generateKeyfileEmail() {

    if (!this.emailRecipient) return;

    let recipient = this.publicKeys.find((pk) => pk.name == this.emailRecipient);
    if (!recipient) return;

    this._encryptionService.generateEmailWithEncryptedKey(recipient);
  }



  userNotice(message: string, action?: string) {
    this._snackBar.open(message, action, {duration: 5000, panelClass: 'app-encryption-snackbar'});
    console.log('User notice: ' + message);
  }
}



interface KeyfilePasswordDialogData {
  keyfile: File,
  needsPassword: boolean,
  needsKeyfile: boolean
}


@Component({
  selector: 'keyfile-password-dialog',
  templateUrl: 'keyfile-password-dialog.html',
  styleUrls: ['./keyfile-password-dialog.css']
})
export class KeyfilePasswordDialog {

  // whether the user is retrying or not
  retryPassword = false;
  password = '';
  passwordVisible = false;

  wrappingKeyFile: File;

  tries = 0;

  // these have been moved into dialogData
  // needsPassword: boolean;
  // needsKeyfile:
  // keyfile: File;boolean;

  dialogData: KeyfilePasswordDialogData;


  @Output() importClicked = new EventEmitter<KeyfileWithPasswordOrWrappingKey>();

  constructor(
    public dialogRef: MatDialogRef<KeyfilePasswordDialog>,
    @Inject(MAT_DIALOG_DATA) public _data: KeyfilePasswordDialogData
    ) {
    // this..keyfile = _data.keyfile;
    // this.needsPassword = _data.needsPassword;
    // this.needsKeyfile = _data.needsKeyfile;
    this.dialogData = _data;
  }


  onImportClick() {
    let event = <KeyfileWithPasswordOrWrappingKey>{
      keyfile: this.dialogData.keyfile
    };

    if (this.dialogData.needsPassword) event.password        = this.password;
    if (this.dialogData.needsKeyfile)  event.wrappingKeyFile = this.wrappingKeyFile;

    this.importClicked.emit(event);
    this.tries++;
  }

  onNoClick() {
    this.dialogRef.close();
  }

  reportError(error: WrongPasswordError | WrappingKeyImportError | WrongWrappingKeyError ) {

    if (this.tries > 0) {
      this.retryPassword = true;
      setTimeout(() => { this.retryPassword = false; }, 300);
    }

    if (error instanceof WrongPasswordError) {
      console.log('KeyfilePasswordDialog: wrong password.');
    }

    if (error instanceof WrappingKeyImportError) {
      console.log('KeyfilePasswordDialog: wrapping key import failed.');
    }

    if (error instanceof WrongWrappingKeyError) {
      console.log('KeyfilePasswordDialog: wrong wrapping key.');
    }
  }

}
