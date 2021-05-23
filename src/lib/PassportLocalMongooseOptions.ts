import { Document, FilterQuery, Model, PassportLocalErrorMessages, PassportLocalOptions } from 'mongoose';
import { promisify } from 'util';

class PassportLocalMongooseOptions implements PassportLocalOptions{
  saltlen: number;
  iterations: number;
  keylen: number;
  encoding: string;
  digestAlgorithm: string;
  passwordValidator: (password: string, cb: (err: any) => void) => void;
  passwordValidatorAsync: (password: string) => void;
  usernameField: string;
  usernameUnique: boolean;
  usernameQueryFields: Array<string>;
  usernameCaseInsensitive: boolean;
  selectFields: string;
  populateFields: string;
  usernameLowerCase: boolean;
  hashField: string;
  saltField: string;
  limitAttempts: boolean;
  lastLoginField?: string;
  attemptsField?: string;
  interval?: number;
  maxInterval?: number;
  maxAttempts?: number;
  findByUsername: (userModel: Model<any>, queryParameters: FilterQuery<any>) => Document;
  errorMessages: PassportLocalErrorMessages;

  constructor(options?: PassportLocalOptions | any) {
    const defaultUsernameField: string = 'username';
    function defaultPasswordValidator(password: string, cb: any): void {
      cb(null);
    }

    this.saltlen = options?.saltlen ?? 32;
    this.iterations = options?.iterations ?? 25000;
    this.keylen = options?.keylen ?? 512;
    this.encoding = options?.encoding ?? 'hex';
    this.digestAlgorithm = options?.digestAlgorithm ?? 'sha256';
    this.passwordValidator = options?.passwordValidator ?? defaultPasswordValidator;
    this.passwordValidatorAsync = options?.passwordValidatorAsync ?? promisify(this.passwordValidator);
    this.usernameField = options?.usernameField ?? defaultUsernameField;
    this.usernameUnique = options?.usernameUnique ?? true;
    this.usernameQueryFields = [this.usernameField];
    if (options?.usernameQueryFields) {
      this.usernameQueryFields = [...this.usernameQueryFields, ...options.usernameQueryFields];
    }
    this.usernameCaseInsensitive = options?.usernameCaseInsensitive ?? false;
    this.usernameLowerCase = options?.usernameLowerCase ?? false;
    this.selectFields = options?.selectFields;
    this.populateFields = options?.populateFields;
    this.hashField = options?.hashField ?? 'hash';
    this.saltField = options?.saltField ?? 'salt';

    this.limitAttempts = options?.limitAttempts ?? false;

    if (this.limitAttempts) {
      this.lastLoginField = options.lastLoginField ?? 'last';
      this.attemptsField = options.attemptsField ?? 'attempts';
      this.interval = options.interval ?? 100; //100 ms
      this.maxInterval = options.maxInterval ?? 5 * 60 * 1000; // 5 minutes
      this.maxAttempts = options.maxAttempts ?? Infinity;
    }

    this.findByUsername =
      options?.findByUsername ?? ((userModel: Model<any>, queryParameters: FilterQuery<any>) => userModel.findOne(queryParameters));
    this.errorMessages = options?.errorMessages ?? {};
    // leaving errorMessage creation in index.js for now
  }
}

module.exports = PassportLocalMongooseOptions;
