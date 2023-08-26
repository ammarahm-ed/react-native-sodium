export type FileCipher = {
  salt?: string;
  hash?: string;
  hashType?: string;
  iv?: string;
  length?: number;
  mime?: string;
  fileName?: string;
  uri?: string;
  appGroupId?: string;
};

export type Password = {
  key?: string;
  salt?: string;
  password?: string;
};

export type Cipher = {
  salt: string;
  iv: string;
  length: number;
  cipher?: string;
};
