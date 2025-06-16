export type FileCipher = {
  salt: string;
  hash: string;
  hashType: string;
  iv: string;
  size: number;
  mime: string;
  fileName: string;
  uri: string;
  appGroupId: string;
  chunkSize: number
};

export type Password = {
  key?: string;
  salt?: string;
  password?: string;
};

export type Cipher<OutputType = "base64"> = {
  format: OutputType;
  salt: string;
  iv: string;
  length: number;
  cipher: string;
  output?: 'plain'
};
